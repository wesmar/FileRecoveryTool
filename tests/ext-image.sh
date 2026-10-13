#!/bin/bash
# ext-image.sh <disk size> - the ext2/3/4 recovery test disk, made by the Linux
# kernel in WSL: three partitions (ext4, ext3, ext2) get files with known
# contents, then lose them the ways people lose files on Linux - rm, rm -r,
# half of a directory - and are unmounted cleanly. Prints one line per file
# the deletion took:  MANIFEST <fs>|<case>|<path>|<size>|<sha256>
# The disk is found by its size.
size=$1
fixtures=${2:-}
mapfile -t disks < <(lsblk -b -o NAME,SIZE,TYPE -n -d | awk -v s="$size" '$2==s && $3=="disk" {print $1}')
[ "${#disks[@]}" -ne 1 ] && { echo "expected exactly one isolated test disk, found ${#disks[@]}"; exit 2; }
dev=/dev/${disks[0]}
set -e
echo 'label: gpt
size=160MiB, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4
size=120MiB, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4
type=0FC63DAF-8483-4772-8E79-3D69D8477DE4' | sfdisk -q "$dev"
sleep 1
mkfs.ext4 -q -F -L FRText4 -J size=16 "${dev}1"
mkfs.ext3 -q -F -L FRText3 -J size=16 "${dev}2"
mkfs.ext2 -q -F -L FRText2 "${dev}3"

gen=$(mktemp)
cat > "$gen" <<'EOF'
import hashlib, os, random, sys
# put <seed> <size> <kind> <path>: deterministic bytes, prints the sha256
seed, size, kind, path = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
r = random.Random(seed)
data = bytearray(r.getrandbits(8) for _ in range(size)) if size < 65536 else bytearray(r.randbytes(size))
if kind == 'txt':
    data = bytearray(0x41 + b % 26 for b in data)
elif kind == 'jpg' and size >= 16:
    data[0:11] = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0, 16, 0x4A, 0x46, 0x49, 0x46, 0])
    for i in range(11, size - 2):
        if data[i] == 0xFF: data[i] = 0xFE
    data[-2:] = bytes([0xFF, 0xD9])
os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
with open(path, 'wb') as f:
    f.write(data)
print(hashlib.sha256(data).hexdigest())
EOF

declare -A SHA
put() {   # put <seed> <size> <kind> <rel>
    SHA["$4"]=$(python3 "$gen" "$1" "$2" "$3" "$mnt/$4")
    SIZE["$4"]=$2
}
declare -A SIZE
gone() {  # gone <fs> <case> <rel>
    echo "MANIFEST $1|$2|$3|${SIZE[$3]}|${SHA[$3]}"
}

mnt=$(mktemp -d)
for part in 1 2; do
    fs=$([ $part = 1 ] && echo ext4 || echo ext3)
    mount "${dev}${part}" "$mnt"
    media=()
    if [ -n "$fixtures" ]; then
        for file in "$fixtures"/*; do
            [ -f "$file" ] || continue
            rel=${file##*/}
            cp "$file" "$mnt/$rel"
            SHA["$rel"]=$(sha256sum "$file" | cut -d' ' -f1)
            SIZE["$rel"]=$(stat -c%s "$file")
            media+=("$rel")
        done
    fi
    put 1 120 txt tiny.txt
    put 3 300000 jpg photo.jpg
    put 4 6291456 bin archive.bin
    put 5 5000 txt 'Zażółć gęślą jaźń Ελληνικά 日本語.txt'
    put 6 70000 bin 'a very long file name that does not fit in eight dot three at all.pdf'
    put 7 150000 jpg 'deep/level two/level three/nested.jpg'
    put 8 40000 bin gone/one.bin
    put 9 90000 jpg gone/two.jpg
    put 10 3000 txt gone/inner/three.txt
    for n in $(seq 0 119); do put $((100 + n)) $((500 + 37 * n)) txt "$(printf 'many/file%03d.txt' $n)"; done
    : > "$mnt/empty.dat"; SHA[empty.dat]=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855; SIZE[empty.dat]=0
    sync
    # holes of 64 KiB everywhere: a file written now is cut into many pieces
    # (ext4: more than the inode's four extents, so a tree of depth one)
    for n in $(seq 0 9999); do
        dd if=/dev/zero of="$mnt/fill$n" bs=64k count=1 status=none 2>/dev/null || { rm -f "$mnt/fill$n"; break; }
    done
    sync
    for f in "$mnt"/fill*; do n=${f##*fill}; [ $((n % 2)) = 0 ] && rm -f "$f"; done
    sync
    put 11 1572864 bin frag.bin
    sync
    # all but a little free space taken: a file written after a delete lands
    # on the deleted file's blocks (freed once the delete has committed)
    mkdir -p "$mnt/olddir" "$mnt/newdir"
    free=$(df -B1 --output=avail "$mnt" | tail -1)
    if [ "$free" -gt 393216 ]; then    # ext3 cannot fallocate: zeros then
        fallocate -l $((free - 393216)) "$mnt/filler.bin" 2>/dev/null ||
            dd if=/dev/zero of="$mnt/filler.bin" bs=4096 count=$(((free - 393216) / 4096)) status=none
    fi
    sync
    put 30 196608 bin olddir/reused-old.bin
    sync
    rm -f "$mnt/olddir/reused-old.bin"
    sync
    put 31 196608 bin newdir/reused-new.bin
    sync
    rm -f "$mnt/newdir/reused-new.bin"
    sync

    rm -f "$mnt/tiny.txt" "$mnt/photo.jpg" "$mnt/archive.bin" "$mnt/empty.dat" "$mnt/frag.bin" \
          "$mnt/Zażółć gęślą jaźń Ελληνικά 日本語.txt" \
          "$mnt/a very long file name that does not fit in eight dot three at all.pdf" \
          "$mnt/deep/level two/level three/nested.jpg"
    rm -rf "$mnt/gone"
    for rel in "${media[@]}"; do rm -f "$mnt/$rel"; done
    for n in $(seq 0 2 119); do rm -f "$mnt/$(printf 'many/file%03d.txt' $n)"; done
    sync
    umount "$mnt"
    for rel in "${media[@]}"; do gone "$fs" "media-${rel##*.}" "$rel"; done

    for rel in tiny.txt photo.jpg archive.bin empty.dat frag.bin \
               'Zażółć gęślą jaźń Ελληνικά 日本語.txt' \
               'a very long file name that does not fit in eight dot three at all.pdf'; do
        case "$rel" in
            tiny.txt) c=tiny;; photo.jpg) c=contiguous;; archive.bin) c=large;; empty.dat) c=empty;;
            frag.bin) c=fragmented;; Zaż*) c=unicode-name;; *) c=long-name;;
        esac
        gone $fs $c "$rel"
    done
    gone $fs nested 'deep/level two/level three/nested.jpg'
    gone $fs reused-newer newdir/reused-new.bin
    gone $fs deleted-dir gone/one.bin
    gone $fs deleted-dir gone/two.jpg
    gone $fs deleted-dir gone/inner/three.txt
    for n in $(seq 0 2 119); do gone $fs many "$(printf 'many/file%03d.txt' $n)"; done
    unset SHA SIZE; declare -A SHA SIZE
done
rmdir "$mnt"
rm -f "$gen"
echo "IMAGE READY"
