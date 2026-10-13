"""Deterministic archive/PDF fixtures; uses the already installed pypdf."""
from pathlib import Path
from io import BytesIO
import hashlib
import json
import zipfile
import xml.etree.ElementTree as ET
from pypdf import PdfReader, PdfWriter
from pypdf.generic import NameObject, DictionaryObject, DecodedStreamObject

ROOT = Path(__file__).resolve().parent / "fixtures" / "documents"
ROOT.mkdir(parents=True, exist_ok=True)
TOKEN = "FRT-PDF-2026"


def make_pdf():
    writer = PdfWriter()
    page = writer.add_blank_page(width=400, height=300)
    font = DictionaryObject({NameObject("/Type"): NameObject("/Font"),
                             NameObject("/Subtype"): NameObject("/Type1"),
                             NameObject("/BaseFont"): NameObject("/Helvetica")})
    page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): writer._add_object(font)})})
    content = DecodedStreamObject()
    content.set_data(f"BT /F1 12 Tf 30 250 Td ({TOKEN}) Tj ET\n".encode())
    page[NameObject("/Contents")] = writer._add_object(content)
    writer.add_metadata({"/Author": "Marek Wesolowski", "/Title": "Recovery boundary fixture"})
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


base = make_pdf()
(ROOT / "classic.pdf").write_bytes(base)
writer = PdfWriter(BytesIO(base), incremental=True)
writer.add_metadata({"/Title": "Incremental revision", "/Subject": TOKEN})
writer.write(ROOT / "incremental.pdf")
encrypted = PdfWriter(clone_from=BytesIO(base))
encrypted.encrypt("fixture-password", algorithm="RC4-128")
encrypted.write(ROOT / "encrypted.pdf")

payload = bytes((i * 37 + 19) % 256 for i in range(70000))
for name, compression in (("stored.zip", zipfile.ZIP_STORED), ("deflated.zip", zipfile.ZIP_DEFLATED),
                          ("bzip2.zip", zipfile.ZIP_BZIP2), ("lzma.zip", zipfile.ZIP_LZMA)):
    with zipfile.ZipFile(ROOT / name, "w", compression=compression) as archive:
        archive.writestr("folder/data.bin", payload)
        archive.writestr("notes.txt", "FRT-ZIP-2026\n")
        archive.comment = b"Comment with a false footer: PK\x05\x06" + b"\0" * 18
with zipfile.ZipFile(ROOT / "empty.zip", "w") as archive:
    archive.comment = b"Empty but valid archive"
with zipfile.ZipFile(ROOT / "zip64.zip", "w", allowZip64=True) as archive:
    with archive.open("data.bin", "w", force_zip64=True) as entry:
        entry.write(payload)

# A non-seekable writer exercises ZIP data descriptors.
class NonSeekable(BytesIO):
    def seekable(self): return False
    def seek(self, *args): raise OSError("Fixture output is not seekable")

stream = NonSeekable()
with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    archive.writestr("data.bin", payload)
(ROOT / "descriptor.zip").write_bytes(stream.getvalue())

manifest = []
for path in sorted(ROOT.iterdir()):
    if path.suffix not in (".zip", ".docx", ".pdf", ".7z"): continue
    data = path.read_bytes()
    if path.suffix in (".zip", ".docx"):
        with zipfile.ZipFile(path) as archive:
            assert archive.testzip() is None
            members = archive.namelist()
            if path.suffix == ".docx":
                for name in members:
                    if name.endswith((".xml", ".rels")): ET.fromstring(archive.read(name))
                assert "FRT-DOCX-2026" in archive.read("word/document.xml").decode()
    elif path.suffix == ".pdf":
        reader = PdfReader(path, strict=True)
        if reader.is_encrypted: assert reader.decrypt("fixture-password")
        assert len(reader.pages) == 1
        assert "FRT-" in reader.pages[0].extract_text()
    manifest.append({"name": path.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
(ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
print(f"Validated {len(manifest)} archive/document fixtures: {ROOT}")

# Exact-length RAW images plus deliberately damaged inputs. Keep expected
# boundary results separate from decoder validation above.
cases = ROOT / "cases"
cases.mkdir(exist_ok=True)
expectations = []


def raw_case(name, data, expected):
    (cases / (name + ".img")).write_bytes(data)
    expectations.append({"name": name, "sourceSha256": hashlib.sha256(data).hexdigest(), "outputs": expected})


def recovered(data, extension, quality="Full"):
    return {"sha256": hashlib.sha256(data).hexdigest(), "extension": extension, "quality": quality}


mixed = bytearray(b"\0" * 37)
expected = []
for entry in manifest:
    data = (ROOT / entry["name"]).read_bytes()
    mixed += data + b"\0" * 23
    expected.append(recovered(data, Path(entry["name"]).suffix))
raw_case("mixed", mixed, expected)
second_pdf = (ROOT / "encrypted.pdf").read_bytes()
raw_case("adjacent-pdfs", base + second_pdf, [recovered(base, ".pdf"), recovered(second_pdf, ".pdf")])
update = (ROOT / "incremental.pdf").read_bytes()
assert update.startswith(base)
raw_case("incomplete-pdf-update", update[:update.rfind(b"%%EOF")], [recovered(base, ".pdf", "Partial")])
zip64 = (ROOT / "zip64.zip").read_bytes()
raw_case("truncated-zip", zip64[:-5], [])
damaged = bytearray(zip64)
footer = damaged.rfind(b"PK\x05\x06")
damaged[footer + 16:footer + 20] = b"\xff" * 4
raw_case("invalid-zip-directory", damaged, [])
seven = (ROOT / "sample.7z").read_bytes()
damaged = bytearray(seven); damaged[8] ^= 1
raw_case("invalid-7z-start-crc", damaged, [])
damaged = bytearray(seven); damaged[-1] ^= 1
raw_case("invalid-7z-next-crc", damaged, [])
raw_case("truncated-7z", seven[:-1], [])
damaged = bytearray(base)
at = damaged.rfind(b"startxref") + len(b"startxref")
while damaged[at] in b" \r\n": at += 1
while damaged[at] in b"0123456789": damaged[at] = ord("9"); at += 1
raw_case("invalid-pdf-xref", damaged, [])
raw_case("fake-pdf", b"%PDF-1.7\nUnrelated bytes\n%%EOF\n", [])
(cases / "expectations.json").write_text(json.dumps(expectations, indent=2), encoding="utf-8")
print(f"Prepared {len(expectations)} RAW cases, including rejection and partial-revision expectations")
