// Test-only use of the Windows defragmentation API on an isolated VHD volume.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class FragmentLayout {
    public sealed class Extent {
        public long Vcn { get; set; }
        public long Lcn { get; set; }
        public long Clusters { get; set; }
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct MoveData { public IntPtr File; public long Vcn; public long Lcn; public uint Clusters; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool DeviceIoControl(SafeFileHandle handle, uint code, byte[] input, uint inputSize,
        byte[] output, uint outputSize, out uint returned, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool DeviceIoControl(SafeFileHandle handle, uint code, ref MoveData input, uint inputSize,
        IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);

    private static SafeFileHandle Open(string path) {
        var h = CreateFile(path, 0xC0000000, 7, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (h.IsInvalid) { h.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error(), "Open " + path); }
        return h;
    }
    public static Extent[] Read(string path) {
        using (var file = Open(path)) {
            var output = new byte[1024 * 1024]; uint returned;
            if (!DeviceIoControl(file, 0x90073, new byte[8], 8, output, (uint)output.Length, out returned, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "FSCTL_GET_RETRIEVAL_POINTERS");
            uint count = BitConverter.ToUInt32(output, 0);
            if (returned < 16 || count > (returned - 16) / 16) throw new Exception("Truncated retrieval pointers");
            long vcn = BitConverter.ToInt64(output, 8);
            var extents = new List<Extent>();
            for (uint i = 0; i < count; ++i) {
                int at = checked(16 + (int)i * 16);
                long next = BitConverter.ToInt64(output, at), lcn = BitConverter.ToInt64(output, at + 8);
                if (next <= vcn || lcn < 0) throw new Exception("Sparse or invalid extent in a non-sparse fixture");
                if (extents.Count > 0 && extents[extents.Count - 1].Lcn + extents[extents.Count - 1].Clusters == lcn)
                    extents[extents.Count - 1].Clusters += next - vcn;
                else extents.Add(new Extent { Vcn = vcn, Lcn = lcn, Clusters = next - vcn });
                vcn = next;
            }
            return extents.ToArray();
        }
    }
    private static long[] FindFree(SafeFileHandle volume, long[] lengths) {
        var output = new byte[1024 * 1024]; uint returned;
        if (!DeviceIoControl(volume, 0x9006F, new byte[8], 8, output, (uint)output.Length, out returned, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "FSCTL_GET_VOLUME_BITMAP");
        if (returned < 16) throw new Exception("Truncated volume bitmap");
        long start = BitConverter.ToInt64(output, 0), bits = BitConverter.ToInt64(output, 8);
        bits = Math.Min(bits, ((long)returned - 16) * 8);
        var places = new long[lengths.Length];
        long run = 0; int wanted = 0;
        // One forward bitmap sweep; fragments may occupy different free runs.
        // Leave at least one physical cluster between destinations so the
        // measured extent count is exactly the requested number.
        for (long bit = 0; bit < bits && wanted < lengths.Length; ++bit) {
            run = (output[16 + (int)(bit / 8)] & (1 << (int)(bit % 8))) == 0 ? run + 1 : 0;
            if (run == lengths[wanted]) {
                places[wanted++] = start + bit + 1 - run;
                run = 0; ++bit;
            }
        }
        if (wanted != lengths.Length) throw new Exception("Insufficient free runs for the requested test layout");
        return places;
    }
    public static Extent[] Create(string path, string volumePath, long clusters, int count, bool reverse) {
        if (count < 1 || clusters < count) throw new ArgumentOutOfRangeException("count");
        // Only the fresh test volume is supplied by the guest harness. Both
        // allocation and movement are done by its file system, never by raw writes.
        using (var volume = Open(volumePath)) using (var file = Open(path)) {
            var lengths = new long[count];
            for (int i = 0; i < count; ++i)
                lengths[i] = clusters / count + (i < clusters % count ? 1 : 0);
            var physical = FindFree(volume, lengths);
            long vcn = 0;
            var plan = new List<Extent>();
            for (int i = 0; i < count; ++i) {
                int index = reverse ? count - 1 - i : i;
                var move = new MoveData { File = file.DangerousGetHandle(), Vcn = vcn, Lcn = physical[index], Clusters = checked((uint)lengths[index]) };
                uint returned;
                if (!DeviceIoControl(volume, 0x90074, ref move, (uint)Marshal.SizeOf(typeof(MoveData)), IntPtr.Zero, 0, out returned, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "FSCTL_MOVE_FILE at VCN " + vcn);
                plan.Add(new Extent { Vcn = vcn, Lcn = physical[index], Clusters = lengths[index] });
                vcn += lengths[index];
            }
            return plan.ToArray();
        }
    }
}
