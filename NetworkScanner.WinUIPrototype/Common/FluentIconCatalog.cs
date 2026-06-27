using System.Runtime.InteropServices;

namespace NetworkScanner.WinUIPrototype.Common;

internal static class FluentIconCatalog
{
    private static Task<IReadOnlyList<string>>? _loadTask;
    private static volatile IReadOnlyList<string>? _cached;

    public static IReadOnlyList<string> AllGlyphs =>
        _cached ?? Array.Empty<string>();

    public static bool IsReady => _cached is not null;

    public static void Preload() => _ = GetGlyphsAsync();

    public static Task<IReadOnlyList<string>> GetGlyphsAsync()
    {
        if (_cached is not null)
            return Task.FromResult(_cached);

        return _loadTask ??= LoadCoreAsync();
    }

    private static async Task<IReadOnlyList<string>> LoadCoreAsync()
    {
        var glyphs = await Task.Run(Build).ConfigureAwait(false);
        _cached = glyphs;
        return glyphs;
    }

    private static IReadOnlyList<string> Build()
    {
        var codePoints = new SortedSet<int>();

        try
        {
            Marshal.ThrowExceptionForHR(
                DWriteCreateFactory(DWriteFactoryType.Shared, typeof(IDWriteFactory).GUID, out var factoryObj));

            var factory = (IDWriteFactory)factoryObj;
            factory.GetSystemFontCollection(out var collection, false);
            collection.FindFamilyName("Segoe Fluent Icons", out var familyIndex, out var exists);
            if (!exists)
                return FallbackGlyphs();

            collection.GetFontFamily(familyIndex, out var family);
            family.GetFirstMatchingFont(
                DWriteFontWeight.Normal,
                DWriteFontStretch.Normal,
                DWriteFontStyle.Normal,
                out var font);

            foreach (var (start, end) in ScanRanges)
            {
                for (var cp = start; cp <= end; cp++)
                {
                    font.HasCharacter((uint)cp, out var hasCharacter);
                    if (hasCharacter)
                        codePoints.Add(cp);
                }
            }
        }
        catch
        {
            return FallbackGlyphs();
        }

        return codePoints.Count == 0
            ? FallbackGlyphs()
            : codePoints.Select(cp => cp.ToString("X4")).ToList();
    }

    private static IReadOnlyList<string> FallbackGlyphs()
    {
        var codePoints = new SortedSet<int>();
        foreach (var (start, end) in ScanRanges)
        {
            for (var cp = start; cp <= end; cp++)
                codePoints.Add(cp);
        }

        return codePoints.Select(cp => cp.ToString("X4")).ToList();
    }

    private static readonly (int Start, int End)[] ScanRanges =
    {
        (0xE700, 0xE7FF),
        (0xE800, 0xE8FF),
        (0xE900, 0xE9FF),
        (0xEA00, 0xEAFF),
        (0xEB00, 0xEBFF),
        (0xEC00, 0xECFF),
        (0xED00, 0xEDFF),
        (0xEE00, 0xEEFF),
        (0xEF00, 0xEFFF),
        (0xF000, 0xF0FF),
        (0xF100, 0xF1FF),
        (0xF200, 0xF2FF),
        (0xF300, 0xF3FF),
        (0xF400, 0xF4FF),
        (0xF500, 0xF5FF),
        (0xF600, 0xF6FF),
        (0xF700, 0xF7FF),
        (0xF800, 0xF8FF)
    };

    private enum DWriteFactoryType
    {
        Shared = 0
    }

    private enum DWriteFontWeight
    {
        Normal = 400
    }

    private enum DWriteFontStretch
    {
        Normal = 5
    }

    private enum DWriteFontStyle
    {
        Normal = 0
    }

    [DllImport("DWrite.dll")]
    private static extern int DWriteCreateFactory(
        DWriteFactoryType factoryType,
        [MarshalAs(UnmanagedType.LPStruct)] Guid iid,
        [MarshalAs(UnmanagedType.IUnknown, IidParameterIndex = 1)] out object factory);

    [ComImport]
    [Guid("727CAD4E-D6AE-4269-0810-7908EBBB980A")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IDWriteFactory
    {
        void GetSystemFontCollection(out IDWriteFontCollection fontCollection, [MarshalAs(UnmanagedType.Bool)] bool checkForUpdates);
    }

    [ComImport]
    [Guid("A84CEE02-3EEA-4EEE-A827-87C16A0AA325")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IDWriteFontCollection
    {
        uint GetFontFamilyCount();
        void GetFontFamily(uint index, out IDWriteFontFamily fontFamily);
        void FindFamilyName([MarshalAs(UnmanagedType.LPWStr)] string familyName, out uint index, [MarshalAs(UnmanagedType.Bool)] out bool exists);
    }

    [ComImport]
    [Guid("DA20D8BF-12A4-433C-8474-D7C17195EBFE")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IDWriteFontFamily
    {
        void GetFamilyNames(out IntPtr names);
        void GetFontCount(out uint count);
        void GetFont(uint index, out IDWriteFont font);
        void GetFirstMatchingFont(DWriteFontWeight weight, DWriteFontStretch stretch, DWriteFontStyle style, out IDWriteFont font);
    }

    [ComImport]
    [Guid("ACDE7186-8AE4-4218-9546-48A8650AB7A2")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IDWriteFont
    {
        void GetFontFamily(out IDWriteFontFamily fontFamily);
        DWriteFontWeight GetWeight();
        DWriteFontStretch GetStretch();
        DWriteFontStyle GetStyle();
        [PreserveSig]
        int IsSymbolFont();
        void GetFaceNames(out IntPtr faceNames);
        void GetInformationalStrings(
            uint informationalStringId,
            out IntPtr informationalStrings,
            [MarshalAs(UnmanagedType.Bool)] out bool exists);
        int GetSimulations();
        void GetMetrics(out IntPtr fontMetrics);
        void HasCharacter(uint unicodeChar, [MarshalAs(UnmanagedType.Bool)] out bool exists);
        void CreateFontFace(out IntPtr fontFace);
    }
}
