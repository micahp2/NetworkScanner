using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

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
        IntPtr hdc = IntPtr.Zero;
        IntPtr hFont = IntPtr.Zero;
        IntPtr hOldFont = IntPtr.Zero;

        try
        {
            hdc = CreateCompatibleDC(IntPtr.Zero);
            if (hdc == IntPtr.Zero)
                return FallbackGlyphs();

            // Try Segoe Fluent Icons first
            hFont = CreateFontW(
                -16, 0, 0, 0, 400, 0, 0, 0,
                1, // DEFAULT_CHARSET
                0, 0, 0, 0,
                "Segoe Fluent Icons");

            if (hFont != IntPtr.Zero)
            {
                hOldFont = SelectObject(hdc, hFont);
                
                // Verify if GDI actually selected Segoe Fluent Icons
                var sb = new StringBuilder(128);
                GetTextFaceW(hdc, sb.Capacity, sb);
                var faceName = sb.ToString();

                if (!faceName.Equals("Segoe Fluent Icons", StringComparison.OrdinalIgnoreCase))
                {
                    // Clean up and fallback to Segoe MDL2 Assets
                    SelectObject(hdc, hOldFont);
                    DeleteObject(hFont);
                    hFont = IntPtr.Zero;
                    hOldFont = IntPtr.Zero;
                }
            }

            // Fallback to Segoe MDL2 Assets if Segoe Fluent Icons is not found
            if (hFont == IntPtr.Zero)
            {
                hFont = CreateFontW(
                    -16, 0, 0, 0, 400, 0, 0, 0,
                    1, // DEFAULT_CHARSET
                    0, 0, 0, 0,
                    "Segoe MDL2 Assets");

                if (hFont != IntPtr.Zero)
                {
                    hOldFont = SelectObject(hdc, hFont);
                }
            }

            if (hFont == IntPtr.Zero)
                return FallbackGlyphs();

            var glyphIndices = new ushort[1];

            foreach (var (start, end) in ScanRanges)
            {
                for (var cp = start; cp <= end; cp++)
                {
                    var chStr = char.ConvertFromUtf32(cp);
                    glyphIndices[0] = 0;
                    
                    var res = GetGlyphIndicesW(hdc, chStr, chStr.Length, glyphIndices, GGI_MARK_NONEXISTING_GLYPHS);
                    // In GDI, if character doesn't exist, it returns 0xFFFF (due to GGI_MARK_NONEXISTING_GLYPHS flag)
                    if (res != 0xFFFFFFFF && glyphIndices[0] != 0xFFFF && glyphIndices[0] != 0)
                    {
                        codePoints.Add(cp);
                    }
                }
            }
        }
        catch
        {
            return FallbackGlyphs();
        }
        finally
        {
            if (hdc != IntPtr.Zero)
            {
                if (hOldFont != IntPtr.Zero)
                    SelectObject(hdc, hOldFont);
                if (hFont != IntPtr.Zero)
                    DeleteObject(hFont);
                DeleteDC(hdc);
            }
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
        (0xE100, 0xE2FF), // Core system icons
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

    [DllImport("gdi32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateCompatibleDC(IntPtr hdc);

    [DllImport("gdi32.dll", CharSet = CharSet.Unicode)]
    private static extern bool DeleteDC(IntPtr hdc);

    [DllImport("gdi32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFontW(
        int nHeight,
        int nWidth,
        int nEscapement,
        int nOrientation,
        int fnWeight,
        uint fdwItalic,
        uint fdwUnderline,
        uint fdwStrikeOut,
        uint fdwCharSet,
        uint fdwOutputPrecision,
        uint fdwClipPrecision,
        uint fdwQuality,
        uint fdwPitchAndFamily,
        string lpszFace);

    [DllImport("gdi32.dll")]
    private static extern IntPtr SelectObject(IntPtr hdc, IntPtr hgdiobj);

    [DllImport("gdi32.dll")]
    private static extern bool DeleteObject(IntPtr hObject);

    [DllImport("gdi32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetTextFaceW(IntPtr hdc, int c, StringBuilder name);

    [DllImport("gdi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetGlyphIndicesW(
        IntPtr hdc,
        string lpstr,
        int c,
        [Out] ushort[] pgi,
        uint fl);

    private const uint GGI_MARK_NONEXISTING_GLYPHS = 0x0001;
}
