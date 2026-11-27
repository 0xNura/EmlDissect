using System.Text;

namespace EmlDissect.Utils;

/// <summary>
/// Result of inspecting an attachment's file signature (magic bytes) against its declared filename extension.
/// </summary>
public sealed record MagicBytesInspectionResult(
    string MagicBytesHex,
    string DetectedFileType,
    bool IsExtensionSpoofed,
    string? SpoofingDetail,
    bool IsHighRiskExtension
);

/// <summary>
/// Verifies file magic bytes against declared extensions to uncover disguised executables,
/// archives, scripts, or HTML-smuggling payloads.
/// </summary>
public static class MagicBytesChecker
{
    private sealed record MagicSignature(
        string FileType,
        byte[] Bytes,
        string[] ExpectedExtensions,
        bool IsExecutableOrDangerous = false
    );

    private static readonly MagicSignature[] Signatures =
    {
        new("Windows PE Executable (MZ)", [0x4D, 0x5A], [".exe", ".dll", ".scr", ".sys", ".cpl", ".ocx", ".drv", ".com"], true),
        new("ELF Executable", [0x7F, 0x45, 0x4C, 0x46], [".elf", ".so", ".bin", ".out", ""], true),
        new("Mach-O Binary (32-bit)", [0xFE, 0xED, 0xFA, 0xCE], [".macho", ".dylib", ""], true),
        new("Mach-O Binary (64-bit)", [0xFE, 0xED, 0xFA, 0xCF], [".macho", ".dylib", ""], true),
        new("Mach-O Binary (LE 64-bit)", [0xCF, 0xFA, 0xED, 0xFE], [".macho", ".dylib", ""], true),
        new("Mach-O Universal/Java Class", [0xCA, 0xFE, 0xBA, 0xBE], [".class", ".macho", ""], true),
        new("PDF Document", [0x25, 0x50, 0x44, 0x46, 0x2D], [".pdf"]),
        new("ZIP Archive / OOXML / JAR", [0x50, 0x4B, 0x03, 0x04], [".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".jar", ".apk", ".xlsm", ".docm", ".pptm", ".onepkg"]),
        new("ZIP Empty Archive", [0x50, 0x4B, 0x05, 0x06], [".zip"]),
        new("ZIP Spanned Archive", [0x50, 0x4B, 0x07, 0x08], [".zip"]),
        new("RAR Archive", [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], [".rar"]),
        new("7-Zip Archive", [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], [".7z"]),
        new("GZIP Archive", [0x1F, 0x8B, 0x08], [".gz", ".tgz"]),
        new("Microsoft OLE2 Compound Binary", [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], [".doc", ".xls", ".ppt", ".msi", ".msg", ".dot", ".xlt", ".pub"]),
        new("Rich Text Format (RTF)", [0x7B, 0x5C, 0x72, 0x74, 0x66], [".rtf"]),
        new("PNG Image", [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], [".png"]),
        new("JPEG Image", [0xFF, 0xD8, 0xFF], [".jpg", ".jpeg", ".jfif"]),
        new("GIF Image", [0x47, 0x49, 0x46, 0x38], [".gif"]),
        new("BMP Image", [0x42, 0x4D], [".bmp"]),
        new("Windows Shortcut (LNK)", [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00], [".lnk"], true),
        new("Microsoft OneNote Section", [0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D], [".one"]),
        new("SQLite 3 Database", [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66], [".sqlite", ".sqlite3", ".db"]),
        new("CAB Archive", [0x4D, 0x53, 0x43, 0x46], [".cab"])
    };

    private static readonly HashSet<string> HighRiskExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".iso", ".img", ".vhd",
        ".vhdx", ".msi", ".msp", ".chm", ".cpl", ".pif", ".reg", ".html", ".htm",
        ".svg", ".docm", ".xlsm", ".pptm", ".jar", ".one"
    };

    /// <summary>
    /// Inspects the leading bytes of an attachment and checks for extension spoofing.
    /// </summary>
    public static MagicBytesInspectionResult Inspect(
        ReadOnlySpan<byte> data,
        string filename,
        string declaredMimeType)
    {
        string extension = Path.GetExtension(filename ?? string.Empty).ToLowerInvariant();
        bool isHighRiskExt = !string.IsNullOrEmpty(extension) && HighRiskExtensions.Contains(extension);

        int previewLen = Math.Min(data.Length, 8);
        string magicHex = previewLen > 0
            ? BitConverter.ToString(data[..previewLen].ToArray()).Replace("-", " ")
            : "(empty)";

        if (data.IsEmpty)
        {
            return new MagicBytesInspectionResult(magicHex, "Empty File", false, null, isHighRiskExt);
        }

        // 1. Check exact binary signatures
        foreach (MagicSignature sig in Signatures)
        {
            if (data.Length >= sig.Bytes.Length && data[..sig.Bytes.Length].SequenceEqual(sig.Bytes))
            {
                bool matchesExpected = string.IsNullOrEmpty(extension)
                    ? !sig.IsExecutableOrDangerous
                    : sig.ExpectedExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase);

                if (!matchesExpected)
                {
                    string detail =
                        $"Extension spoofing detected: '{filename}' claims extension '{(string.IsNullOrEmpty(extension) ? "(none)" : extension)}' " +
                        $"(MIME: {declaredMimeType}), but magic bytes [{magicHex}] identify it as {sig.FileType}.";

                    return new MagicBytesInspectionResult(
                        magicHex,
                        sig.FileType,
                        true,
                        detail,
                        isHighRiskExt || sig.IsExecutableOrDangerous);
                }

                return new MagicBytesInspectionResult(
                    magicHex,
                    sig.FileType,
                    false,
                    null,
                    isHighRiskExt || sig.IsExecutableOrDangerous);
            }
        }

        // 2. Check text-based signatures (e.g., HTML smuggling or scripts disguised as .pdf/.jpg/.doc)
        string textProbe = DecodeAsciiProbe(data[..Math.Min(data.Length, 512)]).TrimStart();
        if (LooksLikeHtmlOrSvg(textProbe))
        {
            bool allowedHtmlExt = extension is ".html" or ".htm" or ".svg" or ".xhtml" or ".xml" or ".txt";
            string detected = textProbe.StartsWith("<svg", StringComparison.OrdinalIgnoreCase)
                ? "SVG Markup (potential script smuggling)"
                : "HTML Document (potential HTML smuggling)";

            string? detail = allowedHtmlExt
                ? null
                : $"Extension spoofing detected: '{filename}' has extension '{extension}' but contains {detected}.";

            return new MagicBytesInspectionResult(
                magicHex,
                detected,
                !allowedHtmlExt,
                detail,
                isHighRiskExt || !allowedHtmlExt);
        }

        if (LooksLikeScript(textProbe))
        {
            bool allowedScriptExt = extension is ".ps1" or ".bat" or ".cmd" or ".vbs" or ".js" or ".sh" or ".py" or ".txt";
            string detected = "Executable Script Content";
            string? detail = allowedScriptExt
                ? null
                : $"Extension spoofing detected: '{filename}' has extension '{extension}' but contains {detected}.";

            return new MagicBytesInspectionResult(
                magicHex,
                detected,
                !allowedScriptExt,
                detail,
                true);
        }

        // 3. Fallback: check whether content appears to be plain ASCII/UTF-8 text vs unknown binary
        string fallbackType = IsLikelyPlainText(data[..Math.Min(data.Length, 256)])
            ? "Plain Text / UTF-8"
            : "Unknown Binary Format";

        bool binaryInTextDisguise = fallbackType == "Unknown Binary Format" && extension is ".txt" or ".csv" or ".log";
        string? binarySpoofDetail = binaryInTextDisguise
            ? $"File '{filename}' claims plain-text extension '{extension}' but contains non-text binary bytes [{magicHex}]."
            : null;

        return new MagicBytesInspectionResult(
            magicHex,
            fallbackType,
            binaryInTextDisguise,
            binarySpoofDetail,
            isHighRiskExt);
    }

    private static string DecodeAsciiProbe(ReadOnlySpan<byte> slice)
    {
        // Strip UTF-8 BOM if present
        if (slice.Length >= 3 && slice[0] == 0xEF && slice[1] == 0xBB && slice[2] == 0xBF)
        {
            slice = slice[3..];
        }

        return Encoding.UTF8.GetString(slice);
    }

    private static bool LooksLikeHtmlOrSvg(string probe)
    {
        return probe.StartsWith("<!DOCTYPE html", StringComparison.OrdinalIgnoreCase) ||
               probe.StartsWith("<html", StringComparison.OrdinalIgnoreCase) ||
               probe.StartsWith("<script", StringComparison.OrdinalIgnoreCase) ||
               probe.StartsWith("<svg", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LooksLikeScript(string probe)
    {
        return probe.StartsWith("#!", StringComparison.Ordinal) ||
               probe.StartsWith("@echo off", StringComparison.OrdinalIgnoreCase) ||
               probe.StartsWith("<?php", StringComparison.OrdinalIgnoreCase) ||
               probe.Contains("powershell", StringComparison.OrdinalIgnoreCase) &&
               probe.Contains("-enc", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsLikelyPlainText(ReadOnlySpan<byte> slice)
    {
        if (slice.IsEmpty)
        {
            return true;
        }

        int controlBytes = 0;
        foreach (byte b in slice)
        {
            if (b == 0x00)
            {
                return false;
            }

            if (b < 0x20 && b is not (0x09 or 0x0A or 0x0D))
            {
                controlBytes++;
            }
        }

        return controlBytes <= slice.Length / 20;
    }
}
