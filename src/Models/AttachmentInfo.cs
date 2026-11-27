namespace EmlDissect.Models;

/// <summary>
/// Metadata and hashes for an email attachment processed in memory.
/// </summary>
public sealed class AttachmentInfo
{
    public string Filename { get; set; } = string.Empty;
    public string DeclaredMimeType { get; set; } = string.Empty;
    public long SizeBytes { get; set; }
    public string Md5 { get; set; } = string.Empty;
    public string Sha1 { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public string MagicBytesHex { get; set; } = string.Empty;
    public string DetectedFileType { get; set; } = "Unknown";
    public bool IsExtensionSpoofed { get; set; }
    public string? SpoofingDetail { get; set; }
    public bool IsHighRiskExtension { get; set; }
    public bool IsEmbeddedMessage { get; set; }

    public VirusTotalFileResult? VirusTotal { get; set; }
}
