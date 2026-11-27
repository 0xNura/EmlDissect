namespace EmlDissect.Models;

/// <summary>
/// Root report model containing all extracted data for an analyzed .eml file.
/// </summary>
public sealed class ForensicReport
{
    public string ToolName { get; set; } = "EmlDissect";
    public string ToolVersion { get; set; } = "2.0.0";
    public DateTimeOffset AnalyzedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string SourceFile { get; set; } = string.Empty;
    public string FileSha256 { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public bool OfflineMode { get; set; }

    public EmailHeaderInfo Headers { get; set; } = new();
    public NetworkIocCollection NetworkIocs { get; set; } = new();
    public List<AttachmentInfo> Attachments { get; set; } = new();
    public List<SecurityWarning> SecurityWarnings { get; set; } = new();
}

/// <summary>
/// Security warning or spoofing anomaly flagged during analysis.
/// </summary>
public sealed class SecurityWarning
{
    public WarningSeverity Severity { get; set; } = WarningSeverity.Info;
    public string Category { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}

public enum WarningSeverity
{
    Info,
    Low,
    Medium,
    High,
    Critical
}
