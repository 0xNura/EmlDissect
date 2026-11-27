namespace EmlDissect.Models;

/// <summary>
/// Container for all extracted IPv4 addresses, URLs, and domains.
/// </summary>
public sealed class NetworkIocCollection
{
    public List<ExtractedIp> IpAddresses { get; set; } = new();
    public List<ExtractedUrl> Urls { get; set; } = new();
    public List<string> DefangedDomains { get; set; } = new();
}

/// <summary>
/// Extracted IPv4 indicator with defanged representation and optional threat intelligence enrichment.
/// </summary>
public sealed class ExtractedIp
{
    public string RawIp { get; set; } = string.Empty;
    public string DefangedIp { get; set; } = string.Empty;
    public bool IsPrivateOrReserved { get; set; }
    public List<string> Sources { get; set; } = new();

    public IpInfoResult? IpInfo { get; set; }
    public AbuseIpDbResult? AbuseIpDb { get; set; }
}

/// <summary>
/// Extracted URL indicator with defanged representation, anchor-mismatch tracking, and VirusTotal enrichment.
/// </summary>
public sealed class ExtractedUrl
{
    public string RawUrl { get; set; } = string.Empty;
    public string DefangedUrl { get; set; } = string.Empty;
    public string? Domain { get; set; }
    public string? DefangedDomain { get; set; }
    public string Source { get; set; } = string.Empty;
    public string? AnchorText { get; set; }
    public bool HasAnchorMismatch { get; set; }
    public string? MismatchReason { get; set; }

    public VirusTotalUrlResult? VirusTotal { get; set; }
}
