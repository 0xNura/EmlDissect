namespace EmlDissect.Models;

/// <summary>
/// Geolocation and ASN metadata returned from ipinfo.io.
/// </summary>
public sealed class IpInfoResult
{
    public string Ip { get; set; } = string.Empty;
    public string? Hostname { get; set; }
    public string? City { get; set; }
    public string? Region { get; set; }
    public string? Country { get; set; }
    public string? Org { get; set; }
    public string? Asn { get; set; }
    public string? Isp { get; set; }
    public string? Location { get; set; }
    public string? Timezone { get; set; }
    public string? Error { get; set; }
}

/// <summary>
/// IP reputation data returned from AbuseIPDB API v2.
/// </summary>
public sealed class AbuseIpDbResult
{
    public string IpAddress { get; set; } = string.Empty;
    public bool IsPublic { get; set; }
    public int AbuseConfidenceScore { get; set; }
    public string? CountryCode { get; set; }
    public string? UsageType { get; set; }
    public string? Isp { get; set; }
    public string? Domain { get; set; }
    public int TotalReports { get; set; }
    public int NumDistinctUsers { get; set; }
    public DateTimeOffset? LastReportedAt { get; set; }
    public bool? IsWhitelisted { get; set; }
    public string? Error { get; set; }
}

/// <summary>
/// File hash scan statistics returned from VirusTotal API v3.
/// </summary>
public sealed class VirusTotalFileResult
{
    public string Sha256 { get; set; } = string.Empty;
    public bool Found { get; set; }
    public int Malicious { get; set; }
    public int Suspicious { get; set; }
    public int Harmless { get; set; }
    public int Undetected { get; set; }
    public int TotalEngines { get; set; }
    public string DetectionRatio { get; set; } = "0/0";
    public string? MeaningfulName { get; set; }
    public string? PopularThreatLabel { get; set; }
    public string? Error { get; set; }
}

/// <summary>
/// URL scan statistics returned from VirusTotal API v3.
/// </summary>
public sealed class VirusTotalUrlResult
{
    public string Url { get; set; } = string.Empty;
    public string DefangedUrl { get; set; } = string.Empty;
    public bool Found { get; set; }
    public int Malicious { get; set; }
    public int Suspicious { get; set; }
    public int Harmless { get; set; }
    public int Undetected { get; set; }
    public int TotalEngines { get; set; }
    public string DetectionRatio { get; set; } = "0/0";
    public string? Error { get; set; }
}
