namespace EmlDissect.Models;

/// <summary>
/// Extracted email envelope headers, chronological relay hops, and authentication statuses.
/// </summary>
public sealed class EmailHeaderInfo
{
    public string From { get; set; } = string.Empty;
    public string? FromDisplayName { get; set; }
    public string? FromAddress { get; set; }
    public List<string> To { get; set; } = new();
    public List<string> Cc { get; set; } = new();
    public string Subject { get; set; } = string.Empty;
    public DateTimeOffset? Date { get; set; }
    public string? DateRaw { get; set; }
    public string? MessageId { get; set; }
    public string? ReturnPath { get; set; }
    public List<string> ReplyTo { get; set; } = new();
    public string? XOriginatingIp { get; set; }
    public string? XMailer { get; set; }

    /// <summary>
    /// Chronological list of mail relay hops ordered from originating sender (Hop 1) to final recipient.
    /// </summary>
    public List<RoutingHop> RoutingHops { get; set; } = new();

    public AuthenticationSummary Authentication { get; set; } = new();
    public List<string> SpoofingIndicators { get; set; } = new();
}

/// <summary>
/// Represents a single parsed Received header hop in chronological transit order.
/// </summary>
public sealed class RoutingHop
{
    public int HopNumber { get; set; }
    public string? FromServer { get; set; }
    public string? ByServer { get; set; }
    public string? WithProtocol { get; set; }
    public List<string> IpAddresses { get; set; } = new();
    public DateTimeOffset? Timestamp { get; set; }
    public TimeSpan? DelayFromPrevious { get; set; }
    public string? DelayNote { get; set; }
    public string RawHeader { get; set; } = string.Empty;
}

/// <summary>
/// Parsed SPF, DKIM, and DMARC verification results from Authentication-Results / Received-SPF headers.
/// </summary>
public sealed class AuthenticationSummary
{
    public string SpfStatus { get; set; } = "none";
    public string? SpfDetails { get; set; }
    public string DkimStatus { get; set; } = "none";
    public string? DkimDomain { get; set; }
    public string? DkimDetails { get; set; }
    public string DmarcStatus { get; set; } = "none";
    public string? DmarcDetails { get; set; }
    public List<string> RawHeaders { get; set; } = new();
}
