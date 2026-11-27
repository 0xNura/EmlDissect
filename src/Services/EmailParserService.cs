using System.Net;
using System.Text.RegularExpressions;
using EmlDissect.Models;
using MimeKit;
using MimeKit.Utils;

namespace EmlDissect.Services;

/// <summary>
/// Intermediate output produced by <see cref="EmailParserService"/> for downstream IOC and attachment analysis.
/// </summary>
public sealed class ParsedEmailContext
{
    public required MimeMessage Message { get; init; }
    public required EmailHeaderInfo HeaderInfo { get; init; }
    public string TextBody { get; init; } = string.Empty;
    public string HtmlBody { get; init; } = string.Empty;
    public List<HtmlAnchorLink> HtmlLinks { get; init; } = new();
    public List<string> RawReceivedHeaders { get; init; } = new();
    public List<string> RawAuthHeaders { get; init; } = new();
}

public sealed record HtmlAnchorLink(string Href, string AnchorText);

/// <summary>
/// Safely parses .eml files in memory using MimeKit, extracting headers, chronological routing hops,
/// authentication results, spoofing anomalies, and HTML anchor links.
/// </summary>
public sealed partial class EmailParserService
{
    [GeneratedRegex(@"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b", RegexOptions.Compiled)]
    private static partial Regex Ipv4Regex();

    [GeneratedRegex(@"\bfrom\s+(?<from>[^\s;()]+(?:\s*\([^)]*\))?)", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex ReceivedFromRegex();

    [GeneratedRegex(@"\bby\s+(?<by>[^\s;()]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex ReceivedByRegex();

    [GeneratedRegex(@"\bwith\s+(?<with>[A-Za-z0-9_-]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex ReceivedWithRegex();

    [GeneratedRegex(@"\b(?<mech>spf|dkim|dmarc)\s*=\s*(?<status>[a-zA-Z0-9_-]+)(?<detail>[^;]*)", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex AuthMechanismRegex();

    [GeneratedRegex(@"\bheader\.d\s*=\s*(?<domain>[A-Za-z0-9.-]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex HeaderDomainRegex();

    [GeneratedRegex(@"<a\s+[^>]*?href\s*=\s*(?:""(?<href>[^""]*)""|'(?<href>[^']*)'|(?<href>[^\s>]+))[^>]*>(?<text>.*?)</a>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled)]
    private static partial Regex HtmlAnchorRegex();

    [GeneratedRegex(@"<[^>]+>", RegexOptions.Singleline | RegexOptions.Compiled)]
    private static partial Regex StripHtmlTagsRegex();

    [GeneratedRegex(@"[A-Za-z0-9._%+-]+@(?<domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,})", RegexOptions.Compiled)]
    private static partial Regex EmailAddressRegex();

    /// <summary>
    /// Parses an .eml file stream entirely in memory without writing temporary files.
    /// </summary>
    public async Task<ParsedEmailContext> ParseAsync(Stream emlStream, CancellationToken cancellationToken = default)
    {
        MimeMessage message = await MimeMessage.LoadAsync(emlStream, cancellationToken);

        var headerInfo = new EmailHeaderInfo
        {
            From = message.From.ToString(),
            Subject = message.Subject ?? string.Empty,
            MessageId = message.MessageId,
            DateRaw = message.Headers[HeaderId.Date],
            Date = message.Headers.Contains(HeaderId.Date) ? message.Date : null,
            ReturnPath = CleanAngleBrackets(message.Headers[HeaderId.ReturnPath]),
            XOriginatingIp = message.Headers["X-Originating-IP"]?.Trim(),
            XMailer = message.Headers[HeaderId.XMailer]?.Trim()
        };

        MailboxAddress? primaryFrom = message.From.Mailboxes.FirstOrDefault();
        if (primaryFrom is not null)
        {
            headerInfo.FromDisplayName = primaryFrom.Name;
            headerInfo.FromAddress = primaryFrom.Address;
        }

        headerInfo.To.AddRange(message.To.Mailboxes.Select(m => FormatMailbox(m)));
        headerInfo.Cc.AddRange(message.Cc.Mailboxes.Select(m => FormatMailbox(m)));
        headerInfo.ReplyTo.AddRange(message.ReplyTo.Mailboxes.Select(m => m.Address));

        // 1. Parse Received headers chronologically (bottom-to-top)
        List<string> rawReceived = message.Headers
            .Where(h => h.Field.Equals("Received", StringComparison.OrdinalIgnoreCase))
            .Select(h => h.Value)
            .ToList();

        headerInfo.RoutingHops = ParseRoutingHops(rawReceived);

        // 2. Parse Authentication-Results / ARC-Authentication-Results / Received-SPF
        List<string> rawAuth = message.Headers
            .Where(h =>
                h.Field.Equals("Authentication-Results", StringComparison.OrdinalIgnoreCase) ||
                h.Field.Equals("ARC-Authentication-Results", StringComparison.OrdinalIgnoreCase) ||
                h.Field.Equals("Received-SPF", StringComparison.OrdinalIgnoreCase))
            .Select(h => $"{h.Field}: {h.Value}")
            .ToList();

        headerInfo.Authentication = ParseAuthenticationResults(message.Headers, rawAuth);

        // 3. Detect spoofing anomalies
        DetectSpoofingAnomalies(headerInfo);

        // 4. Extract text/html bodies and HTML <a href> links
        string textBody = message.TextBody ?? string.Empty;
        string htmlBody = message.HtmlBody ?? string.Empty;
        List<HtmlAnchorLink> htmlLinks = ExtractHtmlLinks(htmlBody);

        return new ParsedEmailContext
        {
            Message = message,
            HeaderInfo = headerInfo,
            TextBody = textBody,
            HtmlBody = htmlBody,
            HtmlLinks = htmlLinks,
            RawReceivedHeaders = rawReceived,
            RawAuthHeaders = rawAuth
        };
    }

    private static List<RoutingHop> ParseRoutingHops(List<string> topToBottomReceived)
    {
        var hops = new List<RoutingHop>();
        if (topToBottomReceived.Count == 0)
        {
            return hops;
        }

        // Reverse so Hop 1 is the earliest (originating) relay at the bottom of the header block.
        var chronological = topToBottomReceived.AsEnumerable().Reverse().ToList();
        DateTimeOffset? previousTimestamp = null;

        for (int i = 0; i < chronological.Count; i++)
        {
            string raw = chronological[i];
            var hop = new RoutingHop
            {
                HopNumber = i + 1,
                RawHeader = CollapseWhitespace(raw)
            };

            Match fromMatch = ReceivedFromRegex().Match(hop.RawHeader);
            if (fromMatch.Success)
            {
                hop.FromServer = fromMatch.Groups["from"].Value.Trim();
            }

            Match byMatch = ReceivedByRegex().Match(hop.RawHeader);
            if (byMatch.Success)
            {
                hop.ByServer = byMatch.Groups["by"].Value.Trim();
            }

            Match withMatch = ReceivedWithRegex().Match(hop.RawHeader);
            if (withMatch.Success)
            {
                hop.WithProtocol = withMatch.Groups["with"].Value.Trim();
            }

            foreach (Match ipMatch in Ipv4Regex().Matches(hop.RawHeader))
            {
                if (!hop.IpAddresses.Contains(ipMatch.Value, StringComparer.Ordinal))
                {
                    hop.IpAddresses.Add(ipMatch.Value);
                }
            }

            // Timestamp usually follows the final semicolon in a Received header.
            int lastSemicolon = raw.LastIndexOf(';');
            if (lastSemicolon >= 0 && lastSemicolon < raw.Length - 1)
            {
                string datePart = raw[(lastSemicolon + 1)..].Trim();
                if (DateUtils.TryParse(datePart, out DateTimeOffset parsedDate))
                {
                    hop.Timestamp = parsedDate;
                    if (previousTimestamp.HasValue)
                    {
                        TimeSpan delta = parsedDate - previousTimestamp.Value;
                        hop.DelayFromPrevious = delta;
                        if (delta < TimeSpan.Zero)
                        {
                            hop.DelayNote = $"Clock skew ({delta.TotalSeconds:F0}s)";
                        }
                        else if (delta > TimeSpan.FromMinutes(10))
                        {
                            hop.DelayNote = "Elevated relay delay";
                        }
                    }

                    previousTimestamp = parsedDate;
                }
            }

            hops.Add(hop);
        }

        return hops;
    }

    private static AuthenticationSummary ParseAuthenticationResults(HeaderList headers, List<string> rawAuthHeaders)
    {
        var summary = new AuthenticationSummary
        {
            RawHeaders = rawAuthHeaders
        };

        var authResultValues = headers
            .Where(h =>
                h.Field.Equals("Authentication-Results", StringComparison.OrdinalIgnoreCase) ||
                h.Field.Equals("ARC-Authentication-Results", StringComparison.OrdinalIgnoreCase))
            .Select(h => h.Value)
            .ToList();

        foreach (string value in authResultValues)
        {
            foreach (Match match in AuthMechanismRegex().Matches(value))
            {
                string mech = match.Groups["mech"].Value.ToLowerInvariant();
                string status = match.Groups["status"].Value.ToLowerInvariant();
                string detail = CollapseWhitespace(match.Groups["detail"].Value);

                switch (mech)
                {
                    case "spf" when summary.SpfStatus == "none":
                        summary.SpfStatus = status;
                        summary.SpfDetails = string.IsNullOrWhiteSpace(detail) ? null : detail;
                        break;
                    case "dkim" when summary.DkimStatus == "none":
                        summary.DkimStatus = status;
                        summary.DkimDetails = string.IsNullOrWhiteSpace(detail) ? null : detail;
                        Match domMatch = HeaderDomainRegex().Match(detail);
                        if (domMatch.Success)
                        {
                            summary.DkimDomain = domMatch.Groups["domain"].Value;
                        }
                        break;
                    case "dmarc" when summary.DmarcStatus == "none":
                        summary.DmarcStatus = status;
                        summary.DmarcDetails = string.IsNullOrWhiteSpace(detail) ? null : detail;
                        break;
                }
            }
        }

        // Fallback to Received-SPF if Authentication-Results lacked SPF status
        if (summary.SpfStatus == "none")
        {
            string? receivedSpf = headers["Received-SPF"];
            if (!string.IsNullOrWhiteSpace(receivedSpf))
            {
                string firstToken = receivedSpf.Trim().Split([' ', '\t', ';', '('], StringSplitOptions.RemoveEmptyEntries)
                    .FirstOrDefault()?.ToLowerInvariant() ?? "unknown";
                summary.SpfStatus = firstToken;
                summary.SpfDetails = CollapseWhitespace(receivedSpf);
            }
        }

        return summary;
    }

    private static void DetectSpoofingAnomalies(EmailHeaderInfo info)
    {
        string? fromDomain = ExtractDomain(info.FromAddress);
        string? returnPathDomain = ExtractDomain(info.ReturnPath);

        if (!string.IsNullOrEmpty(fromDomain) && !string.IsNullOrEmpty(returnPathDomain))
        {
            if (!DomainsShareOrganization(fromDomain, returnPathDomain))
            {
                info.SpoofingIndicators.Add(
                    $"From domain ({fromDomain}) mismatches Return-Path domain ({returnPathDomain}).");
            }
        }
        else if (!string.IsNullOrEmpty(info.FromAddress) && string.IsNullOrEmpty(info.ReturnPath))
        {
            info.SpoofingIndicators.Add("Missing Return-Path header.");
        }

        foreach (string replyAddress in info.ReplyTo)
        {
            string? replyDomain = ExtractDomain(replyAddress);
            if (!string.IsNullOrEmpty(fromDomain) &&
                !string.IsNullOrEmpty(replyDomain) &&
                !DomainsShareOrganization(fromDomain, replyDomain))
            {
                info.SpoofingIndicators.Add(
                    $"From domain ({fromDomain}) mismatches Reply-To domain ({replyDomain}) — common BEC/phishing indicator.");
            }
        }

        // Display name spoofing: e.g. Display Name contains an email from another domain
        if (!string.IsNullOrWhiteSpace(info.FromDisplayName) && !string.IsNullOrEmpty(fromDomain))
        {
            Match embeddedEmail = EmailAddressRegex().Match(info.FromDisplayName);
            if (embeddedEmail.Success)
            {
                string displayDomain = embeddedEmail.Groups["domain"].Value;
                if (!DomainsShareOrganization(fromDomain, displayDomain))
                {
                    info.SpoofingIndicators.Add(
                        $"Display name impersonation: From display name contains '{embeddedEmail.Value}' while actual sender domain is '{fromDomain}'.");
                }
            }
        }

        if (string.IsNullOrWhiteSpace(info.MessageId))
        {
            info.SpoofingIndicators.Add("Missing Message-ID header.");
        }

        if (info.RoutingHops.Count == 0)
        {
            info.SpoofingIndicators.Add("No Received headers found; mail routing path could not be verified.");
        }
    }

    private static List<HtmlAnchorLink> ExtractHtmlLinks(string htmlBody)
    {
        var links = new List<HtmlAnchorLink>();
        if (string.IsNullOrWhiteSpace(htmlBody))
        {
            return links;
        }

        foreach (Match match in HtmlAnchorRegex().Matches(htmlBody))
        {
            string href = WebUtility.HtmlDecode(match.Groups["href"].Value).Trim();
            string rawText = StripHtmlTagsRegex().Replace(match.Groups["text"].Value, " ");
            string cleanText = CollapseWhitespace(WebUtility.HtmlDecode(rawText));

            if (!string.IsNullOrWhiteSpace(href))
            {
                links.Add(new HtmlAnchorLink(href, cleanText));
            }
        }

        return links;
    }

    private static string FormatMailbox(MailboxAddress mailbox)
    {
        return string.IsNullOrWhiteSpace(mailbox.Name)
            ? mailbox.Address
            : $"{mailbox.Name} <{mailbox.Address}>";
    }

    private static string? CleanAngleBrackets(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        string trimmed = value.Trim();
        if (trimmed.StartsWith('<') && trimmed.EndsWith('>') && trimmed.Length >= 2)
        {
            trimmed = trimmed[1..^1].Trim();
        }

        return string.IsNullOrEmpty(trimmed) ? null : trimmed;
    }

    private static string? ExtractDomain(string? emailAddress)
    {
        if (string.IsNullOrWhiteSpace(emailAddress))
        {
            return null;
        }

        int atIdx = emailAddress.LastIndexOf('@');
        if (atIdx < 0 || atIdx == emailAddress.Length - 1)
        {
            return null;
        }

        return emailAddress[(atIdx + 1)..].Trim().TrimEnd('>').ToLowerInvariant();
    }

    private static bool DomainsShareOrganization(string domainA, string domainB)
    {
        string a = domainA.ToLowerInvariant().Trim('.');
        string b = domainB.ToLowerInvariant().Trim('.');
        if (a == b)
        {
            return true;
        }

        // Allow exact parent/subdomain relationship (e.g. bounce.company.com vs company.com)
        return a.EndsWith("." + b, StringComparison.Ordinal) ||
               b.EndsWith("." + a, StringComparison.Ordinal);
    }

    private static string CollapseWhitespace(string input)
    {
        return string.Join(' ', input.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
    }
}
