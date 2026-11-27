using System.Net;
using System.Text.RegularExpressions;
using EmlDissect.Models;
using EmlDissect.Utils;

namespace EmlDissect.Services;

/// <summary>
/// Extracts IPv4 addresses, URLs, and domains from email headers and body content,
/// applies private/loopback IP filtering, detects HTML anchor-text deception, and defangs all IOCs.
/// </summary>
public sealed partial class IocExtractorService
{
    [GeneratedRegex(@"(?<![.\d])(?<ip>(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))(?![.\d])", RegexOptions.Compiled)]
    private static partial Regex Ipv4Regex();

    [GeneratedRegex(@"\b(?<url>(?:https?|hxxps?|ftp)://[^\s""'<>()\]\[`]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex UrlRegex();

    [GeneratedRegex(@"\b(?<domain>(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|edu|gov|io|co|xyz|top|ru|cn|info|biz|me|online|site|club|vip|app|dev|uk|de|fr|nl|au|ca))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex DomainLikeTextRegex();

    private static readonly string[] BenignSchemaPrefixes =
    {
        "http://www.w3.org/",
        "https://www.w3.org/",
        "http://schemas.microsoft.com/",
        "https://schemas.microsoft.com/",
        "http://schemas.openxmlformats.org/",
        "http://purl.org/",
        "http://ns.adobe.com/"
    };

    /// <summary>
    /// Extracts and defangs network IOCs from parsed headers, text body, and HTML body.
    /// </summary>
    public NetworkIocCollection Extract(ParsedEmailContext context, bool includePrivateIps = false)
    {
        var ipMap = new Dictionary<string, ExtractedIp>(StringComparer.OrdinalIgnoreCase);
        var urlList = new List<ExtractedUrl>();
        var seenUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var uniqueDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 1. Extract IPs from Routing Hops
        foreach (RoutingHop hop in context.HeaderInfo.RoutingHops)
        {
            foreach (string ip in hop.IpAddresses)
            {
                AddIp(ipMap, ip, $"Received Header (Hop {hop.HopNumber})", includePrivateIps);
            }
        }

        // 2. Extract IPs from X-Originating-IP & Authentication Headers
        if (!string.IsNullOrWhiteSpace(context.HeaderInfo.XOriginatingIp))
        {
            foreach (Match m in Ipv4Regex().Matches(context.HeaderInfo.XOriginatingIp))
            {
                AddIp(ipMap, m.Groups["ip"].Value, "X-Originating-IP Header", includePrivateIps);
            }
        }

        foreach (string authHeader in context.RawAuthHeaders)
        {
            foreach (Match m in Ipv4Regex().Matches(authHeader))
            {
                AddIp(ipMap, m.Groups["ip"].Value, "Authentication Header", includePrivateIps);
            }
        }

        // 3. Extract IPs from Plain Text and HTML Body
        foreach (Match m in Ipv4Regex().Matches(context.TextBody))
        {
            AddIp(ipMap, m.Groups["ip"].Value, "PlainText Body", includePrivateIps);
        }

        foreach (Match m in Ipv4Regex().Matches(context.HtmlBody))
        {
            AddIp(ipMap, m.Groups["ip"].Value, "HTML Body", includePrivateIps);
        }

        // 4. Extract HTML <a href="..."> links first so anchor text mismatches are captured
        foreach (HtmlAnchorLink link in context.HtmlLinks)
        {
            string normalizedHref = NormalizeExtractedUrl(link.Href);
            if (!IsNavigableWebUrl(normalizedHref))
            {
                continue;
            }

            if (seenUrls.Add(normalizedHref))
            {
                ExtractedUrl extracted = BuildUrlRecord(normalizedHref, "HTML <a href>", link.AnchorText);
                urlList.Add(extracted);
                RecordDomainAndEmbeddedIp(extracted, ipMap, uniqueDomains, "HTML <a href> URL", includePrivateIps);
            }
        }

        // 5. Extract URLs from Plain Text Body
        foreach (Match m in UrlRegex().Matches(context.TextBody))
        {
            string url = NormalizeExtractedUrl(m.Groups["url"].Value);
            if (IsBenignSchemaNamespace(url))
            {
                continue;
            }

            if (seenUrls.Add(url))
            {
                ExtractedUrl extracted = BuildUrlRecord(url, "PlainText Body", null);
                urlList.Add(extracted);
                RecordDomainAndEmbeddedIp(extracted, ipMap, uniqueDomains, "PlainText URL", includePrivateIps);
            }
        }

        // 6. Extract remaining URLs from HTML Body (e.g., img src, form action, script src, inline text)
        foreach (Match m in UrlRegex().Matches(context.HtmlBody))
        {
            string url = NormalizeExtractedUrl(m.Groups["url"].Value);
            if (IsBenignSchemaNamespace(url))
            {
                continue;
            }

            if (seenUrls.Add(url))
            {
                ExtractedUrl extracted = BuildUrlRecord(url, "HTML Body", null);
                urlList.Add(extracted);
                RecordDomainAndEmbeddedIp(extracted, ipMap, uniqueDomains, "HTML Body URL", includePrivateIps);
            }
        }

        return new NetworkIocCollection
        {
            IpAddresses = ipMap.Values.ToList(),
            Urls = urlList,
            DefangedDomains = uniqueDomains
                .Select(DefangHelper.DefangDomain)
                .OrderBy(d => d, StringComparer.OrdinalIgnoreCase)
                .ToList()
        };
    }

    private static void AddIp(
        Dictionary<string, ExtractedIp> ipMap,
        string candidate,
        string source,
        bool includePrivateIps)
    {
        if (!IPAddress.TryParse(candidate, out IPAddress? addr) ||
            addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return;
        }

        bool isPrivate = IsPrivateOrReservedIpv4(addr);
        if (isPrivate && !includePrivateIps)
        {
            return;
        }

        string canonical = addr.ToString();
        if (!ipMap.TryGetValue(canonical, out ExtractedIp? entry))
        {
            entry = new ExtractedIp
            {
                RawIp = canonical,
                DefangedIp = DefangHelper.DefangIp(canonical),
                IsPrivateOrReserved = isPrivate
            };
            ipMap[canonical] = entry;
        }

        if (!entry.Sources.Contains(source, StringComparer.OrdinalIgnoreCase))
        {
            entry.Sources.Add(source);
        }
    }

    private static ExtractedUrl BuildUrlRecord(string rawUrl, string source, string? anchorText)
    {
        string refangedForUri = DefangHelper.Refang(rawUrl);
        string? domain = null;
        if (Uri.TryCreate(refangedForUri, UriKind.Absolute, out Uri? uri) && !string.IsNullOrWhiteSpace(uri.Host))
        {
            domain = uri.Host.ToLowerInvariant();
        }

        var record = new ExtractedUrl
        {
            RawUrl = refangedForUri,
            DefangedUrl = DefangHelper.DefangUrl(refangedForUri),
            Domain = domain,
            DefangedDomain = domain is not null ? DefangHelper.DefangDomain(domain) : null,
            Source = source,
            AnchorText = string.IsNullOrWhiteSpace(anchorText) ? null : anchorText
        };

        // Check for anchor text mismatch (e.g., anchor displays https://microsoft.com but href goes to evil.com)
        if (!string.IsNullOrWhiteSpace(anchorText) && !string.IsNullOrEmpty(domain))
        {
            string? displayedHost = ExtractHostFromAnchorText(anchorText);
            if (!string.IsNullOrEmpty(displayedHost) &&
                !HostsMatch(domain, displayedHost))
            {
                record.HasAnchorMismatch = true;
                record.MismatchReason =
                    $"Anchor text displays '{DefangHelper.DefangDomain(displayedHost)}' while href points to '{DefangHelper.DefangDomain(domain)}'.";
            }
        }

        return record;
    }

    private static void RecordDomainAndEmbeddedIp(
        ExtractedUrl urlRecord,
        Dictionary<string, ExtractedIp> ipMap,
        HashSet<string> uniqueDomains,
        string ipSource,
        bool includePrivateIps)
    {
        if (string.IsNullOrEmpty(urlRecord.Domain))
        {
            return;
        }

        if (IPAddress.TryParse(urlRecord.Domain, out _))
        {
            AddIp(ipMap, urlRecord.Domain, ipSource, includePrivateIps);
        }
        else
        {
            uniqueDomains.Add(urlRecord.Domain);
        }
    }

    private static string? ExtractHostFromAnchorText(string anchorText)
    {
        string trimmed = DefangHelper.Refang(anchorText.Trim());

        if (Uri.TryCreate(trimmed, UriKind.Absolute, out Uri? uri) && !string.IsNullOrWhiteSpace(uri.Host))
        {
            return uri.Host.ToLowerInvariant();
        }

        Match urlMatch = UrlRegex().Match(trimmed);
        if (urlMatch.Success &&
            Uri.TryCreate(DefangHelper.Refang(urlMatch.Groups["url"].Value), UriKind.Absolute, out Uri? innerUri))
        {
            return innerUri.Host.ToLowerInvariant();
        }

        Match domMatch = DomainLikeTextRegex().Match(trimmed);
        if (domMatch.Success)
        {
            return domMatch.Groups["domain"].Value.ToLowerInvariant();
        }

        return null;
    }

    private static bool HostsMatch(string actualHost, string displayedHost)
    {
        string a = actualHost.Trim('.').ToLowerInvariant();
        string b = displayedHost.Trim('.').ToLowerInvariant();
        if (a == b)
        {
            return true;
        }

        return a.EndsWith("." + b, StringComparison.Ordinal) ||
               b.EndsWith("." + a, StringComparison.Ordinal);
    }

    /// <summary>
    /// Returns true for RFC1918, loopback, link-local, CGNAT, multicast, and reserved IPv4 ranges.
    /// </summary>
    public static bool IsPrivateOrReservedIpv4(IPAddress address)
    {
        byte[] bytes = address.GetAddressBytes();
        if (bytes.Length != 4)
        {
            return true;
        }

        return bytes[0] switch
        {
            0 => true,                                            // 0.0.0.0/8 (Current network)
            10 => true,                                           // 10.0.0.0/8 (RFC1918)
            127 => true,                                          // 127.0.0.0/8 (Loopback)
            100 when bytes[1] >= 64 && bytes[1] <= 127 => true,   // 100.64.0.0/10 (CGNAT)
            169 when bytes[1] == 254 => true,                     // 169.254.0.0/16 (Link-local)
            172 when bytes[1] >= 16 && bytes[1] <= 31 => true,    // 172.16.0.0/12 (RFC1918)
            192 when bytes[1] == 168 => true,                     // 192.168.0.0/16 (RFC1918)
            192 when bytes[1] == 0 && bytes[2] == 0 => true,      // 192.0.0.0/24 (IETF Protocol)
            192 when bytes[1] == 0 && bytes[2] == 2 => true,      // 192.0.2.0/24 (TEST-NET-1)
            198 when bytes[1] == 51 && bytes[2] == 100 => true,   // 198.51.100.0/24 (TEST-NET-2)
            203 when bytes[1] == 0 && bytes[2] == 113 => true,    // 203.0.113.0/24 (TEST-NET-3)
            >= 224 => true,                                       // 224.0.0.0/4 Multicast & 240.0.0.0/4 Reserved
            _ => false
        };
    }

    private static string NormalizeExtractedUrl(string raw)
    {
        return raw.Trim().TrimEnd('.', ',', ';', ')', ']', '>', '"', '\'');
    }

    private static bool IsNavigableWebUrl(string url)
    {
        return url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
               url.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
               url.StartsWith("hxxp://", StringComparison.OrdinalIgnoreCase) ||
               url.StartsWith("hxxps://", StringComparison.OrdinalIgnoreCase) ||
               url.StartsWith("ftp://", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsBenignSchemaNamespace(string url)
    {
        foreach (string prefix in BenignSchemaPrefixes)
        {
            if (url.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
