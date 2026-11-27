using System.Text.RegularExpressions;

namespace EmlDissect.Utils;

/// <summary>
/// Helper methods to defang URLs, IP addresses, domains, and email addresses.
/// </summary>
public static partial class DefangHelper
{
    [GeneratedRegex(@"^(?<scheme>https?|ftp|wss?)(://)", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex SchemeRegex();

    [GeneratedRegex(@"^(?<prefix>(?:hxxps?|fxp|wss?)://)(?<authority>[^/?#]+)(?<rest>.*)$", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex AuthoritySplitRegex();

    /// <summary>
    /// Defangs a URL by replacing http/https with hxxp/hxxps, ftp with fxp,
    /// neutralizing dots in the host/authority with [.], and neutralizing @ in userinfo.
    /// Example: http://evil.com/login -> hxxp://evil[.]com/login
    /// </summary>
    public static string DefangUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return string.Empty;
        }

        string trimmed = url.Trim();

        // Normalize any already-defanged dots in the host temporarily to avoid double brackets.
        string result = SchemeRegex().Replace(trimmed, match =>
        {
            string scheme = match.Groups["scheme"].Value.ToLowerInvariant();
            string defangedScheme = scheme switch
            {
                "http" => "hxxp",
                "https" => "hxxps",
                "ftp" => "fxp",
                "ws" => "wxs",
                "wss" => "wxss",
                _ => scheme
            };
            return defangedScheme + match.Groups[2].Value;
        });

        Match authMatch = AuthoritySplitRegex().Match(result);
        if (authMatch.Success)
        {
            string prefix = authMatch.Groups["prefix"].Value;
            string authority = authMatch.Groups["authority"].Value;
            string rest = authMatch.Groups["rest"].Value;

            // Defang host/userinfo dots and '@' (e.g., https://trusted.com@evil.com)
            string cleanAuthority = authority.Replace("[.]", ".").Replace("[@]", "@");
            string defangedAuthority = cleanAuthority.Replace(".", "[.]").Replace("@", "[@]");

            return string.Concat(prefix, defangedAuthority, rest);
        }

        // Fallback for schemeless URLs
        return trimmed.Replace("[.]", ".").Replace(".", "[.]");
    }

    /// <summary>
    /// Defangs an IPv4 address by replacing dots with [.].
    /// Example: 185.220.101.1 -> 185[.]220[.]101[.]1
    /// </summary>
    public static string DefangIp(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
        {
            return string.Empty;
        }

        string normalized = ip.Trim().Replace("[.]", ".");
        return normalized.Replace(".", "[.]");
    }

    /// <summary>
    /// Defangs a domain name by replacing dots with [.].
    /// Example: evil.com -> evil[.]com
    /// </summary>
    public static string DefangDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return string.Empty;
        }

        string normalized = domain.Trim().Replace("[.]", ".");
        return normalized.Replace(".", "[.]");
    }

    /// <summary>
    /// Defangs an email address by replacing '@' with '[@]' and domain dots with '[.]'.
    /// </summary>
    public static string DefangEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return string.Empty;
        }

        string trimmed = email.Trim();
        int atIndex = trimmed.LastIndexOf('@');
        if (atIndex <= 0 || atIndex == trimmed.Length - 1)
        {
            return trimmed.Replace(".", "[.]");
        }

        string local = trimmed[..atIndex];
        string domain = DefangDomain(trimmed[(atIndex + 1)..]);
        return $"{local}[@]{domain}";
    }

    /// <summary>
    /// Reverses defanging (e.g. hxxps://evil[.]com -> https://evil.com) when needed for API lookups.
    /// </summary>
    public static string Refang(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        string refanged = value.Trim()
            .Replace("[.]", ".")
            .Replace("(.)", ".")
            .Replace("[@]", "@");

        if (refanged.StartsWith("hxxps://", StringComparison.OrdinalIgnoreCase))
        {
            refanged = "https://" + refanged[8..];
        }
        else if (refanged.StartsWith("hxxp://", StringComparison.OrdinalIgnoreCase))
        {
            refanged = "http://" + refanged[7..];
        }
        else if (refanged.StartsWith("fxp://", StringComparison.OrdinalIgnoreCase))
        {
            refanged = "ftp://" + refanged[6..];
        }

        return refanged;
    }
}
