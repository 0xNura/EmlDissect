using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using EmlDissect.Models;

namespace EmlDissect.Services;

/// <summary>
/// Queries ipinfo.io for geolocation, ISP, and ASN metadata for public IPv4 addresses.
/// Supports optional IPINFO_TOKEN environment variable for higher rate limits.
/// </summary>
public sealed class IpInfoService
{
    private readonly HttpClient _httpClient;
    private readonly string? _token;

    public IpInfoService(HttpClient httpClient)
    {
        _httpClient = httpClient;
        _token = Environment.GetEnvironmentVariable("IPINFO_TOKEN")?.Trim();
    }

    public bool HasToken => !string.IsNullOrEmpty(_token);

    /// <summary>
    /// Enriches a single public IPv4 address via https://ipinfo.io/{ip}/json.
    /// </summary>
    public async Task<IpInfoResult> LookupAsync(string ipAddress, CancellationToken cancellationToken = default)
    {
        var result = new IpInfoResult { Ip = ipAddress };

        if (IPAddress.TryParse(ipAddress, out IPAddress? parsed) &&
            IocExtractorService.IsPrivateOrReservedIpv4(parsed))
        {
            result.Error = "Private/reserved IP address (skipped)";
            return result;
        }

        try
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Get,
                $"https://ipinfo.io/{Uri.EscapeDataString(ipAddress)}/json");

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            if (!string.IsNullOrEmpty(_token))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
            }

            using HttpResponseMessage response = await _httpClient.SendAsync(request, cancellationToken);
            string body = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                result.Error = $"HTTP {(int)response.StatusCode} ({response.ReasonPhrase})";
                return result;
            }

            using JsonDocument doc = JsonDocument.Parse(body);
            JsonElement root = doc.RootElement;

            result.Hostname = GetOptionalString(root, "hostname");
            result.City = GetOptionalString(root, "city");
            result.Region = GetOptionalString(root, "region");
            result.Country = GetOptionalString(root, "country");
            result.Org = GetOptionalString(root, "org");
            result.Location = GetOptionalString(root, "loc");
            result.Timezone = GetOptionalString(root, "timezone");

            if (!string.IsNullOrWhiteSpace(result.Org))
            {
                string[] parts = result.Org.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 1 && parts[0].StartsWith("AS", StringComparison.OrdinalIgnoreCase))
                {
                    result.Asn = parts[0];
                    result.Isp = parts.Length > 1 ? parts[1] : null;
                }
                else
                {
                    result.Isp = result.Org;
                }
            }
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            result.Error = "Request timed out";
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
        }

        return result;
    }

    private static string? GetOptionalString(JsonElement root, string propertyName)
    {
        return root.TryGetProperty(propertyName, out JsonElement prop) &&
               prop.ValueKind == JsonValueKind.String
            ? prop.GetString()
            : null;
    }
}
