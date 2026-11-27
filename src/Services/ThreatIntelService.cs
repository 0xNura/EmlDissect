using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using EmlDissect.Models;
using EmlDissect.Utils;

namespace EmlDissect.Services;

/// <summary>
/// Enriches extracted hashes, URLs, and public IPv4 addresses using VirusTotal API v3
/// (with free-tier 4 req/min rate limiting) and AbuseIPDB API v2.
/// </summary>
public sealed class ThreatIntelService
{
    private const int VtMaxRequestsPerWindow = 4;
    private static readonly TimeSpan VtRateWindow = TimeSpan.FromSeconds(61);

    private readonly HttpClient _httpClient;
    private readonly string? _vtApiKey;
    private readonly string? _abuseIpDbKey;
    private readonly SemaphoreSlim _vtThrottleLock = new(1, 1);
    private readonly Queue<DateTimeOffset> _vtRequestTimestamps = new();

    public ThreatIntelService(HttpClient httpClient)
    {
        _httpClient = httpClient;
        _vtApiKey = Environment.GetEnvironmentVariable("VT_API_KEY")?.Trim();
        _abuseIpDbKey = Environment.GetEnvironmentVariable("ABUSEIPDB_API_KEY")?.Trim();
    }

    public bool HasVirusTotalKey => !string.IsNullOrEmpty(_vtApiKey);
    public bool HasAbuseIpDbKey => !string.IsNullOrEmpty(_abuseIpDbKey);

    /// <summary>
    /// Queries VirusTotal API v3 for a file's SHA-256 hash.
    /// </summary>
    public async Task<VirusTotalFileResult> LookupFileHashAsync(
        string sha256,
        Action<string>? onStatus = null,
        CancellationToken cancellationToken = default)
    {
        var result = new VirusTotalFileResult { Sha256 = sha256 };

        if (string.IsNullOrEmpty(_vtApiKey))
        {
            result.Error = "VT_API_KEY environment variable is not set";
            return result;
        }

        string endpoint = $"https://www.virustotal.com/api/v3/files/{Uri.EscapeDataString(sha256)}";
        (HttpStatusCode status, string body, string? error) =
            await SendVirusTotalGetAsync(endpoint, onStatus, cancellationToken);

        if (error is not null)
        {
            result.Error = error;
            return result;
        }

        if (status == HttpStatusCode.NotFound)
        {
            result.Found = false;
            result.DetectionRatio = "Not in VT";
            return result;
        }

        if (status != HttpStatusCode.OK)
        {
            result.Error = $"VirusTotal HTTP {(int)status}";
            return result;
        }

        try
        {
            using JsonDocument doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("data", out JsonElement data) ||
                !data.TryGetProperty("attributes", out JsonElement attrs))
            {
                result.Error = "Unexpected VirusTotal response format";
                return result;
            }

            result.Found = true;
            ParseVtAnalysisStats(attrs, out int mal, out int susp, out int harm, out int undet);
            result.Malicious = mal;
            result.Suspicious = susp;
            result.Harmless = harm;
            result.Undetected = undet;
            result.TotalEngines = mal + susp + harm + undet;
            result.DetectionRatio = result.TotalEngines > 0
                ? $"{mal + susp}/{result.TotalEngines}"
                : "0/0";

            if (attrs.TryGetProperty("meaningful_name", out JsonElement nameProp) &&
                nameProp.ValueKind == JsonValueKind.String)
            {
                result.MeaningfulName = nameProp.GetString();
            }

            if (attrs.TryGetProperty("popular_threat_classification", out JsonElement ptc) &&
                ptc.TryGetProperty("suggested_threat_label", out JsonElement labelProp) &&
                labelProp.ValueKind == JsonValueKind.String)
            {
                result.PopularThreatLabel = labelProp.GetString();
            }
        }
        catch (Exception ex)
        {
            result.Error = $"JSON parse error: {ex.Message}";
        }

        return result;
    }

    /// <summary>
    /// Queries VirusTotal API v3 for a URL using its unpadded Base64URL identifier.
    /// </summary>
    public async Task<VirusTotalUrlResult> LookupUrlAsync(
        string rawUrl,
        Action<string>? onStatus = null,
        CancellationToken cancellationToken = default)
    {
        var result = new VirusTotalUrlResult
        {
            Url = rawUrl,
            DefangedUrl = DefangHelper.DefangUrl(rawUrl)
        };

        if (string.IsNullOrEmpty(_vtApiKey))
        {
            result.Error = "VT_API_KEY environment variable is not set";
            return result;
        }

        string urlId = ToBase64UrlNoPadding(rawUrl);
        string endpoint = $"https://www.virustotal.com/api/v3/urls/{urlId}";
        (HttpStatusCode status, string body, string? error) =
            await SendVirusTotalGetAsync(endpoint, onStatus, cancellationToken);

        if (error is not null)
        {
            result.Error = error;
            return result;
        }

        if (status == HttpStatusCode.NotFound)
        {
            result.Found = false;
            result.DetectionRatio = "Not in VT";
            return result;
        }

        if (status != HttpStatusCode.OK)
        {
            result.Error = $"VirusTotal HTTP {(int)status}";
            return result;
        }

        try
        {
            using JsonDocument doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("data", out JsonElement data) ||
                !data.TryGetProperty("attributes", out JsonElement attrs))
            {
                result.Error = "Unexpected VirusTotal response format";
                return result;
            }

            result.Found = true;
            ParseVtAnalysisStats(attrs, out int mal, out int susp, out int harm, out int undet);
            result.Malicious = mal;
            result.Suspicious = susp;
            result.Harmless = harm;
            result.Undetected = undet;
            result.TotalEngines = mal + susp + harm + undet;
            result.DetectionRatio = result.TotalEngines > 0
                ? $"{mal + susp}/{result.TotalEngines}"
                : "0/0";
        }
        catch (Exception ex)
        {
            result.Error = $"JSON parse error: {ex.Message}";
        }

        return result;
    }

    /// <summary>
    /// Queries AbuseIPDB API v2 for IP reputation, abuse confidence score, and report count.
    /// </summary>
    public async Task<AbuseIpDbResult> LookupAbuseIpDbAsync(
        string ipAddress,
        CancellationToken cancellationToken = default)
    {
        var result = new AbuseIpDbResult { IpAddress = ipAddress };

        if (string.IsNullOrEmpty(_abuseIpDbKey))
        {
            result.Error = "ABUSEIPDB_API_KEY environment variable is not set";
            return result;
        }

        if (IPAddress.TryParse(ipAddress, out IPAddress? parsed) &&
            IocExtractorService.IsPrivateOrReservedIpv4(parsed))
        {
            result.Error = "Private/reserved IP address (skipped)";
            return result;
        }

        try
        {
            string url = $"https://api.abuseipdb.com/api/v2/check?ipAddress={Uri.EscapeDataString(ipAddress)}&maxAgeInDays=90&verbose";
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("Key", _abuseIpDbKey);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using HttpResponseMessage response = await _httpClient.SendAsync(request, cancellationToken);
            string body = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                result.Error = $"AbuseIPDB HTTP {(int)response.StatusCode} ({response.ReasonPhrase})";
                return result;
            }

            using JsonDocument doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("data", out JsonElement data))
            {
                result.Error = "Unexpected AbuseIPDB response format";
                return result;
            }

            result.IsPublic = data.TryGetProperty("isPublic", out JsonElement pub) && pub.ValueKind == JsonValueKind.True;
            result.AbuseConfidenceScore = GetInt(data, "abuseConfidenceScore");
            result.TotalReports = GetInt(data, "totalReports");
            result.NumDistinctUsers = GetInt(data, "numDistinctUsers");
            result.CountryCode = GetString(data, "countryCode");
            result.UsageType = GetString(data, "usageType");
            result.Isp = GetString(data, "isp");
            result.Domain = GetString(data, "domain");

            if (data.TryGetProperty("isWhitelisted", out JsonElement wl) &&
                (wl.ValueKind == JsonValueKind.True || wl.ValueKind == JsonValueKind.False))
            {
                result.IsWhitelisted = wl.GetBoolean();
            }

            string? lastRep = GetString(data, "lastReportedAt");
            if (!string.IsNullOrEmpty(lastRep) && DateTimeOffset.TryParse(lastRep, out DateTimeOffset dt))
            {
                result.LastReportedAt = dt;
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

    /// <summary>
    /// Enforces VirusTotal free-tier rate limit (4 requests / minute) and retries once on HTTP 429.
    /// </summary>
    private async Task<(HttpStatusCode Status, string Body, string? Error)> SendVirusTotalGetAsync(
        string url,
        Action<string>? onStatus,
        CancellationToken cancellationToken)
    {
        for (int attempt = 0; attempt < 2; attempt++)
        {
            await WaitForVtRateSlotAsync(onStatus, cancellationToken);

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.Add("x-apikey", _vtApiKey!);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                using HttpResponseMessage response = await _httpClient.SendAsync(request, cancellationToken);
                string body = await response.Content.ReadAsStringAsync(cancellationToken);

                if (response.StatusCode == HttpStatusCode.TooManyRequests && attempt == 0)
                {
                    TimeSpan retryDelay = response.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(61);
                    onStatus?.Invoke($"[VT] HTTP 429 rate limit hit; backing off for {retryDelay.TotalSeconds:F0}s...");
                    await Task.Delay(retryDelay, cancellationToken);
                    continue;
                }

                return (response.StatusCode, body, null);
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return (HttpStatusCode.RequestTimeout, string.Empty, "Request timed out");
            }
            catch (Exception ex)
            {
                return (HttpStatusCode.ServiceUnavailable, string.Empty, ex.Message);
            }
        }

        return (HttpStatusCode.TooManyRequests, string.Empty, "VirusTotal rate limit exceeded after retry");
    }

    private async Task WaitForVtRateSlotAsync(Action<string>? onStatus, CancellationToken cancellationToken)
    {
        await _vtThrottleLock.WaitAsync(cancellationToken);
        try
        {
            while (true)
            {
                DateTimeOffset now = DateTimeOffset.UtcNow;
                while (_vtRequestTimestamps.Count > 0 && now - _vtRequestTimestamps.Peek() >= VtRateWindow)
                {
                    _vtRequestTimestamps.Dequeue();
                }

                if (_vtRequestTimestamps.Count < VtMaxRequestsPerWindow)
                {
                    _vtRequestTimestamps.Enqueue(now);
                    return;
                }

                TimeSpan waitTime = VtRateWindow - (now - _vtRequestTimestamps.Peek());
                if (waitTime < TimeSpan.FromMilliseconds(250))
                {
                    waitTime = TimeSpan.FromMilliseconds(250);
                }

                onStatus?.Invoke($"[VT] Free-tier rate limit (4 req/min): waiting {waitTime.TotalSeconds:F1}s...");
                await Task.Delay(waitTime, cancellationToken);
            }
        }
        finally
        {
            _vtThrottleLock.Release();
        }
    }

    private static string ToBase64UrlNoPadding(string input)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(input);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static void ParseVtAnalysisStats(
        JsonElement attributes,
        out int malicious,
        out int suspicious,
        out int harmless,
        out int undetected)
    {
        malicious = 0;
        suspicious = 0;
        harmless = 0;
        undetected = 0;

        if (attributes.TryGetProperty("last_analysis_stats", out JsonElement stats))
        {
            malicious = GetInt(stats, "malicious");
            suspicious = GetInt(stats, "suspicious");
            harmless = GetInt(stats, "harmless");
            undetected = GetInt(stats, "undetected");
        }
    }

    private static int GetInt(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out JsonElement prop) &&
               prop.ValueKind == JsonValueKind.Number &&
               prop.TryGetInt32(out int val)
            ? val
            : 0;
    }

    private static string? GetString(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out JsonElement prop) &&
               prop.ValueKind == JsonValueKind.String
            ? prop.GetString()
            : null;
    }
}
