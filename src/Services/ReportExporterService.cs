using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using EmlDissect.Models;
using EmlDissect.Utils;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Services;
using Google.Apis.Sheets.v4;
using Google.Apis.Sheets.v4.Data;

namespace EmlDissect.Services;

/// <summary>
/// Exports ForensicReport data to formatted JSON, SIEM/Excel-friendly CSV,
/// and Google Sheets (via Google Sheets API v4 Service Account or configurable Webhook).
/// </summary>
public sealed class ReportExporterService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    private static readonly string[] FlatColumns =
    {
        "AnalyzedAtUtc",
        "SourceFile",
        "FileSha256",
        "From",
        "ReturnPath",
        "ReplyTo",
        "Subject",
        "DateUtc",
        "Spf",
        "Dkim",
        "Dmarc",
        "OriginatingIpDefanged",
        "PublicIpsDefanged",
        "DefangedUrls",
        "AttachmentNames",
        "AttachmentSha256s",
        "MaxVtDetections",
        "MaxAbuseConfidenceScore",
        "WarningCount",
        "WarningsSummary"
    };

    private readonly HttpClient _httpClient;

    public ReportExporterService(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    /// <summary>
    /// Exports the full ForensicReport object as indented JSON.
    /// </summary>
    public async Task ExportJsonAsync(
        ForensicReport report,
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        EnsureParentDirectory(outputPath);
        string json = JsonSerializer.Serialize(report, JsonOptions);
        await File.WriteAllTextAsync(outputPath, json, Encoding.UTF8, cancellationToken);
    }

    /// <summary>
    /// Exports a flattened summary row suitable for Excel or SIEM ingestion.
    /// </summary>
    public async Task ExportCsvAsync(
        ForensicReport report,
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        EnsureParentDirectory(outputPath);

        string[] values = BuildFlatSummaryRow(report).Select(v => v?.ToString() ?? string.Empty).ToArray();

        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", FlatColumns.Select(EscapeCsvField)));
        sb.AppendLine(string.Join(",", values.Select(EscapeCsvField)));

        await File.WriteAllTextAsync(outputPath, sb.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true), cancellationToken);
    }

    /// <summary>
    /// Appends the flattened forensic analysis row to a Google Sheet using either
    /// Google Sheets API v4 (GOOGLE_APPLICATION_CREDENTIALS) or a Webhook URL (GSHEET_WEBHOOK_URL).
    /// </summary>
    public async Task<string> ExportGoogleSheetAsync(
        ForensicReport report,
        string spreadsheetId,
        string? sheetRange = null,
        string? webhookUrl = null,
        CancellationToken cancellationToken = default)
    {
        string targetRange = string.IsNullOrWhiteSpace(sheetRange) ? "Sheet1!A:T" : sheetRange.Trim();
        string? effectiveWebhook = !string.IsNullOrWhiteSpace(webhookUrl)
            ? webhookUrl.Trim()
            : Environment.GetEnvironmentVariable("GSHEET_WEBHOOK_URL")?.Trim();

        string? credentialsPath = Environment.GetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS")?.Trim();

        // If an explicit webhook URL is passed or credentials are not set while a webhook env var exists, use Webhook POST.
        if (!string.IsNullOrWhiteSpace(webhookUrl) ||
            (string.IsNullOrWhiteSpace(credentialsPath) && !string.IsNullOrWhiteSpace(effectiveWebhook)))
        {
            await SendToWebhookAsync(report, spreadsheetId, targetRange, effectiveWebhook!, cancellationToken);
            return $"Appended forensic summary via Webhook ({effectiveWebhook})";
        }

        if (string.IsNullOrWhiteSpace(credentialsPath))
        {
            throw new InvalidOperationException(
                "Google Sheets export requires either GOOGLE_APPLICATION_CREDENTIALS (path to Service Account JSON) " +
                "or GSHEET_WEBHOOK_URL / --gsheet-webhook.");
        }

        if (!File.Exists(credentialsPath))
        {
            throw new FileNotFoundException(
                $"GOOGLE_APPLICATION_CREDENTIALS file not found at '{credentialsPath}'.",
                credentialsPath);
        }

        GoogleCredential credential;
        await using (FileStream credStream = File.OpenRead(credentialsPath))
        {
            credential = GoogleCredential.FromStream(credStream)
                .CreateScoped(SheetsService.Scope.Spreadsheets);
        }

        using var sheetsService = new SheetsService(new BaseClientService.Initializer
        {
            HttpClientInitializer = credential,
            ApplicationName = "EmlDissect"
        });

        IList<object> rowValues = BuildFlatSummaryRow(report);
        var valueRange = new ValueRange
        {
            Values = new List<IList<object>> { rowValues }
        };

        SpreadsheetsResource.ValuesResource.AppendRequest appendRequest =
            sheetsService.Spreadsheets.Values.Append(valueRange, spreadsheetId, targetRange);
        appendRequest.ValueInputOption = SpreadsheetsResource.ValuesResource.AppendRequest.ValueInputOptionEnum.USERENTERED;
        appendRequest.InsertDataOption = SpreadsheetsResource.ValuesResource.AppendRequest.InsertDataOptionEnum.INSERTROWS;

        AppendValuesResponse response = await appendRequest.ExecuteAsync(cancellationToken);
        string updatedRange = response.Updates?.UpdatedRange ?? targetRange;
        return $"Appended 1 row to Google Sheet '{spreadsheetId}' ({updatedRange})";
    }

    private async Task SendToWebhookAsync(
        ForensicReport report,
        string spreadsheetId,
        string range,
        string webhookUrl,
        CancellationToken cancellationToken)
    {
        var payload = new
        {
            spreadsheetId,
            range,
            columns = FlatColumns,
            row = BuildFlatSummaryRow(report),
            report
        };

        using HttpResponseMessage response = await _httpClient.PostAsJsonAsync(webhookUrl, payload, JsonOptions, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            string body = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new HttpRequestException(
                $"Google Sheet webhook returned HTTP {(int)response.StatusCode}: {body}");
        }
    }

    private static IList<object> BuildFlatSummaryRow(ForensicReport report)
    {
        string originatingIp = report.Headers.RoutingHops
            .FirstOrDefault(h => h.IpAddresses.Count > 0)?
            .IpAddresses.FirstOrDefault() ?? string.Empty;

        if (!string.IsNullOrEmpty(originatingIp))
        {
            originatingIp = DefangHelper.DefangIp(originatingIp);
        }

        string publicIps = string.Join("; ", report.NetworkIocs.IpAddresses
            .Where(i => !i.IsPrivateOrReserved)
            .Select(i => i.DefangedIp));

        string urls = string.Join("; ", report.NetworkIocs.Urls.Select(u => u.DefangedUrl));
        string attNames = string.Join("; ", report.Attachments.Select(a => a.Filename));
        string attHashes = string.Join("; ", report.Attachments.Select(a => a.Sha256));

        int maxVtFile = report.Attachments
            .Where(a => a.VirusTotal is { Found: true })
            .Select(a => a.VirusTotal!.Malicious + a.VirusTotal!.Suspicious)
            .DefaultIfEmpty(0)
            .Max();

        int maxVtUrl = report.NetworkIocs.Urls
            .Where(u => u.VirusTotal is { Found: true })
            .Select(u => u.VirusTotal!.Malicious + u.VirusTotal!.Suspicious)
            .DefaultIfEmpty(0)
            .Max();

        int maxAbuse = report.NetworkIocs.IpAddresses
            .Where(i => i.AbuseIpDb is { Error: null })
            .Select(i => i.AbuseIpDb!.AbuseConfidenceScore)
            .DefaultIfEmpty(0)
            .Max();

        string warningsSummary = string.Join(" | ",
            report.SecurityWarnings.Select(w => $"[{w.Severity}] {w.Message}"));

        return new List<object>
        {
            report.AnalyzedAtUtc.ToString("O"),
            Path.GetFileName(report.SourceFile),
            report.FileSha256,
            DefangEmailIfPresent(report.Headers.FromAddress ?? report.Headers.From),
            DefangEmailIfPresent(report.Headers.ReturnPath),
            string.Join("; ", report.Headers.ReplyTo.Select(DefangHelper.DefangEmail)),
            report.Headers.Subject,
            report.Headers.Date?.ToUniversalTime().ToString("O") ?? string.Empty,
            report.Headers.Authentication.SpfStatus,
            report.Headers.Authentication.DkimStatus,
            report.Headers.Authentication.DmarcStatus,
            originatingIp,
            publicIps,
            urls,
            attNames,
            attHashes,
            Math.Max(maxVtFile, maxVtUrl),
            maxAbuse,
            report.SecurityWarnings.Count,
            warningsSummary
        };
    }

    private static string DefangEmailIfPresent(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return string.Empty;
        }

        return email.Contains('@') ? DefangHelper.DefangEmail(email) : email;
    }

    private static string EscapeCsvField(string field)
    {
        if (string.IsNullOrEmpty(field))
        {
            return string.Empty;
        }

        // Neutralize spreadsheet formula injection (=, +, -, @ at start) if opened in Excel
        string safe = field;
        if (safe.StartsWith('=') || safe.StartsWith('+') || safe.StartsWith('-') || safe.StartsWith('@'))
        {
            safe = "'" + safe;
        }

        if (safe.Contains(',') || safe.Contains('"') || safe.Contains('\n') || safe.Contains('\r'))
        {
            return "\"" + safe.Replace("\"", "\"\"") + "\"";
        }

        return safe;
    }

    private static void EnsureParentDirectory(string path)
    {
        string? dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrWhiteSpace(dir))
        {
            Directory.CreateDirectory(dir);
        }
    }
}
