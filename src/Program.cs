using System.Security.Cryptography;
using EmlDissect.Models;
using EmlDissect.Services;
using EmlDissect.Utils;

namespace EmlDissect;

/// <summary>
// CLI entry point and argument parsing
/// </summary>
public static class Program
{
    private const string ToolVersion = "2.0.0";

    private sealed class CliOptions
    {
        public string? EmlFilePath { get; set; }
        public bool NoIntel { get; set; }
        public bool IncludePrivateIps { get; set; }
        public string? ExportJsonPath { get; set; }
        public string? ExportCsvPath { get; set; }
        public string? ExportGSheetId { get; set; }
        public string? GSheetRange { get; set; }
        public string? GSheetWebhookUrl { get; set; }
        public bool ShowHelp { get; set; }
        public bool ShowVersion { get; set; }
    }

    public static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        if (!TryParseArgs(args, out CliOptions options, out string? parseError))
        {
            WriteColoredLine($"[ERROR] {parseError}", ConsoleColor.Red);
            Console.WriteLine();
            PrintUsage();
            return 1;
        }

        if (options.ShowVersion)
        {
            Console.WriteLine($"EmlDissect v{ToolVersion}");
            return 0;
        }

        if (options.ShowHelp || string.IsNullOrWhiteSpace(options.EmlFilePath))
        {
            PrintBanner();
            PrintUsage();
            return options.ShowHelp ? 0 : 1;
        }

        string emlPath = Path.GetFullPath(options.EmlFilePath);
        if (!File.Exists(emlPath))
        {
            WriteColoredLine($"[ERROR] Input .eml file not found: {emlPath}", ConsoleColor.Red);
            return 1;
        }

        PrintBanner();
        WriteColoredLine($"[*] Target File : {emlPath}", ConsoleColor.Cyan);
        WriteColoredLine($"[*] Intel Mode  : {(options.NoIntel ? "OFFLINE (--no-intel)" : "ONLINE (IPinfo / VirusTotal / AbuseIPDB)")}", ConsoleColor.Cyan);

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        try
        {
            byte[] rawEmlBytes = await File.ReadAllBytesAsync(emlPath, cts.Token);
            string fileSha256 = Convert.ToHexString(SHA256.HashData(rawEmlBytes)).ToLowerInvariant();

            // 1. Parse headers, routing hops, authentication, and HTML links in memory
            var emailParser = new EmailParserService();
            using var emlStream = new MemoryStream(rawEmlBytes, writable: false);
            ParsedEmailContext parsed = await emailParser.ParseAsync(emlStream, cts.Token);

            // 2. Extract and defang network IOCs
            var iocExtractor = new IocExtractorService();
            NetworkIocCollection networkIocs = iocExtractor.Extract(parsed, options.IncludePrivateIps);

            // 3. Analyze attachments strictly in memory
            var attachmentForensics = new AttachmentForensics();
            List<AttachmentInfo> attachments = await attachmentForensics.AnalyzeAttachmentsAsync(parsed.Message, cts.Token);

            var report = new ForensicReport
            {
                ToolVersion = ToolVersion,
                AnalyzedAtUtc = DateTimeOffset.UtcNow,
                SourceFile = emlPath,
                FileSha256 = fileSha256,
                FileSizeBytes = rawEmlBytes.LongLength,
                OfflineMode = options.NoIntel,
                Headers = parsed.HeaderInfo,
                NetworkIocs = networkIocs,
                Attachments = attachments
            };

            // 4. Online Threat Intelligence Enrichment
            List<string> intelNotices = new();
            if (!options.NoIntel)
            {
                intelNotices = await EnrichWithThreatIntelAsync(report, cts.Token);
            }

            // 5. Aggregate Security Warnings
            BuildSecurityWarnings(report);

            // 6. Render ASCII/Color Terminal Report
            RenderReport(report, intelNotices);

            // 7. Export Reports
            int exportExitCode = await RunExportsAsync(report, options, cts.Token);
            return exportExitCode;
        }
        catch (OperationCanceledException)
        {
            WriteColoredLine("\n[!] Operation cancelled by user.", ConsoleColor.Yellow);
            return 130;
        }
        catch (Exception ex)
        {
            WriteColoredLine($"\n[ERROR] Analysis failed: {ex.Message}", ConsoleColor.Red);
            return 1;
        }
    }

    private static async Task<List<string>> EnrichWithThreatIntelAsync(
        ForensicReport report,
        CancellationToken cancellationToken)
    {
        var notices = new List<string>();
        using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        httpClient.DefaultRequestHeaders.UserAgent.ParseAdd($"EmlDissect/{ToolVersion}");

        var ipInfoService = new IpInfoService(httpClient);
        var threatIntelService = new ThreatIntelService(httpClient);

        if (!ipInfoService.HasToken)
        {
            notices.Add("IPINFO_TOKEN not set: using unauthenticated ipinfo.io tier (rate-limited).");
        }

        if (!threatIntelService.HasVirusTotalKey)
        {
            notices.Add("VT_API_KEY not set: skipping VirusTotal v3 hash and URL lookups.");
        }

        if (!threatIntelService.HasAbuseIpDbKey)
        {
            notices.Add("ABUSEIPDB_API_KEY not set: skipping AbuseIPDB v2 IP reputation lookups.");
        }

        // Enrich public IPv4s (IPinfo + AbuseIPDB)
        List<ExtractedIp> publicIps = report.NetworkIocs.IpAddresses
            .Where(ip => !ip.IsPrivateOrReserved)
            .ToList();

        if (publicIps.Count > 0)
        {
            WriteColoredLine($"[*] Enriching {publicIps.Count} public IPv4 indicator(s)...", ConsoleColor.DarkCyan);
        }

        foreach (ExtractedIp ip in publicIps)
        {
            ip.IpInfo = await ipInfoService.LookupAsync(ip.RawIp, cancellationToken);
            if (threatIntelService.HasAbuseIpDbKey)
            {
                ip.AbuseIpDb = await threatIntelService.LookupAbuseIpDbAsync(ip.RawIp, cancellationToken);
            }
        }

        // Enrich attachments and URLs via VirusTotal (rate-limited at 4 req/min)
        if (threatIntelService.HasVirusTotalKey)
        {
            int vtQueries = report.Attachments.Count + report.NetworkIocs.Urls.Count;
            if (vtQueries > 0)
            {
                WriteColoredLine($"[*] Querying VirusTotal v3 for {report.Attachments.Count} attachment(s) and {report.NetworkIocs.Urls.Count} URL(s)...", ConsoleColor.DarkCyan);
            }

            foreach (AttachmentInfo attachment in report.Attachments)
            {
                attachment.VirusTotal = await threatIntelService.LookupFileHashAsync(
                    attachment.Sha256,
                    msg => WriteColoredLine($"    {msg}", ConsoleColor.DarkYellow),
                    cancellationToken);
            }

            foreach (ExtractedUrl url in report.NetworkIocs.Urls)
            {
                url.VirusTotal = await threatIntelService.LookupUrlAsync(
                    url.RawUrl,
                    msg => WriteColoredLine($"    {msg}", ConsoleColor.DarkYellow),
                    cancellationToken);
            }
        }

        return notices;
    }

    private static void BuildSecurityWarnings(ForensicReport report)
    {
        List<SecurityWarning> warnings = report.SecurityWarnings;

        // Spoofing indicators from headers
        foreach (string indicator in report.Headers.SpoofingIndicators)
        {
            warnings.Add(new SecurityWarning
            {
                Severity = indicator.Contains("Reply-To", StringComparison.OrdinalIgnoreCase) ||
                           indicator.Contains("impersonation", StringComparison.OrdinalIgnoreCase)
                    ? WarningSeverity.High
                    : WarningSeverity.Medium,
                Category = "Header Spoofing",
                Message = indicator
            });
        }

        // Authentication failures
        AuthenticationSummary auth = report.Headers.Authentication;
        AddAuthWarningIfBad(warnings, "SPF", auth.SpfStatus);
        AddAuthWarningIfBad(warnings, "DKIM", auth.DkimStatus);
        AddAuthWarningIfBad(warnings, "DMARC", auth.DmarcStatus);

        // Anchor text mismatches
        foreach (ExtractedUrl url in report.NetworkIocs.Urls.Where(u => u.HasAnchorMismatch))
        {
            warnings.Add(new SecurityWarning
            {
                Severity = WarningSeverity.High,
                Category = "Phishing Link Deception",
                Message = $"{url.MismatchReason} (Target: {url.DefangedUrl})"
            });
        }

        // Attachment extension spoofing & dangerous types
        foreach (AttachmentInfo att in report.Attachments)
        {
            if (att.IsExtensionSpoofed)
            {
                warnings.Add(new SecurityWarning
                {
                    Severity = WarningSeverity.Critical,
                    Category = "Attachment Spoofing",
                    Message = att.SpoofingDetail ?? $"Extension spoofing detected in '{att.Filename}'."
                });
            }
            else if (att.IsHighRiskExtension)
            {
                warnings.Add(new SecurityWarning
                {
                    Severity = WarningSeverity.High,
                    Category = "High-Risk Attachment",
                    Message = $"Attachment '{att.Filename}' uses a high-risk/executable file type ({att.DetectedFileType})."
                });
            }

            if (att.VirusTotal is { Found: true } vt && (vt.Malicious > 0 || vt.Suspicious > 0))
            {
                warnings.Add(new SecurityWarning
                {
                    Severity = vt.Malicious >= 5 ? WarningSeverity.Critical : WarningSeverity.High,
                    Category = "VirusTotal File Detection",
                    Message = $"Attachment '{att.Filename}' flagged by {vt.DetectionRatio} vendors on VirusTotal" +
                              (string.IsNullOrEmpty(vt.PopularThreatLabel) ? "." : $" ({vt.PopularThreatLabel}).")
                });
            }
        }

        // URL VirusTotal detections
        foreach (ExtractedUrl url in report.NetworkIocs.Urls)
        {
            if (url.VirusTotal is { Found: true } vt && (vt.Malicious > 0 || vt.Suspicious > 0))
            {
                warnings.Add(new SecurityWarning
                {
                    Severity = vt.Malicious >= 3 ? WarningSeverity.Critical : WarningSeverity.High,
                    Category = "VirusTotal URL Detection",
                    Message = $"URL {url.DefangedUrl} flagged by {vt.DetectionRatio} vendors on VirusTotal."
                });
            }
        }

        // AbuseIPDB high-confidence IPs
        foreach (ExtractedIp ip in report.NetworkIocs.IpAddresses)
        {
            if (ip.AbuseIpDb is { Error: null } abuse && abuse.AbuseConfidenceScore >= 50)
            {
                warnings.Add(new SecurityWarning
                {
                    Severity = abuse.AbuseConfidenceScore >= 80 ? WarningSeverity.Critical : WarningSeverity.High,
                    Category = "AbuseIPDB Reputation",
                    Message = $"IP {ip.DefangedIp} has Abuse Confidence Score {abuse.AbuseConfidenceScore}% ({abuse.TotalReports} reports)."
                });
            }
        }
    }

    private static void AddAuthWarningIfBad(List<SecurityWarning> warnings, string protocol, string status)
    {
        string normalized = status.ToLowerInvariant();
        if (normalized is "fail" or "hardfail")
        {
            warnings.Add(new SecurityWarning
            {
                Severity = WarningSeverity.High,
                Category = "Email Authentication",
                Message = $"{protocol} verification FAILED ({status})."
            });
        }
        else if (normalized is "softfail" or "temperror" or "permerror")
        {
            warnings.Add(new SecurityWarning
            {
                Severity = WarningSeverity.Medium,
                Category = "Email Authentication",
                Message = $"{protocol} verification returned '{status}'."
            });
        }
        else if (normalized == "none")
        {
            warnings.Add(new SecurityWarning
            {
                Severity = WarningSeverity.Low,
                Category = "Email Authentication",
                Message = $"No {protocol} Authentication-Results record present."
            });
        }
    }

    private static async Task<int> RunExportsAsync(
        ForensicReport report,
        CliOptions options,
        CancellationToken cancellationToken)
    {
        bool anyExport = !string.IsNullOrWhiteSpace(options.ExportJsonPath) ||
                         !string.IsNullOrWhiteSpace(options.ExportCsvPath) ||
                         !string.IsNullOrWhiteSpace(options.ExportGSheetId);

        if (!anyExport)
        {
            return 0;
        }

        using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        var exporter = new ReportExporterService(httpClient);
        int exitCode = 0;

        PrintSectionHeader("EXPORTS");

        if (!string.IsNullOrWhiteSpace(options.ExportJsonPath))
        {
            try
            {
                string fullPath = Path.GetFullPath(options.ExportJsonPath);
                await exporter.ExportJsonAsync(report, fullPath, cancellationToken);
                WriteColoredLine($"  [+] JSON report exported  : {fullPath}", ConsoleColor.Green);
            }
            catch (Exception ex)
            {
                WriteColoredLine($"  [!] JSON export failed    : {ex.Message}", ConsoleColor.Red);
                exitCode = 1;
            }
        }

        if (!string.IsNullOrWhiteSpace(options.ExportCsvPath))
        {
            try
            {
                string fullPath = Path.GetFullPath(options.ExportCsvPath);
                await exporter.ExportCsvAsync(report, fullPath, cancellationToken);
                WriteColoredLine($"  [+] CSV summary exported  : {fullPath}", ConsoleColor.Green);
            }
            catch (Exception ex)
            {
                WriteColoredLine($"  [!] CSV export failed     : {ex.Message}", ConsoleColor.Red);
                exitCode = 1;
            }
        }

        if (!string.IsNullOrWhiteSpace(options.ExportGSheetId))
        {
            try
            {
                string statusMsg = await exporter.ExportGoogleSheetAsync(
                    report,
                    options.ExportGSheetId,
                    options.GSheetRange,
                    options.GSheetWebhookUrl,
                    cancellationToken);
                WriteColoredLine($"  [+] Google Sheet export   : {statusMsg}", ConsoleColor.Green);
            }
            catch (Exception ex)
            {
                WriteColoredLine($"  [!] Google Sheet failed   : {ex.Message}", ConsoleColor.Red);
                exitCode = 1;
            }
        }

        Console.WriteLine();
        return exitCode;
    }

    private static void RenderReport(ForensicReport report, List<string> intelNotices)
    {
        Console.WriteLine();

        // 1. Headers & Envelope
        PrintSectionHeader("1. HEADERS & ENVELOPE METADATA");
        EmailHeaderInfo h = report.Headers;
        PrintKvTable(new (string Key, string Value, ConsoleColor? Color)[]
        {
            ("EML SHA-256", report.FileSha256, ConsoleColor.Gray),
            ("EML Size", $"{report.FileSizeBytes:N0} bytes", ConsoleColor.Gray),
            ("From", string.IsNullOrWhiteSpace(h.From) ? "(missing)" : h.From, ConsoleColor.White),
            ("Return-Path", h.ReturnPath ?? "(missing)", string.IsNullOrEmpty(h.ReturnPath) ? ConsoleColor.Yellow : ConsoleColor.White),
            ("Reply-To", h.ReplyTo.Count > 0 ? string.Join(", ", h.ReplyTo) : "(none)", h.ReplyTo.Count > 0 ? ConsoleColor.Yellow : ConsoleColor.Gray),
            ("To", h.To.Count > 0 ? string.Join(", ", h.To) : "(none)", ConsoleColor.White),
            ("Cc", h.Cc.Count > 0 ? string.Join(", ", h.Cc) : "(none)", ConsoleColor.Gray),
            ("Subject", string.IsNullOrWhiteSpace(h.Subject) ? "(empty)" : h.Subject, ConsoleColor.Cyan),
            ("Date", h.Date?.ToString("yyyy-MM-dd HH:mm:ss zzz") ?? h.DateRaw ?? "(missing)", ConsoleColor.White),
            ("Message-ID", h.MessageId ?? "(missing)", ConsoleColor.Gray),
            ("X-Originating-IP", string.IsNullOrEmpty(h.XOriginatingIp) ? "(none)" : DefangHelper.DefangIp(h.XOriginatingIp.Trim('[', ']')), ConsoleColor.White),
            ("X-Mailer", h.XMailer ?? "(none)", ConsoleColor.Gray)
        });

        // Routing Hops
        PrintSectionHeader("2. ROUTING HOPS (CHRONOLOGICAL: ORIGIN -> DESTINATION)");
        if (h.RoutingHops.Count == 0)
        {
            WriteColoredLine("  (No Received headers found)", ConsoleColor.Yellow);
        }
        else
        {
            var hopRows = new List<string[]>();
            foreach (RoutingHop hop in h.RoutingHops)
            {
                string delayStr = hop.DelayFromPrevious.HasValue
                    ? FormatDelay(hop.DelayFromPrevious.Value, hop.DelayNote)
                    : (hop.HopNumber == 1 ? "Origin" : "N/A");

                string ips = hop.IpAddresses.Count > 0
                    ? string.Join(", ", hop.IpAddresses.Select(DefangHelper.DefangIp))
                    : "-";

                hopRows.Add([
                    hop.HopNumber.ToString(),
                    Truncate(hop.FromServer ?? "-", 26),
                    Truncate(hop.ByServer ?? "-", 26),
                    Truncate(ips, 20),
                    hop.Timestamp?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'") ?? "Unknown",
                    Truncate(delayStr, 20)
                ]);
            }

            PrintAsciiTable(
                ["Hop", "From", "By", "IPs (Defanged)", "Timestamp", "Delay"],
                [4, 26, 26, 20, 23, 20],
                hopRows);
        }

        // 3. Authentication
        PrintSectionHeader("3. AUTHENTICATION RESULTS (SPF / DKIM / DMARC)");
        AuthenticationSummary auth = h.Authentication;
        PrintKvTable(new (string Key, string Value, ConsoleColor? Color)[]
        {
            ("SPF", FormatAuthLine(auth.SpfStatus, auth.SpfDetails), GetAuthColor(auth.SpfStatus)),
            ("DKIM", FormatAuthLine(auth.DkimStatus, auth.DkimDomain is not null ? $"domain={auth.DkimDomain} {auth.DkimDetails}" : auth.DkimDetails), GetAuthColor(auth.DkimStatus)),
            ("DMARC", FormatAuthLine(auth.DmarcStatus, auth.DmarcDetails), GetAuthColor(auth.DmarcStatus))
        });

        // 4. Network IOCs + IPinfo / AbuseIPDB / VirusTotal
        PrintSectionHeader("4. NETWORK IOCs (DEFANGED) & THREAT INTELLIGENCE");
        if (intelNotices.Count > 0)
        {
            foreach (string notice in intelNotices)
            {
                WriteColoredLine($"  [i] {notice}", ConsoleColor.DarkYellow);
            }
            Console.WriteLine();
        }

        WriteColoredLine($"  [IPv4 Addresses] ({report.NetworkIocs.IpAddresses.Count})", ConsoleColor.Cyan);
        if (report.NetworkIocs.IpAddresses.Count == 0)
        {
            Console.WriteLine("    (None extracted)");
        }
        else
        {
            var ipRows = new List<string[]>();
            foreach (ExtractedIp ip in report.NetworkIocs.IpAddresses)
            {
                string geo = ip.IpInfo is { Error: null } info
                    ? FormatGeo(info)
                    : (ip.IpInfo?.Error ?? (report.OfflineMode ? "Offline" : "-"));

                string asnOrg = ip.IpInfo is { Error: null } orgInfo
                    ? (orgInfo.Org ?? "-")
                    : "-";

                string abuse = ip.AbuseIpDb is { Error: null } ab
                    ? $"{ab.AbuseConfidenceScore}% ({ab.TotalReports} reports, {ab.UsageType ?? "N/A"})"
                    : (ip.AbuseIpDb?.Error ?? (report.OfflineMode ? "Offline" : "Skipped"));

                ipRows.Add([
                    ip.DefangedIp + (ip.IsPrivateOrReserved ? " [PRIV]" : ""),
                    Truncate(string.Join(", ", ip.Sources), 26),
                    Truncate(geo, 24),
                    Truncate(asnOrg, 26),
                    Truncate(abuse, 28)
                ]);
            }

            PrintAsciiTable(
                ["Defanged IP", "Source(s)", "Location (IPinfo)", "ASN / ISP", "AbuseIPDB"],
                [21, 26, 24, 26, 28],
                ipRows);
        }

        Console.WriteLine();
        WriteColoredLine($"  [URLs & Domains] ({report.NetworkIocs.Urls.Count} URLs, {report.NetworkIocs.DefangedDomains.Count} unique domains)", ConsoleColor.Cyan);
        if (report.NetworkIocs.Urls.Count == 0)
        {
            Console.WriteLine("    (None extracted)");
        }
        else
        {
            var urlRows = new List<string[]>();
            foreach (ExtractedUrl u in report.NetworkIocs.Urls)
            {
                string vtStatus = u.VirusTotal switch
                {
                    null => report.OfflineMode ? "Offline" : "Skipped",
                    { Error: not null } err => err.Error,
                    { Found: false } => "Not in VT",
                    _ => $"{u.VirusTotal.DetectionRatio} mal/susp"
                };

                string mismatchFlag = u.HasAnchorMismatch ? "MISMATCH!" : "OK";
                urlRows.Add([
                    Truncate(u.DefangedUrl, 48),
                    Truncate(u.Source, 15),
                    mismatchFlag,
                    Truncate(vtStatus, 26)
                ]);
            }

            PrintAsciiTable(
                ["Defanged URL", "Source", "Link Check", "VirusTotal v3"],
                [48, 15, 10, 26],
                urlRows);

            if (report.NetworkIocs.DefangedDomains.Count > 0)
            {
                Console.WriteLine($"  Unique Defanged Domains: {string.Join(", ", report.NetworkIocs.DefangedDomains)}");
            }
        }

        // 5. Attachment Forensics
        PrintSectionHeader("5. ATTACHMENT FORENSICS (IN-MEMORY)");
        if (report.Attachments.Count == 0)
        {
            Console.WriteLine("  (No attachments found)");
        }
        else
        {
            for (int i = 0; i < report.Attachments.Count; i++)
            {
                AttachmentInfo att = report.Attachments[i];
                Console.WriteLine($"  Attachment #{i + 1}: {att.Filename}");
                string spoofStatus = att.IsExtensionSpoofed
                    ? $"SPOOFED! ({att.SpoofingDetail})"
                    : "Verified (matches magic bytes or non-spoofed)";

                string vtText = att.VirusTotal switch
                {
                    null => report.OfflineMode ? "Offline (--no-intel)" : "Skipped (VT_API_KEY not set)",
                    { Error: not null } err => $"Error: {err.Error}",
                    { Found: false } => "Not found in VirusTotal database",
                    _ => $"{att.VirusTotal.DetectionRatio} malicious/suspicious" +
                         (string.IsNullOrEmpty(att.VirusTotal.PopularThreatLabel) ? "" : $" [{att.VirusTotal.PopularThreatLabel}]")
                };

                PrintKvTable(new (string Key, string Value, ConsoleColor? Color)[]
                {
                    ("Declared MIME", att.DeclaredMimeType, ConsoleColor.White),
                    ("Size", $"{att.SizeBytes:N0} bytes", ConsoleColor.White),
                    ("Magic Bytes", $"{att.MagicBytesHex} -> {att.DetectedFileType}", att.IsExtensionSpoofed ? ConsoleColor.Red : ConsoleColor.Cyan),
                    ("Extension Check", spoofStatus, att.IsExtensionSpoofed ? ConsoleColor.Red : ConsoleColor.Green),
                    ("MD5", att.Md5, ConsoleColor.Gray),
                    ("SHA-1", att.Sha1, ConsoleColor.Gray),
                    ("SHA-256", att.Sha256, ConsoleColor.White),
                    ("VirusTotal v3", vtText, att.VirusTotal is { Malicious: > 0 } ? ConsoleColor.Red : ConsoleColor.White)
                });
            }
        }

        // 6. Security Warnings
        PrintSectionHeader("6. SECURITY WARNINGS & SPOOFING ANOMALIES");
        if (report.SecurityWarnings.Count == 0)
        {
            WriteColoredLine("  [+] No spoofing anomalies or high-risk indicators detected.", ConsoleColor.Green);
        }
        else
        {
            foreach (SecurityWarning w in report.SecurityWarnings.OrderByDescending(x => x.Severity))
            {
                ConsoleColor color = w.Severity switch
                {
                    WarningSeverity.Critical => ConsoleColor.Red,
                    WarningSeverity.High => ConsoleColor.DarkRed,
                    WarningSeverity.Medium => ConsoleColor.Yellow,
                    WarningSeverity.Low => ConsoleColor.DarkYellow,
                    _ => ConsoleColor.Gray
                };

                WriteColoredLine($"  [{w.Severity.ToString().ToUpperInvariant(),-8}] [{w.Category}] {w.Message}", color);
            }
        }

        Console.WriteLine();
    }

    private static bool TryParseArgs(string[] args, out CliOptions options, out string? error)
    {
        options = new CliOptions();
        error = null;

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            switch (arg)
            {
                case "-h":
                case "--help":
                    options.ShowHelp = true;
                    return true;

                case "-v":
                case "--version":
                    options.ShowVersion = true;
                    return true;

                case "--no-intel":
                    options.NoIntel = true;
                    break;

                case "--include-private-ips":
                    options.IncludePrivateIps = true;
                    break;

                case "--export-json":
                    if (!TryConsumeValue(args, ref i, arg, out string? jsonPath, out error)) return false;
                    options.ExportJsonPath = jsonPath;
                    break;

                case "--export-csv":
                    if (!TryConsumeValue(args, ref i, arg, out string? csvPath, out error)) return false;
                    options.ExportCsvPath = csvPath;
                    break;

                case "--export-gsheet":
                    if (!TryConsumeValue(args, ref i, arg, out string? sheetId, out error)) return false;
                    options.ExportGSheetId = sheetId;
                    break;

                case "--gsheet-range":
                    if (!TryConsumeValue(args, ref i, arg, out string? range, out error)) return false;
                    options.GSheetRange = range;
                    break;

                case "--gsheet-webhook":
                    if (!TryConsumeValue(args, ref i, arg, out string? webhook, out error)) return false;
                    options.GSheetWebhookUrl = webhook;
                    break;

                default:
                    if (arg.StartsWith('-'))
                    {
                        error = $"Unknown option '{arg}'.";
                        return false;
                    }

                    if (options.EmlFilePath is not null)
                    {
                        error = $"Unexpected extra positional argument '{arg}'.";
                        return false;
                    }

                    options.EmlFilePath = arg;
                    break;
            }
        }

        return true;
    }

    private static bool TryConsumeValue(
        string[] args,
        ref int index,
        string flag,
        out string? value,
        out string? error)
    {
        if (index + 1 >= args.Length || args[index + 1].StartsWith('-'))
        {
            value = null;
            error = $"Option '{flag}' requires a value.";
            return false;
        }

        value = args[++index];
        error = null;
        return true;
    }

    private static void PrintBanner()
    {
        WriteColoredLine("===================================================================================", ConsoleColor.DarkCyan);
        WriteColoredLine($"  EmlDissect Static .eml forensics and IOC extraction", ConsoleColor.Cyan);
        WriteColoredLine("===================================================================================", ConsoleColor.DarkCyan);
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  emldissect <file.eml> [options]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --no-intel                 Offline mode (skip IPinfo, VirusTotal, and AbuseIPDB)");
        Console.WriteLine("  --include-private-ips      Include private/loopback IPv4 ranges (RFC1918, 127.0.0.0/8)");
        Console.WriteLine("  --export-json <path>       Export full ForensicReport as indented JSON");
        Console.WriteLine("  --export-csv <path>        Export flattened SIEM/Excel summary row as CSV");
        Console.WriteLine("  --export-gsheet <sheetId>  Append flattened analysis row to a Google Sheet");
        Console.WriteLine("  --gsheet-range <range>     Target A1 range for Google Sheets (default: Sheet1!A:T)");
        Console.WriteLine("  --gsheet-webhook <url>     Optional Webhook URL instead of Service Account credentials");
        Console.WriteLine("  -h, --help                 Show this help message");
        Console.WriteLine("  -v, --version              Show tool version");
        Console.WriteLine();
        Console.WriteLine("Environment Variables:");
        Console.WriteLine("  IPINFO_TOKEN                   Optional ipinfo.io API token");
        Console.WriteLine("  VT_API_KEY                     VirusTotal API v3 key (free tier: 4 req/min throttled)");
        Console.WriteLine("  ABUSEIPDB_API_KEY              AbuseIPDB API v2 key");
        Console.WriteLine("  GOOGLE_APPLICATION_CREDENTIALS Path to Google Service Account JSON key");
        Console.WriteLine("  GSHEET_WEBHOOK_URL             Optional Google Apps Script / Webhook URL");
    }

    private static void PrintSectionHeader(string title)
    {
        Console.WriteLine();
        WriteColoredLine($"+-- {title} " + new string('-', Math.Max(4, 78 - title.Length)), ConsoleColor.Blue);
    }

    private static void PrintKvTable((string Key, string Value, ConsoleColor? Color)[] rows)
    {
        const int keyWidth = 18;
        string border = "  +" + new string('-', keyWidth + 2) + "+" + new string('-', 62) + "+";
        Console.WriteLine(border);
        foreach ((string key, string val, ConsoleColor? color) in rows)
        {
            Console.Write($"  | {key,-keyWidth} | ");
            WriteColored(Truncate(val, 60).PadRight(60), color ?? ConsoleColor.White);
            Console.WriteLine(" |");
        }
        Console.WriteLine(border);
    }

    private static void PrintAsciiTable(string[] headers, int[] widths, List<string[]> rows)
    {
        string separator = "  +" + string.Join("+", widths.Select(w => new string('-', w + 2))) + "+";
        Console.WriteLine(separator);

        Console.Write("  |");
        for (int i = 0; i < headers.Length; i++)
        {
            Console.Write($" {Truncate(headers[i], widths[i]).PadRight(widths[i])} |");
        }
        Console.WriteLine();
        Console.WriteLine(separator);

        foreach (string[] row in rows)
        {
            Console.Write("  |");
            for (int i = 0; i < widths.Length; i++)
            {
                string cell = i < row.Length ? row[i] : string.Empty;
                Console.Write($" {Truncate(cell, widths[i]).PadRight(widths[i])} |");
            }
            Console.WriteLine();
        }
        Console.WriteLine(separator);
    }

    private static string FormatDelay(TimeSpan delta, string? note)
    {
        string baseDelay = delta.TotalSeconds < 60
            ? $"+{delta.TotalSeconds:F1}s"
            : $"+{delta.TotalMinutes:F1}m";

        return string.IsNullOrEmpty(note) ? baseDelay : $"{baseDelay} ({note})";
    }

    private static string FormatAuthLine(string status, string? details)
    {
        string upper = status.ToUpperInvariant();
        return string.IsNullOrWhiteSpace(details) ? upper : $"{upper} ({details})";
    }

    private static ConsoleColor GetAuthColor(string status)
    {
        return status.ToLowerInvariant() switch
        {
            "pass" => ConsoleColor.Green,
            "fail" or "hardfail" => ConsoleColor.Red,
            "softfail" or "neutral" => ConsoleColor.Yellow,
            _ => ConsoleColor.DarkYellow
        };
    }

    private static string FormatGeo(IpInfoResult info)
    {
        var parts = new[] { info.City, info.Region, info.Country }
            .Where(p => !string.IsNullOrWhiteSpace(p));
        string joined = string.Join(", ", parts);
        return string.IsNullOrEmpty(joined) ? "-" : joined;
    }

    private static string Truncate(string value, int maxLen)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxLen)
        {
            return value;
        }

        return maxLen <= 3 ? value[..maxLen] : value[..(maxLen - 3)] + "...";
    }

    private static void WriteColored(string text, ConsoleColor color)
    {
        ConsoleColor prev = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.Write(text);
        Console.ForegroundColor = prev;
    }

    private static void WriteColoredLine(string text, ConsoleColor color)
    {
        ConsoleColor prev = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine(text);
        Console.ForegroundColor = prev;
    }
}
