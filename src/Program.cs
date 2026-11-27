using System.Globalization;
using System.Security.Cryptography;
using EmlDissect.Models;
using EmlDissect.Services;
using EmlDissect.Utils;

namespace EmlDissect;

/// <summary>
/// CLI entry point and argument parsing.
/// </summary>
public static class Program
{
    private const string ToolVersion = "1.1.0";

    private sealed class CliOptions
    {
        public string? EmlFilePath { get; set; }
        public string? DirPath { get; set; }
        public string? FetchImapDir { get; set; }
        public string ImapFolder { get; set; } = "INBOX";
        public bool ImapFolderExplicit { get; set; }
        public string? ImapFrom { get; set; }
        public string? ImapSubject { get; set; }
        public DateOnly? ImapSince { get; set; }
        public bool ImapUnseen { get; set; }
        public int ImapLimit { get; set; } = 50;
        public bool ImapLimitExplicit { get; set; }
        public bool AnalyzeAfterFetch { get; set; }
        public int? DumpPartIndex { get; set; }
        public string? DumpDir { get; set; }
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

    private sealed class IntelServicesContext : IDisposable
    {
        public HttpClient HttpClient { get; }
        public IpInfoService IpInfoService { get; }
        public ThreatIntelService ThreatIntelService { get; }

        public IntelServicesContext()
        {
            HttpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
            HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd($"EmlDissect/{ToolVersion}");
            IpInfoService = new IpInfoService(HttpClient);
            ThreatIntelService = new ThreatIntelService(HttpClient);
        }

        public List<string> GetMissingCredentialNotices()
        {
            var notices = new List<string>();
            if (!IpInfoService.HasToken)
            {
                notices.Add("IPINFO_TOKEN not set: using unauthenticated ipinfo.io tier (rate-limited).");
            }

            if (!ThreatIntelService.HasVirusTotalKey)
            {
                notices.Add("VT_API_KEY not set: skipping VirusTotal v3 hash and URL lookups.");
            }

            if (!ThreatIntelService.HasAbuseIpDbKey)
            {
                notices.Add("ABUSEIPDB_API_KEY not set: skipping AbuseIPDB v2 IP reputation lookups.");
            }

            return notices;
        }

        public void Dispose()
        {
            HttpClient.Dispose();
        }
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

        bool hasTargetMode = !string.IsNullOrWhiteSpace(options.EmlFilePath) ||
                             !string.IsNullOrWhiteSpace(options.DirPath) ||
                             !string.IsNullOrWhiteSpace(options.FetchImapDir);

        if (options.ShowHelp || !hasTargetMode)
        {
            PrintHeader();
            PrintUsage();
            return options.ShowHelp ? 0 : 1;
        }

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        try
        {
            if (!string.IsNullOrWhiteSpace(options.FetchImapDir))
            {
                return await RunImapFetchAsync(options, cts.Token);
            }

            if (!string.IsNullOrWhiteSpace(options.DirPath))
            {
                return await RunBatchDirectoryAnalysisAsync(options.DirPath, options, cts.Token);
            }

            return await RunSingleFileAnalysisAsync(options.EmlFilePath!, options, cts.Token);
        }
        catch (OperationCanceledException)
        {
            WriteColoredLine("\n[!] Operation cancelled by user.", ConsoleColor.Yellow);
            return 130;
        }
        catch (Exception ex)
        {
            WriteColoredLine($"\n[ERROR] {ex.Message}", ConsoleColor.Red);
            return 1;
        }
    }

    private static async Task<int> RunSingleFileAnalysisAsync(
        string inputPath,
        CliOptions options,
        CancellationToken cancellationToken)
    {
        string emlPath = Path.GetFullPath(inputPath);
        if (!File.Exists(emlPath))
        {
            WriteColoredLine($"[ERROR] Input .eml file not found: {emlPath}", ConsoleColor.Red);
            return 1;
        }

        PrintHeader();
        WriteColoredLine($"[*] Target File : {emlPath}", ConsoleColor.Cyan);
        WriteColoredLine($"[*] Intel Mode  : {(options.NoIntel ? "OFFLINE (--no-intel)" : "ONLINE (IPinfo / VirusTotal / AbuseIPDB)")}", ConsoleColor.Cyan);

        var attachmentForensics = new AttachmentForensics();
        (ForensicReport report, ParsedEmailContext parsed) = await AnalyzeFileCoreAsync(
            emlPath,
            options,
            attachmentForensics,
            cancellationToken);

        List<string> intelNotices = new();
        if (!options.NoIntel)
        {
            using var intel = new IntelServicesContext();
            intelNotices = intel.GetMissingCredentialNotices();
            await EnrichWithThreatIntelAsync(report, intel, verboseProgress: true, cancellationToken);
        }

        BuildSecurityWarnings(report);
        RenderReport(report, intelNotices);

        int exitCode = 0;

        if (options.DumpPartIndex.HasValue)
        {
            string dumpDir = options.DumpDir ?? "./quarantine";
            PrintSectionHeader("QUARANTINE EXTRACTION");
            try
            {
                QuarantinedAttachmentResult dumped = await attachmentForensics.ExtractAttachmentToQuarantineAsync(
                    parsed.Message,
                    options.DumpPartIndex.Value,
                    dumpDir,
                    cancellationToken);

                PrintKvTable(new (string Key, string Value, ConsoleColor? Color)[]
                {
                    ("Part Index", $"Attachment #{dumped.PartIndex}", ConsoleColor.Cyan),
                    ("Original Name", dumped.OriginalFilename, ConsoleColor.White),
                    ("Size", $"{dumped.SizeBytes:N0} bytes", ConsoleColor.Gray),
                    ("SHA-256", dumped.Sha256, ConsoleColor.White),
                    ("Quarantine Path", dumped.QuarantinedPath, ConsoleColor.Green)
                });
                WriteColoredLine($"  [+] Extracted to: {dumped.QuarantinedPath}", ConsoleColor.Green);
                WriteColoredLine($"  [+] SHA-256     : {dumped.Sha256}", ConsoleColor.Green);
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                WriteColoredLine($"  [ERROR] Quarantine extraction failed: {ex.Message}", ConsoleColor.Red);
                Console.WriteLine();
                exitCode = 1;
            }
        }

        int exportExitCode = await RunExportsAsync(new[] { report }, isBatch: false, options, cancellationToken);
        return exitCode != 0 ? exitCode : exportExitCode;
    }

    private static async Task<int> RunBatchDirectoryAnalysisAsync(
        string targetDir,
        CliOptions options,
        CancellationToken cancellationToken)
    {
        string fullDir = Path.GetFullPath(targetDir);
        if (!Directory.Exists(fullDir))
        {
            WriteColoredLine($"[ERROR] Target directory not found: {fullDir}", ConsoleColor.Red);
            return 1;
        }

        List<string> emlFiles = Directory
            .EnumerateFiles(fullDir, "*.eml", SearchOption.AllDirectories)
            .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
            .ToList();

        PrintHeader();
        WriteColoredLine($"[*] Target Dir  : {fullDir}", ConsoleColor.Cyan);
        WriteColoredLine($"[*] EML Files   : {emlFiles.Count} discovered", ConsoleColor.Cyan);
        WriteColoredLine($"[*] Intel Mode  : {(options.NoIntel ? "OFFLINE (--no-intel)" : "ONLINE (IPinfo / VirusTotal / AbuseIPDB)")}", ConsoleColor.Cyan);

        if (emlFiles.Count == 0)
        {
            WriteColoredLine($"[i] No .eml files found in '{fullDir}'.", ConsoleColor.Yellow);
            return 0;
        }

        using IntelServicesContext? intel = options.NoIntel ? null : new IntelServicesContext();
        if (intel is not null)
        {
            List<string> notices = intel.GetMissingCredentialNotices();
            foreach (string notice in notices)
            {
                WriteColoredLine($"[i] {notice}", ConsoleColor.DarkYellow);
            }
        }

        Console.WriteLine();
        var attachmentForensics = new AttachmentForensics();
        var reports = new List<ForensicReport>(emlFiles.Count);
        var failures = new List<(string FilePath, string Error)>();

        for (int i = 0; i < emlFiles.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string emlPath = emlFiles[i];
            string displayPath = Path.GetRelativePath(fullDir, emlPath);

            try
            {
                (ForensicReport report, _) = await AnalyzeFileCoreAsync(
                    emlPath,
                    options,
                    attachmentForensics,
                    cancellationToken);

                if (intel is not null)
                {
                    await EnrichWithThreatIntelAsync(report, intel, verboseProgress: false, cancellationToken);
                }

                BuildSecurityWarnings(report);
                reports.Add(report);

                PrintBatchFileSummary(i + 1, emlFiles.Count, displayPath, report);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                failures.Add((displayPath, ex.Message));
                WriteColoredLine($"[{i + 1}/{emlFiles.Count}] {displayPath} -> ERROR: {ex.Message}", ConsoleColor.Red);
            }
        }

        RenderBatchSummaryTable(fullDir, reports, failures);

        int exportExitCode = 0;
        if (reports.Count > 0)
        {
            exportExitCode = await RunExportsAsync(reports, isBatch: true, options, cancellationToken);
        }

        return exportExitCode != 0 || failures.Count > 0 ? 1 : 0;
    }

    private static async Task<int> RunImapFetchAsync(
        CliOptions options,
        CancellationToken cancellationToken)
    {
        string outputDir = Path.GetFullPath(options.FetchImapDir!);

        PrintHeader();
        WriteColoredLine($"[*] IMAP Folder : {options.ImapFolder}", ConsoleColor.Cyan);
        WriteColoredLine($"[*] Output Dir  : {outputDir}", ConsoleColor.Cyan);
        WriteColoredLine($"[*] Fetch Limit : {options.ImapLimit}", ConsoleColor.Cyan);

        var fetchOptions = new ImapFetchOptions
        {
            OutputDirectory = outputDir,
            FolderName = options.ImapFolder,
            FromFilter = options.ImapFrom,
            SubjectFilter = options.ImapSubject,
            SinceDate = options.ImapSince,
            UnseenOnly = options.ImapUnseen,
            Limit = options.ImapLimit
        };

        var fetcher = new ImapFetcherService();
        ImapFetchResult result = await fetcher.FetchAsync(
            fetchOptions,
            msg => WriteColoredLine($"[*] {msg}", ConsoleColor.Gray),
            cancellationToken);

        PrintSectionHeader("IMAP ACQUISITION SUMMARY");
        PrintKvTable(new (string Key, string Value, ConsoleColor? Color)[]
        {
            ("IMAP Server", $"{result.Host}:{result.Port}", ConsoleColor.White),
            ("Folder", result.FolderName, ConsoleColor.White),
            ("Matched", result.TotalMatched.ToString(CultureInfo.InvariantCulture), ConsoleColor.Cyan),
            ("Downloaded", result.DownloadedFiles.Count.ToString(CultureInfo.InvariantCulture), ConsoleColor.Green),
            ("Output Dir", outputDir, ConsoleColor.White)
        });
        Console.WriteLine();

        if (options.AnalyzeAfterFetch)
        {
            return await RunBatchDirectoryAnalysisAsync(outputDir, options, cancellationToken);
        }

        return 0;
    }

    private static async Task<(ForensicReport Report, ParsedEmailContext Parsed)> AnalyzeFileCoreAsync(
        string emlPath,
        CliOptions options,
        AttachmentForensics attachmentForensics,
        CancellationToken cancellationToken)
    {
        byte[] rawEmlBytes = await File.ReadAllBytesAsync(emlPath, cancellationToken);
        string fileSha256 = Convert.ToHexString(SHA256.HashData(rawEmlBytes)).ToLowerInvariant();

        // 1. Parse headers, routing hops, authentication, and HTML links in memory
        var emailParser = new EmailParserService();
        using var emlStream = new MemoryStream(rawEmlBytes, writable: false);
        ParsedEmailContext parsed = await emailParser.ParseAsync(emlStream, cancellationToken);

        // 2. Extract and defang network IOCs
        var iocExtractor = new IocExtractorService();
        NetworkIocCollection networkIocs = iocExtractor.Extract(parsed, options.IncludePrivateIps);

        // 3. Analyze attachments strictly in memory
        List<AttachmentInfo> attachments = await attachmentForensics.AnalyzeAttachmentsAsync(parsed.Message, cancellationToken);

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

        return (report, parsed);
    }

    private static async Task EnrichWithThreatIntelAsync(
        ForensicReport report,
        IntelServicesContext intel,
        bool verboseProgress,
        CancellationToken cancellationToken)
    {
        List<ExtractedIp> publicIps = report.NetworkIocs.IpAddresses
            .Where(ip => !ip.IsPrivateOrReserved)
            .ToList();

        if (verboseProgress && publicIps.Count > 0)
        {
            WriteColoredLine($"[*] Enriching {publicIps.Count} public IPv4 indicator(s)...", ConsoleColor.DarkCyan);
        }

        foreach (ExtractedIp ip in publicIps)
        {
            ip.IpInfo = await intel.IpInfoService.LookupAsync(ip.RawIp, cancellationToken);
            if (intel.ThreatIntelService.HasAbuseIpDbKey)
            {
                ip.AbuseIpDb = await intel.ThreatIntelService.LookupAbuseIpDbAsync(ip.RawIp, cancellationToken);
            }
        }

        if (intel.ThreatIntelService.HasVirusTotalKey)
        {
            int vtQueries = report.Attachments.Count + report.NetworkIocs.Urls.Count;
            if (verboseProgress && vtQueries > 0)
            {
                WriteColoredLine(
                    $"[*] Querying VirusTotal v3 for {report.Attachments.Count} attachment(s) and {report.NetworkIocs.Urls.Count} URL(s)...",
                    ConsoleColor.DarkCyan);
            }

            foreach (AttachmentInfo attachment in report.Attachments)
            {
                attachment.VirusTotal = await intel.ThreatIntelService.LookupFileHashAsync(
                    attachment.Sha256,
                    msg => WriteColoredLine($"    {msg}", ConsoleColor.DarkYellow),
                    cancellationToken);
            }

            foreach (ExtractedUrl url in report.NetworkIocs.Urls)
            {
                url.VirusTotal = await intel.ThreatIntelService.LookupUrlAsync(
                    url.RawUrl,
                    msg => WriteColoredLine($"    {msg}", ConsoleColor.DarkYellow),
                    cancellationToken);
            }
        }
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
        IReadOnlyList<ForensicReport> reports,
        bool isBatch,
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
                if (isBatch)
                {
                    await exporter.ExportJsonAsync(reports, fullPath, cancellationToken);
                    WriteColoredLine($"  [+] JSON batch exported   : {fullPath} ({reports.Count} report(s))", ConsoleColor.Green);
                }
                else
                {
                    await exporter.ExportJsonAsync(reports[0], fullPath, cancellationToken);
                    WriteColoredLine($"  [+] JSON report exported  : {fullPath}", ConsoleColor.Green);
                }
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
                await exporter.ExportCsvAsync(reports, fullPath, cancellationToken);
                WriteColoredLine($"  [+] CSV summary exported  : {fullPath} ({reports.Count} row(s))", ConsoleColor.Green);
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
                    reports,
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

    private static void PrintBatchFileSummary(
        int index,
        int total,
        string relativePath,
        ForensicReport report)
    {
        int criticalCount = report.SecurityWarnings.Count(w => w.Severity == WarningSeverity.Critical);
        int highCount = report.SecurityWarnings.Count(w => w.Severity == WarningSeverity.High);
        string sender = string.IsNullOrWhiteSpace(report.Headers.From) ? "(missing)" : report.Headers.From;
        string subject = string.IsNullOrWhiteSpace(report.Headers.Subject) ? "(empty)" : report.Headers.Subject;
        AuthenticationSummary auth = report.Headers.Authentication;
        string authSummary = $"{auth.SpfStatus.ToUpperInvariant()}/{auth.DkimStatus.ToUpperInvariant()}/{auth.DmarcStatus.ToUpperInvariant()}";
        string hits = BuildThreatSummaryLabel(report);

        ConsoleColor headerColor = criticalCount > 0 || hits != "None"
            ? ConsoleColor.Red
            : (highCount > 0 ? ConsoleColor.DarkYellow : ConsoleColor.Green);

        WriteColoredLine($"[{index}/{total}] {relativePath}", headerColor);
        Console.WriteLine($"  From     : {Truncate(sender, 90)}");
        Console.WriteLine($"  Subject  : {Truncate(subject, 90)}");
        Console.WriteLine($"  Auth     : SPF/DKIM/DMARC = {authSummary} | Crit/High Warnings = {criticalCount}/{highCount} | Hits = {hits}");
    }

    private static void RenderBatchSummaryTable(
        string rootDir,
        IReadOnlyList<ForensicReport> reports,
        IReadOnlyList<(string FilePath, string Error)> failures)
    {
        PrintSectionHeader("BATCH TRIAGE SUMMARY");

        if (reports.Count > 0)
        {
            var rows = new List<string[]>(reports.Count);
            int filesWithCritHigh = 0;

            foreach (ForensicReport report in reports)
            {
                int crit = report.SecurityWarnings.Count(w => w.Severity == WarningSeverity.Critical);
                int high = report.SecurityWarnings.Count(w => w.Severity == WarningSeverity.High);
                if (crit + high > 0)
                {
                    filesWithCritHigh++;
                }

                string filename = Path.GetRelativePath(rootDir, report.SourceFile);
                string sender = string.IsNullOrWhiteSpace(report.Headers.FromAddress)
                    ? (string.IsNullOrWhiteSpace(report.Headers.From) ? "(missing)" : report.Headers.From)
                    : report.Headers.FromAddress;

                AuthenticationSummary auth = report.Headers.Authentication;
                string authStr = $"{auth.SpfStatus.ToUpperInvariant()}/{auth.DkimStatus.ToUpperInvariant()}/{auth.DmarcStatus.ToUpperInvariant()}";
                string warnStr = $"{crit}C / {high}H";
                string hitsStr = BuildThreatSummaryLabel(report);

                rows.Add([
                    Truncate(filename, 26),
                    Truncate(sender, 28),
                    Truncate(authStr, 17),
                    Truncate(warnStr, 11),
                    Truncate(hitsStr, 28)
                ]);
            }

            PrintAsciiTable(
                ["Filename", "From", "SPF/DKIM/DMARC", "Crit / High", "Spoofed / Malicious Hits"],
                [26, 28, 17, 11, 28],
                rows);

            Console.WriteLine(
                $"  Analyzed: {reports.Count} | Failed: {failures.Count} | Files with Critical/High warnings: {filesWithCritHigh}");
        }
        else
        {
            WriteColoredLine($"  Analyzed: 0 | Failed: {failures.Count}", ConsoleColor.Red);
        }

        if (failures.Count > 0)
        {
            Console.WriteLine();
            WriteColoredLine("  Failed Files:", ConsoleColor.Red);
            foreach ((string filePath, string error) in failures)
            {
                WriteColoredLine($"    - {filePath}: {error}", ConsoleColor.Red);
            }
        }

        Console.WriteLine();
    }

    private static string BuildThreatSummaryLabel(ForensicReport report)
    {
        var flags = new List<string>();

        int spoofedCount = report.Attachments.Count(a => a.IsExtensionSpoofed);
        if (spoofedCount > 0)
        {
            flags.Add($"SpoofedAtt({spoofedCount})");
        }

        int vtFileHits = report.Attachments.Count(a => a.VirusTotal is { Found: true, Malicious: > 0 });
        if (vtFileHits > 0)
        {
            flags.Add($"VT-File({vtFileHits})");
        }

        int vtUrlHits = report.NetworkIocs.Urls.Count(u => u.VirusTotal is { Found: true, Malicious: > 0 });
        if (vtUrlHits > 0)
        {
            flags.Add($"VT-URL({vtUrlHits})");
        }

        int abuseIpHits = report.NetworkIocs.IpAddresses.Count(ip => ip.AbuseIpDb is { Error: null, AbuseConfidenceScore: >= 50 });
        if (abuseIpHits > 0)
        {
            flags.Add($"AbuseIP({abuseIpHits})");
        }

        return flags.Count == 0 ? "None" : string.Join(", ", flags);
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

                case "--dir":
                    if (!TryConsumeValue(args, ref i, arg, out string? dirPath, out error)) return false;
                    options.DirPath = dirPath;
                    break;

                case "--fetch-imap":
                    if (!TryConsumeValue(args, ref i, arg, out string? fetchDir, out error)) return false;
                    options.FetchImapDir = fetchDir;
                    break;

                case "--imap-folder":
                    if (!TryConsumeValue(args, ref i, arg, out string? folder, out error)) return false;
                    options.ImapFolder = folder!;
                    options.ImapFolderExplicit = true;
                    break;

                case "--imap-from":
                    if (!TryConsumeValue(args, ref i, arg, out string? fromFilter, out error)) return false;
                    options.ImapFrom = fromFilter;
                    break;

                case "--imap-subject":
                    if (!TryConsumeValue(args, ref i, arg, out string? subjectFilter, out error)) return false;
                    options.ImapSubject = subjectFilter;
                    break;

                case "--imap-since":
                    if (!TryConsumeValue(args, ref i, arg, out string? sinceRaw, out error)) return false;
                    if (!DateOnly.TryParseExact(sinceRaw, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateOnly sinceDate))
                    {
                        error = $"Option '--imap-since' requires a valid date in YYYY-MM-DD format (got '{sinceRaw}').";
                        return false;
                    }
                    options.ImapSince = sinceDate;
                    break;

                case "--imap-unseen":
                    options.ImapUnseen = true;
                    break;

                case "--imap-limit":
                    if (!TryConsumeValue(args, ref i, arg, out string? limitRaw, out error)) return false;
                    if (!int.TryParse(limitRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out int limit) || limit <= 0)
                    {
                        error = $"Option '--imap-limit' requires a positive integer (got '{limitRaw}').";
                        return false;
                    }
                    options.ImapLimit = limit;
                    options.ImapLimitExplicit = true;
                    break;

                case "--analyze":
                    options.AnalyzeAfterFetch = true;
                    break;

                case "--dump-part":
                    if (!TryConsumeValue(args, ref i, arg, out string? partRaw, out error)) return false;
                    if (!int.TryParse(partRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out int partIndex) || partIndex < 1)
                    {
                        error = $"Option '--dump-part' requires a positive 1-based attachment index (got '{partRaw}').";
                        return false;
                    }
                    options.DumpPartIndex = partIndex;
                    break;

                case "--dump-dir":
                    if (!TryConsumeValue(args, ref i, arg, out string? dumpDir, out error)) return false;
                    options.DumpDir = dumpDir;
                    break;

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

        int modeCount = (options.EmlFilePath is not null ? 1 : 0) +
                        (options.DirPath is not null ? 1 : 0) +
                        (options.FetchImapDir is not null ? 1 : 0);

        if (modeCount > 1)
        {
            error = "Specify only one input mode: <file.eml>, --dir <folder_path>, or --fetch-imap <output_dir>.";
            return false;
        }

        bool anyImapOption = options.ImapFolderExplicit ||
                             options.ImapFrom is not null ||
                             options.ImapSubject is not null ||
                             options.ImapSince.HasValue ||
                             options.ImapUnseen ||
                             options.ImapLimitExplicit ||
                             options.AnalyzeAfterFetch;

        if (anyImapOption && options.FetchImapDir is null)
        {
            error = "Options --imap-* and --analyze can only be used with --fetch-imap <output_dir>.";
            return false;
        }

        if (options.DumpPartIndex.HasValue && options.EmlFilePath is null)
        {
            error = "Option --dump-part requires a single <file.eml> input.";
            return false;
        }

        if (options.DumpDir is not null && !options.DumpPartIndex.HasValue)
        {
            error = "Option --dump-dir requires --dump-part <index>.";
            return false;
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

    private static void PrintHeader()
    {
        WriteColoredLine($"EmlDissect v{ToolVersion} - Static .eml forensics, IOC extraction, and IMAP triage", ConsoleColor.Cyan);
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  emldissect <file.eml> [options]");
        Console.WriteLine("  emldissect --dir <folder_path> [options]");
        Console.WriteLine("  emldissect --fetch-imap <output_dir> [imap options] [analysis/export options]");
        Console.WriteLine();
        Console.WriteLine("Input & Acquisition Options:");
        Console.WriteLine("  --dir <folder_path>        Recursively analyze all *.eml files in a directory");
        Console.WriteLine("  --fetch-imap <output_dir>  Fetch matching messages via IMAP as raw .eml files");
        Console.WriteLine("  --imap-folder <name>       Target IMAP folder (default: INBOX)");
        Console.WriteLine("  --imap-from <sender>       Filter IMAP messages by sender address or domain");
        Console.WriteLine("  --imap-subject <keyword>   Filter IMAP messages by subject keyword");
        Console.WriteLine("  --imap-since <YYYY-MM-DD>  Filter IMAP messages delivered on or after date");
        Console.WriteLine("  --imap-unseen              Fetch only unread IMAP messages");
        Console.WriteLine("  --imap-limit <number>      Maximum messages to download per run (default: 50)");
        Console.WriteLine("  --analyze                  Run batch analysis on <output_dir> after IMAP fetch");
        Console.WriteLine();
        Console.WriteLine("Attachment Quarantine Options (single-file mode):");
        Console.WriteLine("  --dump-part <index>        Safely extract 1-based attachment as .quarantine");
        Console.WriteLine("  --dump-dir <folder_path>   Quarantine output directory (default: ./quarantine)");
        Console.WriteLine();
        Console.WriteLine("Analysis & Export Options:");
        Console.WriteLine("  --no-intel                 Offline mode (skip IPinfo, VirusTotal, and AbuseIPDB)");
        Console.WriteLine("  --include-private-ips      Include private/loopback IPv4 ranges (RFC1918, 127.0.0.0/8)");
        Console.WriteLine("  --export-json <path>       Export ForensicReport (or array in batch mode) as JSON");
        Console.WriteLine("  --export-csv <path>        Export flattened summary row(s) as CSV");
        Console.WriteLine("  --export-gsheet <sheetId>  Append flattened summary row(s) to a Google Sheet");
        Console.WriteLine("  --gsheet-range <range>     Target A1 range for Google Sheets (default: Sheet1!A:T)");
        Console.WriteLine("  --gsheet-webhook <url>     Optional Webhook URL instead of Service Account credentials");
        Console.WriteLine("  -h, --help                 Show this help message");
        Console.WriteLine("  -v, --version              Show tool version");
        Console.WriteLine();
        Console.WriteLine("Environment Variables:");
        Console.WriteLine("  IMAP_HOST                      IMAP server hostname (e.g., imap.gmail.com)");
        Console.WriteLine("  IMAP_PORT                      IMAP TCP port (default: 993)");
        Console.WriteLine("  IMAP_USER                      IMAP login username / email address");
        Console.WriteLine("  IMAP_PASS                      IMAP password or app-specific password");
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
