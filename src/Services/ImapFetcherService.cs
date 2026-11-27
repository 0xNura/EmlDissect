using System.Globalization;
using System.Net.Sockets;
using System.Text;
using MailKit;
using MailKit.Net.Imap;
using MailKit.Search;
using MailKit.Security;
using MimeKit;

namespace EmlDissect.Services;

/// <summary>
/// Filter and output options for bulk IMAP email acquisition.
/// </summary>
public sealed class ImapFetchOptions
{
    public required string OutputDirectory { get; init; }
    public string FolderName { get; init; } = "INBOX";
    public string? FromFilter { get; init; }
    public string? SubjectFilter { get; init; }
    public DateOnly? SinceDate { get; init; }
    public bool UnseenOnly { get; init; }
    public int Limit { get; init; } = 50;
}

/// <summary>
/// Metadata describing a raw .eml file saved by <see cref="ImapFetcherService"/>.
/// </summary>
public sealed record FetchedEmailFile(
    uint Uid,
    string FilePath,
    string Subject,
    string From,
    DateTimeOffset DateUtc
);

/// <summary>
/// Summary returned after completing an IMAP fetch run.
/// </summary>
public sealed record ImapFetchResult(
    string Host,
    int Port,
    string FolderName,
    int TotalMatched,
    IReadOnlyList<FetchedEmailFile> DownloadedFiles
);

/// <summary>
/// Connects to an IMAP mailbox over SSL/TLS using credentials from environment variables
/// and downloads matching raw messages as .eml files into a local quarantine directory.
/// </summary>
public sealed class ImapFetcherService
{
    private const int DefaultImapPort = 993;

    /// <summary>
    /// Fetches matching emails via IMAP and writes each raw message as an .eml file.
    /// </summary>
    public async Task<ImapFetchResult> FetchAsync(
        ImapFetchOptions options,
        Action<string>? onProgress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Limit <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "IMAP fetch limit must be greater than zero.");
        }

        (string host, int port, string user, string pass) = ReadCredentialsFromEnvironment();

        string fullOutputDir = Path.GetFullPath(options.OutputDirectory);
        Directory.CreateDirectory(fullOutputDir);
        string normalizedDirPrefix = EnsureTrailingSeparator(fullOutputDir);

        string targetFolderName = string.IsNullOrWhiteSpace(options.FolderName)
            ? "INBOX"
            : options.FolderName.Trim();

        using var client = new ImapClient();
        IMailFolder? folder = null;

        try
        {
            SecureSocketOptions sslOptions = port == DefaultImapPort
                ? SecureSocketOptions.SslOnConnect
                : SecureSocketOptions.StartTls;

            onProgress?.Invoke($"Connecting to {host}:{port} ({sslOptions})...");
            await client.ConnectAsync(host, port, sslOptions, cancellationToken);

            onProgress?.Invoke($"Authenticating as {user}...");
            await client.AuthenticateAsync(user, pass, cancellationToken);

            folder = string.Equals(targetFolderName, "INBOX", StringComparison.OrdinalIgnoreCase)
                ? client.Inbox
                : await client.GetFolderAsync(targetFolderName, cancellationToken);

            await folder.OpenAsync(FolderAccess.ReadOnly, cancellationToken);

            SearchQuery query = BuildSearchQuery(options);
            IList<UniqueId> matchedUids = await folder.SearchAsync(query, cancellationToken);

            List<UniqueId> targetUids = matchedUids
                .OrderByDescending(uid => uid.Id)
                .Take(options.Limit)
                .ToList();

            onProgress?.Invoke($"Matched {matchedUids.Count} message(s) in '{folder.FullName}'; downloading {targetUids.Count}.");

            var downloaded = new List<FetchedEmailFile>(targetUids.Count);
            for (int i = 0; i < targetUids.Count; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                UniqueId uid = targetUids[i];

                MimeMessage message = await folder.GetMessageAsync(uid, cancellationToken);
                DateTimeOffset msgDate = message.Date != DateTimeOffset.MinValue
                    ? message.Date.ToUniversalTime()
                    : DateTimeOffset.UtcNow;

                string timestamp = msgDate.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
                string sanitizedSubject = SanitizeSubjectForFilename(message.Subject);
                string fileName = $"{timestamp}_{uid.Id}_{sanitizedSubject}.eml";

                string targetPath = Path.GetFullPath(Path.Combine(fullOutputDir, fileName));
                if (!targetPath.StartsWith(normalizedDirPrefix, GetPathComparison()))
                {
                    throw new InvalidOperationException($"Resolved output path escaped target directory: {targetPath}");
                }

                await using (var stream = new FileStream(
                    targetPath,
                    FileMode.Create,
                    FileAccess.Write,
                    FileShare.None,
                    bufferSize: 81920,
                    useAsync: true))
                {
                    await message.WriteToAsync(stream, cancellationToken);
                }

                string subjectDisplay = string.IsNullOrWhiteSpace(message.Subject) ? "(empty)" : message.Subject;
                string fromDisplay = message.From.ToString();
                downloaded.Add(new FetchedEmailFile(uid.Id, targetPath, subjectDisplay, fromDisplay, msgDate));

                onProgress?.Invoke($"  [{i + 1}/{targetUids.Count}] Saved {fileName}");
            }

            return new ImapFetchResult(
                host,
                port,
                folder.FullName,
                matchedUids.Count,
                downloaded);
        }
        catch (AuthenticationException ex)
        {
            throw new InvalidOperationException(
                $"IMAP authentication failed for '{user}' on '{host}': {ex.Message}. " +
                "Verify IMAP_USER and IMAP_PASS (use an app-specific password if MFA is enabled).",
                ex);
        }
        catch (FolderNotFoundException ex)
        {
            throw new InvalidOperationException(
                $"IMAP folder '{targetFolderName}' was not found on '{host}'.",
                ex);
        }
        catch (SslHandshakeException ex)
        {
            throw new InvalidOperationException(
                $"TLS/SSL handshake failed with IMAP server '{host}:{port}': {ex.Message}",
                ex);
        }
        catch (SocketException ex)
        {
            throw new InvalidOperationException(
                $"Unable to reach IMAP server '{host}:{port}': {ex.Message}",
                ex);
        }
        catch (ImapCommandException ex)
        {
            throw new InvalidOperationException(
                $"IMAP command failed on '{host}': {ex.Message}",
                ex);
        }
        catch (ImapProtocolException ex)
        {
            throw new InvalidOperationException(
                $"IMAP protocol error on '{host}': {ex.Message}",
                ex);
        }
        finally
        {
            if (folder is { IsOpen: true })
            {
                try
                {
                    await folder.CloseAsync(false, CancellationToken.None);
                }
                catch
                {
                    // Best-effort cleanup on disconnect.
                }
            }

            if (client.IsConnected)
            {
                try
                {
                    await client.DisconnectAsync(true, CancellationToken.None);
                }
                catch
                {
                    // Best-effort cleanup on disconnect.
                }
            }
        }
    }

    private static (string Host, int Port, string User, string Pass) ReadCredentialsFromEnvironment()
    {
        string? host = Environment.GetEnvironmentVariable("IMAP_HOST")?.Trim();
        string? portRaw = Environment.GetEnvironmentVariable("IMAP_PORT")?.Trim();
        string? user = Environment.GetEnvironmentVariable("IMAP_USER")?.Trim();
        string? pass = Environment.GetEnvironmentVariable("IMAP_PASS");

        var missing = new List<string>();
        if (string.IsNullOrWhiteSpace(host))
        {
            missing.Add("IMAP_HOST");
        }
        if (string.IsNullOrWhiteSpace(user))
        {
            missing.Add("IMAP_USER");
        }
        if (string.IsNullOrEmpty(pass))
        {
            missing.Add("IMAP_PASS");
        }

        if (missing.Count > 0)
        {
            throw new InvalidOperationException(
                $"Missing required IMAP environment variable(s): {string.Join(", ", missing)}. " +
                "Set IMAP_HOST, IMAP_USER, IMAP_PASS (and optionally IMAP_PORT, default 993) before running --fetch-imap.");
        }

        int port = DefaultImapPort;
        if (!string.IsNullOrWhiteSpace(portRaw))
        {
            if (!int.TryParse(portRaw, NumberStyles.None, CultureInfo.InvariantCulture, out port) ||
                port < 1 ||
                port > 65535)
            {
                throw new InvalidOperationException(
                    $"Invalid IMAP_PORT value '{portRaw}'. Expected a TCP port between 1 and 65535.");
            }
        }

        return (host!, port, user!, pass!);
    }

    private static SearchQuery BuildSearchQuery(ImapFetchOptions options)
    {
        SearchQuery query = SearchQuery.All;

        if (options.UnseenOnly)
        {
            query = query.And(SearchQuery.NotSeen);
        }

        if (!string.IsNullOrWhiteSpace(options.FromFilter))
        {
            query = query.And(SearchQuery.FromContains(options.FromFilter.Trim()));
        }

        if (!string.IsNullOrWhiteSpace(options.SubjectFilter))
        {
            query = query.And(SearchQuery.SubjectContains(options.SubjectFilter.Trim()));
        }

        if (options.SinceDate.HasValue)
        {
            query = query.And(SearchQuery.DeliveredAfter(options.SinceDate.Value.ToDateTime(TimeOnly.MinValue)));
        }

        return query;
    }

    private static string SanitizeSubjectForFilename(string? subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            return "no_subject";
        }

        char[] invalidChars = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(subject.Length);
        bool lastWasUnderscore = false;

        foreach (char ch in subject.Trim())
        {
            bool invalid = char.IsWhiteSpace(ch) ||
                           char.IsControl(ch) ||
                           ch == '/' ||
                           ch == '\\' ||
                           Array.IndexOf(invalidChars, ch) >= 0;

            if (invalid)
            {
                if (!lastWasUnderscore)
                {
                    sb.Append('_');
                    lastWasUnderscore = true;
                }
            }
            else
            {
                sb.Append(ch);
                lastWasUnderscore = false;
            }
        }

        string cleaned = sb.ToString().Replace("..", "_", StringComparison.Ordinal).Trim('_', '.');
        if (string.IsNullOrEmpty(cleaned))
        {
            return "no_subject";
        }

        const int maxSubjectLen = 60;
        return cleaned.Length > maxSubjectLen ? cleaned[..maxSubjectLen].TrimEnd('_', '.') : cleaned;
    }

    private static string EnsureTrailingSeparator(string directoryPath)
    {
        return directoryPath.EndsWith(Path.DirectorySeparatorChar)
            ? directoryPath
            : directoryPath + Path.DirectorySeparatorChar;
    }

    private static StringComparison GetPathComparison()
    {
        return OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
    }
}
