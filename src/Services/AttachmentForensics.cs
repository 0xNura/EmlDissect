using System.Security.Cryptography;
using System.Text;
using EmlDissect.Models;
using EmlDissect.Utils;
using MimeKit;

namespace EmlDissect.Services;

/// <summary>
/// Metadata for an attachment safely written to a quarantine directory.
/// </summary>
public sealed record QuarantinedAttachmentResult(
    int PartIndex,
    string OriginalFilename,
    string QuarantinedPath,
    long SizeBytes,
    string Sha256
);

/// <summary>
/// Analyzes email attachments strictly in memory: computes MD5, SHA-1, and SHA-256
/// simultaneously, validates magic bytes against declared extensions, and supports
/// explicit quarantined extraction by 1-based attachment index.
/// </summary>
public sealed class AttachmentForensics
{
    private static readonly HashSet<string> WindowsReservedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    private sealed record AttachmentCandidate(
        MimeEntity Entity,
        string Filename,
        string DeclaredMimeType,
        bool IsEmbeddedMessage
    );

    /// <summary>
    /// Recursively inspects all attachments in a MimeMessage without writing payloads to disk.
    /// </summary>
    public async Task<List<AttachmentInfo>> AnalyzeAttachmentsAsync(
        MimeMessage message,
        CancellationToken cancellationToken = default)
    {
        var candidates = new List<AttachmentCandidate>();
        if (message.Body is not null)
        {
            CollectAttachmentCandidates(message.Body, candidates);
        }

        var results = new List<AttachmentInfo>(candidates.Count);
        foreach (AttachmentCandidate candidate in candidates)
        {
            byte[] bytes = await DecodeCandidateBytesAsync(candidate, cancellationToken);
            results.Add(BuildAttachmentInfo(
                candidate.Filename,
                candidate.DeclaredMimeType,
                bytes,
                candidate.IsEmbeddedMessage));
        }

        return results;
    }

    /// <summary>
    /// Extracts a single attachment by its 1-based index into <paramref name="outputDirectory"/>,
    /// sanitizing the filename and appending ".quarantine" so it cannot be executed directly.
    /// </summary>
    public async Task<QuarantinedAttachmentResult> ExtractAttachmentToQuarantineAsync(
        MimeMessage message,
        int oneBasedPartIndex,
        string outputDirectory,
        CancellationToken cancellationToken = default)
    {
        if (oneBasedPartIndex < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(oneBasedPartIndex),
                "Attachment index must be 1 or greater.");
        }

        var candidates = new List<AttachmentCandidate>();
        if (message.Body is not null)
        {
            CollectAttachmentCandidates(message.Body, candidates);
        }

        if (candidates.Count == 0)
        {
            throw new InvalidOperationException("No attachments found in the target .eml file.");
        }

        if (oneBasedPartIndex > candidates.Count)
        {
            throw new ArgumentOutOfRangeException(
                nameof(oneBasedPartIndex),
                $"Invalid attachment index #{oneBasedPartIndex}. Valid range is 1 to {candidates.Count}.");
        }

        AttachmentCandidate target = candidates[oneBasedPartIndex - 1];
        byte[] payload = await DecodeCandidateBytesAsync(target, cancellationToken);
        string sha256 = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();

        string quarantineDir = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(quarantineDir);

        string safeFilename = SanitizeAttachmentFilename(target.Filename, oneBasedPartIndex);
        string quarantinedFilename = $"{safeFilename}.quarantine";
        string destinationPath = Path.GetFullPath(Path.Combine(quarantineDir, quarantinedFilename));

        string normalizedDirPrefix = quarantineDir.EndsWith(Path.DirectorySeparatorChar)
            ? quarantineDir
            : quarantineDir + Path.DirectorySeparatorChar;
        StringComparison pathComparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        if (!destinationPath.StartsWith(normalizedDirPrefix, pathComparison))
        {
            throw new InvalidOperationException(
                $"Quarantine path escaped target directory: '{destinationPath}'.");
        }

        await File.WriteAllBytesAsync(destinationPath, payload, cancellationToken);

        return new QuarantinedAttachmentResult(
            oneBasedPartIndex,
            target.Filename,
            destinationPath,
            payload.LongLength,
            sha256);
    }

    private static void CollectAttachmentCandidates(
        MimeEntity entity,
        List<AttachmentCandidate> candidates)
    {
        switch (entity)
        {
            case Multipart multipart:
                foreach (MimeEntity child in multipart)
                {
                    CollectAttachmentCandidates(child, candidates);
                }
                break;

            case MessagePart messagePart:
                if (IsAttachmentEntity(messagePart))
                {
                    string filename = messagePart.ContentDisposition?.FileName
                        ?? messagePart.ContentType?.Name
                        ?? "embedded_message.eml";
                    string mimeType = messagePart.ContentType?.MimeType ?? "message/rfc822";
                    candidates.Add(new AttachmentCandidate(messagePart, filename, mimeType, IsEmbeddedMessage: true));
                }

                if (messagePart.Message?.Body is not null)
                {
                    CollectAttachmentCandidates(messagePart.Message.Body, candidates);
                }
                break;

            case MimePart part:
                if (IsAttachmentEntity(part))
                {
                    string filename = part.FileName
                        ?? part.ContentType?.Name
                        ?? "unnamed_attachment.bin";
                    string mimeType = part.ContentType?.MimeType ?? "application/octet-stream";
                    candidates.Add(new AttachmentCandidate(part, filename, mimeType, IsEmbeddedMessage: false));
                }
                break;
        }
    }

    private static async Task<byte[]> DecodeCandidateBytesAsync(
        AttachmentCandidate candidate,
        CancellationToken cancellationToken)
    {
        using var memoryStream = new MemoryStream();
        if (candidate.Entity is MessagePart messagePart)
        {
            if (messagePart.Message is not null)
            {
                await messagePart.Message.WriteToAsync(memoryStream, cancellationToken);
            }
        }
        else if (candidate.Entity is MimePart part && part.Content is not null)
        {
            await part.Content.DecodeToAsync(memoryStream, cancellationToken);
        }

        return memoryStream.ToArray();
    }

    private static string SanitizeAttachmentFilename(string rawFilename, int partIndex)
    {
        string fallback = $"attachment_part_{partIndex}.bin";
        if (string.IsNullOrWhiteSpace(rawFilename))
        {
            return fallback;
        }

        // Normalize both Windows and POSIX separators before extracting the leaf name to defeat traversal.
        string[] segments = rawFilename.Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries);
        string leaf = segments.Length > 0 ? segments[^1] : string.Empty;

        char[] invalidChars = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(leaf.Length);
        foreach (char ch in leaf)
        {
            if (char.IsControl(ch) || Array.IndexOf(invalidChars, ch) >= 0)
            {
                sb.Append('_');
            }
            else
            {
                sb.Append(ch);
            }
        }

        string cleaned = sb.ToString().Replace("..", "_", StringComparison.Ordinal).Trim(' ', '.');
        if (string.IsNullOrWhiteSpace(cleaned))
        {
            return fallback;
        }

        string stem = Path.GetFileNameWithoutExtension(cleaned);
        if (WindowsReservedNames.Contains(stem))
        {
            cleaned = "_" + cleaned;
        }

        const int maxFilenameLength = 180;
        if (cleaned.Length > maxFilenameLength)
        {
            string ext = Path.GetExtension(cleaned);
            int maxStemLen = Math.Max(16, maxFilenameLength - ext.Length);
            string baseName = Path.GetFileNameWithoutExtension(cleaned);
            cleaned = (baseName.Length > maxStemLen ? baseName[..maxStemLen] : baseName) + ext;
        }

        return cleaned;
    }

    private static bool IsAttachmentEntity(MimeEntity entity)
    {
        if (entity.IsAttachment)
        {
            return true;
        }

        if (entity.ContentDisposition?.Disposition?.Equals(ContentDisposition.Attachment, StringComparison.OrdinalIgnoreCase) == true)
        {
            return true;
        }

        if (entity is MimePart part && !string.IsNullOrWhiteSpace(part.FileName))
        {
            return true;
        }

        return false;
    }

    private static AttachmentInfo BuildAttachmentInfo(
        string filename,
        string mimeType,
        byte[] data,
        bool isEmbeddedMessage)
    {
        (string md5, string sha1, string sha256) = ComputeHashesSimultaneously(data);
        MagicBytesInspectionResult magic = MagicBytesChecker.Inspect(data, filename, mimeType);

        return new AttachmentInfo
        {
            Filename = filename,
            DeclaredMimeType = mimeType,
            SizeBytes = data.LongLength,
            Md5 = md5,
            Sha1 = sha1,
            Sha256 = sha256,
            MagicBytesHex = magic.MagicBytesHex,
            DetectedFileType = isEmbeddedMessage ? "Embedded RFC822 Email (.eml)" : magic.DetectedFileType,
            IsExtensionSpoofed = !isEmbeddedMessage && magic.IsExtensionSpoofed,
            SpoofingDetail = isEmbeddedMessage ? null : magic.SpoofingDetail,
            IsHighRiskExtension = magic.IsHighRiskExtension,
            IsEmbeddedMessage = isEmbeddedMessage
        };
    }

    /// <summary>
    /// Computes MD5, SHA-1, and SHA-256 in a single pass over the in-memory payload.
    /// </summary>
    public static (string Md5, string Sha1, string Sha256) ComputeHashesSimultaneously(ReadOnlySpan<byte> data)
    {
        using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        const int chunkSize = 8192;
        int offset = 0;
        while (offset < data.Length)
        {
            int count = Math.Min(chunkSize, data.Length - offset);
            ReadOnlySpan<byte> slice = data.Slice(offset, count);
            md5.AppendData(slice);
            sha1.AppendData(slice);
            sha256.AppendData(slice);
            offset += count;
        }

        return (
            Convert.ToHexString(md5.GetHashAndReset()).ToLowerInvariant(),
            Convert.ToHexString(sha1.GetHashAndReset()).ToLowerInvariant(),
            Convert.ToHexString(sha256.GetHashAndReset()).ToLowerInvariant()
        );
    }
}
