using System.Security.Cryptography;
using EmlDissect.Models;
using EmlDissect.Utils;
using MimeKit;

namespace EmlDissect.Services;

/// <summary>
/// Analyzes email attachments strictly in memory: computes MD5, SHA-1, and SHA-256
/// simultaneously and validates magic bytes against declared extensions.
/// </summary>
public sealed class AttachmentForensics
{
    /// <summary>
    /// Recursively inspects all attachments in a MimeMessage without writing payloads to disk.
    /// </summary>
    public async Task<List<AttachmentInfo>> AnalyzeAttachmentsAsync(
        MimeMessage message,
        CancellationToken cancellationToken = default)
    {
        var results = new List<AttachmentInfo>();
        if (message.Body is not null)
        {
            await WalkEntityAsync(message.Body, results, cancellationToken);
        }

        return results;
    }

    private async Task WalkEntityAsync(
        MimeEntity entity,
        List<AttachmentInfo> results,
        CancellationToken cancellationToken)
    {
        switch (entity)
        {
            case Multipart multipart:
                foreach (MimeEntity child in multipart)
                {
                    await WalkEntityAsync(child, results, cancellationToken);
                }
                break;

            case MessagePart messagePart:
                if (IsAttachmentEntity(messagePart))
                {
                    AttachmentInfo embeddedInfo = await InspectEmbeddedMessageAsync(messagePart, cancellationToken);
                    results.Add(embeddedInfo);
                }

                if (messagePart.Message?.Body is not null)
                {
                    await WalkEntityAsync(messagePart.Message.Body, results, cancellationToken);
                }
                break;

            case MimePart part:
                if (IsAttachmentEntity(part))
                {
                    AttachmentInfo partInfo = await InspectMimePartAsync(part, cancellationToken);
                    results.Add(partInfo);
                }
                break;
        }
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

    private static async Task<AttachmentInfo> InspectMimePartAsync(
        MimePart part,
        CancellationToken cancellationToken)
    {
        string filename = part.FileName
            ?? part.ContentType?.Name
            ?? "unnamed_attachment.bin";
        string mimeType = part.ContentType?.MimeType ?? "application/octet-stream";

        using var memoryStream = new MemoryStream();
        if (part.Content is not null)
        {
            await part.Content.DecodeToAsync(memoryStream, cancellationToken);
        }

        byte[] bytes = memoryStream.ToArray();
        return BuildAttachmentInfo(filename, mimeType, bytes, isEmbeddedMessage: false);
    }

    private static async Task<AttachmentInfo> InspectEmbeddedMessageAsync(
        MessagePart messagePart,
        CancellationToken cancellationToken)
    {
        string filename = messagePart.ContentDisposition?.FileName
            ?? messagePart.ContentType?.Name
            ?? "embedded_message.eml";
        string mimeType = messagePart.ContentType?.MimeType ?? "message/rfc822";

        using var memoryStream = new MemoryStream();
        if (messagePart.Message is not null)
        {
            await messagePart.Message.WriteToAsync(memoryStream, cancellationToken);
        }

        byte[] bytes = memoryStream.ToArray();
        return BuildAttachmentInfo(filename, mimeType, bytes, isEmbeddedMessage: true);
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
