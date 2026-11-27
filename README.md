# EmlDissect

> .NET 8.0+ | C# | DFIR / Blue Team | GNU GPLv3

---

## Overview

**EmlDissect** is a command-line static `.eml` parser, bulk IMAP collector, and IOC extraction utility written in C# (.NET 8.0). It parses email files purely in memory without writing or executing attachments on disk by default, extracts routing headers and authentication checks, defangs network indicators, verifies attachment file signatures, supports safe attachment quarantine extraction, and optionally enriches IOCs via Threat Intelligence APIs.

## Features

### Static Forensics & Batch Triage
- **Headers & Routing:** Extracts `From`, `To`, `Cc`, `Subject`, `Date`, `Message-ID`, `Return-Path`, `Reply-To`, `X-Originating-IP`, and `X-Mailer`. Reconstructs chronological `Received` hops with transit delays and flags display-name or domain mismatches.
- **Authentication:** Parses `Authentication-Results` and `Received-SPF` headers for **SPF**, **DKIM**, and **DMARC** status (`PASS` / `FAIL`).
- **Network IOCs & Defanging:** Extracts public IPv4 addresses, domains, and URLs from plain-text and HTML bodies. Flags `<a href>` vs anchor-text discrepancies (`MISMATCH!`) and prints indicators in defanged format (`http://evil.com` -> `hxxp://evil[.]com`).
- **In-Memory Attachment Inspection:** Lists attachments (declared MIME type, size), computes **MD5**, **SHA-1**, and **SHA-256** hashes in memory, and checks leading **magic bytes** against declared extensions to detect extension spoofing (e.g., an `MZ` executable disguised as `.pdf`).
- **Safe Attachment Quarantine (`--dump-part`):** Extracts a specific attachment by its 1-based index into a quarantine directory (`--dump-dir`, default: `./quarantine`), sanitizing the filename and appending `.quarantine` to prevent accidental execution.
- **Bulk Folder Analysis (`--dir`):** Scans a directory of `.eml` files sequentially and prints a consolidated batch triage table summarizing senders, auth results, warning counts, and malicious hits.

### Bulk IMAP Acquisition (`--fetch-imap`)
- Connects to any IMAP server over SSL/TLS (`MailKit`) using environment variables (`IMAP_HOST`, `IMAP_PORT`, `IMAP_USER`, `IMAP_PASS`).
- Filters messages by folder (`--imap-folder`), sender (`--imap-from`), subject (`--imap-subject`), date (`--imap-since`), unread state (`--imap-unseen`), and max count (`--imap-limit`).
- Saves raw `.eml` files locally (`yyyyMMdd_HHmmss_<uid>_<subject>.eml`) and optionally triggers immediate batch triage with `--analyze`.

### Threat Intelligence & Exports
- **IPinfo.io Lookup:** Resolves City, Region, Country, ASN, and ISP/Hosting provider for extracted public IPv4 addresses.
- **VirusTotal & AbuseIPDB:** Optional enrichment via **VirusTotal API v3** (attachment SHA-256 hashes and URLs) and **AbuseIPDB API v2** (IPv4 abuse confidence score).
- **Offline Mode (`--no-intel`):** Runs purely local static analysis with zero external network requests.
- **Exports:** Saves single or batch reports to **JSON** (`--export-json`), **CSV** (`--export-csv`), or appends rows directly to a **Google Sheet** (`--export-gsheet`).

## Prerequisites (Building from Source)

- [.NET 8.0 SDK](https://microsoft.com) or higher.
- [MimeKit](https://github.com) and [MailKit](https://github.com) `>= 4.15.1` (restored automatically via NuGet).
- *(Optional)* API keys for **IPinfo**, **VirusTotal**, **AbuseIPDB**, IMAP credentials, or a **Google Service Account** JSON key.

## Installation & Build

```bash
git clone https://github.com/0xNura/EmlDissect.git
cd EmlDissect

dotnet restore src/EmlDissect.csproj
dotnet build src/EmlDissect.csproj -c Release
```

## Environment Variables (Optional)

Credentials and API keys are read from environment variables. Set them in your shell before running online lookups or IMAP acquisition:

**Windows (PowerShell):**
```powershell
\$env:IPINFO_TOKEN="your_ipinfo_token"
\$env:VT_API_KEY="your_virustotal_api_key"
\$env:ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
\$env:GOOGLE_APPLICATION_CREDENTIALS="C:\(\path\to\service-\)account.json"

\$env:IMAP_HOST="imap.gmail.com"
\$env:IMAP_PORT="993"
\$env:IMAP_USER="analyst@example.com"
\$env:IMAP_PASS="your_app_specific_password"
```

**Windows (CMD):**
```cmd
set IPINFO_TOKEN=your_ipinfo_token
set VT_API_KEY=your_virustotal_api_key
set ABUSEIPDB_API_KEY=your_abuseipdb_api_key
set GOOGLE_APPLICATION_CREDENTIALS=C:\(\path\to\service-\)account.json

set IMAP_HOST=imap.gmail.com
set IMAP_PORT=993
set IMAP_USER=analyst@example.com
set IMAP_PASS=your_app_specific_password
```

**Linux / macOS (Bash):**
```bash
export IPINFO_TOKEN="your_ipinfo_token"
export VT_API_KEY="your_virustotal_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"

export IMAP_HOST="imap.gmail.com"
export IMAP_PORT="993"
export IMAP_USER="analyst@example.com"
export IMAP_PASS="your_app_specific_password"
```

## Usage

### Option A: Pre-compiled Windows Binary (Release)
1. Download `EmlDissect-win-x64.zip` from the [Releases](https://github.com/0xNura/EmlDissect/releases) page and extract it.
2. Double-click **`Start_CLI.bat`** to open a terminal in the extracted folder.
3. Run `emldissect.exe`:

```cmd
# Single-file offline analysis
emldissect.exe samples\phishing_test.eml --no-intel

# Single-file online analysis with Threat Intel enrichment
emldissect.exe "%USERPROFILE%\Downloads\email.eml"

# Safely dump Attachment #1 to ./quarantine with a .quarantine extension
emldissect.exe samples\phishing_test.eml --no-intel --dump-part 1 --dump-dir ".\quarantine"

# Bulk analysis on an entire folder of .eml files
emldissect.exe --dir ".\dump_eml" --no-intel --export-csv batch_report.csv

# Fetch suspicious emails via IMAP and run immediate batch triage
emldissect.exe --fetch-imap ".\dump_eml" --imap-folder "Junk" --imap-since 2026-11-01 --imap-limit 25 --analyze --no-intel

# Export to JSON or Google Sheets
emldissect.exe samples\phishing_test.eml --export-json report.json
emldissect.exe samples\phishing_test.eml --export-gsheet <SPREADSHEET_ID>
```

### Option B: Running from Source

```bash
# Single-file offline analysis
dotnet run --project src/EmlDissect.csproj -- samples/phishing_test.eml --no-intel

# Safely extract Attachment #1 to ./quarantine
dotnet run --project src/EmlDissect.csproj -- samples/phishing_test.eml --no-intel --dump-part 1

# Bulk folder triage
dotnet run --project src/EmlDissect.csproj -- --dir ./dump_eml --no-intel

# Bulk IMAP fetch + immediate analysis
dotnet run --project src/EmlDissect.csproj -- --fetch-imap ./dump_eml --imap-folder INBOX --imap-unseen --analyze
```

## Disclaimer

For educational, defensive, and authorized forensic analysis only. Always inspect suspicious `.eml` files and quarantined attachments inside an isolated sandbox environment.

## License

Licensed under the **GNU General Public License v3.0 (GPLv3)**. See [LICENSE](LICENSE) for details.
