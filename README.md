# EmlDissect

> .NET 8.0+ | C# | DFIR / Blue Team | GNU GPLv3

---

## Overview

**EmlDissect** is a command-line static `.eml` parser and IOC extraction utility written in C# (.NET 8.0). It parses email files purely in memory without writing or executing attachments on disk, extracts routing headers and authentication checks, defangs network indicators, verifies attachment file signatures, and optionally enriches IOCs via Threat Intelligence APIs.

## Features

### Static Forensics
- **Headers & Routing:** Extracts `From`, `To`, `Cc`, `Subject`, `Date`, `Message-ID`, `Return-Path`, `Reply-To`, `X-Originating-IP`, and `X-Mailer`. Reconstructs chronological `Received` hops with transit delays and flags display-name or domain mismatches.
- **Authentication:** Parses `Authentication-Results` and `Received-SPF` headers for **SPF**, **DKIM**, and **DMARC** status (`PASS` / `FAIL`).
- **Network IOCs & Defanging:** Extracts public IPv4 addresses, domains, and URLs from plain-text and HTML bodies. Flags `<a href>` vs anchor-text discrepancies (`MISMATCH!`) and prints indicators in defanged format (`http://evil.com` -> `hxxp://evil[.]com`).
- **In-Memory Attachment Inspection:** Lists attachments (declared MIME type, size), computes **MD5**, **SHA-1**, and **SHA-256** hashes in memory, and checks leading **magic bytes** against declared extensions to detect extension spoofing (e.g., an `MZ` executable disguised as `.pdf`).

### Threat Intelligence & Exports
- **IPinfo.io Lookup:** Resolves City, Region, Country, ASN, and ISP/Hosting provider for extracted public IPv4 addresses.
- **VirusTotal & AbuseIPDB:** Optional enrichment via **VirusTotal API v3** (attachment SHA-256 hashes and URLs) and **AbuseIPDB API v2** (IPv4 abuse confidence score).
- **Offline Mode (`--no-intel`):** Runs purely local static analysis with zero external network requests.
- **Exports:** Saves reports to **JSON** (`--export-json`), **CSV** (`--export-csv`), or appends rows directly to a **Google Sheet** (`--export-gsheet`).

## Prerequisites (Building from Source)

- [.NET 8.0 SDK](https://microsoft.com) or higher.
- [MimeKit](https://github.com) `>= 4.15.1` (restored automatically via NuGet).
- *(Optional)* API keys for **IPinfo**, **VirusTotal**, **AbuseIPDB**, and a **Google Service Account** JSON key for Google Sheets export.

## Installation & Build

```bash
git clone https://github.com/0xNura/EmlDissect.git
cd EmlDissect

dotnet restore src/EmlDissect.csproj
dotnet build src/EmlDissect.csproj -c Release
```

## API Keys Configuration (Optional)

API keys are read from environment variables. Set them in your shell before running online lookups:

**Windows (PowerShell):**
```powershell
\$env:IPINFO_TOKEN="your_ipinfo_token"
\$env:VT_API_KEY="your_virustotal_api_key"
\$env:ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
\$env:GOOGLE_APPLICATION_CREDENTIALS="C:\(\path\to\service-\)account.json"
```

**Windows (CMD):**
```cmd
set IPINFO_TOKEN=your_ipinfo_token
set VT_API_KEY=your_virustotal_api_key
set ABUSEIPDB_API_KEY=your_abuseipdb_api_key
set GOOGLE_APPLICATION_CREDENTIALS=C:\(\path\to\service-\)account.json
```

**Linux / macOS (Bash):**
```bash
export IPINFO_TOKEN="your_ipinfo_token"
export VT_API_KEY="your_virustotal_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
```

## Usage

### 1. Exporting an `.eml` File
- **Gmail:** Open the message -> click the three dots (`⋮`) next to Reply -> **Download message**.
- **Outlook:** Open the message -> click (`...`) -> **Download** (or drag and drop the message onto your Desktop).

### 2. Option A: Pre-compiled Windows Binary (Release)
1. Download `EmlDissect-win-x64.zip` from the [Releases](https://github.com/0xNura/EmlDissect/releases) page and extract it.
2. Double-click **`Start_CLI.bat`** to open a terminal in the extracted folder.
3. Run `emldissect.exe`:

```cmd
# Offline analysis on the included sample
emldissect.exe samples\phishing_test.eml --no-intel

# Online analysis with IPinfo / Threat Intel enrichment
emldissect.exe "%USERPROFILE%\Downloads\email.eml"

# Export to JSON or CSV
emldissect.exe samples\phishing_test.eml --export-json report.json
emldissect.exe samples\phishing_test.eml --export-csv report.csv

# Append results to a Google Sheet
emldissect.exe samples\phishing_test.eml --export-gsheet <SPREADSHEET_ID>
```

### 3. Option B: Running from Source

```bash
# Offline analysis
dotnet run --project src/EmlDissect.csproj -- samples/phishing_test.eml --no-intel

# Online analysis with Threat Intel enrichment
dotnet run --project src/EmlDissect.csproj -- "%USERPROFILE%/Downloads/email.eml"
```

## Disclaimer

For educational, defensive, and authorized forensic analysis only. Always inspect suspicious `.eml` files and attachments inside an isolated sandbox environment.

## License

Licensed under the **GNU General Public License v3.0 (GPLv3)**. See [LICENSE](LICENSE) for details.
