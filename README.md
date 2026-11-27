# EmlDissect 🔍

[![.NET](https://shields.io)](https://microsoft.com)
[![Language](https://shields.io)](https://microsoft.com)
[![Domain](https://shields.io)]()
[![License: GPL v3](https://shields.io)](https://gnu.org)

*🇬🇧 English version below | 🇫🇷 Version française plus bas*

---

## 🇬🇧 English

### Overview
**EmlDissect** is an open-source, lightweight command-line forensic and Threat Intelligence tool written in C# (.NET 8.0+) for SOC analysts and DFIR (Digital Forensics and Incident Response) practitioners. It safely dissects suspicious `.eml` files purely in memory—without writing or executing payloads on disk—to extract headers, authentication checks, neutralized (defanged) network IOCs, attachment hashes, file signature anomalies, and automated Threat Intel enrichment.

### Features

#### Core Forensics
* **Envelope & Header Analysis:** Extracts `From`, `To`, `Cc`, `Subject`, `Date`, `Message-ID`, `Return-Path`, `Reply-To`, `X-Originating-IP`, and `X-Mailer`. Automatically flags display-name impersonation and domain mismatches.
* **Chronological Routing Hops:** Parses `Received` headers bottom-to-top to reconstruct the exact server path from origin to destination and calculates transit delays between hops.
* **Authentication Checks:** Parses `Authentication-Results` headers for **SPF**, **DKIM**, and **DMARC** status (`PASS` / `FAIL`).
* **Network IOC Extraction & Defanging:** Extracts public IPv4 addresses, unique domains, and URLs from both plain-text and HTML bodies. Detects `<a href>` vs anchor-text mismatches (`MISMATCH!`) and outputs all indicators in safe **defanged** format (`http://evil.com` → `hxxp://evil[.]com`).
* **In-Memory Attachment Forensics:** Lists attachments (MIME type, size), computes **MD5**, **SHA-1**, and **SHA-256** cryptographic hashes in memory, and inspects **Magic Bytes** to detect extension spoofing (e.g., a Windows PE executable `4D 5A` disguised as `.pdf`).
* **IP Geolocation & ASN Lookup (IPinfo.io):** Queries `ipinfo.io` to identify the City, Region, Country, ASN, and ISP/Hosting provider for every public IPv4 extracted.

#### Threat Intelligence & Reporting
* **VirusTotal & AbuseIPDB Enrichment:** Queries **VirusTotal API v3** (for attachment SHA-256 hashes and URLs) and **AbuseIPDB API v2** (for IPv4 abuse confidence scores).
* **Multi-Format & Google Sheets Export:** Exports structured forensic reports to **JSON**, **CSV**, or appends findings directly into a centralized **Google Sheet** for SOC phishing campaign tracking.
* **Offline Triage Mode (`--no-intel`):** Runs purely local static analysis without making any external API requests.

### Prerequisites
* [.NET 8.0 SDK](https://microsoft.comdownload) or higher.
* [MimeKit](https://github.com) `>= 4.15.1` (restored automatically via NuGet).
* *(Optional)* Free API keys for **IPinfo**, **VirusTotal**, **AbuseIPDB**, and a **Google Service Account** JSON key for Google Sheets export.

### Installation & Build
```bash
# Clone the repository
git clone https://github.com<your-username>/EmlDissect.git
cd EmlDissect

# Restore dependencies and build in Release mode
dotnet restore src/EmlDissect.csproj
dotnet build src/EmlDissect.csproj -c Release
```

### API Keys Configuration (Optional)
Never hardcode API keys in the source code. Set them via environment variables before running the tool with Threat Intel enabled:

**Windows (PowerShell):**
```powershell
$env:IPINFO_TOKEN="your_ipinfo_token"
$env:VT_API_KEY="your_virustotal_api_key"
$env:ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
$env:GOOGLE_APPLICATION_CREDENTIALS="C:\path\to\service-account.json"
```

**Linux / macOS (Bash):**
```bash
export IPINFO_TOKEN="your_ipinfo_token"
export VT_API_KEY="your_virustotal_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
```

### How to Use & Quickstart

#### 1. Obtaining an `.eml` File
* **Gmail:** Open the email → Click the three dots (`⋮`) next to Reply → **Download message**.
* **Outlook:** Open the email → Click (`...`) → **Download** (or drag and drop the email onto your Desktop).

#### 2. Running Commands
```bash
# Test with the included phishing sample (Offline mode)
dotnet run --project src/EmlDissect.csproj -- samples/phishing_test.eml --no-intel

# Analyze a real email with IPinfo / Threat Intel enrichment
dotnet run --project src/EmlDissect.csproj -- "C:\path\to\downloaded_email.eml"

# Export full forensic report to JSON or CSV
dotnet run --project src/EmlDissect.csproj -- samples/phishing_test.eml --export-json report.json
dotnet run --project src/EmlDissect.csproj -- samples/phishing_test.eml --export-csv report.csv

# Append findings directly to a Google Sheet
dotnet run --project src/EmlDissect.csproj -- samples/phishing_test.eml --export-gsheet <SPREADSHEET_ID>
```

### Disclaimer
This tool is intended strictly for educational, defensive, and authorized forensic analysis purposes. Always handle suspicious email samples inside an isolated sandbox environment.

### License
This project is licensed under the **GNU General Public License v3.0 (GPLv3)** — see the [LICENSE](LICENSE) file for details.

---

## 🇫🇷 Français

### Présentation
**EmlDissect** est un outil d'investigation numérique (DFIR) et de Threat Intelligence léger et open source, développé en C# (.NET 8.0+) pour les analystes SOC et les équipes Blue Team. Il analyse de manière statique et sécurisée les fichiers emails suspects (`.eml`) directement en mémoire—sans écriture ni exécution sur le disque—afin d'extraire les en-têtes, les contrôles d'authentification, les IOCs réseau neutralisés (*defanged*), les empreintes de pièces jointes, les anomalies de signatures de fichiers et leur réputation.

### Fonctionnalités

#### Forensique de base
* **Analyse de l'enveloppe et des en-têtes :** Extraction des champs `From`, `To`, `Cc`, `Subject`, `Date`, `Message-ID`, `Return-Path`, `Reply-To`, `X-Originating-IP` et `X-Mailer`. Détection automatique de l'usurpation du nom d'affichage et des discordances de domaines.
* **Traçage chronologique des relais (`Received`) :** Analyse des en-têtes de bas en haut pour reconstituer le trajet exact des serveurs (de l'origine jusqu'à la destination) et calculer les délais de transit entre chaque saut.
* **Vérification d'authentification :** Lecture des statuts **SPF**, **DKIM** et **DMARC** dans les en-têtes `Authentication-Results` (`PASS` / `FAIL`).
* **Extraction et « Defang » des IOCs réseau :** Extraction automatique des adresses IPv4 publiques, domaines uniques et URLs depuis le texte brut et le HTML. Détection des liens trompeurs (`<a href>` différent du texte affiché : `MISMATCH!`) et affichage sécurisé au format **defanged** (`http://evil.com` → `hxxp://evil[.]com`).
* **Forensique des pièces jointes en mémoire :** Liste les pièces jointes (type MIME, taille), calcule simultanément les empreintes **MD5**, **SHA-1** et **SHA-256** en mémoire, et inspecte les **Magic Bytes** pour détecter les extensions falsifiées (ex : un exécutable Windows `4D 5A` déguisé en `.pdf`).
* **Géolocalisation IP & ASN (IPinfo.io) :** Interrogation de l'API `ipinfo.io` pour identifier la ville, la région, le pays, l'ASN et le fournisseur (ISP/Hébergeur) de chaque IP publique extraite.

#### Threat Intelligence & Rapports
* **Enrichissement VirusTotal & AbuseIPDB :** Interrogation automatique de **VirusTotal API v3** (pour les empreintes SHA-256 et les URLs) et d'**AbuseIPDB API v2** (pour le score de confiance d'abus des IPv4).
* **Exports multi-formats & Google Sheets :** Sauvegarde des rapports au format **JSON**, **CSV**, ou ajout automatique d'une ligne dans un tableau **Google Sheets** partagé pour le suivi des campagnes de phishing en SOC.
* **Mode hors-ligne (`--no-intel`) :** Analyse purement locale sans aucune requête réseau externe.

### Prérequis
* [SDK .NET 8.0](https://microsoft.comdownload) ou supérieur.
* [MimeKit](https://github.com) `>= 4.15.1` (téléchargé automatiquement via NuGet).
* *(Optionnel)* Clés API gratuites pour **IPinfo**, **VirusTotal**, **AbuseIPDB**, et un fichier JSON de compte de service Google pour l'export Google Sheets.

### Installation et Compilation
```bash
# Cloner le dépôt
git clone https://github.com<votre-pseudo>/EmlDissect.git
cd EmlDissect

# Restaurer les dépendances et compiler en mode Release
dotnet restore src/EmlDissect.csproj
dotnet build src/EmlDissect.csproj -c Release
```

### Configuration des clés API (Optionnel)
N'inscrivez jamais vos clés API en dur dans le code source. Définissez-les via les variables d'environnement avant d'exécuter l'outil avec la Threat Intelligence activée :

**Windows (PowerShell) :**
```powershell
$env:IPINFO_TOKEN="votre_token_ipinfo"
$env:VT_API_KEY="votre_cle_api_virustotal"
$env:ABUSEIPDB_API_KEY="votre_cle_api_abuseipdb"
$env:GOOGLE_APPLICATION_CREDENTIALS="C:\chemin\vers\service-account.json"
```

**Linux / macOS (Bash) :**
```bash
export IPINFO_TOKEN="votre_token_ipinfo"
export VT_API_KEY="votre_cle_api_virustotal"
export ABUSEIPDB_API_KEY="votre_cle_api_abuseipdb"
export GOOGLE_APPLICATION_CREDENTIALS="/chemin/vers/service-account.json"
```

### Guide d'utilisation rapide

#### 1. Récupérer un fichier `.eml`
* **Gmail :** Ouvrez l'email → Cliquez sur les trois petits points (`⋮`) à côté de Répondre → **Télécharger le message**.
