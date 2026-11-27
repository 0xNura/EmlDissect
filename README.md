# IOC-Harvester 🔍

[![.NET](https://shields.io)](https://microsoft.com)
[![Language](https://shields.io)](https://microsoft.com)
[![Domain](https://shields.io)]()
[![License: MIT](https://shields.io)](https://opensource.org)

---

## 🇫🇷 Français

### Présentation
**IOC-Harvester** est un outil d'investigation numérique (DFIR) et de Threat Intelligence léger et open source, développé en C# (.NET 8.0+) pour les analystes SOC et les équipes Blue Team. Il analyse de manière statique et sécurisée les fichiers emails suspects (`.eml`) directement en mémoire—sans écriture ni exécution sur le disque—afin d'extraire les en-têtes, les contrôles d'authentification, les IOCs réseau neutralisés (*defanged*), les empreintes de pièces jointes et leur réputation.

### Fonctionnalités

#### Forensique de base
* **Analyse des en-têtes et du routage :** Extraction des champs `From`, `To`, `Subject`, `Date`, `Message-ID`, `Return-Path` et `Reply-To`. Reconstitution chronologique des serveurs relais (`Received`) et détection des incohérences d'usurpation (*spoofing*).
* **Vérification d'authentification :** Lecture des statuts **SPF**, **DKIM** et **DMARC** dans les en-têtes `Authentication-Results`.
* **Extraction et « Defang » des IOCs réseau :** Détection automatique des adresses IPv4 publiques, noms de domaine et URLs (incluant la détection de discordances entre les liens HTML `<a href>` et le texte affiché) avec neutralisation automatique (`http://evil.com` → `hxxp://evil[.]com`).
* **Forensique des pièces jointes en mémoire :** Extraction des métadonnées (nom, type MIME, taille), calcul simultané des empreintes **MD5**, **SHA-1** et **SHA-256**, et vérification des **Magic Bytes** pour détecter les extensions falsifiées (ex : un `.exe` déguisé en `.pdf`).
* **Géolocalisation IP & ASN (IPinfo.io) :** Interrogation de l'API `ipinfo.io` pour obtenir la ville, la région, le pays, le fournisseur (ISP/Hébergeur) et l'ASN de chaque IP publique extraite.

#### Threat Intelligence & Rapports
* **Enrichissement VirusTotal & AbuseIPDB :** Vérification automatique des empreintes **SHA-256** et **URLs** via l'API **VirusTotal v3**, et du score de confiance d'abus des **IPv4** via **AbuseIPDB v2**.
* **Exports multi-formats & Google Sheets :** Sauvegarde des rapports au format **JSON**, **CSV**, ou ajout automatique d'une ligne dans un tableau **Google Sheets** partagé pour le suivi des campagnes de phishing en SOC.
* **Mode hors-ligne (`--no-intel`) :** Analyse purement locale sans aucune requête réseau externe.

### Prérequis
* [SDK .NET 8.0](https://microsoft.comdownload) ou supérieur.
* [MimeKit](https://github.com) (installé automatiquement via NuGet).
* *(Optionnel)* Clés API gratuites pour **IPinfo**, **VirusTotal**, **AbuseIPDB**, et un fichier JSON de compte de service Google pour l'export Google Sheets.

### Installation et Compilation
```bash
# Cloner le dépôt
git clone https://github.com<votre-pseudo>/IOC-Harvester.git
cd IOC-Harvester

# Compiler en mode Release
dotnet build src/IOC-Harvester.csproj -c Release
```

### Configuration des clés API (Variables d'environnement)
Ne inscrivez jamais vos clés API en dur dans le code source. Définissez-les via les variables d'environnement avant d'exécuter l'outil :

**Windows (PowerShell) :**
```powershell
\$env:IPINFO_TOKEN="votre_token_ipinfo"
\$env:VT_API_KEY="votre_cle_api_virustotal"
\$env:ABUSEIPDB_API_KEY="votre_cle_api_abuseipdb"
\$env:GOOGLE_APPLICATION_CREDENTIALS="C:\chemin\vers\service-account.json"
```

**Linux / macOS (Bash) :**
```bash
export IPINFO_TOKEN="votre_token_ipinfo"
export VT_API_KEY="votre_cle_api_virustotal"
export ABUSEIPDB_API_KEY="votre_cle_api_abuseipdb"
export GOOGLE_APPLICATION_CREDENTIALS="/chemin/vers/service-account.json"
```

### Utilisation
```bash
# Analyse standard avec enrichissement Threat Intel
./IOC-Harvester.exe samples/phishing_test.eml

# Mode hors-ligne (sans appels API externes)
./IOC-Harvester.exe samples/phishing_test.eml --no-intel

# Exporter les résultats en JSON ou CSV
./IOC-Harvester.exe samples/phishing_test.eml --export-json rapport.json
./IOC-Harvester.exe samples/phishing_test.eml --export-csv rapport.csv

# Ajouter les résultats directement dans une feuille Google Sheets
./IOC-Harvester.exe samples/phishing_test.eml --export-gsheet <ID_DU_GOOGLE_SHEET>
```

### Avertissement
Cet outil est conçu exclusivement à des fins pédagogiques, défensives et d'investigation numérique autorisée. Manipulez toujours les échantillons d'emails suspects dans un environnement isolé (machine virtuelle / sandbox).

---

### License / Licence
Distributed under the MIT License. See `LICENSE` for more information.
