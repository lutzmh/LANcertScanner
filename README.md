# LAN Certificate & TLS Scanner

Two equivalent scripts that scan your LAN with **nmap** for SSL/TLS certificates and
cipher configuration, then produce a **self-contained tabbed HTML report**.

- `Invoke-CertScan.ps1` — PowerShell (Windows)
- `cert-scan.sh` — Bash + Python 3 (Linux/macOS)

## What it reports

Each certificate found is reported with:
- **Expiration date** and **days until expiration**
- **Hostname used to access** the service (nmap-resolved hostname / IP)
- **Subject CN** (hostname in certificate subject)
- **Subject Alternative Names** (all SANs)
- Issuer, port, and service

The HTML report has **four tabs**:
1. **Dashboard** — summary cards (total, expired, critical, warning, healthy, systems with weak ciphers) plus a scan summary table.
2. **Expiring Certificates** — everything expiring within the warning window, colour-coded EXPIRED / CRITICAL / WARNING, sorted by days-left.
3. **Weak Ciphers & Protocols** — hosts offering SSLv2/SSLv3/TLS 1.0/TLS 1.1 or weak cipher suites (NULL, EXPORT, RC4, DES, 3DES, MD5, anon).
4. **Full Inventory** — every certificate discovered, with searchable/sortable columns.

All tables are client-side **searchable** (filter box) and **sortable** (click column headers). The report is a single HTML file with no external dependencies.

## Requirements

- **nmap** in PATH — https://nmap.org/download.html
- PowerShell 5.1+ (Windows script) **or** Python 3 (bash script)
- Run elevated / as root for best host-discovery results

## Ports scanned (default)

Common TLS service ports:
`443, 465, 563, 587, 636, 853, 993, 995, 989, 990, 992, 1443, 2083, 2087, 2096, 3269, 3389, 5061, 5986, 8443, 8834, 9443, 10000`

(HTTPS, SMTPS, NNTPS, submission/STARTTLS, LDAPS, DoT, IMAPS, POP3S, FTPS, MSSQL-TLS, cPanel, RDP, SIP-TLS, WinRM-HTTPS, alt-HTTPS, Nessus, Webmin, etc.)

Override with `-Ports` / `-p`.

## Usage

### PowerShell
```powershell
# Basic scan of a /24
.\Invoke-CertScan.ps1 -Targets "10.0.0.0/24"

# Custom thresholds and output path
.\Invoke-CertScan.ps1 -Targets "10.0.0.0/24" -WarnDays 60 -CriticalDays 14 -OutputPath C:\Reports\certs.html

# Multiple ranges, custom ports
.\Invoke-CertScan.ps1 -Targets "10.0.0.0/24 10.0.1.0/24" -Ports "443,8443,636"
```

### Bash
```bash
# Basic scan of a /24
./cert-scan.sh -t 10.0.0.0/24

# Custom thresholds and output path
./cert-scan.sh -t 10.0.0.0/24 -w 60 -c 14 -o /tmp/certs.html

# Multiple ranges, custom ports
./cert-scan.sh -t "10.0.0.0/24 10.0.1.0/24" -p "443,8443,636"
```

## Parameters

| PowerShell | Bash | Default | Meaning |
|---|---|---|---|
| `-Targets` | `-t` | (required) | nmap target spec (CIDR, range, or list) |
| `-Ports` | `-p` | see above | comma-separated ports |
| `-OutputPath` | `-o` | `./CertScanReport_<timestamp>.html` | report path |
| `-WarnDays` | `-w` | 30 | days-to-expiry warning threshold |
| `-CriticalDays` | `-c` | 7 | days-to-expiry critical threshold |

## How it works

Runs:
```
nmap -Pn -p <ports> --script ssl-cert,ssl-enum-ciphers --open -oX <tmp> <targets>
```
then parses the XML: `ssl-cert` provides subject/SAN/validity, `ssl-enum-ciphers`
provides per-protocol cipher lists and a least-strength grade. Days-to-expiry is
computed from the certificate's notAfter against the current date.

## Notes & tuning

- `-Pn` skips host discovery so filtered hosts still get their ports probed. Drop it if you only want responsive hosts (faster).
- For large ranges, add nmap timing to the script (e.g. `-T4`) or scan in batches.
- `ssl-enum-ciphers` is the slow part; remove it from the `--script` list if you only need expiry data.
- The weak-cipher patterns (NULL, EXPORT, RC4, DES, 3DES, MD5, anon) and weak protocols (SSLv2/3, TLS 1.0/1.1) are defined near the top of each script — adjust to your policy (e.g. flag all CBC, or flag TLS 1.2 if you require 1.3-only).
- **Only scan networks you are authorised to scan.**

## Scheduling

- **Windows:** wrap in a Scheduled Task; email the HTML or drop it on a share.
- **Linux:** cron job; pipe the summary line to your alerting, archive the HTML.

For PCI DSS environments this doubles as evidence for the annual cipher-suite review
(Req. 4.2.1.2) and supports the certificate inventory requirement (Req. 4.2.1.1).
