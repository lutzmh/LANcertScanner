<#
.SYNOPSIS
    Scans a LAN with nmap for SSL/TLS certificates and cipher configuration, then
    produces a self-contained tabbed HTML report (Dashboard, Expiring Certificates,
    Weak Ciphers/Protocols, Full Inventory).

.DESCRIPTION
    Wraps nmap's ssl-cert and ssl-enum-ciphers NSE scripts, parses the XML output,
    computes days-to-expiry, flags weak protocols and cipher suites, and renders a
    single HTML file with tabs, a dashboard, and searchable/sortable tables.

.PARAMETER Targets
    Target spec passed to nmap: CIDR, range, or space-separated list.
    e.g. "10.0.0.0/24", "10.0.0.1-254", "192.168.1.0/24 192.168.2.0/24"

.PARAMETER Ports
    Comma-separated ports to scan. Defaults to common TLS service ports.

.PARAMETER OutputPath
    Path for the HTML report. Defaults to .\CertScanReport_<timestamp>.html

.PARAMETER WarnDays        Days-to-expiry "warning" threshold. Default 30.
.PARAMETER CriticalDays    Days-to-expiry "critical" threshold. Default 7.

.EXAMPLE
    .\Invoke-CertScan.ps1 -Targets "10.0.0.0/24"

.EXAMPLE
    .\Invoke-CertScan.ps1 -Targets "10.0.0.0/24" -WarnDays 60 -CriticalDays 14 -OutputPath C:\Reports\certs.html

.NOTES
    Requires nmap in PATH (https://nmap.org/download.html). Run elevated for best results.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Targets,

    [string]$Ports = "443,465,563,587,636,853,993,995,989,990,992,1443,2083,2087,2096,3269,3389,5061,5986,8443,8834,9443,10000",

    [string]$OutputPath = ".\CertScanReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [int]$WarnDays = 30,
    [int]$CriticalDays = 7
)

$ErrorActionPreference = 'Stop'

# ============================================================================
#  HTML REPORT GENERATOR
# ============================================================================
function New-CertScanHtml {
    param([Parameter(Mandatory=$true)][object]$Data)

    $certs   = $Data.Certs
    $ciphers = $Data.Ciphers
    $warn    = $Data.WarnDays
    $crit    = $Data.CriticalDays

    # ---- Metrics ----
    $total       = $certs.Count
    $expired     = @($certs | Where-Object { $_.DaysLeft -ne $null -and $_.DaysLeft -lt 0 }).Count
    $critical    = @($certs | Where-Object { $_.DaysLeft -ne $null -and $_.DaysLeft -ge 0 -and $_.DaysLeft -le $crit }).Count
    $warning     = @($certs | Where-Object { $_.DaysLeft -ne $null -and $_.DaysLeft -gt $crit -and $_.DaysLeft -le $warn }).Count
    $healthy     = @($certs | Where-Object { $_.DaysLeft -ne $null -and $_.DaysLeft -gt $warn }).Count
    $weakSystems = @($ciphers | Select-Object -ExpandProperty Host -Unique).Count
    $uniqueHosts = @($certs | Select-Object -ExpandProperty Host -Unique).Count

    # ---- Helpers ----
    function E([string]$s) {
        if ($null -eq $s) { return '' }
        return [System.Web.HttpUtility]::HtmlEncode($s)
    }

    # ---- Expiring rows (expired + critical + warning), sorted by DaysLeft ----
    $expiringRows = ""
    $expiringSet = $certs | Where-Object { $_.DaysLeft -ne $null -and $_.DaysLeft -le $warn } | Sort-Object DaysLeft
    foreach ($c in $expiringSet) {
        if ($c.DaysLeft -lt 0)            { $sev='expired';  $lbl='EXPIRED';  $badge='sev-expired' }
        elseif ($c.DaysLeft -le $crit)    { $sev='critical'; $lbl='CRITICAL'; $badge='sev-critical' }
        else                              { $sev='warning';  $lbl='WARNING';  $badge='sev-warning' }
        $expiringRows += "<tr data-sev='$sev'>" +
            "<td><span class='badge $badge'>$lbl</span></td>" +
            "<td>$(E $c.Hostname)</td>" +
            "<td>$(E $c.Host)</td>" +
            "<td>$($c.Port)</td>" +
            "<td>$(E $c.SubjectCN)</td>" +
            "<td>$(E $c.Expiry)</td>" +
            "<td class='num'>$($c.DaysLeft)</td>" +
            "<td class='sans'>$(E $c.SANs)</td>" +
            "</tr>`n"
    }
    if (-not $expiringRows) { $expiringRows = "<tr><td colspan='8' class='empty'>No certificates expiring within $warn days. </td></tr>" }

    # ---- Weak cipher rows ----
    $cipherRows = ""
    foreach ($w in ($ciphers | Sort-Object Host, Port, Protocol)) {
        $protoBadge = if ($w.WeakProtocol) { "<span class='badge sev-critical'>$(E $w.Protocol)</span>" } else { E $w.Protocol }
        $cipherRows += "<tr>" +
            "<td>$(E $w.Hostname)</td>" +
            "<td>$(E $w.Host)</td>" +
            "<td>$($w.Port)</td>" +
            "<td>$protoBadge</td>" +
            "<td>$(E $w.LeastStrength)</td>" +
            "<td class='sans'>$(E $w.WeakCiphers)</td>" +
            "</tr>`n"
    }
    if (-not $cipherRows) { $cipherRows = "<tr><td colspan='6' class='empty'>No weak protocols or ciphers detected. </td></tr>" }

    # ---- Full inventory rows ----
    $invRows = ""
    foreach ($c in ($certs | Sort-Object Host, Port)) {
        $dl = if ($c.DaysLeft -ne $null) { $c.DaysLeft } else { 'N/A' }
        $rowCls = ''
        if ($c.DaysLeft -ne $null) {
            if ($c.DaysLeft -lt 0)         { $rowCls='row-expired' }
            elseif ($c.DaysLeft -le $crit) { $rowCls='row-critical' }
            elseif ($c.DaysLeft -le $warn) { $rowCls='row-warning' }
        }
        $invRows += "<tr class='$rowCls'>" +
            "<td>$(E $c.Hostname)</td>" +
            "<td>$(E $c.Host)</td>" +
            "<td>$($c.Port)</td>" +
            "<td>$(E $c.Service)</td>" +
            "<td>$(E $c.SubjectCN)</td>" +
            "<td>$(E $c.Issuer)</td>" +
            "<td>$(E $c.Expiry)</td>" +
            "<td class='num'>$dl</td>" +
            "<td class='sans'>$(E $c.SANs)</td>" +
            "</tr>`n"
    }
    if (-not $invRows) { $invRows = "<tr><td colspan='9' class='empty'>No certificates found. </td></tr>" }

    $scanMeta = "Scanned $(E $Data.Targets) on ports $(E $Data.Ports) &middot; $(E $Data.ScanTime)"

    # ---- Assemble HTML ----
@"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width, initial-scale=1.0'>
<title>LAN Certificate Scan Report</title>
<style>
  * { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:'Segoe UI',system-ui,sans-serif; background:#0f1420; color:#e4e8f0; font-size:14px; }
  header { background:linear-gradient(135deg,#1a2440,#0f1420); padding:1.5rem 2rem; border-bottom:1px solid #2a3550; }
  header h1 { font-size:1.4rem; font-weight:600; color:#fff; }
  header .meta { font-size:12px; color:#8792a8; margin-top:4px; }
  .tabs { display:flex; gap:2px; background:#161d2e; padding:0 2rem; border-bottom:1px solid #2a3550; flex-wrap:wrap; }
  .tab { padding:12px 20px; cursor:pointer; color:#8792a8; font-weight:500; border-bottom:2px solid transparent; user-select:none; }
  .tab:hover { color:#c4cde0; }
  .tab.active { color:#5b9dff; border-bottom-color:#5b9dff; }
  .panel { display:none; padding:1.5rem 2rem; }
  .panel.active { display:block; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:1rem; margin-bottom:1.5rem; }
  .card { background:#161d2e; border:1px solid #2a3550; border-radius:10px; padding:1.1rem 1.25rem; }
  .card .num { font-size:2rem; font-weight:700; line-height:1; }
  .card .lbl { font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:#8792a8; margin-top:6px; }
  .card.total .num{color:#5b9dff} .card.expired .num{color:#ff5b6e} .card.critical .num{color:#ff8a3d}
  .card.warning .num{color:#ffd23d} .card.healthy .num{color:#3ddc84} .card.weak .num{color:#c77dff}
  table { width:100%; border-collapse:collapse; background:#161d2e; border-radius:10px; overflow:hidden; }
  th { background:#1c273f; color:#c4cde0; text-align:left; padding:10px 12px; font-size:12px; text-transform:uppercase; letter-spacing:.04em; cursor:pointer; white-space:nowrap; }
  th:hover { background:#233150; }
  td { padding:9px 12px; border-top:1px solid #222c44; vertical-align:top; }
  tr:hover td { background:#1a2136; }
  td.num { text-align:right; font-variant-numeric:tabular-nums; }
  td.sans { font-size:12px; color:#9aa6be; max-width:340px; word-break:break-word; }
  td.empty { text-align:center; color:#6b7690; padding:2rem; }
  .badge { display:inline-block; padding:2px 9px; border-radius:5px; font-size:11px; font-weight:700; letter-spacing:.03em; }
  .sev-expired  { background:#3a0d13; color:#ff8a97; border:1px solid #7a2531; }
  .sev-critical { background:#3a1c0d; color:#ffab6e; border:1px solid #7a4425; }
  .sev-warning  { background:#3a340d; color:#ffe27a; border:1px solid #7a6d25; }
  .row-expired td  { background:#22060a !important; }
  .row-critical td { background:#221206 !important; }
  .row-warning td  { background:#221f06 !important; }
  .toolbar { display:flex; gap:10px; margin-bottom:1rem; flex-wrap:wrap; align-items:center; }
  .toolbar input { background:#0f1420; border:1px solid #2a3550; color:#e4e8f0; padding:8px 12px; border-radius:8px; min-width:260px; font-size:13px; }
  .toolbar .hint { font-size:12px; color:#6b7690; }
  h2.section { font-size:1rem; color:#c4cde0; margin-bottom:.75rem; font-weight:600; }
  .legend { font-size:12px; color:#8792a8; margin-top:1rem; display:flex; gap:1.25rem; flex-wrap:wrap; }
  .legend span::before { content:''; display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:5px; vertical-align:middle; }
  .lg-exp::before{background:#ff5b6e} .lg-crit::before{background:#ff8a3d} .lg-warn::before{background:#ffd23d}
  .footer { padding:1rem 2rem; color:#6b7690; font-size:12px; border-top:1px solid #2a3550; }
</style>
</head>
<body>
<header>
  <h1>LAN Certificate &amp; TLS Configuration Report</h1>
  <div class='meta'>$scanMeta</div>
</header>

<div class='tabs'>
  <div class='tab active' onclick="showTab(event,'dash')">Dashboard</div>
  <div class='tab' onclick="showTab(event,'expiring')">Expiring Certificates</div>
  <div class='tab' onclick="showTab(event,'ciphers')">Weak Ciphers &amp; Protocols</div>
  <div class='tab' onclick="showTab(event,'inventory')">Full Inventory</div>
</div>

<!-- DASHBOARD -->
<div id='dash' class='panel active'>
  <div class='cards'>
    <div class='card total'><div class='num'>$total</div><div class='lbl'>Certificates Found</div></div>
    <div class='card expired'><div class='num'>$expired</div><div class='lbl'>Expired</div></div>
    <div class='card critical'><div class='num'>$critical</div><div class='lbl'>Critical (&le;$crit days)</div></div>
    <div class='card warning'><div class='num'>$warning</div><div class='lbl'>Warning (&le;$warn days)</div></div>
    <div class='card healthy'><div class='num'>$healthy</div><div class='lbl'>Healthy</div></div>
    <div class='card weak'><div class='num'>$weakSystems</div><div class='lbl'>Systems w/ Weak Ciphers</div></div>
  </div>
  <h2 class='section'>Scan Summary</h2>
  <table>
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>Unique hosts with certificates</td><td>$uniqueHosts</td></tr>
    <tr><td>Total certificates discovered</td><td>$total</td></tr>
    <tr><td>Expired certificates</td><td>$expired</td></tr>
    <tr><td>Expiring within $crit days (critical)</td><td>$critical</td></tr>
    <tr><td>Expiring within $warn days (warning)</td><td>$warning</td></tr>
    <tr><td>Systems with weak protocols/ciphers</td><td>$weakSystems</td></tr>
  </table>
  <div class='legend'>
    <span class='lg-exp'>Expired</span>
    <span class='lg-crit'>Critical (&le;$crit days)</span>
    <span class='lg-warn'>Warning (&le;$warn days)</span>
  </div>
</div>

<!-- EXPIRING -->
<div id='expiring' class='panel'>
  <div class='toolbar'>
    <input type='text' id='f-expiring' onkeyup="filterTable('t-expiring','f-expiring')" placeholder='Filter expiring certificates...'>
    <span class='hint'>Click any column header to sort.</span>
  </div>
  <table id='t-expiring'>
    <thead><tr>
      <th onclick="sortTable('t-expiring',0)">Severity</th>
      <th onclick="sortTable('t-expiring',1)">Hostname (access)</th>
      <th onclick="sortTable('t-expiring',2)">IP</th>
      <th onclick="sortTable('t-expiring',3)">Port</th>
      <th onclick="sortTable('t-expiring',4)">Subject CN</th>
      <th onclick="sortTable('t-expiring',5)">Expiry Date</th>
      <th onclick="sortTable('t-expiring',6)">Days Left</th>
      <th onclick="sortTable('t-expiring',7)">SANs</th>
    </tr></thead>
    <tbody>
$expiringRows
    </tbody>
  </table>
</div>

<!-- CIPHERS -->
<div id='ciphers' class='panel'>
  <div class='toolbar'>
    <input type='text' id='f-ciphers' onkeyup="filterTable('t-ciphers','f-ciphers')" placeholder='Filter weak cipher findings...'>
    <span class='hint'>Weak protocols (SSLv2/3, TLS 1.0/1.1) and weak cipher suites (NULL, EXPORT, RC4, DES, 3DES, MD5, anon).</span>
  </div>
  <table id='t-ciphers'>
    <thead><tr>
      <th onclick="sortTable('t-ciphers',0)">Hostname</th>
      <th onclick="sortTable('t-ciphers',1)">IP</th>
      <th onclick="sortTable('t-ciphers',2)">Port</th>
      <th onclick="sortTable('t-ciphers',3)">Protocol</th>
      <th onclick="sortTable('t-ciphers',4)">Least Strength</th>
      <th onclick="sortTable('t-ciphers',5)">Weak Cipher Suites</th>
    </tr></thead>
    <tbody>
$cipherRows
    </tbody>
  </table>
</div>

<!-- INVENTORY -->
<div id='inventory' class='panel'>
  <div class='toolbar'>
    <input type='text' id='f-inv' onkeyup="filterTable('t-inv','f-inv')" placeholder='Filter all certificates...'>
    <span class='hint'>Full discovered inventory. Colour-coded rows indicate expiry status.</span>
  </div>
  <table id='t-inv'>
    <thead><tr>
      <th onclick="sortTable('t-inv',0)">Hostname (access)</th>
      <th onclick="sortTable('t-inv',1)">IP</th>
      <th onclick="sortTable('t-inv',2)">Port</th>
      <th onclick="sortTable('t-inv',3)">Service</th>
      <th onclick="sortTable('t-inv',4)">Subject CN</th>
      <th onclick="sortTable('t-inv',5)">Issuer</th>
      <th onclick="sortTable('t-inv',6)">Expiry</th>
      <th onclick="sortTable('t-inv',7)">Days Left</th>
      <th onclick="sortTable('t-inv',8)">SANs</th>
    </tr></thead>
    <tbody>
$invRows
    </tbody>
  </table>
</div>

<div class='footer'>Generated by Invoke-CertScan.ps1 &middot; nmap ssl-cert + ssl-enum-ciphers &middot; $(E $Data.ScanTime)</div>

<script>
function showTab(e,id){
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  e.target.classList.add('active');
}
function filterTable(tid,fid){
  var q=document.getElementById(fid).value.toLowerCase();
  var rows=document.getElementById(tid).tBodies[0].rows;
  for(var i=0;i<rows.length;i++){
    rows[i].style.display = rows[i].innerText.toLowerCase().indexOf(q)>-1 ? '' : 'none';
  }
}
function sortTable(tid,col){
  var tb=document.getElementById(tid).tBodies[0];
  var rows=Array.prototype.slice.call(tb.rows);
  var dir=tb.getAttribute('data-sort-'+col)==='asc'?'desc':'asc';
  tb.setAttribute('data-sort-'+col,dir);
  rows.sort(function(a,b){
    var x=a.cells[col].innerText.trim(), y=b.cells[col].innerText.trim();
    var nx=parseFloat(x), ny=parseFloat(y);
    if(!isNaN(nx)&&!isNaN(ny)){ return dir==='asc'?nx-ny:ny-nx; }
    return dir==='asc'? x.localeCompare(y): y.localeCompare(x);
  });
  rows.forEach(function(r){ tb.appendChild(r); });
}
</script>
</body>
</html>
"@
}

# ============================================================================
#  MAIN
# ============================================================================
Add-Type -AssemblyName System.Web

$nmap = Get-Command nmap -ErrorAction SilentlyContinue
if (-not $nmap) { Write-Error "nmap not found in PATH. Install from https://nmap.org/download.html"; exit 1 }

$xmlOut = [System.IO.Path]::GetTempFileName() + ".xml"
Write-Host "[*] Scanning $Targets on ports $Ports ..." -ForegroundColor Cyan
Write-Host "[*] Large ranges can take a while." -ForegroundColor DarkGray

$nmapArgs = @("-Pn","-p",$Ports,"--script","ssl-cert,ssl-enum-ciphers","-oX",$xmlOut,"--open") + ($Targets -split '\s+')
& nmap @nmapArgs | Out-Null
if (-not (Test-Path $xmlOut)) { Write-Error "nmap produced no output. Check target syntax."; exit 1 }

[xml]$scan = Get-Content $xmlOut -Raw

$certRecords   = New-Object System.Collections.Generic.List[object]
$cipherRecords = New-Object System.Collections.Generic.List[object]
$weakProtocols = @('SSLv2','SSLv3','TLSv1.0','TLSv1.1')
$weakCipherPatterns = @('NULL','EXPORT','_RC4_','RC4','_DES_','DES-','3DES','MD5','anon')

foreach ($node in $scan.nmaprun.host) {
    $addr = ($node.address | Where-Object { $_.addrtype -eq 'ipv4' } | Select-Object -First 1).addr
    if (-not $addr) { $addr = ($node.address | Select-Object -First 1).addr }
    $hn = ($node.hostnames.hostname | Select-Object -First 1).name
    if (-not $hn) { $hn = $addr }

    foreach ($port in $node.ports.port) {
        $portId = $port.portid
        $svc = $port.service.name
        foreach ($script in $port.script) {

            if ($script.id -eq 'ssl-cert') {
                $subjectCN=$null; $sans=@(); $notAfter=$null; $notBefore=$null; $issuer=$null
                foreach ($t in $script.table) {
                    switch ($t.key) {
                        'subject'  { $cn=($t.elem | Where-Object {$_.key -eq 'commonName'}).'#text'; if($cn){$subjectCN=$cn} }
                        'issuer'   { $io=($t.elem | Where-Object {$_.key -eq 'commonName'}).'#text'; if($io){$issuer=$io} }
                        'validity' {
                            $notBefore=($t.elem | Where-Object {$_.key -eq 'notBefore'}).'#text'
                            $notAfter =($t.elem | Where-Object {$_.key -eq 'notAfter'}).'#text'
                        }
                        'extensions' {
                            foreach ($ext in $t.table) {
                                $en=($ext.elem | Where-Object {$_.key -eq 'name'}).'#text'
                                if ($en -eq 'X509v3 Subject Alternative Name') {
                                    $val=($ext.elem | Where-Object {$_.key -eq 'value'}).'#text'
                                    if ($val) { $sans=($val -split ',') | ForEach-Object { ($_ -replace 'DNS:','').Trim() } }
                                }
                            }
                        }
                    }
                }
                if (-not $notAfter) { $na=($script.elem | Where-Object {$_.key -eq 'notAfter'}).'#text'; if($na){$notAfter=$na} }

                $expiryDate=$null; $daysLeft=$null
                if ($notAfter) {
                    try { $expiryDate=[datetime]::Parse($notAfter) } catch {}
                    if ($expiryDate) { $daysLeft=[math]::Floor(($expiryDate-(Get-Date)).TotalDays) }
                }
                $certRecords.Add([pscustomobject]@{
                    Host=$addr; Hostname=$hn; Port=[int]$portId; Service=$svc
                    SubjectCN=$subjectCN; SANs=($sans -join ', '); Issuer=$issuer
                    NotBefore=$notBefore
                    Expiry= if($expiryDate){$expiryDate.ToString('yyyy-MM-dd')}else{'Unknown'}
                    DaysLeft=$daysLeft
                })
            }

            if ($script.id -eq 'ssl-enum-ciphers') {
                foreach ($proto in $script.table) {
                    $protoName=$proto.key
                    $least=($proto.elem | Where-Object {$_.key -eq 'least strength'}).'#text'
                    $weak=New-Object System.Collections.Generic.List[string]
                    foreach ($sub in $proto.table) {
                        if ($sub.key -eq 'ciphers') {
                            foreach ($ct in $sub.table) {
                                $cn=($ct.elem | Where-Object {$_.key -eq 'name'}).'#text'
                                if ($cn) {
                                    foreach ($p in $weakCipherPatterns) { if ($cn -match $p) { $weak.Add($cn); break } }
                                }
                            }
                        }
                    }
                    $protoWeak = $weakProtocols -contains $protoName
                    if ($protoWeak -or $weak.Count -gt 0 -or $least -in @('D','E','F')) {
                        $cipherRecords.Add([pscustomobject]@{
                            Host=$addr; Hostname=$hn; Port=[int]$portId; Protocol=$protoName
                            WeakProtocol=$protoWeak; LeastStrength=$least
                            WeakCiphers=(($weak | Select-Object -Unique) -join ', ')
                        })
                    }
                }
            }
        }
    }
}

Write-Host "[*] Parsed $($certRecords.Count) certificates, $($cipherRecords.Count) weak findings." -ForegroundColor Green

$reportData=[pscustomobject]@{
    Certs=$certRecords; Ciphers=$cipherRecords
    WarnDays=$WarnDays; CriticalDays=$CriticalDays
    ScanTime=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Targets=$Targets; Ports=$Ports
}
$html = New-CertScanHtml -Data $reportData
$html | Out-File -FilePath $OutputPath -Encoding UTF8
Remove-Item $xmlOut -ErrorAction SilentlyContinue
Write-Host "[*] Report written to $OutputPath" -ForegroundColor Cyan
