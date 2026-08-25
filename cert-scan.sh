#!/usr/bin/env bash
#
# cert-scan.sh - Scan a LAN with nmap for SSL/TLS certificates and cipher config,
#                then generate a tabbed HTML report (dashboard, expiring, weak ciphers,
#                full inventory).
#
# Requires: nmap, python3 (for parsing/report generation)
#
# Usage:
#   ./cert-scan.sh -t 10.0.0.0/24
#   ./cert-scan.sh -t "10.0.0.0/24 10.0.1.0/24" -w 60 -c 14 -o /tmp/report.html
#
set -euo pipefail

TARGETS=""
PORTS="443,465,563,587,636,853,993,995,989,990,992,1443,2083,2087,2096,3269,3389,5061,5986,8443,8834,9443,10000"
OUTPUT="./CertScanReport_$(date +%Y%m%d_%H%M%S).html"
WARN_DAYS=30
CRIT_DAYS=7

usage() { echo "Usage: $0 -t <targets> [-p ports] [-o output.html] [-w warn_days] [-c crit_days]"; exit 1; }

while getopts "t:p:o:w:c:h" opt; do
  case $opt in
    t) TARGETS="$OPTARG" ;;
    p) PORTS="$OPTARG" ;;
    o) OUTPUT="$OPTARG" ;;
    w) WARN_DAYS="$OPTARG" ;;
    c) CRIT_DAYS="$OPTARG" ;;
    h|*) usage ;;
  esac
done

[ -z "$TARGETS" ] && usage
command -v nmap >/dev/null 2>&1 || { echo "ERROR: nmap not found. Install it first."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found."; exit 1; }

XMLOUT="$(mktemp).xml"
echo "[*] Scanning $TARGETS on ports $PORTS ..."
echo "[*] Large ranges can take a while."

# shellcheck disable=SC2086
nmap -Pn -p "$PORTS" --script ssl-cert,ssl-enum-ciphers --open -oX "$XMLOUT" $TARGETS >/dev/null

echo "[*] Parsing results and generating report ..."

WARN_DAYS="$WARN_DAYS" CRIT_DAYS="$CRIT_DAYS" TARGETS="$TARGETS" PORTS="$PORTS" \
OUTPUT="$OUTPUT" XMLOUT="$XMLOUT" python3 - << 'PYEOF'
import os, sys, html, datetime
import xml.etree.ElementTree as ET

xmlout   = os.environ["XMLOUT"]
warn     = int(os.environ["WARN_DAYS"])
crit     = int(os.environ["CRIT_DAYS"])
targets  = os.environ["TARGETS"]
ports    = os.environ["PORTS"]
output   = os.environ["OUTPUT"]
now      = datetime.datetime.now()
scantime = now.strftime('%Y-%m-%d %H:%M:%S')

def E(s): return html.escape(str(s)) if s is not None else ''

weak_protocols = {'SSLv2','SSLv3','TLSv1.0','TLSv1.1'}
weak_patterns  = ['NULL','EXPORT','RC4','_DES_','DES-','3DES','MD5','anon']

tree = ET.parse(xmlout); root = tree.getroot()
certs, ciphers = [], []

for host in root.findall('host'):
    addr = None
    for a in host.findall('address'):
        if a.get('addrtype')=='ipv4': addr=a.get('addr'); break
    if not addr:
        a=host.find('address'); addr=a.get('addr') if a is not None else '?'
    hn=addr
    hnames=host.find('hostnames')
    if hnames is not None:
        h0=hnames.find('hostname')
        if h0 is not None and h0.get('name'): hn=h0.get('name')

    ports_el=host.find('ports')
    if ports_el is None: continue
    for port in ports_el.findall('port'):
        pid=port.get('portid'); svc=''
        s=port.find('service')
        if s is not None: svc=s.get('name','')
        for script in port.findall('script'):
            sid=script.get('id')

            if sid=='ssl-cert':
                subjectCN=issuer=notAfter=notBefore=None; sans=[]
                for t in script.findall('table'):
                    key=t.get('key')
                    if key=='subject':
                        for e in t.findall('elem'):
                            if e.get('key')=='commonName': subjectCN=e.text
                    elif key=='issuer':
                        for e in t.findall('elem'):
                            if e.get('key')=='commonName': issuer=e.text
                    elif key=='validity':
                        for e in t.findall('elem'):
                            if e.get('key')=='notBefore': notBefore=e.text
                            if e.get('key')=='notAfter':  notAfter=e.text
                    elif key=='extensions':
                        for ext in t.findall('table'):
                            name=val=None
                            for e in ext.findall('elem'):
                                if e.get('key')=='name': name=e.text
                                if e.get('key')=='value': val=e.text
                            if name=='X509v3 Subject Alternative Name' and val:
                                sans=[x.replace('DNS:','').strip() for x in val.split(',')]
                if not notAfter:
                    for e in script.findall('elem'):
                        if e.get('key')=='notAfter': notAfter=e.text
                expiry='Unknown'; days=None
                if notAfter:
                    for fmt in ('%Y-%m-%dT%H:%M:%S','%Y-%m-%dT%H:%M:%S+00:00'):
                        try:
                            d=datetime.datetime.strptime(notAfter[:19],'%Y-%m-%dT%H:%M:%S')
                            expiry=d.strftime('%Y-%m-%d'); days=(d-now).days; break
                        except Exception: pass
                certs.append(dict(Host=addr,Hostname=hn,Port=int(pid),Service=svc,
                    SubjectCN=subjectCN,SANs=', '.join(sans),Issuer=issuer,
                    Expiry=expiry,DaysLeft=days))

            if sid=='ssl-enum-ciphers':
                for proto in script.findall('table'):
                    pname=proto.get('key'); least=None; weak=[]
                    for e in proto.findall('elem'):
                        if e.get('key')=='least strength': least=e.text
                    for sub in proto.findall('table'):
                        if sub.get('key')=='ciphers':
                            for ct in sub.findall('table'):
                                cname=None
                                for e in ct.findall('elem'):
                                    if e.get('key')=='name': cname=e.text
                                if cname:
                                    for p in weak_patterns:
                                        if p in cname: weak.append(cname); break
                    pweak = pname in weak_protocols
                    if pweak or weak or least in ('D','E','F'):
                        ciphers.append(dict(Host=addr,Hostname=hn,Port=int(pid),Protocol=pname,
                            WeakProtocol=pweak,LeastStrength=least or '',
                            WeakCiphers=', '.join(sorted(set(weak)))))

# ---- Metrics ----
def dl(c): return c["DaysLeft"]
total=len(certs)
expired=len([c for c in certs if dl(c) is not None and dl(c)<0])
critical=len([c for c in certs if dl(c) is not None and 0<=dl(c)<=crit])
warning=len([c for c in certs if dl(c) is not None and crit<dl(c)<=warn])
healthy=len([c for c in certs if dl(c) is not None and dl(c)>warn])
weakSystems=len(set(w["Host"] for w in ciphers))
uniqueHosts=len(set(c["Host"] for c in certs))

# ---- Rows ----
expRows=""
for c in sorted([c for c in certs if dl(c) is not None and dl(c)<=warn], key=lambda x:x["DaysLeft"]):
    if c["DaysLeft"]<0: sev,lbl,b='expired','EXPIRED','sev-expired'
    elif c["DaysLeft"]<=crit: sev,lbl,b='critical','CRITICAL','sev-critical'
    else: sev,lbl,b='warning','WARNING','sev-warning'
    expRows+=f"<tr data-sev='{sev}'><td><span class='badge {b}'>{lbl}</span></td><td>{E(c['Hostname'])}</td><td>{E(c['Host'])}</td><td>{c['Port']}</td><td>{E(c['SubjectCN'])}</td><td>{E(c['Expiry'])}</td><td class='num'>{c['DaysLeft']}</td><td class='sans'>{E(c['SANs'])}</td></tr>\n"
if not expRows: expRows=f"<tr><td colspan='8' class='empty'>No certificates expiring within {warn} days.</td></tr>"

cipRows=""
for w in sorted(ciphers, key=lambda x:(x["Host"],x["Port"],x["Protocol"])):
    pb=f"<span class='badge sev-critical'>{E(w['Protocol'])}</span>" if w["WeakProtocol"] else E(w["Protocol"])
    cipRows+=f"<tr><td>{E(w['Hostname'])}</td><td>{E(w['Host'])}</td><td>{w['Port']}</td><td>{pb}</td><td>{E(w['LeastStrength'])}</td><td class='sans'>{E(w['WeakCiphers'])}</td></tr>\n"
if not cipRows: cipRows="<tr><td colspan='6' class='empty'>No weak protocols or ciphers detected.</td></tr>"

invRows=""
for c in sorted(certs, key=lambda x:(x["Host"],x["Port"])):
    rc=''
    if c["DaysLeft"] is not None:
        if c["DaysLeft"]<0: rc='row-expired'
        elif c["DaysLeft"]<=crit: rc='row-critical'
        elif c["DaysLeft"]<=warn: rc='row-warning'
    dld = c["DaysLeft"] if c["DaysLeft"] is not None else 'N/A'
    invRows+=f"<tr class='{rc}'><td>{E(c['Hostname'])}</td><td>{E(c['Host'])}</td><td>{c['Port']}</td><td>{E(c['Service'])}</td><td>{E(c['SubjectCN'])}</td><td>{E(c['Issuer'])}</td><td>{E(c['Expiry'])}</td><td class='num'>{dld}</td><td class='sans'>{E(c['SANs'])}</td></tr>\n"
if not invRows: invRows="<tr><td colspan='9' class='empty'>No certificates found.</td></tr>"

meta=f"Scanned {E(targets)} on ports {E(ports)} &middot; {E(scantime)}"

TEMPLATE=r'''<!DOCTYPE html>
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
  <div class='meta'>@@META@@</div>
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
    <div class='card total'><div class='num'>@@TOTAL@@</div><div class='lbl'>Certificates Found</div></div>
    <div class='card expired'><div class='num'>@@EXPIRED@@</div><div class='lbl'>Expired</div></div>
    <div class='card critical'><div class='num'>@@CRITICAL@@</div><div class='lbl'>Critical (&le;@@CRITDAYS@@ days)</div></div>
    <div class='card warning'><div class='num'>@@WARNING@@</div><div class='lbl'>Warning (&le;@@WARNDAYS@@ days)</div></div>
    <div class='card healthy'><div class='num'>@@HEALTHY@@</div><div class='lbl'>Healthy</div></div>
    <div class='card weak'><div class='num'>@@WEAK@@</div><div class='lbl'>Systems w/ Weak Ciphers</div></div>
  </div>
  <h2 class='section'>Scan Summary</h2>
  <table>
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>Unique hosts with certificates</td><td>@@UNIQUE@@</td></tr>
    <tr><td>Total certificates discovered</td><td>@@TOTAL@@</td></tr>
    <tr><td>Expired certificates</td><td>@@EXPIRED@@</td></tr>
    <tr><td>Expiring within @@CRITDAYS@@ days (critical)</td><td>@@CRITICAL@@</td></tr>
    <tr><td>Expiring within @@WARNDAYS@@ days (warning)</td><td>@@WARNING@@</td></tr>
    <tr><td>Systems with weak protocols/ciphers</td><td>@@WEAK@@</td></tr>
  </table>
  <div class='legend'>
    <span class='lg-exp'>Expired</span>
    <span class='lg-crit'>Critical (&le;@@CRITDAYS@@ days)</span>
    <span class='lg-warn'>Warning (&le;@@WARNDAYS@@ days)</span>
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
@@EXPROWS@@
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
@@CIPROWS@@
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
@@INVROWS@@
    </tbody>
  </table>
</div>

<div class='footer'>Generated by Invoke-CertScan.ps1 &middot; nmap ssl-cert + ssl-enum-ciphers &middot; @@SCANTIME@@</div>

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
</html>'''
out=(TEMPLATE.replace('@@META@@',meta).replace('@@TOTAL@@',str(total)).replace('@@EXPIRED@@',str(expired))
    .replace('@@CRITICAL@@',str(critical)).replace('@@WARNING@@',str(warning)).replace('@@HEALTHY@@',str(healthy))
    .replace('@@WEAK@@',str(weakSystems)).replace('@@UNIQUE@@',str(uniqueHosts)).replace('@@CRITDAYS@@',str(crit))
    .replace('@@WARNDAYS@@',str(warn)).replace('@@EXPROWS@@',expRows).replace('@@CIPROWS@@',cipRows)
    .replace('@@INVROWS@@',invRows).replace('@@SCANTIME@@',E(scantime)))
open(output,'w').write(out)
print(f"[*] Parsed {len(certs)} certificates, {len(ciphers)} weak findings.")
print(f"[*] Report written to {output}")
PYEOF

rm -f "$XMLOUT"
