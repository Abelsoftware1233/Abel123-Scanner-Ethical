#!/usr/bin/env python3
"""
ABEL123 :: DEEP SCAN
Webapp/website kwetsbaarheidsscanner voor eigen systemen.
Flask backend - scope-restricted, non-destructief, detectie-only.

WAARSCHUWING: Scan alleen domeinen/IP's die je zelf bezit of expliciete
schriftelijke toestemming voor hebt om te testen. Ongeautoriseerd scannen
van systemen van derden kan strafbaar zijn (art. 138ab Sr - computervredebreuk).
"""

import json
import re
import socket
import ssl
import time
import uuid
import threading
import ipaddress
import urllib.parse
from datetime import datetime, timezone

import requests
import urllib3
from flask import Flask, request, jsonify, send_from_directory

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__, static_folder=".", static_url_path="")

# ============================================================
# IN-MEMORY STATE (per sessie, geen persistente opslag nodig)
# ============================================================
SCANS = {}          # scan_id -> scan state dict
SCANS_LOCK = threading.Lock()

LOG_FILE = "scope_audit.log"

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 3000, 3306, 3389, 5000, 5432, 5900, 5985,
    6379, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200,
    9300, 11211, 27017, 27018,
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "advies": "Voeg HSTS toe om downgrade-aanvallen naar HTTP te voorkomen.",
    },
    "Content-Security-Policy": {
        "severity": "high",
        "advies": "Definieer een CSP om XSS en data-injectie te beperken.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "advies": "Voeg X-Frame-Options (DENY/SAMEORIGIN) toe tegen clickjacking.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "advies": "Voeg 'nosniff' toe om MIME-sniffing aanvallen te voorkomen.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "advies": "Stel een Referrer-Policy in om info-lekkage te beperken.",
    },
    "Permissions-Policy": {
        "severity": "low",
        "advies": "Beperk browserfuncties (camera, microfoon, geolocatie) expliciet.",
    },
}

XSS_PAYLOADS = [
    "<script>alert('DEEPSCAN_XSS_1')</script>",
    "\"'><img src=x onerror=alert('DEEPSCAN_XSS_2')>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1' AND SLEEP(0)-- -",
    "\" OR \"1\"=\"1",
    "1;--",
]

SQL_ERROR_PATTERNS = [
    r"sql syntax.*mysql", r"warning.*mysqli", r"unclosed quotation mark",
    r"quoted string not properly terminated", r"microsoft ole db provider for sql server",
    r"postgresql.*error", r"pg_query\(\)", r"sqlite3\.OperationalError",
    r"ORA-\d{5}", r"SQLSTATE\[",
]


def log_scope_event(event: str):
    ts = datetime.now(timezone.utc).isoformat()
    with open(LOG_FILE, "a") as f:
        f.write(f"[{ts}] {event}\n")


def is_private_or_reserved(host: str) -> bool:
    """Check of host een private/reserved IP is (voor scope-veiligheid info, niet blokkerend)."""
    try:
        ip = socket.gethostbyname(host)
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved
    except Exception:
        return False


def normalize_target(raw: str):
    raw = raw.strip()
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    return parsed


def push_finding(scan_id, module, severity, title, detail, evidence=None):
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
        if not scan:
            return
        finding = {
            "id": str(uuid.uuid4())[:8],
            "module": module,
            "severity": severity,
            "title": title,
            "detail": detail,
            "evidence": evidence or "",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        scan["findings"].append(finding)


def push_log(scan_id, message):
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
        if not scan:
            return
        scan["log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": message,
        })


def set_progress(scan_id, module, pct, status="running"):
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
        if not scan:
            return
        scan["current_module"] = module
        scan["progress"] = pct
        scan["status"] = status


# ============================================================
# MODULE 1: PASSIEF - Headers, SSL, Cookies, Tech Detectie
# ============================================================
def scan_passive(scan_id, base_url, host):
    push_log(scan_id, f"Passieve module gestart tegen {base_url}")
    try:
        resp = requests.get(base_url, timeout=10, verify=True, allow_redirects=True)
    except requests.exceptions.SSLError:
        push_finding(scan_id, "passief", "medium", "SSL-certificaat probleem",
                     "Kon geen geldige TLS-verbinding maken (certificaatfout).")
        try:
            resp = requests.get(base_url, timeout=10, verify=False, allow_redirects=True)
        except Exception as e:
            push_log(scan_id, f"Passieve module kon geen verbinding maken: {e}")
            return None
    except Exception as e:
        push_log(scan_id, f"Passieve module kon geen verbinding maken: {e}")
        push_finding(scan_id, "passief", "info", "Kon niet verbinden", str(e))
        return None

    headers = resp.headers

    # --- Security headers check ---
    for hname, meta in SECURITY_HEADERS.items():
        if hname not in headers:
            push_finding(
                scan_id, "passief", meta["severity"],
                f"Ontbrekende header: {hname}",
                meta["advies"],
            )
    push_log(scan_id, "Security headers gecontroleerd")

    # --- Server / tech detectie ---
    server = headers.get("Server", "")
    powered_by = headers.get("X-Powered-By", "")
    tech_hits = []
    if server:
        tech_hits.append(f"Server: {server}")
    if powered_by:
        tech_hits.append(f"X-Powered-By: {powered_by}")

    body_sample = resp.text[:20000] if resp.text else ""
    tech_signatures = {
        "WordPress": r"wp-content|wp-includes",
        "Joomla": r"/media/jui/|Joomla!",
        "Drupal": r"Drupal.settings|sites/default/files",
        "Laravel": r"laravel_session",
        "Django": r"csrftoken",
        "React": r"__REACT_DEVTOOLS|react-root|data-reactroot",
        "jQuery": r"jquery(?:-|\.)[0-9.]*\.js",
        "Nginx": r"nginx",
        "Apache": r"Apache",
        "PHP": r"\.php|PHPSESSID",
    }
    for tech, pattern in tech_signatures.items():
        if re.search(pattern, body_sample, re.IGNORECASE) or re.search(pattern, str(headers), re.IGNORECASE):
            tech_hits.append(tech)

    if tech_hits:
        push_finding(scan_id, "passief", "info", "Technologie-stack gedetecteerd",
                     ", ".join(sorted(set(tech_hits))))
    push_log(scan_id, f"Tech-detectie voltooid: {len(tech_hits)} signalen")

    if server:
        push_finding(scan_id, "passief", "low", "Server-header onthult software",
                     f"Server header lekt implementatiedetails: '{server}'. Overweeg dit te verbergen.")
    if powered_by:
        push_finding(scan_id, "passief", "low", "X-Powered-By header onthult techstack",
                     f"'{powered_by}' geeft aanvallers info voor gerichte exploits.")

    # --- Cookies ---
    set_cookie_headers = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw.headers, "get_all") else []
    if not set_cookie_headers:
        sc = headers.get("Set-Cookie")
        set_cookie_headers = [sc] if sc else []

    for cookie_str in set_cookie_headers:
        name = cookie_str.split("=")[0].strip()
        flags_missing = []
        if "secure" not in cookie_str.lower():
            flags_missing.append("Secure")
        if "httponly" not in cookie_str.lower():
            flags_missing.append("HttpOnly")
        if "samesite" not in cookie_str.lower():
            flags_missing.append("SameSite")
        if flags_missing:
            push_finding(scan_id, "passief", "medium",
                         f"Cookie '{name}' mist beveiligingsvlaggen",
                         f"Ontbrekende vlaggen: {', '.join(flags_missing)}.")
    push_log(scan_id, f"Cookie-analyse voltooid: {len(set_cookie_headers)} cookies gezien")

    # --- SSL/TLS diepte-check ---
    if base_url.startswith("https://"):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    not_after = cert.get("notAfter")
                    if not_after:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
                        if days_left < 14:
                            push_finding(scan_id, "passief", "high",
                                        "SSL-certificaat verloopt binnenkort",
                                        f"Nog {days_left} dagen geldig (tot {not_after}).")
                        elif days_left < 30:
                            push_finding(scan_id, "passief", "medium",
                                        "SSL-certificaat verloopt binnen 30 dagen",
                                        f"Nog {days_left} dagen geldig (tot {not_after}).")
                    push_finding(scan_id, "passief", "info", "TLS-versie gedetecteerd",
                                f"Verbinding gebruikt {tls_version}.")
                    if tls_version in ("TLSv1", "TLSv1.1"):
                        push_finding(scan_id, "passief", "high",
                                    "Verouderd TLS-protocol",
                                    f"{tls_version} is verouderd en onveilig, upgrade naar TLS 1.2+.")
        except Exception as e:
            push_log(scan_id, f"TLS deep-check faalde: {e}")
        push_log(scan_id, "SSL/TLS analyse voltooid")

    return resp


# ============================================================
# MODULE 2: ACTIEF NETWERK - Poortscan + banner grab
# ============================================================
def scan_ports(scan_id, host):
    push_log(scan_id, f"Poortscan gestart tegen {host} ({len(TOP_PORTS)} poorten)")
    open_ports = []
    total = len(TOP_PORTS)
    for i, port in enumerate(TOP_PORTS):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.6)
                result = s.connect_ex((host, port))
                if result == 0:
                    banner = ""
                    try:
                        s.settimeout(0.5)
                        if port in (80, 8080, 8000, 8888):
                            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = s.recv(128).decode(errors="ignore").strip()
                    except Exception:
                        pass
                    open_ports.append({"port": port, "banner": banner})
                    push_finding(scan_id, "netwerk", "info" if port in (80, 443) else "medium",
                                f"Open poort: {port}",
                                f"Poort {port} staat open." + (f" Banner: {banner[:80]}" if banner else ""))
        except Exception:
            pass
        if i % 5 == 0:
            set_progress(scan_id, "netwerk", int((i / total) * 100))
    push_log(scan_id, f"Poortscan voltooid: {len(open_ports)} open poorten gevonden")
    return open_ports


# ============================================================
# MODULE 3: CVE LOOKUP (via CIRCL/NVD publieke API, best-effort)
# ============================================================
def scan_cve_lookup(scan_id, tech_hits_text):
    push_log(scan_id, "CVE-lookup gestart voor gedetecteerde technologieën")
    candidates = re.findall(r"([A-Za-z][A-Za-z0-9._-]{2,20})[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", tech_hits_text or "")
    if not candidates:
        push_log(scan_id, "Geen versienummers gevonden om te matchen tegen CVE-databases")
        return
    seen = set()
    for product, version in candidates[:5]:
        key = f"{product}:{version}"
        if key in seen:
            continue
        seen.add(key)
        try:
            url = f"https://cve.circl.lu/api/search/{urllib.parse.quote(product)}"
            r = requests.get(url, timeout=8)
            if r.status_code == 200:
                data = r.json()
                results = data.get("data", data if isinstance(data, list) else [])
                match_count = len(results) if isinstance(results, list) else 0
                if match_count:
                    push_finding(scan_id, "cve", "high",
                                f"Mogelijke CVE's voor {product} {version}",
                                f"{match_count} gerelateerde CVE-vermeldingen gevonden voor '{product}'. Handmatig verifiëren tegen exacte versie {version}.")
        except Exception as e:
            push_log(scan_id, f"CVE-lookup voor {product} faalde: {e}")
    push_log(scan_id, "CVE-lookup module voltooid")


# ============================================================
# MODULE 4: LICHTE KWETSBAARHEIDSCHECKS (XSS/SQLi, non-destructief)
# ============================================================
def find_forms(html, base_url):
    forms = []
    for match in re.finditer(r"<form[^>]*>(.*?)</form>", html, re.IGNORECASE | re.DOTALL):
        form_html = match.group(0)
        action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        action = action_match.group(1) if action_match else ""
        method = (method_match.group(1) if method_match else "get").lower()
        target_url = urllib.parse.urljoin(base_url, action) if action else base_url
        inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        if inputs:
            forms.append({"url": target_url, "method": method, "inputs": inputs})
    return forms


def scan_light_vuln(scan_id, base_url, html):
    push_log(scan_id, "Lichte kwetsbaarheidschecks gestart (non-destructief, detectie-only)")
    forms = find_forms(html, base_url)

    # Ook query params in de URL zelf testen indien aanwezig
    parsed = urllib.parse.urlparse(base_url)
    qs_params = list(urllib.parse.parse_qs(parsed.query).keys())

    if not forms and not qs_params:
        push_log(scan_id, "Geen forms of query-parameters gevonden om te testen")
        return

    tested = 0
    for form in forms[:5]:
        for payload in XSS_PAYLOADS[:1]:
            data = {name: payload for name in form["inputs"]}
            try:
                if form["method"] == "post":
                    r = requests.post(form["url"], data=data, timeout=8, verify=False)
                else:
                    r = requests.get(form["url"], params=data, timeout=8, verify=False)
                if payload in r.text:
                    push_finding(scan_id, "vuln", "critical",
                                "Mogelijke reflected XSS",
                                f"Payload werd ongefilterd gereflecteerd in response van form op {form['url']} (velden: {', '.join(form['inputs'])}).",
                                evidence=payload)
            except Exception:
                pass
            tested += 1

        for payload in SQLI_PAYLOADS[:2]:
            data = {name: payload for name in form["inputs"]}
            try:
                if form["method"] == "post":
                    r = requests.post(form["url"], data=data, timeout=8, verify=False)
                else:
                    r = requests.get(form["url"], params=data, timeout=8, verify=False)
                for pattern in SQL_ERROR_PATTERNS:
                    if re.search(pattern, r.text, re.IGNORECASE):
                        push_finding(scan_id, "vuln", "critical",
                                    "Mogelijke SQL-injectie kwetsbaarheid",
                                    f"SQL-foutmelding zichtbaar na testpayload op form {form['url']} (velden: {', '.join(form['inputs'])}). Patroon: {pattern}",
                                    evidence=payload)
                        break
            except Exception:
                pass
            tested += 1

    if qs_params:
        for param in qs_params[:5]:
            for payload in XSS_PAYLOADS[:1]:
                test_params = dict(urllib.parse.parse_qsl(parsed.query))
                test_params[param] = payload
                test_url = parsed._replace(query=urllib.parse.urlencode(test_params)).geturl()
                try:
                    r = requests.get(test_url, timeout=8, verify=False)
                    if payload in r.text:
                        push_finding(scan_id, "vuln", "critical",
                                    "Mogelijke reflected XSS in URL-parameter",
                                    f"Parameter '{param}' reflecteert payload ongefilterd.",
                                    evidence=payload)
                except Exception:
                    pass
                tested += 1

    push_log(scan_id, f"Lichte kwetsbaarheidschecks voltooid: {len(forms)} forms, {len(qs_params)} params getest ({tested} payloads)")


# ============================================================
# ORCHESTRATOR
# ============================================================
def run_full_scan(scan_id, target_raw, modules):
    try:
        parsed = normalize_target(target_raw)
        host = parsed.hostname
        base_url = parsed.geturl()

        with SCANS_LOCK:
            SCANS[scan_id]["host"] = host
            SCANS[scan_id]["target_url"] = base_url

        log_scope_event(f"SCAN GESTART scan_id={scan_id} target={base_url} modules={modules}")
        push_log(scan_id, f"Scope bevestigd voor {base_url} — start scan")

        resp = None
        if "passief" in modules:
            set_progress(scan_id, "passief", 5)
            resp = scan_passive(scan_id, base_url, host)
            set_progress(scan_id, "passief", 100)

        tech_text = ""
        with SCANS_LOCK:
            for f in SCANS[scan_id]["findings"]:
                if f["title"] == "Technologie-stack gedetecteerd":
                    tech_text = f["detail"]

        if "netwerk" in modules:
            set_progress(scan_id, "netwerk", 0)
            scan_ports(scan_id, host)
            set_progress(scan_id, "netwerk", 100)

        if "cve" in modules:
            set_progress(scan_id, "cve", 10)
            scan_cve_lookup(scan_id, tech_text)
            set_progress(scan_id, "cve", 100)

        if "vuln" in modules and resp is not None:
            set_progress(scan_id, "vuln", 10)
            scan_light_vuln(scan_id, base_url, resp.text or "")
            set_progress(scan_id, "vuln", 100)

        with SCANS_LOCK:
            findings = SCANS[scan_id]["findings"]
            summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in findings:
                summary[f["severity"]] = summary.get(f["severity"], 0) + 1
            SCANS[scan_id]["summary"] = summary
            SCANS[scan_id]["status"] = "voltooid"
            SCANS[scan_id]["progress"] = 100
            SCANS[scan_id]["finished_at"] = datetime.now(timezone.utc).isoformat()

        push_log(scan_id, "Scan volledig voltooid")
        log_scope_event(f"SCAN VOLTOOID scan_id={scan_id} findings={len(findings)}")

    except Exception as e:
        push_log(scan_id, f"FOUT: {e}")
        with SCANS_LOCK:
            SCANS[scan_id]["status"] = "fout"
        log_scope_event(f"SCAN FOUT scan_id={scan_id} error={e}")


# ============================================================
# ROUTES
# ============================================================
@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    data = request.get_json(force=True)
    target = (data.get("target") or "").strip()
    confirmed = data.get("scope_confirmed", False)
    modules = data.get("modules", ["passief"])

    if not target:
        return jsonify({"error": "Geen doel opgegeven"}), 400
    if not confirmed:
        return jsonify({"error": "Scope-bevestiging vereist: je moet bevestigen dat dit jouw eigen systeem is."}), 403

    scan_id = str(uuid.uuid4())[:12]
    with SCANS_LOCK:
        SCANS[scan_id] = {
            "id": scan_id,
            "target_raw": target,
            "host": None,
            "target_url": None,
            "status": "gestart",
            "progress": 0,
            "current_module": "init",
            "modules": modules,
            "findings": [],
            "log": [],
            "summary": {},
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
        }

    log_scope_event(f"SCOPE BEVESTIGD door gebruiker voor target={target} scan_id={scan_id}")

    thread = threading.Thread(target=run_full_scan, args=(scan_id, target, modules), daemon=True)
    thread.start()

    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/<scan_id>/status")
def scan_status(scan_id):
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
        if not scan:
            return jsonify({"error": "Scan niet gevonden"}), 404
        return jsonify(scan)


@app.route("/api/scan/<scan_id>/report")
def scan_report(scan_id):
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
        if not scan:
            return jsonify({"error": "Scan niet gevonden"}), 404
        return jsonify(scan)


if __name__ == "__main__":
    print("=" * 60)
    print(" ABEL123 :: DEEP SCAN — Webapp Kwetsbaarheidsscanner")
    print(" WAARSCHUWING: gebruik alleen tegen eigen systemen!")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
