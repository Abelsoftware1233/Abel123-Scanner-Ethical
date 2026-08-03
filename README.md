# ABEL123 :: DEEP SCAN

Webapp- en website-kwetsbaarheidsscanner voor eigen systemen. Flask backend, single-page dashboard frontend, live voortgang tijdens de scan.

> **⚠️ Alleen voor eigen systemen.** Deze tool voert actieve checks uit (poortscan, XSS/SQLi testpayloads). Scan uitsluitend domeinen/IP's die je zelf bezit of waarvoor je expliciete schriftelijke toestemming hebt om te testen. Ongeautoriseerd scannen van systemen van derden kan strafbaar zijn onder **art. 138ab Sr (computervredebreuk)**.

---

## Overzicht

DEEP SCAN combineert passieve en actieve controles in één workflow, met een live dashboard dat bevindingen toont zodra ze binnenkomen — geen wachten op een eindrapport.

| Module | Wat het checkt |
|---|---|
| **Passief** | Security headers (HSTS, CSP, X-Frame-Options, ...), SSL/TLS-versie en certificaatvervaldatum, cookie-vlaggen (Secure/HttpOnly/SameSite), technologie-stack detectie |
| **Netwerk** | Poortscan over top ~40 poorten (socket-based, geen root nodig), banner grabbing |
| **CVE-lookup** | Matcht gedetecteerde technologie + versie tegen de CIRCL CVE-database |
| **Vuln-checks** | Non-destructieve XSS/SQLi testpayloads op gevonden forms en URL-parameters (detectie via reflectie of foutmeldingen) |

Alles draait lokaal, single-user, geen externe database nodig.

---

## Installatie

```bash
git clone <repo-url>
cd deepscan
pip install -r requirements.txt
```

Werkt ook op Android via **Termux**:

```bash
pkg install python
pip install -r requirements.txt
```

## Gebruik

```bash
python3 app.py
```

Open vervolgens `http://localhost:5009` (of `http://<jouw-ip>:5009` vanaf een ander apparaat op hetzelfde netwerk).

1. Vul het doelwit in (domein of volledige URL)
2. Selecteer de gewenste modules
3. Bevestig dat het doelwit van jezelf is
4. **Start Deep Scan** — bevindingen en logs verschijnen live
5. Download het rapport als JSON via de knop onderaan het dashboard

---

## Bestandsstructuur

```
deepscan/
├── app.py              # Flask backend + scanlogica
├── index.html           # Dashboard frontend (HTML/CSS/JS, geen build-stap)
├── requirements.txt
└── scope_audit.log       # Wordt automatisch aangemaakt bij eerste scan
```

Flat structuur, geen frameworks nodig aan de frontend-kant — direct te openen/serveren.

---

## Scope-logging

Elke scan-start wordt met tijdstempel weggeschreven naar `scope_audit.log`, inclusief het bevestigde doelwit en de gekozen modules. Dit dient als eigen audit-trail — bewaar dit logbestand als bewijs van geautoriseerde scans.

---

## Beperkingen

- Detectie-only: er wordt niets geëxploiteerd, alleen op afwijkend gedrag/foutmeldingen gecontroleerd
- Poortscan is TCP-connect-based (geen SYN-scan), dus iets trager maar vereist geen root/raw sockets
- CVE-matching is best-effort tekstmatching op productnaam/versie — handmatige verificatie blijft nodig
- Geen opslag tussen sessies; scanresultaten leven in het geheugen van het draaiende proces

---

## Licentie / gebruik

Interne tool voor Abelsoftware123. Gebruik uitsluitend tegen systemen waarvoor je autorisatie hebt.
