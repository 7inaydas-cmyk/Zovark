"""Detection tools — composite tools that combine extraction, parsing, and scoring."""
import re
import json
import math
from collections import Counter

from tools.extraction import extract_ipv4, extract_usernames, extract_urls, extract_domains, extract_emails, _make_ioc
from tools.parsing import parse_windows_event, parse_auth_log, parse_dns_query
from tools.scoring import score_brute_force, score_phishing, score_c2_beacon, score_exfiltration, score_generic
from tools.analysis import calculate_entropy, count_pattern

import ipaddress


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP is RFC1918 private (10.x, 172.16-31.x, 192.168.x) or loopback.
    RFC5737 documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x) are treated
    as external/public since they represent real external IPs in SIEM test data."""
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_loopback:
            return True
        # RFC1918 only — not RFC5737 documentation ranges
        rfc1918 = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ]
        return any(addr in net for net in rfc1918)
    except ValueError:
        return False


def detect_kerberoasting(siem_event: dict) -> dict:
    """Detect Kerberoasting: RC4 encryption (0x17), TGS requests for SPNs."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0

    raw_lower = raw_log.lower()

    parsed = parse_windows_event(raw_log)
    event_id = parsed.get("EventID", "")
    # Accept both TicketEncryptionType and EncryptionType (SIEM format varies)
    encryption = parsed.get("TicketEncryptionType", "") or parsed.get("EncryptionType", "")
    service_name = parsed.get("ServiceName", "")

    # Raw log keyword fallback — catches narrative SIEM alerts
    # Single-term patterns (no backtracking risk)
    kerberoast_keywords = [
        (r'\bkerberoast\w*\b', "Kerberoasting keyword detected", 40),
        (r'\bservice\s*ticket\s*crack\w*\b', "Service ticket cracking detected", 35),
        (r'\btgs\s+request\w*\b', "TGS ticket request detected", 25),
        (r'\brc4.hmac\b', "RC4-HMAC encryption — weak Kerberos cipher", 30),
        (r'\binvoke-kerberoast\b', "Invoke-Kerberoast PowerShell detected", 50),
        (r'\bgetuserspns\b', "GetUserSPNs — Kerberoasting tool", 45),
        (r'\bspn\s*(?:enum|scan)\w*\b', "SPN enumeration detected — Kerberoasting recon", 30),
        (r'\b(?:50|100|\d{2,})\s+tgs\b', "Mass TGS requests — Kerberoasting pattern", 35),
    ]
    for pattern, description, score in kerberoast_keywords:
        if re.search(pattern, raw_lower):
            findings.append(description)
            risk += score

    # Compound patterns — split into independent searches to avoid ReDoS
    if re.search(r'\bspn\w*\b', raw_lower) and re.search(r'\brc4\b', raw_lower):
        findings.append("SPN with RC4 encryption — Kerberoasting indicator")
        risk += 45
    if re.search(r'\brubeus\b', raw_lower) and re.search(r'\bkerberoast\b', raw_lower):
        findings.append("Rubeus Kerberoasting detected")
        risk += 50

    # RC4 encryption (0x17) — primary indicator
    if encryption == "0x17":
        findings.append("RC4 encryption (0x17) detected — weak encryption type commonly used in Kerberoasting")
        risk += 40

    # TGS request (4769) for service accounts
    if event_id == "4769":
        findings.append(f"TGS ticket request (EventID 4769) for service: {service_name}")
        risk += 15
        if service_name and "krbtgt" not in service_name.lower():
            findings.append(f"Non-krbtgt service SPN targeted: {service_name}")
            risk += 15

    # Extract IOCs
    ips = extract_ipv4(raw_log)
    iocs.extend(ips)

    usernames = extract_usernames(raw_log)
    iocs.extend(usernames)

    # Service account as IOC
    if service_name:
        iocs.append(_make_ioc("service_name", service_name, raw_log))

    # Source IP from siem_event
    src_ip = siem_event.get("source_ip", "")
    if src_ip and not any(i["value"] == src_ip for i in iocs):
        iocs.append(_make_ioc("ipv4", src_ip, raw_log))

    # Username from siem_event
    username = siem_event.get("username", "")
    if username and not any(i["value"] == username for i in iocs):
        iocs.append(_make_ioc("username", username, raw_log))

    # Kerberoasting requires BOTH RC4 encryption AND TGS request for non-krbtgt service
    is_rc4 = encryption == "0x17"
    is_tgs = event_id == "4769"
    is_krbtgt = service_name and "krbtgt" in service_name.lower()

    # Full Kerberoasting combo: RC4 + TGS + non-krbtgt = high confidence
    if is_rc4 and is_tgs and not is_krbtgt:
        risk = max(risk, 80)
    elif is_rc4 and is_tgs and is_krbtgt:
        # RC4 TGT request - suspicious but NOT kerberoasting. Cap risk.
        risk = min(risk, 35)
    elif is_rc4:
        # RC4 used but not TGS - moderate concern
        risk = max(risk, 45)
    elif is_tgs and not is_krbtgt:
        # TGS without RC4 - low concern
        risk = max(risk, 25)

    if not findings:
        risk = max(risk, 10)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_golden_ticket(siem_event: dict) -> dict:
    """Detect Golden Ticket: forged TGT, RC4 encryption, abnormal lifetime."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0

    parsed = parse_windows_event(raw_log)
    event_id = parsed.get("EventID", "")
    encryption = parsed.get("TicketEncryptionType", "")
    service_name = parsed.get("ServiceName", "")
    ticket_options = parsed.get("TicketOptions", "")
    lifetime = parsed.get("Lifetime", "")

    raw_lower = raw_log.lower()

    # Raw log keyword detection — catches narrative SIEM alerts that don't parse into structured fields
    golden_ticket_keywords = [
        (r'\bgolden\s*ticket\b', "Golden Ticket attack keyword detected", 45),
        (r'\bmimikatz\b', "Mimikatz tool detected — credential theft/ticket forging", 50),
        (r'\bforged\s+tg[ts]\b', "Forged Kerberos ticket detected", 50),
        (r'\bkekeo\b', "Kekeo tool detected — Kerberos ticket manipulation", 45),
        (r'\brubeus\b', "Rubeus tool detected — Kerberos abuse toolkit", 45),
        (r'\boverpass.the.hash\b', "Overpass-the-hash technique detected", 40),
        (r'\bpass.the.ticket\b', "Pass-the-ticket technique detected", 40),
        (r'\bntds\.dit\b', "NTDS.dit access — domain credential extraction", 40),
        (r'\babnormal\w*\s+(?:ticket\s+)?lifetime\b', "Abnormal ticket lifetime detected", 40),
        (r'\bforged\b', "Forged/fake TGT reference detected", 50),
    ]
    for pattern, description, score in golden_ticket_keywords:
        if re.search(pattern, raw_lower):
            findings.append(description)
            risk += score

    # Compound patterns — split to avoid ReDoS
    if re.search(r'\bkrbtgt\b', raw_lower) and re.search(r'\bhash\b', raw_lower):
        findings.append("krbtgt hash reference — Golden Ticket prerequisite")
        risk += 50
    if re.search(r'\bticket\b', raw_lower) and re.search(r'\bforg\w+\b', raw_lower):
        findings.append("Ticket forgery language detected")
        risk += 45
    if re.search(r'\btgt\b', raw_lower) and re.search(r'\babnormal\b', raw_lower):
        findings.append("TGT with abnormal characteristics detected")
        risk += 45

    # TGT request with RC4
    if event_id == "4768" and encryption == "0x17":
        findings.append("TGT request with RC4 encryption — possible Golden Ticket")
        risk += 40

    # krbtgt service targeted
    if service_name and "krbtgt" in service_name.lower():
        findings.append(f"krbtgt service targeted: {service_name}")
        risk += 20

    # Abnormal lifetime (check both parsed and raw log)
    if lifetime:
        hour_match = re.search(r'(\d+)h', lifetime)
        if hour_match and int(hour_match.group(1)) > 720:  # > 30 days
            findings.append(f"Abnormally long ticket lifetime: {lifetime}")
            risk += 35
    # Also check raw log for lifetime patterns
    raw_lifetime = re.search(r'Lifetime[=:\s](\d+)h', raw_log)
    if raw_lifetime:
        hours = int(raw_lifetime.group(1))
        if hours > 100:  # > ~4 days is suspicious
            findings.append(f"Extended ticket lifetime: {hours}h")
            risk += 35

    # Suspicious ticket options
    if ticket_options and ticket_options.startswith("0x50"):
        findings.append(f"Suspicious ticket options: {ticket_options}")
        risk += 15
    
    # Also check raw log for ticket options
    if re.search(r'TicketOptions[=:\s]0x50', raw_log):
        findings.append("Suspicious ticket options in raw log")
        risk += 15

    # IOCs
    ips = extract_ipv4(raw_log)
    iocs.extend(ips)

    src_ip = siem_event.get("source_ip", "")
    if src_ip and not any(i["value"] == src_ip for i in iocs):
        iocs.append(_make_ioc("ipv4", src_ip, raw_log))

    username = siem_event.get("username", "")
    if username:
        iocs.append(_make_ioc("username", username, raw_log))

    # Golden ticket with attack-tool/technique keywords = high confidence
    # Only boost if we have strong indicators (tool names, forgery language),
    # not just structural matches like "krbtgt service targeted"
    high_confidence_keywords = [
        "mimikatz", "golden ticket", "forged", "kekeo", "rubeus",
        "overpass", "pass-the-ticket", "ntds.dit", "krbtgt hash",
        "ticket forgery", "abnormal",
    ]
    has_high_confidence = any(
        any(kw in f.lower() for kw in high_confidence_keywords)
        for f in findings
    )
    if has_high_confidence and risk < 75:
        risk = max(risk, 75)

    if not findings:
        risk = max(risk, 10)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_ransomware(siem_event: dict) -> dict:
    """Detect ransomware: shadow copy deletion, mass encryption, ransom notes."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0

    raw_lower = raw_log.lower()

    # Raw log keyword fallback — catches narrative SIEM alerts
    ransomware_keywords = [
        (r'\bransomware\b', "Ransomware keyword detected", 35),
        (r'\b(?:lockbit|conti|revil|blackcat|alphv|clop|royal|akira|rhysida|play)\b', "Known ransomware family detected", 45),
        (r'\bfiles?\s+encrypt\w+\b', "File encryption language detected", 30),
        (r'\bdecryption\s+key\b', "Decryption key reference — ransom context", 30),
        (r'\bwannacry\b', "WannaCry ransomware detected", 45),
    ]
    for pattern, description, score in ransomware_keywords:
        if re.search(pattern, raw_lower):
            findings.append(description)
            risk += score

    # Shadow copy deletion
    if re.search(r'vssadmin\s+delete\s+shadows', raw_lower):
        findings.append("Shadow copy deletion detected (vssadmin delete shadows)")
        risk += 40
    if re.search(r'wmic\s+shadowcopy\s+delete', raw_lower):
        findings.append("Shadow copy deletion via WMI")
        risk += 40

    # Mass encryption indicators
    if re.search(r'mass\s+encrypt', raw_lower):
        findings.append("Mass encryption activity detected")
        risk += 30

    # File extension changes
    ransom_extensions = [r'\.locked', r'\.encrypted', r'\.crypt', r'\.ransom', r'\.cry\b']
    for ext in ransom_extensions:
        if re.search(ext, raw_lower):
            findings.append(f"Ransomware file extension detected: {ext.replace(chr(92), '')}")
            risk += 25
            break

    # Ransom notes
    if re.search(r'ransom|readme\.txt|decrypt|bitcoin|btc|payment', raw_lower):
        findings.append("Ransom-related language detected")
        risk += 20

    # IOCs
    ips = extract_ipv4(raw_log)
    iocs.extend(ips)

    src_ip = siem_event.get("source_ip", "")
    if src_ip and not any(i.get("value") == src_ip for i in iocs):
        iocs.append(_make_ioc("ipv4", src_ip, raw_log))

    # Ransomware indicators should have minimum risk if detected
    if findings and risk < 50:
        risk = 60  # Ensure detection meets threshold
    
    if not findings:
        risk = max(risk, 5)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_phishing(siem_event: dict) -> dict:
    """Detect phishing: suspicious URLs, credential harvesting, urgency language."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0

    raw_lower = raw_log.lower()

    # Extract URLs and domains
    urls = extract_urls(raw_log)
    domains = extract_domains(raw_log)
    emails = extract_emails(raw_log)

    iocs.extend(urls)
    iocs.extend(domains)
    iocs.extend(emails)

    # Urgency language
    urgency_patterns = [r'urgent', r'immediate', r'action\s+required', r'verify.*account', r'suspend', r'expire',
                        r'click\s+here', r'act\s+now', r'wire\s+transfer', r'confirm.*identity', r'within\s+\d+\s*hours']
    has_urgency = False
    for pat in urgency_patterns:
        if re.search(pat, raw_lower):
            has_urgency = True
            findings.append(f"Urgency/social engineering language detected")
            risk += 15
            break

    # Credential form indicators
    has_cred_form = bool(re.search(r'login|password|credential|verify|secure.*login|credential\s+harvest', raw_lower))
    if has_cred_form:
        findings.append("Credential harvesting indicators detected")
        risk += 25

    # Suspicious domains
    suspicious_count = 0
    for d in domains:
        domain_val = d["value"]
        if re.search(r'(login|secure|verify|account|update|confirm)', domain_val):
            suspicious_count += 1
            findings.append(f"Suspicious domain: {domain_val}")
            risk += 15

    # URL count
    if len(urls) > 0:
        risk += 10

    # Compound: URL + urgency together is high-confidence phishing
    if len(urls) > 0 and has_urgency:
        risk += 10

    # Spoofed sender
    if re.search(r'from:?\s*\S+@\S+', raw_lower) and domains:
        findings.append("Email with embedded URLs detected")
        risk += 5

    # BEC (Business Email Compromise) — no URLs needed
    bec_executive = bool(re.search(r'from:?\s*(?:ceo|cfo|coo|cto|president|director|vp)\b', raw_lower))
    bec_payment = bool(re.search(r'\b(?:wire\s+transfer|payment|invoice|bank\s+account|routing\s+number)\b', raw_lower))
    bec_originating_ip = bool(re.search(r'x-originating-ip:', raw_lower))
    if bec_executive:
        findings.append("Executive impersonation detected (BEC pattern)")
        risk += 25
    if bec_payment:
        findings.append("Financial transaction language in email (BEC pattern)")
        risk += 20
    if bec_executive and bec_payment:
        risk += 15  # Compound: executive + payment = high confidence BEC
    if bec_originating_ip:
        findings.append("X-Originating-IP header present — external email source")
        risk += 10

    # Reduce false positives for internal IT notifications
    is_internal_notification = bool(re.search(r'internal|company policy|it department|system administrator', raw_lower))
    if is_internal_notification and risk < 70:
        risk = min(risk, 25)  # Cap risk for internal notifications

    # Phishing/BEC indicators require minimum risk
    elif findings and risk < 55:
        risk = 55  # Ensure detection when clear indicators present

    if not findings:
        risk = max(risk, 5)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_c2(siem_event: dict) -> dict:
    """Detect C2: regular beacon intervals, DGA domains, encoded payloads."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0

    raw_lower = raw_log.lower()

    # Extract IOCs
    ips = extract_ipv4(raw_log)
    domains = extract_domains(raw_log)
    iocs.extend(ips)
    iocs.extend(domains)

    # Beacon interval detection
    interval_match = re.search(r'(?:beacon|interval)\s*[=:]?\s*(\d+)\s*s', raw_lower)
    stddev_match = re.search(r'stddev\s*=\s*([\d.]+)', raw_lower)
    conn_match = re.search(r'connections?\s*=\s*(\d+)', raw_lower)

    avg_interval = float(interval_match.group(1)) if interval_match else 0
    stddev = float(stddev_match.group(1)) if stddev_match else 999
    connections = int(conn_match.group(1)) if conn_match else 0

    if avg_interval > 0 and stddev < 5:
        findings.append(f"Regular beacon interval detected: {avg_interval}s (stddev={stddev})")
        risk += 30

    if connections >= 100:
        findings.append(f"High connection count: {connections}")
        risk += 20

    # DGA domain detection — entropy OR explicit "DGA" keyword + random-looking subdomain
    dga_detected = False
    for d in domains:
        subdomain = d["value"].split(".")[0]
        entropy = calculate_entropy(subdomain)
        # Short random subdomains (< 10 chars) have lower entropy but are still suspicious
        entropy_threshold = 3.0 if len(subdomain) <= 8 else 3.5
        if entropy > entropy_threshold:
            findings.append(f"High-entropy domain (possible DGA): {d['value']} (entropy={entropy:.2f})")
            risk += 25
            dga_detected = True
            break
    # Also detect DGA via keyword
    if not dga_detected and re.search(r'\bdga\b', raw_lower):
        findings.append("DGA (Domain Generation Algorithm) keyword detected")
        risk += 20
        dga_detected = True

    # C2 keywords - expanded
    c2_keywords = ["beacon", "c2", "command.and.control", "callback", "implant", "cobalt", "meterpreter", 
                   "cobalt strike", "jitter", "interval=", "beacon interval"]
    for kw in c2_keywords:
        if kw in raw_lower:
            findings.append(f"C2 keyword detected: {kw}")
            risk += 20
            break
    
    # Known bad user agents
    if re.search(r'user-agent', raw_lower) and re.search(r'cobalt|meterpreter|implant', raw_lower):
        findings.append("Malicious User-Agent detected")
        risk += 25
    
    # DNS tunneling patterns
    if (re.search(r'\bdns\b', raw_lower) and re.search(r'\btunnel\b', raw_lower)) or re.search(r'type=txt|\.[^.]{20,}\.', raw_lower):
        findings.append("DNS tunneling pattern detected")
        risk += 20

    # Port 443 to unusual destination (check raw_log for :443 even if IP was filtered)
    if re.search(r':443\b', raw_log):
        risk += 5

    # Compound bonus: multiple C2 indicators together is high confidence
    c2_indicator_count = sum([
        avg_interval > 0 and stddev < 5,
        connections >= 100,
        dga_detected,
    ])
    if c2_indicator_count >= 3:
        risk += 15
    elif c2_indicator_count >= 2:
        risk += 10

    src_ip = siem_event.get("source_ip", "")
    if src_ip and not any(i["value"] == src_ip for i in iocs):
        iocs.append(_make_ioc("ipv4", src_ip, raw_log))
    
    # C2 indicators require minimum risk
    if findings and risk >= 20 and risk < 55:
        risk = 55  # Ensure detection when indicators present
    
    if not findings:
        risk = max(risk, 5)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_data_exfil(siem_event: dict) -> dict:
    """Detect data exfiltration: large transfers, off-hours, external dest."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0

    raw_lower = raw_log.lower()

    # Extract IOCs
    ips = extract_ipv4(raw_log)
    iocs.extend(ips)

    # Data volume
    size_match = re.search(r'([\d.]+)\s*(GB|MB|KB|TB|bytes?)\b', raw_log, re.IGNORECASE)
    bytes_transferred = 0
    if size_match:
        amount = float(size_match.group(1))
        unit = size_match.group(2).upper()
        multipliers = {"TB": 1e12, "GB": 1e9, "MB": 1e6, "KB": 1e3, "BYTE": 1, "BYTES": 1}
        bytes_transferred = int(amount * multipliers.get(unit, 1))
        if bytes_transferred > 100 * 1024 * 1024:  # > 100MB
            findings.append(f"Large data transfer: {size_match.group(0)}")
            risk += 30

    # External destination — keyword, non-RFC1918 IP, or "transferred to <IP>" pattern
    is_external = bool(re.search(r'external|internet|public|outside', raw_lower))
    if not is_external and ips:
        # Check if any extracted IP is a public (non-RFC1918) address
        for ip_ioc in ips:
            ip_val = ip_ioc.get("value", "")
            if ip_val and not _is_private_ip(ip_val):
                is_external = True
                break
    if not is_external:
        # Check for "to <IP>" patterns in raw_log — IPs may have been filtered by extract_ipv4
        dest_ip_match = re.search(r'(?:to|destination|dest)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', raw_log, re.IGNORECASE)
        if dest_ip_match:
            dest_ip = dest_ip_match.group(1)
            if not _is_private_ip(dest_ip):
                is_external = True
                iocs.append(_make_ioc("ipv4", dest_ip, raw_log))
    if is_external:
        findings.append("Transfer to external destination")
        risk += 20

    # Off-hours
    is_off_hours = bool(re.search(r'off.hours|after.hours|night|weekend|0[0-5]:\d{2}', raw_lower))
    if is_off_hours:
        findings.append("Activity during off-hours")
        risk += 15

    # Encryption/encoding
    is_encrypted = bool(re.search(r'encrypt|encoded|base64|compressed|archive', raw_lower))
    if is_encrypted:
        findings.append("Data appears encrypted or encoded")
        risk += 10

    # Cloud storage
    if re.search(r'dropbox|gdrive|onedrive|s3|azure.blob|mega\.|wetransfer', raw_lower):
        findings.append("Cloud storage destination detected")
        risk += 15
    
    # Archive/Packaging tools often used for exfil
    has_archive = bool(re.search(r'\.rar|\.zip|\.7z|\.tar\.gz|compress|archive|rar\.exe|zip\.', raw_lower))
    if has_archive:
        findings.append("Archiving/packaging detected")
        risk += 15
    
    # Compound: Cloud storage + Archive = high confidence exfil
    has_cloud = bool(re.search(r'dropbox|gdrive|onedrive|s3|azure.blob|mega\.|wetransfer', raw_lower))
    if has_cloud and has_archive:
        findings.append("Archived data to cloud storage - exfiltration pattern")
        risk += 25
    
    # Multiple failed auth then success — high-confidence exfil indicator
    if (re.search(r'\bfailed\b', raw_lower) and re.search(r'\bauth\b', raw_lower) or re.search(r'\bmultiple\b', raw_lower) and re.search(r'\bfail\b', raw_lower)) and (re.search(r'\bthen\b', raw_lower) and re.search(r'\bsuccess\b', raw_lower) or re.search(r'\bupload\b', raw_lower)):
        findings.append("Suspicious access pattern detected")
        risk += 50

    # Keyword fallback — catches narrative SIEM alerts
    exfil_keywords = [
        (r'\bexfiltrat\w+\b', "Exfiltration keyword detected", 20),
        (r'\bexfil\b', "Exfiltration shorthand detected", 20),
        (r'\bdata\s+(?:theft|leak|stolen|breach)\b', "Data theft/breach language detected", 20),
        (r'\bunauthorized\s+(?:transfer|copy|download|access)\b', "Unauthorized data movement detected", 20),
        (r'\bstaging\s+(?:area|server|directory)\b', "Data staging detected", 15),
        (r'\bbulk\s+(?:download|export|transfer|copy)\b', "Bulk data movement detected", 20),
        (r'\bsensitive\s+(?:data|files|documents)\b', "Sensitive data reference", 10),
        (r'\bhigh.entropy\b', "High-entropy traffic detected — potential covert channel", 15),
        (r'\bencoding\s+data\b', "Data encoding for transfer detected", 15),
        (r'\bdns\s+(?:tunnel|exfil|covert)\b', "DNS-based exfiltration technique", 25),
        (r'\bdata\s+in\s+subdomains?\b', "Subdomain-encoded data transfer", 25),
        (r'\b\d+\s+queries\s+in\s+\d+\s+minutes?\b', "High-frequency query burst detected", 15),
    ]
    for pattern, description, score in exfil_keywords:
        if re.search(pattern, raw_lower):
            if not any(description in f for f in findings):
                findings.append(description)
                risk += score

    src_ip = siem_event.get("source_ip", "")
    if src_ip and not any(i["value"] == src_ip for i in iocs):
        iocs.append(_make_ioc("ipv4", src_ip, raw_log))
    
    # Exfiltration indicators require minimum risk — but only when multiple
    # indicators compound (single cloud storage mention is not exfil)
    if len(findings) >= 2 and risk < 65:
        risk = 65  # Ensure detection when multiple indicators present

    if not findings:
        risk = max(risk, 5)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_lolbin_abuse(siem_event: dict) -> dict:
    """Detect LOLBin abuse: certutil, mshta, bitsadmin, rundll32, etc."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0

    raw_lower = raw_log.lower()

    # LOLBin patterns with malicious indicators
    lolbin_patterns = {
        "certutil": [
            (r'certutil[^\n]{0,500}-urlcache', "certutil download via -urlcache"),
            (r'certutil[^\n]{0,500}-split[^\n]{0,200}-f', "certutil download with -split -f"),
            (r'certutil[^\n]{0,500}-decode', "certutil base64 decode"),
            (r'certutil[^\n]{0,500}-encode', "certutil base64 encode"),
        ],
        "mshta": [
            (r'mshta(?:\.exe)?[\s:]*(?:http|vbscript|javascript)', "mshta executing remote/scripted content"),
        ],
        "bitsadmin": [
            (r'bitsadmin[^\n]{0,500}transfer', "bitsadmin file transfer"),
            (r'bitsadmin[^\n]{0,500}/download', "bitsadmin download"),
        ],
        "rundll32": [
            (r'rundll32[^\n]{0,500}javascript', "rundll32 executing JavaScript"),
            (r'rundll32[^\n]{0,500}shell32', "rundll32 shell32 abuse"),
        ],
        "regsvr32": [
            (r'regsvr32[^\n]{0,500}/s[^\n]{0,200}/u[^\n]{0,200}scrobj', "regsvr32 scriptlet execution (Squiblydoo)"),
            (r'regsvr32[^\n]{0,500}http', "regsvr32 remote COM object"),
        ],
        "wscript": [
            (r'wscript[^\n]{0,500}\.js\b', "wscript executing JavaScript"),
            (r'cscript[^\n]{0,500}\.vbs\b', "cscript executing VBScript"),
        ],
    }

    for lolbin, patterns in lolbin_patterns.items():
        for pattern, description in patterns:
            if re.search(pattern, raw_lower):
                findings.append(f"LOLBin abuse: {description}")
                risk += 35
                break

    # Compound certutil: -urlcache + -split + -f together is high-confidence download
    if re.search(r'certutil', raw_lower) and re.search(r'-urlcache', raw_lower) and re.search(r'-split', raw_lower) and re.search(r'-f\b', raw_lower):
        findings.append("Certutil compound download flags (-urlcache -split -f) — high confidence")
        risk += 20

    # Extract any URLs (download targets)
    urls = extract_urls(raw_log)
    iocs.extend(urls)

    # URL pointing to suspicious file extensions
    for url_ioc in urls:
        url_val = url_ioc.get("value", "")
        if re.search(r'\.(exe|dll|bin|bat|ps1|vbs|hta|scr)\b', url_val, re.IGNORECASE):
            findings.append(f"URL targets suspicious executable: {url_val}")
            risk += 10
            break

    # Extract IPs
    ips = extract_ipv4(raw_log)
    iocs.extend(ips)

    # Check for suspicious file paths
    if re.search(r'\\temp\\|\\tmp\\|\\appdata\\|\\public\\', raw_lower):
        findings.append("Suspicious output path (temp/appdata/public)")
        risk += 10

    # Executable extensions
    if re.search(r'\.(exe|dll|bat|ps1|vbs|js|hta)\b', raw_lower):
        risk += 5

    src_ip = siem_event.get("source_ip", "")
    if src_ip and not any(i.get("value") == src_ip for i in iocs):
        iocs.append(_make_ioc("ipv4", src_ip, raw_log))

    # Benign certutil usage (just -verify)
    if re.search(r'certutil.*-verify', raw_lower) and not findings:
        risk = min(risk, 15)
    
    # LOLBin abuse requires minimum risk when indicators found
    if findings and risk >= 30 and risk < 55:
        risk = 55  # Ensure detection

    if not findings:
        risk = max(risk, 5)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}



def detect_com_hijacking(siem_event: dict) -> dict:
    """Detect COM hijacking via registry modifications."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0
    raw_lower = raw_log.lower()
    
    # COM hijacking registry paths
    com_patterns = [
        r'HKCU\\Software\\Classes\\CLSID',
        r'HKEY_CURRENT_USER\\Software\\Classes\\CLSID',
        r'HKLM\\Software\\Classes\\CLSID',
        r'InprocServer32',
        r'LocalServer32',
    ]
    
    for pattern in com_patterns:
        if re.search(pattern, raw_log, re.IGNORECASE):
            findings.append(f"COM hijacking registry path detected: {pattern}")
            risk += 25
    
    # Suspicious DLL in user-writable location
    if re.search(r'InprocServer32.*\\Users\\.*\.dll', raw_log, re.IGNORECASE):
        findings.append("COM DLL registered in user-writable location")
        risk += 30
    
    # DLL that differs from system default
    if re.search(r'shell32\.dll|kernel32\.dll|kernelbase\.dll', raw_lower):
        if re.search(r'\\Users\\|\\Temp\\|\\AppData\\', raw_lower):
            findings.append("System DLL replaced with user-controlled path")
            risk += 35
    
    if findings:
        risk = max(risk, 75)  # Minimum risk for COM hijacking
    
    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_encoded_service(siem_event: dict) -> dict:
    """Detect malicious services with encoded commands."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0
    raw_lower = raw_log.lower()
    
    # New service installation
    if re.search(r'EventID\s*=\s*(7045|4697)', raw_log):
        findings.append("New Windows service installed")
        risk += 20
    
    # Encoded PowerShell in service
    encoded_patterns = [
        r'-enc\s+[A-Za-z0-9+/]{20,}',  # -enc with base64
        r'-encodedcommand\s+[A-Za-z0-9+/]{20,}',
        r'-e\s+[A-Za-z0-9+/]{20,}',
    ]
    
    for pattern in encoded_patterns:
        if re.search(pattern, raw_lower):
            findings.append("Encoded command in service ImagePath")
            risk += 40
            break
    
    # PowerShell in service path
    if re.search(r'powershell\.exe|pwsh\.exe', raw_lower):
        findings.append("PowerShell executable in service")
        risk += 15
        
        # Suspicious PowerShell flags
        if re.search(r'-nop|-noprofile', raw_lower):
            findings.append("PowerShell -NoProfile flag (evasion)")
            risk += 10
        if re.search(r'-w\s+hidden|-windowstyle\s+hidden', raw_lower):
            findings.append("PowerShell hidden window")
            risk += 15
        if re.search(r'downloadstring|iex\s|invoke-expression', raw_lower):
            findings.append("PowerShell download/cradle detected")
            risk += 25
    
    # Only flag as malicious if there's actual encoded/obfuscated content
    malicious_indicators = ['Encoded command', 'download/cradle', 'hidden window']
    has_malicious = any(mi in ' '.join(findings) for mi in malicious_indicators)
    
    if has_malicious:
        risk = max(risk, 80)
    elif findings and risk < 10:
        risk = 5  # Benign service creation
    
    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_token_impersonation(siem_event: dict) -> dict:
    """Detect token impersonation via RunAs."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0
    raw_lower = raw_log.lower()
    
    # RunAs usage
    if re.search(r'runas\.exe', raw_lower):
        findings.append("RunAs.exe execution detected")
        risk += 15
    
    # Saved credentials flag
    if re.search(r'/savecred', raw_lower):
        findings.append("RunAs with saved credentials (/savecred)")
        risk += 25
    
    # Elevated user target
    if re.search(r'admin|system|domain', raw_lower):
        findings.append("Privilege escalation target detected")
        risk += 20
    
    # Encoded command after runas
    if re.search(r'-enc\s+|/enc\s+|-encodedcommand', raw_lower):
        findings.append("Encoded command in RunAs context")
        risk += 35
    
    # Suspicious execution after impersonation
    if re.search(r'powershell|cmd\.exe|wscript|cscript', raw_lower):
        findings.append("Script execution following impersonation")
        risk += 20
    
    # Only flag if /savecred is used (the actual credential theft vector)
    has_savecred = '/savecred' in raw_lower
    has_encoded = '-enc' in raw_lower or '-encodedcommand' in raw_lower
    
    if has_savecred or has_encoded:
        risk = max(risk, 85)
    elif findings and risk < 20:
        risk = 10  # Benign runas usage
    
    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_appcert_dlls(siem_event: dict) -> dict:
    """Detect AppCert DLLs persistence."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0
    raw_lower = raw_log.lower()
    
    # AppCertDlls registry path
    if re.search(r'AppCertDlls', raw_log, re.IGNORECASE):
        findings.append("AppCertDlls registry modification detected")
        risk += 40
    
    # Session Manager path
    if re.search(r'Session Manager.*AppCert', raw_log, re.IGNORECASE):
        findings.append("Session Manager AppCert configuration")
        risk += 35
    
    # DLL in suspicious location
    if re.search(r'AppCertDlls.*\\Windows\\[^\\]+\.dll', raw_log, re.IGNORECASE):
        findings.append("Custom DLL in AppCertDlls")
        risk += 30
    
    # Registry modification by non-system user
    if re.search(r'\\Users\\|\\Temp\\', raw_lower):
        findings.append("AppCert DLL from user-writable location")
        risk += 25
    
    # Only flag if there's actual DLL registration in AppCert path
    has_dll_registration = 'custom dll' in ' '.join(findings).lower()
    has_user_location = 'user-writable' in ' '.join(findings).lower()
    
    if has_dll_registration or has_user_location:
        risk = max(risk, 85)
    elif findings and risk < 20:
        risk = 10  # Benign mention
    
    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_dns_exfiltration(siem_event: dict) -> dict:
    """Detect DNS exfiltration: high-entropy subdomains, TXT queries, high volume."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0

    raw_lower = raw_log.lower()

    # Parse DNS query
    parsed = parse_dns_query(raw_log)

    # Extract domains for IOCs
    domains = extract_domains(raw_log)
    iocs.extend(domains)
    ips = extract_ipv4(raw_log)
    iocs.extend(ips)

    # High-entropy subdomain detection
    for d in domains:
        parts = d["value"].split(".")
        if len(parts) >= 2:
            subdomain = parts[0]
            entropy = calculate_entropy(subdomain)
            if entropy > 3.5:
                findings.append(f"High-entropy DNS subdomain: {d['value']} (entropy={entropy:.2f})")
                risk += 35
                break
            elif entropy > 3.0 and len(subdomain) > 15:
                findings.append(f"Long high-entropy subdomain: {d['value']} (entropy={entropy:.2f}, len={len(subdomain)})")
                risk += 25
                break

    # Also check domain field from siem_event
    siem_domain = siem_event.get("domain", "")
    if siem_domain and not findings:
        entropy = calculate_entropy(siem_domain.split(".")[0])
        if entropy > 3.5:
            findings.append(f"High-entropy domain: {siem_domain} (entropy={entropy:.2f})")
            risk += 35

    # TXT record queries — primary DNS exfil channel
    has_txt = bool(re.search(r'\bTXT\b|type=txt|query.type.*txt', raw_log, re.IGNORECASE))
    if has_txt:
        findings.append("TXT record query detected — common DNS exfiltration channel")
        risk += 25

    # High query volume
    query_count_match = re.search(r'(?:queries?|count|volume)\s*[=:]\s*(\d+)', raw_log, re.IGNORECASE)
    if query_count_match:
        count = int(query_count_match.group(1))
        if count > 100:
            findings.append(f"High DNS query volume: {count}")
            risk += 25
        elif count > 20:
            findings.append(f"Elevated DNS query volume: {count}")
            risk += 15

    # DNS tunneling keywords
    tunnel_patterns = [
        r'dns.*tunnel', r'dns.*exfil', r'iodine', r'dnscat', r'dns2tcp',
        r'high.entropy.*dns', r'data.*encod.*dns', r'covert.*channel',
    ]
    for pat in tunnel_patterns:
        if re.search(pat, raw_lower):
            findings.append("DNS tunneling/exfiltration keyword detected")
            risk += 20
            break

    # Long subdomain labels (>40 chars suggest encoded data)
    for d in domains:
        labels = d["value"].split(".")
        for label in labels:
            if len(label) > 40:
                findings.append(f"Abnormally long DNS label: {len(label)} chars (possible encoded data)")
                risk += 20
                break

    # nslookup/dig usage in raw log
    if re.search(r'\bnslookup\b|\bdig\b', raw_lower):
        findings.append("DNS lookup tool usage detected")
        risk += 10

    # Source IP
    src_ip = siem_event.get("source_ip", "")
    if src_ip and not any(i["value"] == src_ip for i in iocs):
        iocs.append(_make_ioc("ipv4", src_ip, raw_log))

    # DNS exfil indicators require minimum risk when found
    if findings and risk < 65:
        risk = 65

    if not findings:
        risk = max(risk, 5)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_lateral_movement(siem_event: dict) -> dict:
    """Detect lateral movement: SMB admin shares, PsExec, WMI, SSH, etc."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0
    
    raw_lower = raw_log.lower()
    
    # SMB admin share access
    admin_share_patterns = [
        r'net use.*admin\$',
        r'\\[\d.]+\\(admin|c|d)\$',
        r'smb.*admin\$',
    ]
    for pattern in admin_share_patterns:
        if re.search(pattern, raw_lower):
            findings.append("SMB admin share access detected")
            risk += 30
            break
    
    # PsExec usage
    psexec_patterns = [
        r'psexec\.exe',
        r'psexec64\.exe',
        r'psexec.*-u.*-p',
        r'psexec.*\\\\[\d.]+',
    ]
    for pattern in psexec_patterns:
        if re.search(pattern, raw_lower):
            findings.append("PsExec remote execution detected")
            risk += 35
            break
    
    # WMI remote execution
    wmi_patterns = [
        r'wmic.*\/node:',
        r'wmic.*process call create',
    ]
    for pattern in wmi_patterns:
        if re.search(pattern, raw_lower):
            findings.append("WMI remote execution detected")
            risk += 30
            break
    
    # Remote service creation
    if re.search(r'sc\\.exe.*\\\\[\d.]+.*create', raw_lower):
        findings.append("Remote service creation detected")
        risk += 35
    
    # SSH/SCP to internal hosts
    ssh_patterns = [
        r'ssh\s+\w+@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        r'scp.*\w+@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:',
    ]
    for pattern in ssh_patterns:
        if re.search(pattern, raw_lower):
            findings.append("SSH/SCP to remote host detected")
            risk += 20
            break
    
    # Extract IPs
    ips = extract_ipv4(raw_log)
    iocs.extend(ips)
    
    # Source and destination IP check
    src_ip = siem_event.get("source_ip", "")
    dst_ip = siem_event.get("destination_ip", "")
    
    if src_ip and not any(i.get("value") == src_ip for i in iocs):
        iocs.append(_make_ioc("ipv4", src_ip, raw_log))
    
    if dst_ip and not any(i.get("value") == dst_ip for i in iocs):
        iocs.append(_make_ioc("ipv4", dst_ip, raw_log))
    
    # Different source/destination indicates lateral movement
    if src_ip and dst_ip and src_ip != dst_ip:
        risk += 10
        findings.append(f"Cross-host activity: {src_ip} -> {dst_ip}")
    
    # Lateral movement requires minimum risk when indicators found
    if findings and risk >= 20 and risk < 55:
        risk = 55  # Ensure detection

    if not findings:
        risk = max(risk, 5)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_credential_access(siem_event: dict) -> dict:
    """Detect credential access: LSASS dump, mimikatz, credential theft, SAM extraction."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0

    raw_lower = raw_log.lower()

    # LSASS memory dump — primary credential theft technique
    lsass_patterns = [
        (r'\blsass\b', "LSASS process referenced", 25),
        (r'\bprocdump\b', "ProcDump tool detected — memory dump utility", 30),
        (r'\bcomsvcs\.dll\b', "comsvcs.dll MiniDump — LSASS dump technique", 40),
        (r'\bMiniDump\b', "MiniDump function referenced", 25),
        (r'\blsass[_.\s]*dump\b', "LSASS dump detected", 45),
    ]
    for pattern, description, score in lsass_patterns:
        if re.search(pattern, raw_lower if pattern.islower() else raw_log):
            findings.append(description)
            risk += score

    # Mimikatz and credential tools
    tool_patterns = [
        (r'\bmimikatz\b', "Mimikatz detected — credential theft tool", 50),
        (r'\bsekurlsa\b', "Sekurlsa module — Mimikatz credential extraction", 45),
        (r'\blogonpasswords\b', "LogonPasswords — Mimikatz credential dump", 40),
        (r'\bkiwi\b', "Kiwi (Meterpreter Mimikatz) detected", 40),
        (r'\blazagne\b', "LaZagne credential recovery tool detected", 40),
        (r'\bcredential\s*dump\w*\b', "Credential dumping detected", 35),
        (r'\bcredential\s*(?:theft|steal|harvest|extract)\w*\b', "Credential theft language detected", 30),
    ]
    for pattern, description, score in tool_patterns:
        if re.search(pattern, raw_lower):
            findings.append(description)
            risk += score

    # SAM/NTDS/registry credential extraction
    registry_patterns = [
        (r'\bsam\s+(?:hive|database|dump|export|save)\b', "SAM database extraction", 35),
        (r'\bntds\.dit\b', "NTDS.dit — Active Directory credential database", 40),
        (r'\breg\s+save\s+hklm\\sam\b', "Registry SAM export — credential extraction", 40),
        (r'\breg\s+save\s+hklm\\system\b', "Registry SYSTEM export — for SAM decryption", 30),
        (r'\bvssadmin.*ntds\b', "Shadow copy for NTDS.dit extraction", 35),
    ]
    for pattern, description, score in registry_patterns:
        if re.search(pattern, raw_lower):
            findings.append(description)
            risk += score

    # DCSync
    if re.search(r'\bdcsync\b', raw_lower):
        findings.append("DCSync attack — replicating domain credentials")
        risk += 50
    if re.search(r'\bds-replication\b', raw_lower) or re.search(r'\bGetNCChanges\b', raw_log):
        findings.append("Directory replication request — possible DCSync")
        risk += 35

    # Kerberos credential attacks
    kerberos_patterns = [
        (r'\bpass.the.hash\b', "Pass-the-Hash technique detected", 40),
        (r'\boverpass.the.hash\b', "Overpass-the-Hash technique detected", 40),
        (r'\bcredential\s+access\b', "Credential access activity", 20),
    ]
    for pattern, description, score in kerberos_patterns:
        if re.search(pattern, raw_lower):
            findings.append(description)
            risk += score

    # IOCs
    ips = extract_ipv4(raw_log)
    iocs.extend(ips)

    src_ip = siem_event.get("source_ip", "")
    if src_ip and not any(i["value"] == src_ip for i in iocs):
        iocs.append(_make_ioc("ipv4", src_ip, raw_log))

    username = siem_event.get("username", "")
    if username:
        iocs.append(_make_ioc("username", username, raw_log))

    # LSASS + tool = high confidence
    has_lsass = any("LSASS" in f or "lsass" in f.lower() for f in findings)
    has_tool = any(kw in " ".join(findings).lower() for kw in
                   ["mimikatz", "procdump", "sekurlsa", "comsvcs", "lazagne", "kiwi"])
    if has_lsass and has_tool:
        risk = max(risk, 85)

    # Any tool detection = moderate confidence
    if has_tool and risk < 70:
        risk = max(risk, 70)

    if not findings:
        risk = max(risk, 5)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_supply_chain(siem_event: dict) -> dict:
    """Detect supply chain compromise: package tampering, hash mismatch,
    CI/CD compromise, dependency confusion, typosquatting, download-and-execute."""
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0

    raw_lower = raw_log.lower()

    # Package manager keywords with suspicious activity
    pkg_mgr_patterns = [
        (r'\b(?:npm|pip|gem|nuget|maven|cargo|composer|yarn)\s+(?:install|add|update)\b', "Package manager install detected", 10),
        (r'\bpostinstall\b', "Post-install script execution — supply chain risk", 30),
        (r'\bsetup\.py\b', "setup.py execution detected", 20),
        (r'\bbuild\.gradle\b', "Gradle build file reference", 10),
        (r'\bpackage\.json\b', "package.json modification detected", 10),
    ]
    for pattern, description, score in pkg_mgr_patterns:
        if re.search(pattern, raw_lower):
            findings.append(description)
            risk += score

    # Hash/checksum mismatch
    hash_patterns = [
        (r'\b(?:sha256|sha1|md5|checksum)\s*mismatch\b', "Hash mismatch detected — possible tampered package", 45),
        (r'\bintegrity\s+(?:violation|check\s+failed|error)\b', "Integrity check failed", 40),
        (r'\bexpected\s+[a-f0-9]{64}\b', "Expected SHA256 hash comparison", 20),
        (r'\bsignature\s+(?:invalid|verification\s+failed|mismatch)\b', "Signature verification failed", 40),
    ]
    for pattern, description, score in hash_patterns:
        if re.search(pattern, raw_lower):
            findings.append(description)
            risk += score

    # Download-and-execute (curl|bash, wget|sh)
    dl_exec_patterns = [
        (r'\bcurl\b[^\n]{0,100}\|\s*(?:ba)?sh\b', "curl|bash download-and-execute", 40),
        (r'\bwget\b[^\n]{0,100}\|\s*(?:ba)?sh\b', "wget|sh download-and-execute", 40),
        (r'\bcurl\b[^\n]{0,100}-o\s+/tmp/', "curl download to /tmp — suspicious", 30),
        (r'\bpython\s+-c\s+["\x27]import\s+(?:urllib|requests)\b', "Python download script execution", 30),
    ]
    for pattern, description, score in dl_exec_patterns:
        if re.search(pattern, raw_lower):
            findings.append(description)
            risk += score

    # CI/CD compromise indicators
    cicd_patterns = [
        (r'\b(?:pipeline|build\s+server|ci[/-]cd|jenkins|github\s+actions?|gitlab\s+ci)\b', "CI/CD system referenced", 15),
        (r'\bartifact\s+(?:tamper|modif|replac)\w*\b', "Build artifact tampering detected", 35),
        (r'\bregistry\s+(?:poison|inject|compromise)\w*\b', "Package registry compromise detected", 40),
        (r'\bunauthorized\s+(?:commit|push|merge|deploy)\b', "Unauthorized CI/CD change detected", 30),
    ]
    for pattern, description, score in cicd_patterns:
        if re.search(pattern, raw_lower):
            findings.append(description)
            risk += score

    # Dependency confusion
    dep_confusion_patterns = [
        (r'\b(?:internal|private)\s+package\b', "Internal package reference — potential confusion target", 20),
        (r'\bpublic\s+registry\b', "Public registry reference", 10),
        (r'\bdependency\s+confusion\b', "Dependency confusion attack detected", 45),
        (r'\btyposquat\w*\b', "Typosquatting detected", 40),
    ]
    for pattern, description, score in dep_confusion_patterns:
        if re.search(pattern, raw_lower):
            findings.append(description)
            risk += score

    # Known supply chain attack tools/incidents
    known_patterns = [
        (r'\b(?:codecov|ua-parser|event-stream|flatmap-stream|rest-client)\b', "Known supply chain compromise package", 50),
        (r'\bsupply.chain\b', "Supply chain attack language detected", 25),
        (r'\bbackdoor\w*\s+(?:in|via|through)\s+(?:package|dependency|library)\b', "Backdoor via dependency detected", 45),
    ]
    for pattern, description, score in known_patterns:
        if re.search(pattern, raw_lower):
            findings.append(description)
            risk += score

    # IOCs
    urls = extract_urls(raw_log)
    iocs.extend(urls)
    domains = extract_domains(raw_log)
    iocs.extend(domains)
    ips = extract_ipv4(raw_log)
    iocs.extend(ips)

    src_ip = siem_event.get("source_ip", "")
    if src_ip and not any(i.get("value") == src_ip for i in iocs):
        iocs.append(_make_ioc("ipv4", src_ip, raw_log))

    # Multiple indicators compound
    if len(findings) >= 2 and risk < 65:
        risk = 65

    if not findings:
        risk = max(risk, 5)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}


def detect_powershell_obfuscation(siem_event: dict) -> dict:
    """Detect PowerShell obfuscation: -EncodedCommand, base64-decoded IEX/Invoke-Expression,
    download cradles, and off-hours execution boost.

    Closes the lolbin_abuse gap from the 1000-alert benchmark where novel
    PowerShell -enc variants were scoring 15 instead of being flagged as attacks.
    """
    raw_log = siem_event.get("raw_log", "")
    findings = []
    iocs = []
    risk = 0

    raw_lower = raw_log.lower()

    # PowerShell encoded command — primary indicator
    is_encoded = bool(re.search(
        r'powershell(?:\.exe)?\s+[^\n]{0,200}-(?:enc(?:oded(?:command)?)?|e)\b',
        raw_lower,
    ))
    if is_encoded:
        findings.append("PowerShell -EncodedCommand detected (base64 payload)")
        risk += 75

    # Try to base64-decode any long base64 strings in the raw log and check
    # for IEX / Invoke-Expression / DownloadString / Net.WebClient patterns.
    # The smoking gun: encoded payload that decodes to a download cradle.
    decoded_iex = False
    decoded_download = False
    try:
        import base64 as _b64
        # Find base64-looking strings of >=20 chars (likely real payloads)
        for match in re.finditer(r'[A-Za-z0-9+/]{20,}={0,2}', raw_log):
            blob = match.group(0)
            # Pad to multiple of 4 for safe decode
            pad = (-len(blob)) % 4
            try:
                decoded = _b64.b64decode(blob + ('=' * pad), validate=False)
                # PowerShell -enc uses UTF-16LE — also try plain UTF-8
                for enc in ('utf-16-le', 'utf-8'):
                    try:
                        text = decoded.decode(enc, errors='ignore')
                        if not text:
                            continue
                        text_lower = text.lower()
                        if re.search(r'\b(?:iex|invoke-expression)\b', text_lower):
                            decoded_iex = True
                        if re.search(
                            r'(?:downloadstring|downloadfile|net\.webclient|invoke-webrequest|start-bitstransfer)',
                            text_lower,
                        ):
                            decoded_download = True
                        if decoded_iex or decoded_download:
                            break
                    except Exception:
                        continue
                if decoded_iex or decoded_download:
                    break
            except Exception:
                continue
    except Exception:
        pass

    if decoded_iex:
        findings.append("Base64-decoded payload reveals IEX/Invoke-Expression — code execution")
        risk = max(risk, 90)
    if decoded_download:
        findings.append("Base64-decoded payload reveals download cradle (Net.WebClient/DownloadString)")
        risk = max(risk, 90)

    # Plain-text IEX / download cradle in the raw log (no decoding needed)
    if re.search(r'\b(?:iex|invoke-expression)\b', raw_lower):
        findings.append("PowerShell IEX (Invoke-Expression) detected")
        risk = max(risk, 70)
    if re.search(r'\bnew-object\s+(?:net\.webclient|system\.net\.webclient)\b', raw_lower):
        findings.append("PowerShell Net.WebClient download cradle detected")
        risk = max(risk, 75)
    if re.search(r'\bdownloadstring\s*\(\s*["\x27]https?://', raw_lower):
        findings.append("PowerShell DownloadString from URL — remote code fetch")
        risk = max(risk, 80)
    if re.search(r'\b(?:start-bitstransfer|invoke-webrequest)\b[^\n]{0,200}https?://', raw_lower):
        findings.append("PowerShell remote download via BITS or Invoke-WebRequest")
        risk = max(risk, 70)

    # Other obfuscation techniques
    if re.search(r'\b-(?:nop|noprofile)\b', raw_lower):
        findings.append("PowerShell -NoProfile flag (evasion)")
        risk += 5
    if re.search(r'\b-(?:w(?:indowstyle)?\s+hidden|windowstyle\s+hidden)\b', raw_lower):
        findings.append("PowerShell -WindowStyle Hidden (evasion)")
        risk += 5
    if re.search(r'\b-(?:exec(?:utionpolicy)?|ep)\s+bypass\b', raw_lower):
        findings.append("PowerShell ExecutionPolicy Bypass (evasion)")
        risk += 5
    if re.search(r'\bfromBase64String\b', raw_log):
        findings.append("FromBase64String inline decode (obfuscation)")
        risk += 10

    # Off-hours execution boost — combined with -enc this is the highest signal
    is_off_hours = bool(re.search(
        r'\b(?:off.hours|after.hours|night|weekend|0[0-5]:\d{2}|02:\d{2}|03:\d{2}|04:\d{2})\b',
        raw_lower,
    ))
    if is_off_hours and is_encoded:
        findings.append("Off-hours encoded PowerShell execution — high-confidence attack")
        risk = max(risk, 95)
    elif is_off_hours and findings:
        findings.append("Off-hours execution adds suspicion")
        risk += 10

    # IOCs
    ips = extract_ipv4(raw_log)
    iocs.extend(ips)
    urls = extract_urls(raw_log)
    iocs.extend(urls)
    domains = extract_domains(raw_log)
    iocs.extend(domains)

    src_ip = siem_event.get("source_ip", "")
    if src_ip and not any(i.get("value") == src_ip for i in iocs):
        iocs.append(_make_ioc("ipv4", src_ip, raw_log))

    username = siem_event.get("username", "")
    if username:
        iocs.append(_make_ioc("username", username, raw_log))

    if not findings:
        risk = max(risk, 5)

    return {"findings": findings, "iocs": iocs, "risk_score": min(100, risk)}
