# Every Investigation Plan in Zovark (All 24)

Investigation plans are Zovark's playbooks. When an alert arrives and matches a known attack type, Zovark loads the matching plan and runs its tools in order -- no AI needed, no delay. Each plan is a precise sequence of tools designed to investigate one specific type of attack.

Think of plans like recipes: the same ingredients (tools) appear across many recipes, but the order, combinations, and conditional logic change based on what you are cooking.

Plans live in `worker/tools/investigation_plans.json`. They run in about 5 milliseconds (plan loading, not counting tool execution), compared to 30+ seconds when the AI has to figure out which tools to use from scratch.

---

## 1. brute_force

**Triggers on:** brute_force, credential_stuffing, failed_login, auth_failure

**The investigation steps:**

1. **parse_auth_log** -- Read the raw authentication log and turn it into structured data (who tried to log in, from where, did it succeed or fail).
2. **extract_ipv4** -- Pull out all IP addresses from the log. These are the "who is knocking on the door" addresses.
3. **extract_usernames** -- Pull out all usernames that were targeted. Are they trying one account or many?
4. **count_pattern** -- Count how many "fail|denied|invalid|error|rejected" messages appear. This is the volume measurement.
5. **score_brute_force** -- Calculate the risk. Here Zovark uses conditional logic: if the failure count exceeds 50, it assumes a 60-minute attack window (more aggressive scoring); if under 50, it uses a 120-minute window (more lenient).
6. **correlate_with_history** -- Check if these IPs appeared in previous investigations over the last 72 hours.
7. **map_mitre** -- Tag with MITRE ATT&CK: T1110 (Brute Force), T1110.001 (Password Guessing), T1110.003 (Password Spraying).

**Expected outcome:** A verdict with the number of failed attempts, attacking IPs, targeted accounts, risk score, and whether these IPs are repeat offenders.

**Example alert:** "500 failed SSH logins for root from 185.220.101.45 in 30 minutes."

---

## 2. phishing_investigation

**Triggers on:** phishing, phishing_email, phishing_url, spear_phishing, BEC

**The investigation steps:**

1. **extract_urls** -- Find all web links in the email or alert.
2. **extract_domains** -- Pull out all domain names for reputation checking.
3. **extract_emails** -- Find sender and recipient email addresses.
4. **detect_phishing** -- Run the phishing specialist detector on the full SIEM event.
5. **count_pattern (urgency)** -- Count urgency words: "urgent|immediate|verify account|suspend|expire|click here|act now."
6. **count_pattern (credentials)** -- Count credential-harvesting words: "login|password|credential|verify|secure login."
7. **score_phishing** -- Calculate the risk. Conditional logic: if credential keywords were found (step 6 > 0), assume credential form and urgency are present (higher score); otherwise, score without those factors.
8. **lookup_known_bad** -- Check the sender IP against known-bad threat intelligence.
9. **correlate_with_history** -- Check domains against previous investigations (7-day lookback -- phishing campaigns are persistent).
10. **map_mitre** -- Tag with T1566 (Phishing), T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link).

**Expected outcome:** A verdict identifying malicious URLs, typosquatted domains, credential harvesting attempts, and whether this is part of a known phishing campaign.

**Example alert:** "Email from ceo@acme-verify.xyz with link to credential form, subject: 'Urgent: Verify your account immediately.'"

---

## 3. ransomware_triage

**Triggers on:** ransomware, encryption, shadow_copy, vssadmin

**The investigation steps:**

1. **parse_windows_event** -- Parse the Windows Event Log since ransomware almost always runs on Windows.
2. **extract_ipv4** -- Find IPs involved (command-and-control, lateral movement sources).
3. **extract_hashes** -- Find file hashes of the ransomware executable.
4. **detect_ransomware** -- Run the ransomware specialist detector: shadow copy deletion, mass encryption, ransom note creation.
5. **count_pattern** -- Count ransomware keywords: "vssadmin|shadow|encrypt|ransom|bcdedit|wbadmin|delete|cipher."
6. **lookup_known_bad** -- Check if the source IP is known malicious infrastructure.
7. **correlate_with_history** -- Check file hashes against recent investigations (24-hour lookback -- ransomware moves fast).
8. **map_mitre** -- Tag with T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1027 (Obfuscated Files).

**Expected outcome:** Immediate severity assessment -- is this active ransomware? Are backups being destroyed? What is the ransomware strain (via hash)?

**Example alert:** "Process vssadmin.exe delete shadows /all executed, followed by mass .encrypted file renaming."

---

## 4. data_exfiltration_detection

**Triggers on:** data_exfiltration, data_theft, large_transfer, exfil

**The investigation steps:**

1. **extract_ipv4** -- Find destination IPs where data is being sent.
2. **extract_domains** -- Find destination domains (Dropbox, Mega, custom C2).
3. **extract_urls** -- Find full URLs for upload endpoints.
4. **detect_encoding** -- Check if data is being encoded (base64, hex) to hide the theft.
5. **detect_data_exfil** -- Run the exfiltration specialist detector.
6. **score_exfiltration** -- Calculate risk based on volume, destination, timing, and encryption.
7. **correlate_with_history** -- Check destination IPs against past investigations (48-hour lookback).
8. **map_mitre** -- Tag with T1041 (Exfiltration Over C2), T1048 (Exfiltration Over Alternative Protocol), T1567 (Exfiltration Over Web Service).

**Expected outcome:** Assessment of whether data is actually leaving the organization, how much, where it is going, and whether the destination is known-bad.

**Example alert:** "Workstation sent 2.3GB to external IP 45.33.32.156 over encrypted channel at 2:17 AM."

---

## 5. privilege_escalation_hunt

**Triggers on:** privilege_escalation, sudo_abuse, UAC_bypass, token_manipulation

**The investigation steps:**

1. **parse_auth_log** -- Parse authentication events for privilege changes.
2. **extract_usernames** -- Identify which accounts are involved in the escalation.
3. **extract_ipv4** -- Find source IPs.
4. **count_pattern** -- Count privilege escalation keywords: "sudo|su|UAC|privilege|escalat|suid|setuid|token|impersonat|SeDebugPrivilege."
5. **detect_com_hijacking** -- Check for COM object hijacking (registry-based persistence).
6. **detect_token_impersonation** -- Check for RunAs abuse and token theft.
7. **detect_appcert_dlls** -- Check for AppCert DLL persistence.
8. **score_generic** -- Calculate risk based on the number of escalation indicators found.
9. **correlate_with_history** -- Check usernames against past investigations (48-hour lookback).
10. **map_mitre** -- Tag with T1548 (Abuse Elevation Control), T1068 (Exploitation for Privilege Escalation), T1134 (Access Token Manipulation), T1078 (Valid Accounts), T1546.015 (COM Hijacking), T1546.009 (AppCert DLLs), T1134.001 (Token Impersonation).

**Expected outcome:** Identification of the escalation method, whether persistence was established, and which accounts are compromised.

**Example alert:** "User jsmith executed runas /savecred /user:DOMAIN\admin cmd.exe from 10.0.0.55."

---

## 6. c2_communication_hunt

**Triggers on:** c2, command_and_control, beacon, callback

**The investigation steps:**

1. **extract_ipv4** -- Find IPs the compromised host is contacting.
2. **extract_domains** -- Find domains being queried (potential C2 infrastructure).
3. **calculate_entropy** -- Measure the randomness of the contacted domain. High entropy = likely algorithmically generated.
4. **detect_c2** -- Run the C2 specialist detector.
5. **score_c2_beacon** -- Calculate risk based on connection regularity and domain randomness.
6. **lookup_known_bad** -- Check the source IP against threat intelligence.
7. **correlate_with_history** -- Check IPs against past investigations (7-day lookback -- C2 infrastructure is persistent).
8. **map_mitre** -- Tag with T1071 (Application Layer Protocol), T1095 (Non-Application Layer Protocol), T1573 (Encrypted Channel), T1105 (Ingress Tool Transfer).

**Expected outcome:** Determination of whether a host is actively communicating with an attacker, the C2 infrastructure details, and beacon pattern analysis.

**Example alert:** "Host 10.0.0.22 connecting to x7k2m9.update-service.biz every 60 seconds with 512-byte encoded payloads."

---

## 7. lateral_movement_detection

**Triggers on:** lateral_movement, psexec, wmi_remote, pass_the_hash

**The investigation steps:**

1. **parse_windows_event** -- Parse Windows events (lateral movement is primarily a Windows domain attack).
2. **extract_ipv4** -- Find source and destination IPs (attacker jumping between machines).
3. **extract_usernames** -- Identify the account being used to move laterally.
4. **count_pattern** -- Count lateral movement keywords: "psexec|wmi|winrm|admin$|ipc$|c$|pass.the.hash|ntlm|lateral|remote."
5. **detect_encoded_service** -- Check if the attacker is creating encoded services on remote machines.
6. **score_lateral_movement** -- Calculate risk. Conditional: if movement keywords were found, score with PsExec + admin share + remote exec + pass-the-hash all flagged; otherwise, score conservatively.
7. **correlate_with_history** -- Check IPs against past investigations (48-hour lookback).
8. **map_mitre** -- Tag with T1021 (Remote Services), T1021.002 (SMB/Admin Shares), T1021.006 (Windows Remote Management), T1550.002 (Pass the Hash), T1543.003 (Windows Service).

**Expected outcome:** Map of the attacker's movement across the network, which credentials they are using, and which machines are compromised.

**Example alert:** "PsExec service installed on 10.0.0.30 from 10.0.0.22 using DOMAIN\admin credentials."

---

## 8. insider_threat_detection

**Triggers on:** insider_threat, data_staging, bulk_access, off_hours_access

**The investigation steps:**

1. **extract_usernames** -- Identify the user under investigation.
2. **extract_ipv4** -- Find the IP addresses they are working from.
3. **extract_emails** -- Find any email addresses involved (forwarding data to personal email).
4. **count_pattern** -- Count data staging keywords: "download|copy|transfer|export|bulk|staging|archive|zip|tar|compress."
5. **detect_data_exfil** -- Run the exfiltration detector to check for actual data theft.
6. **score_exfiltration** -- Calculate risk based on data movement indicators.
7. **lookup_institutional_knowledge** -- Check the user against analyst baselines. Is this behavior normal for this person? This step is critical for insider threat because what is suspicious for one employee is routine for another.
8. **map_mitre** -- Tag with T1074 (Data Staged), T1114 (Email Collection), T1530 (Data from Cloud Storage), T1567 (Exfiltration Over Web Service).

**Expected outcome:** Assessment of whether the user's behavior is truly anomalous or matches their normal work patterns, with institutional context.

**Example alert:** "User jsmith accessed 500 files in the /finance/ share at 11:30 PM and compressed them into archive.zip."

---

## 9. network_beaconing

**Triggers on:** beaconing, dns_beacon, periodic_connection, heartbeat

**The investigation steps:**

1. **extract_ipv4** -- Find destination IPs.
2. **extract_domains** -- Find destination domains.
3. **parse_dns_query** -- Parse DNS query logs for the beaconing destination.
4. **calculate_entropy** -- Measure domain randomness.
5. **detect_c2** -- Run C2 detection (beaconing is a subset of C2).
6. **score_c2_beacon** -- Calculate risk with a 30-second average interval assumption (beaconing tends to be faster than general C2).
7. **correlate_with_history** -- Check IPs against past investigations (7-day lookback).
8. **map_mitre** -- Tag with T1071.001 (Web Protocols), T1071.004 (DNS), T1573 (Encrypted Channel).

**Expected outcome:** Confirmation of beaconing pattern, interval analysis, and C2 infrastructure identification.

**Example alert:** "Host making DNS queries to random subdomains of update-check.biz every 30 seconds."

---

## 10. cloud_infrastructure_attack

**Triggers on:** cloud_attack, iam_change, cloudtrail_tampering, resource_spike

**The investigation steps:**

1. **extract_ipv4** -- Find attacker IPs.
2. **extract_usernames** -- Find cloud accounts being used or targeted.
3. **extract_emails** -- Find email addresses associated with IAM changes.
4. **count_pattern** -- Count cloud attack keywords: "iam|cloudtrail|CreateUser|AttachPolicy|PutBucketPolicy|AssumeRole|ConsoleLogin|StopLogging|DeleteTrail."
5. **score_generic** -- Calculate risk based on indicator count.
6. **lookup_known_bad** -- Check source IPs against threat intelligence.
7. **correlate_with_history** -- Check IPs against past investigations (72-hour lookback).
8. **map_mitre** -- Tag with T1078.004 (Cloud Accounts), T1098 (Account Manipulation), T1562.008 (Disable Cloud Logs), T1537 (Transfer Data to Cloud Account).

**Expected outcome:** Assessment of cloud infrastructure changes, whether audit logging is being tampered with, and unauthorized IAM modifications.

**Example alert:** "IAM CreateUser and AttachAdministratorAccess from IP 45.33.32.156 with CloudTrail StopLogging 2 minutes later."

---

## 11. supply_chain_compromise

**Triggers on:** supply_chain, package_tampering, hash_mismatch, dependency_injection

**The investigation steps:**

1. **extract_hashes** -- Find file hashes to verify package integrity.
2. **extract_domains** -- Find package repository domains (PyPI, npm, etc.).
3. **extract_urls** -- Find download URLs for packages.
4. **count_pattern** -- Count supply chain keywords: "npm|pip|gem|nuget|maven|package|install|dependency|typosquat|hash.mismatch|checksum|CI|pipeline|build."
5. **lookup_known_bad** -- Check source IPs against threat intelligence.
6. **score_generic** -- Calculate risk based on indicator count.
7. **correlate_with_history** -- Check hashes against past investigations (7-day lookback -- supply chain attacks are slow-burn).
8. **map_mitre** -- Tag with T1195 (Supply Chain Compromise), T1195.001 (Compromise Software Dependencies), T1195.002 (Compromise Software Supply Chain).

**Expected outcome:** Verification of whether packages are legitimate, hash integrity checks, and identification of typosquatted or malicious dependencies.

**Example alert:** "Package 'reqeusts' (misspelled) installed from PyPI with hash mismatch against known good."

---

## 12. kerberoasting

**Triggers on:** kerberoasting, TGS_request, RC4_ticket, SPN_enumeration

**The investigation steps:**

1. **parse_windows_event** -- Parse the Kerberos event log.
2. **extract_usernames** -- Identify targeted service accounts.
3. **extract_ipv4** -- Find the attacking workstation's IP.
4. **detect_kerberoasting** -- Run the specialist detector for RC4 + TGS + SPN patterns.
5. **count_pattern** -- Count Kerberos-specific keywords: "0x17|RC4|TGS|kerberos|spn|service.ticket|4769."
6. **correlate_with_history** -- Check usernames against past investigations (48-hour lookback).
7. **map_mitre** -- Tag with T1558.003 (Kerberoasting).

**Expected outcome:** Identification of the attack, which service accounts are targeted, and whether RC4 (weak) encryption was requested.

**Example alert:** "Event 4769: TGS ticket requested for MSSQLSvc with EncryptionType=0x17 from workstation 10.0.0.55."

---

## 13. golden_ticket

**Triggers on:** golden_ticket, forged_TGT, abnormal_ticket_lifetime

**Steps:** parse_windows_event, extract_usernames, extract_ipv4, detect_golden_ticket, count_pattern (golden ticket keywords), correlate_with_history (72h), map_mitre (T1558.001).

**Expected outcome:** Detection of forged Kerberos tickets with abnormal lifetimes or encryption types.

**Example alert:** "Kerberos TGT with 10-year lifetime for user 'admin' using RC4 encryption."

---

## 14. dcsync

**Triggers on:** dcsync, directory_replication, DRSGetNCChanges

**Steps:** parse_windows_event, extract_ipv4, extract_usernames, count_pattern (DRSGetNCChanges|replication|DCSync|4662|mimikatz), score_generic, correlate_with_history (48h), map_mitre (T1003.006).

**Expected outcome:** Detection of unauthorized directory replication requests from non-domain-controller machines (a sign that an attacker is dumping all Active Directory passwords).

**Example alert:** "DRSGetNCChanges request from workstation 10.0.0.55 (not a domain controller)."

---

## 15. dll_sideloading

**Triggers on:** dll_sideloading, unsigned_dll, loadlibrary_abuse

**Steps:** parse_windows_event, extract_hashes, extract_ipv4, count_pattern (sideload|unsigned|dll|loadlibrary|appdata|temp), lookup_known_bad, score_generic, correlate_with_history (72h), map_mitre (T1574.002).

**Expected outcome:** Identification of unsigned DLLs being loaded from suspicious paths by legitimate applications.

**Example alert:** "Legitimate application loaded unsigned DLL from C:\Users\Public\Downloads\malware.dll."

---

## 16. lolbin_abuse

**Triggers on:** lolbin, certutil_download, mshta_execution, bitsadmin_abuse

**Steps:** parse_windows_event, extract_ipv4, extract_urls, detect_lolbin_abuse, count_pattern (certutil|mshta|bitsadmin|rundll32|regsvr32|cmstp|msiexec|wscript|cscript|forfiles|pcalua), score_generic, correlate_with_history (48h), map_mitre (T1218 and sub-techniques).

**Expected outcome:** Detection of legitimate Windows tools being abused for malicious purposes, with the specific download URL or execution command.

**Example alert:** "mshta.exe executing remote HTA file from https://evil.com/payload.hta."

---

## 17. process_injection

**Triggers on:** process_injection, CreateRemoteThread, memory_manipulation

**Steps:** parse_windows_event, extract_ipv4, extract_hashes, count_pattern (CreateRemoteThread|NtWriteVirtualMemory|VirtualAllocEx|lsass|inject|hollowing), score_generic, lookup_known_bad, correlate_with_history (48h), map_mitre (T1055, T1055.001, T1055.012).

**Expected outcome:** Detection of code injection into running processes, especially targeting lsass.exe (credential theft) or using process hollowing.

**Example alert:** "CreateRemoteThread call targeting lsass.exe from process mimikatz.exe."

---

## 18. wmi_lateral

**Triggers on:** wmi_lateral, Win32_Process, wmiprvse, wmic_remote

**Steps:** parse_windows_event, extract_ipv4, extract_usernames, count_pattern (wmi|Win32_Process|wmiprvse|wmic|process.call.create|DCOM|5857|5858|5861), score_lateral_movement (method=wmi, remote_exec=true), correlate_with_history (48h), map_mitre (T1047, T1021.003).

**Expected outcome:** Detection of WMI-based remote command execution across machines.

**Example alert:** "WMI process creation: wmic /node:10.0.0.30 process call create 'powershell -enc ...' from 10.0.0.22."

---

## 19. rdp_tunneling

**Triggers on:** rdp_tunnel, ssh_tunnel, port_forwarding, plink

**Steps:** extract_ipv4, extract_usernames, parse_auth_log, count_pattern (tunnel|plink|putty|ssh.*-L|ssh.*-R|rdp|3389|mstsc|reverse.forward|port.forward|netsh), score_generic, lookup_known_bad, correlate_with_history (72h), map_mitre (T1021.001, T1572).

**Expected outcome:** Detection of RDP tunneled through SSH or other port-forwarding tools, which lets attackers bypass firewall rules.

**Example alert:** "SSH tunnel established: ssh -L 3389:target-server:3389 attacker@jumpbox."

---

## 20. dns_exfiltration

**Triggers on:** dns_exfiltration, dns_tunnel, high_entropy_dns, TXT_abuse

**Steps:** parse_dns_query, extract_domains, extract_ipv4, detect_dns_exfiltration, count_pattern (TXT|dns|query|subdomain|nslookup|dig|high.entropy|tunnel), correlate_with_history (7-day lookback -- DNS exfil is slow and persistent), map_mitre (T1048.003, T1071.004).

**Expected outcome:** Detection of data being smuggled out via DNS queries, with entropy analysis of subdomains.

**Example alert:** "1,000 TXT queries to random subdomains of data-sync.biz in 10 minutes."

---

## 21. powershell_obfuscation

**Triggers on:** powershell_obfuscation, encoded_command, IEX, download_cradle, AMSI_bypass

**Steps:** parse_windows_event, check_base64 (decode any encoded payloads), detect_encoding, count_pattern (-enc|-encodedcommand|IEX|Invoke-Expression|Net.WebClient|DownloadString|FromBase64|bypass|amsi|ScriptBlock), detect_lolbin_abuse (PowerShell itself is a LOLBin), score_generic, correlate_with_history (48h), map_mitre (T1059.001, T1027, T1140).

**Expected outcome:** Decoded malicious PowerShell commands with the actual payload revealed, even if the attacker used base64 encoding or string concatenation to hide it.

**Example alert:** "PowerShell -enc SQBFAFgAIAAoAE4A... executed from cmd.exe."

---

## 22. credential_access

**Triggers on:** credential_access, credential_dump, lsass_dump, SAM_dump, keylogger

**Steps:** parse_auth_log, extract_usernames, extract_ipv4, extract_hashes, count_pattern (credential|password|lsass|mimikatz|procdump|SAM|NTDS|vault|keylog|dpapi|sekurlsa|hashdump), score_generic, correlate_with_history (72h), map_mitre (T1003, T1003.001, T1110, T1555).

**Expected outcome:** Detection of credential theft tools or techniques, identification of targeted credential stores, and assessment of how many accounts may be compromised.

**Example alert:** "Process procdump.exe accessing lsass.exe memory on server DC01."

---

## 23. api_key_abuse

**Triggers on:** api_key_abuse, unauthorized_api, token_leak, key_exposure

**Steps:** extract_ipv4, extract_emails, parse_http_request, count_pattern (api.key|token|bearer|authorization|unauthorized|403|401|rate.limit|key.exposed|secret), lookup_known_bad, score_generic, correlate_with_history (48h), map_mitre (T1552.004, T1528).

**Expected outcome:** Detection of API keys being used from unauthorized IPs, leaked tokens, and anomalous API call patterns.

**Example alert:** "API key for production service used from external IP 45.33.32.156 with 500 requests in 1 minute."

---

## 24. benign_system_event

**Triggers on:** 31 benign event types including password_change, windows_update, health_check, software_install, certificate_renewal, group_policy_update, backup_completed, and more.

**Steps (minimal):**

1. **extract_ipv4** -- Extract IPs for record-keeping only.
2. **score_generic** -- Score with zero indicators (result: risk ~0-15).

**Expected outcome:** Risk score of 0-15, verdict of "benign." This plan exists so that routine system events do not waste AI resources. It completes in about 5 milliseconds.

**Example alert:** "Windows Update KB5034441 installed successfully on SERVER01."

---

## How Plans Are Selected

When an alert arrives, Zovark matches it against plans in this order:

1. **Exact match** -- The alert's task_type matches a plan name directly (e.g., "brute_force" matches the brute_force plan).
2. **Alias match** -- 20 aliases map common SIEM names to plans (e.g., "phishing" maps to "phishing_investigation", "ransomware" maps to "ransomware_triage").
3. **Substring match** -- If the task_type contains a plan name as a substring.
4. **LLM fallback (Path C)** -- If no plan matches, the AI selects tools from the catalog. This is slower (2-10 seconds) but handles novel attack types.

The 24 plans cover the vast majority of real-world alerts. In benchmarks, over 90% of alerts match a saved plan and never need the AI for tool selection.
