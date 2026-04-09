#!/usr/bin/env python3
"""Zovark 200-Benign Calibration Test. Runs inside worker container."""
import json, time, sys, subprocess
import urllib.request, urllib.error

API = "http://api:8090"

def login():
    data = json.dumps({"email": "admin@test.local", "password": "TestPass2026"}).encode()
    req = urllib.request.Request(f"{API}/api/v1/auth/login", data=data, headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=10).read())["token"]

token = login()
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
print(f"Authenticated.\n")

users = ["j.smith","a.jones","m.wilson","r.taylor","s.brown","k.davis","l.garcia","p.miller","t.anderson","d.thomas"]

ALERTS = []
# 20 categories × 10 each = 200
cats = [
    ("password_change", "PasswordChange", "Password Changed for {u}", "EventID=4724 TargetUser={u} Status=Success"),
    ("certificate_renewal", "CertRenewal", "SSL Cert Renewed {h}", "Certificate renewed CN={h} issuer=CorpCA"),
    ("windows_update", "WindowsUpdate", "KB50{n} Installed", "KB50{n} installed on WS-PC{i:03d}"),
    ("scheduled_backup", "ScheduledTask", "Backup Completed", "Daily backup: {n}GB written Status=Success"),
    ("ntp_sync", "Heartbeat", "NTP Sync", "NTP sync offset=0.00{i}s stratum=2 Status=Success"),
    ("health_check", "HealthCheck", "Health Check OK", "HTTP 200 /health latency={n}ms uptime=99.99pct"),
    ("service_restart", "Maintenance", "{svc} Restarted", "{svc} restarted during maintenance window"),
    ("log_rotation", "LogRotation", "Log Rotated", "Rotated /var/log/{lf}: {n}MB archived"),
    ("av_update", "AVUpdate", "AV Updated", "Defender definitions updated to 1.407.{n}.0"),
    ("gpo_refresh", "GPORefresh", "GPO Refresh", "GPO refresh for OU={ou},DC=corp,DC=local"),
    ("dhcp_lease", "DHCP", "DHCP Lease", "DHCP lease renewed 10.0.2.{i}"),
    ("dns_cache_flush", "DNSMaintenance", "DNS Cache Flushed", "DNS cache flushed: {n} records cleared"),
    ("user_login", "LoginSuccess", "Login {u}", "EventID=4624 LogonType=10 User={u} Status=Success"),
    ("print_job", "PrintEvent", "Print Job", "Print completed: {u} printed Report.pdf pages=12"),
    ("disk_space", "DiskMonitor", "Disk Space", "Disk usage /data: {n}% on srv-{i}"),
    ("app_deployment", "Deployment", "Deployed {app}", "Deployed {app}:v2.{i}.0 replicas=3 status=Running"),
    ("vpn_connect", "VPNConnect", "VPN Connected {u}", "VPN established: user={u} src=203.0.113.{i}"),
    ("email_delivery", "MailDelivery", "Email Delivered", "Delivered: from={u}@corp.local to=partner@ext.com"),
    ("db_maintenance", "DBMaintenance", "DB {op}", "PostgreSQL {op} completed duration={n}ms"),
    ("ssh_key_rotation", "KeyRotation", "SSH Key Rotated {su}", "SSH key rotated user={su} keytype=ed25519"),
]

svcs = ["nginx","apache","postgres","redis","temporal","grafana","prometheus","caddy","vault","consul"]
lfs = ["syslog","auth.log","access.log","app.log","audit.log","messages","kern.log","cron.log","mail.log","daemon.log"]
ous = ["Workstations","Servers","Developers","HR","Finance","IT","Marketing","Sales","Executive","Contractors"]
apps = ["webapp","api-svc","auth-svc","payment","notify","analytics","dashboard","scheduler","worker","gateway"]
ops = ["VACUUM","ANALYZE","REINDEX","CHECKPOINT","AUTOVACUUM"]*2
sus = ["deploy","ansible","jenkins","terraform","admin","backup","monitoring","puppet","chef","saltstack"]
hosts = [f"web{i}.corp.local" for i in range(10)]

for cat_idx, (tt, rn, title_tpl, log_tpl) in enumerate(cats):
    for i in range(10):
        title = title_tpl.format(u=users[i], h=hosts[i], n=25000+cat_idx*10+i, svc=svcs[i], lf=lfs[i],
                                  ou=ous[i], app=apps[i], op=ops[i], su=sus[i], i=100+i)
        raw_log = log_tpl.format(u=users[i], h=hosts[i], n=100+cat_idx*10+i, svc=svcs[i], lf=lfs[i],
                                  ou=ous[i], app=apps[i], op=ops[i], su=sus[i], i=100+i)
        ALERTS.append({"task_type": tt, "input": {"prompt": "Routine", "severity": "low",
            "siem_event": {"title": title, "source_ip": f"10.0.{cat_idx}.{i+1}",
                           "username": users[i] if i < len(users) else "SYSTEM",
                           "rule_name": rn, "raw_log": raw_log}}})

assert len(ALERTS) == 200, f"Expected 200, got {len(ALERTS)}"
print(f"Submitting 200 benign alerts across 20 categories...\n")

errors = 0
for i, alert in enumerate(ALERTS):
    if i % 10 == 0 and i > 0:
        try: token = login(); headers["Authorization"] = f"Bearer {token}"
        except: pass
    try:
        data = json.dumps(alert).encode()
        req = urllib.request.Request(f"{API}/api/v1/tasks", data=data, headers=headers)
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        errors += 1
    if (i+1) % 50 == 0:
        print(f"  Submitted {i+1}/200 ({errors} errors)")
        time.sleep(3)

print(f"\nAll 200 submitted ({errors} errors). Waiting for processing...\n")

# Poll DB directly via psycopg2 (available in worker container)
import psycopg2
conn = psycopg2.connect("postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")

for elapsed in range(30, 901, 30):
    time.sleep(30)
    with conn.cursor() as cur:
        cur.execute("SELECT status, count(*) FROM agent_tasks WHERE created_at > NOW() - INTERVAL '30 minutes' GROUP BY status")
        rows = dict(cur.fetchall())
    done = rows.get("completed", 0)
    pending = rows.get("pending", 0)
    failed = rows.get("failed", 0)
    print(f"  [{elapsed}s] completed={done} pending={pending} failed={failed}")
    if done >= 195 and pending == 0:
        break

# Results
print(f"\n{'='*65}")
print(f"   ZOVARK 200-BENIGN CALIBRATION RESULTS")
print(f"{'='*65}\n")

with conn.cursor() as cur:
    cur.execute("""
        SELECT output->>'verdict' as verdict, count(*) as cnt,
               round(avg((output->>'risk_score')::numeric),1) as avg_risk,
               min((output->>'risk_score')::numeric)::int as min_risk,
               max((output->>'risk_score')::numeric)::int as max_risk
        FROM agent_tasks WHERE created_at > NOW() - INTERVAL '30 minutes'
        AND status = 'completed' GROUP BY output->>'verdict' ORDER BY cnt DESC
    """)
    print("VERDICT DISTRIBUTION:")
    print(f"  {'verdict':<25} {'count':>6} {'avg_risk':>9} {'min':>5} {'max':>5}")
    print(f"  {'-'*55}")
    for row in cur.fetchall():
        print(f"  {row[0] or 'NULL':<25} {row[1]:>6} {row[2]:>9} {row[3]:>5} {row[4]:>5}")

    cur.execute("""
        SELECT task_type, (output->>'risk_score')::int as risk, output->>'verdict' as verdict
        FROM agent_tasks WHERE created_at > NOW() - INTERVAL '30 minutes'
        AND status = 'completed' AND (output->>'risk_score')::int > 35
        ORDER BY risk DESC LIMIT 20
    """)
    fps = cur.fetchall()
    if not fps:
        print(f"\n  ZERO FALSE POSITIVES — all benign scored <= 35")
    else:
        print(f"\n  FALSE POSITIVES (risk > 35):")
        for fp in fps:
            print(f"    {fp[0]}: risk={fp[1]}, verdict={fp[2]}")
        print(f"\n  FP count: {len(fps)}/200 ({len(fps)/2:.1f}%)")

    cur.execute("""
        SELECT task_type, count(*) as total,
               count(*) FILTER (WHERE output->>'verdict'='benign') as benign,
               count(*) FILTER (WHERE output->>'verdict'!='benign') as not_benign,
               round(avg((output->>'risk_score')::numeric),0) as avg_risk
        FROM agent_tasks WHERE created_at > NOW() - INTERVAL '30 minutes'
        AND status = 'completed' GROUP BY task_type ORDER BY not_benign DESC, avg_risk DESC
    """)
    print(f"\nBY CATEGORY:")
    print(f"  {'task_type':<25} {'total':>6} {'benign':>7} {'!benign':>8} {'avg_risk':>9}")
    print(f"  {'-'*58}")
    for row in cur.fetchall():
        flag = " <-- FP" if row[3] > 0 else ""
        print(f"  {row[0]:<25} {row[1]:>6} {row[2]:>7} {row[3]:>8} {row[4]:>9}{flag}")

conn.close()
print(f"\n{'='*65}")
