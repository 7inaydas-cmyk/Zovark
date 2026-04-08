# How Zovark Works: From Alert to Verdict

## The Big Picture

Imagine a massive hospital with thousands of doors, windows, and hallways. Every second, sensors on those doors report: "Door 7B opened," "Window 14A rattled," "Hallway camera saw movement." Most of this is perfectly normal -- nurses walking, wind blowing, patients moving around. But somewhere in the flood of reports, a few are genuinely dangerous: someone picking a lock, someone propping open a fire exit, someone in a restricted area.

That is exactly what a Security Operations Center (SOC) faces every day. Thousands of alerts pour in from firewalls, servers, email gateways, and endpoint sensors. Zovark is the autonomous investigator that sorts through all of them, runs a full investigation on each one, and delivers a verdict: "This is a real attack," "This is routine noise," or "A human analyst needs to look at this."

Here is what happens from the moment an alert arrives to the moment a verdict appears on the dashboard.

---

## The Three Bouncers at the Door (Burst Protection)

Before an alert even enters the investigation pipeline, it passes through three layers of protection that prevent the system from being overwhelmed during an alert storm -- say, a firewall suddenly generating 10,000 alerts in one minute.

**Bouncer 1 -- The Dedup Check (Layer 1).** Think of this as the bouncer who checks the guest list. If the same alert already came in five minutes ago and was investigated, there is no reason to investigate it again. The bouncer checks a fast lookup table (Valkey/Redis) and says "Already handled, move along." But if the new alert is *more severe* than the one already investigated, the bouncer lets it through -- because a higher-severity version deserves fresh eyes.

**Bouncer 2 -- The Batch Buffer (Layer 2).** Picture a receptionist who groups visitors by appointment type. If 500 alerts all say "failed login from the same IP address" within five seconds, there is no point running 500 separate investigations. The batch buffer groups them into one representative alert, keeping the highest severity among them. One investigation covers all 500.

**Bouncer 3 -- The Backpressure Throttle (Layer 3).** This is the fire marshal who says "the room is full." If there are already 200 investigations queued up, new alerts go into a waiting line. If the queue hits 1,000, the system starts telling the SIEM "slow down" with a 503 response. A background worker drains the queue at a safe pace.

These three layers mean Zovark can handle massive alert storms without choking, while still ensuring every genuinely new or escalated alert gets investigated.

---

## Stage 1: INGEST -- The Intake Desk

Once an alert passes the bouncers, it arrives at the intake desk. This stage does not use any AI -- it is purely mechanical, like a hospital admissions clerk who fills out the standard form regardless of the patient.

First, the alert gets **sanitized**. Zovark scrubs it against 25 known injection patterns -- things an attacker might embed in an alert to try to trick the AI later. Think of it as an X-ray machine at the front door: any concealed weapons (template injections, code injections, Unicode tricks) get confiscated before the alert goes further.

Next, the alert is **normalized**. Different SIEM systems (Splunk, Elastic, firewalls) all format their alerts differently. One might call the attacker's address `src_ip`, another `source_address`, another `SrcAddr`. Zovark maps over 70 different field names to a common format, so the rest of the pipeline always knows where to find the source IP, the username, the timestamp, and so on.

Then a **content scan** runs 70 attack patterns against the raw log data. Even if the alert metadata looks harmless (like "Windows Update"), the content scanner checks whether the actual log contains attack commands. This prevents an attacker from disguising a real attack with an innocent-sounding alert title.

Finally, the alert gets a **skill tag** -- Zovark looks at what kind of alert this is (brute force? phishing? ransomware?) and figures out which investigation playbook to use. If the alert type matches one of 24 pre-built investigation plans, that plan gets attached. If not, the alert is flagged for the AI to figure out.

---

## Stage 2: ANALYZE -- The Detective Picks Up the Case

Now the actual investigation planning begins. There are two paths, and the choice between them is critical for speed.

**Path A -- The Experienced Detective (Saved Plan).** For 24 well-known attack types, Zovark already has a detailed investigation plan written by security experts. When a brute-force alert arrives, Zovark does not need to think -- it grabs the "brute force investigation plan" off the shelf. This takes about 5 milliseconds, uses zero AI, and produces a step-by-step list of tools to run. Think of it as a detective who has investigated 500 burglaries and has a checklist memorized.

**Path C -- The AI Consultant.** For novel or unusual alerts that do not match any saved plan, Zovark asks the on-board AI model (Gemma 4 E4B, running locally with no internet connection) to look at the alert and choose which tools to run from the catalog of 40. This takes about 30 seconds but ensures even never-before-seen attacks get investigated. Think of it as calling in a specialist consultant for an unusual case.

The key insight: Path A handles the vast majority of alerts instantly. Path C is the safety net for everything else.

---

## Stage 3: EXECUTE -- Running the Investigation

Now the tools run. Zovark has 40 investigation tools organized into six categories:

- **Extraction tools** pull out IP addresses, domain names, file hashes, email addresses, and other indicators from the raw log data.
- **Analysis tools** calculate things like entropy (randomness -- high entropy in a domain name suggests it was computer-generated, not human-typed).
- **Parsing tools** break down specific log formats (Windows Event Logs, syslog, authentication logs) into structured data.
- **Scoring tools** apply specialized risk formulas for specific attack types (brute force, phishing, lateral movement).
- **Detection tools** look for specific attack signatures (Kerberoasting, ransomware, DNS exfiltration -- 12 specialized detectors).
- **Enrichment tools** add context: mapping the attack to the MITRE ATT&CK framework, checking against known-bad indicators, and pulling in institutional knowledge from past investigations.

The tools run in sequence according to the plan from Stage 2. Each tool's output becomes a variable that later tools can reference. For example, Step 1 might extract all IP addresses, and Step 3 might check those IPs against a known-bad list. This is like a relay race where each runner hands the baton to the next.

If any tool fails, it is isolated -- the rest of the investigation continues with whatever data is available. No single tool failure can crash the whole investigation.

---

## Stage 4: ASSESS -- The Verdict

This is where Zovark makes its judgment. The assessment stage looks at everything the tools found and produces a structured verdict.

First, a **signal boost** pass runs 11 patterns looking for high-confidence attack indicators (SQL injection strings, cross-site scripting, path traversal). If these show up in the data, the risk score gets a bump.

Next, **IOC extraction** pulls out every Indicator of Compromise -- malicious IPs, suspicious domains, file hashes -- and tags each one with an evidence reference pointing back to the exact log line it came from. This is like a prosecutor citing the specific page of evidence for every claim.

The AI model then generates a **plain-English summary** and a **risk score** from 0 to 100. The summary is written for a Level 1 analyst who needs to understand in 30 seconds what happened and why it matters.

Finally, every finding is mapped to the **MITRE ATT&CK framework** -- the industry-standard catalog of attacker techniques. This tells the analyst not just "something bad happened" but "the attacker used technique T1110 (Brute Force) in the Credential Access phase."

The output is a structured verdict: findings, IOCs with evidence, risk score, verdict label (true_positive, benign, suspicious, needs_manual_review), MITRE techniques, and the plain-English summary.

---

## Stage 4.5: GOVERN -- The Autonomy Slider

Between assessment and storage, a governance check determines how much autonomy Zovark has. This is configurable per tenant and per alert type:

- **Observe mode** (default): Every investigation is flagged for human review. Zovark investigates but an analyst always has the final say.
- **Assist mode**: Only non-benign results need human review. Routine "all clear" verdicts go straight through.
- **Autonomous mode**: Only edge cases (inconclusive results, errors) get flagged. Everything else is handled automatically.

Think of this as the dial between "training wheels" and "full autopilot." New customers start in observe mode and gradually turn up autonomy as they build trust.

---

## Stage 5: STORE -- Filing the Report

Every investigation result is written to the database with `synchronous_commit` -- meaning PostgreSQL confirms the data is safely on disk before moving on. No investigation result is ever lost to a crash.

The results go into several tables: the main task record (`agent_tasks`), the full investigation details (`investigations`), an audit trail (`audit_events`), and the entity graph.

**The Entity Graph** deserves special attention. Every IP address, domain, username, file hash, and other indicator extracted during the investigation becomes a **node** in a graph. Relationships between them become **edges**. Over time, this builds a map of attacker infrastructure: "This IP talked to this domain, which was contacted by this user, who also logged in from this other IP." Analysts can explore this graph visually to see connections that no single alert would reveal.

For multi-tenant deployments, entities can be correlated across tenants using SHA-256 hashes -- so if two different customers are being attacked by the same IP, Zovark can flag the connection without either customer seeing the other's raw data.

After storage, a PostgreSQL `NOTIFY` fires, which triggers a Server-Sent Events (SSE) push to the dashboard. The analyst sees the verdict appear in real time -- no page refresh needed.

---

## The Finish Line

From the analyst's perspective, here is what they see: an alert appears on the dashboard with a colored severity badge. Within seconds (for known attack types) or about 30 seconds (for novel ones), the investigation completes. The verdict panel shows the risk score, the verdict label, a plain-English summary, extracted IOCs with evidence links, and MITRE ATT&CK mappings. If governance says human review is needed, there is an "Approve / Reject" button. If not, the verdict is already final.

The entire journey -- from SIEM alert to analyst-ready verdict -- typically takes under 3 seconds for known patterns and under 30 seconds for novel threats. No alert is ignored. No investigation is skipped. And every decision is auditable, traceable, and explainable.

That is how Zovark works.
