# The Entity Graph -- Zovark's Institutional Memory

## What It Is

Imagine a detective's evidence board -- the kind with photos, string, and pushpins connecting suspects, locations, and events. Now imagine that board is shared across every investigation the detective has ever worked, and it automatically highlights connections between cases.

That is the entity graph. It is a memory that connects the dots between investigations.

Every IP address, domain name, username, file hash, and email address that Zovark encounters during an investigation becomes a permanent node in this graph. Every relationship between them -- "this IP logged into this username," "this domain resolved to this IP," "this process downloaded this file" -- becomes a connection (edge) between nodes.

Over time, as Zovark processes hundreds or thousands of alerts, the graph grows into a comprehensive map of every threat actor, infrastructure component, and attack pattern the organization has encountered. When a new alert arrives, Zovark checks the graph and instantly knows: "I have seen this IP before. It was involved in a supply chain compromise three days ago."

---

## The Three Tables

The entity graph is built on three database tables, each serving a distinct purpose.

### Entities (The Nodes)

The entities table stores every individual piece of evidence Zovark has ever encountered. Each row represents one "thing" -- an IP address, a domain, a username, a file hash, an email address, a device, or a process.

Key fields:
- **entity_type** -- What kind of thing it is: ip, domain, file_hash, url, user, device, process, or email.
- **value** -- The actual value, like "185.220.101.45" or "evil-login.com."
- **entity_hash** -- A SHA-256 fingerprint of the value, used for privacy-safe sharing across customers.
- **threat_score** -- A 0-100 rating that increases every time this entity appears in a malicious investigation and decreases when it appears in benign ones.
- **observation_count** -- How many times Zovark has seen this entity across all investigations. An IP seen in 50 investigations is much more significant than one seen once.
- **first_seen / last_seen** -- The time range, showing how long this entity has been active.

Think of each entity like a suspect card in a police file: name, photo, how many cases they have appeared in, and a danger rating.

### Entity Edges (The Connections)

The entity_edges table stores relationships between entities. Every edge says "entity A is connected to entity B in this specific way."

The relationship types tell a story:
- **communicates_with** -- An IP contacted another IP or domain (network traffic).
- **resolved_to** -- A domain name resolved to an IP address (DNS lookup).
- **logged_into** -- A source IP logged into a username (authentication).
- **executed** -- A process ran on a device (process execution).
- **downloaded** -- A process downloaded a file from a URL.
- **contains** -- A file or email contains another entity (e.g., email contains malicious URL).
- **parent_of** -- A process spawned another process.
- **accessed** -- A user accessed a resource.
- **sent_to / received_from** -- Email communication direction.
- **associated_with** -- A general association when the specific relationship is unclear.

Each edge also records which investigation discovered it, what MITRE ATT&CK technique it relates to, and a confidence score (how certain we are about this connection).

### Cross-Tenant Entities (Shared Intelligence)

The cross_tenant_entities table is where collective intelligence lives. When multiple customers encounter the same entity, this table aggregates the data without revealing which customers were involved.

Key fields:
- **entity_hash** -- Only the SHA-256 hash is stored. The raw value (like the actual IP address) is never shared across tenant boundaries.
- **tenant_count** -- How many different customers have seen this entity.
- **threat_score** -- The aggregate threat score across all customers.

This is privacy-preserving by design. If Hospital A and Defense Contractor B both encounter the same malicious IP, neither learns about the other's existence. They both simply see "this entity has been observed by multiple organizations with a high threat score."

---

## How Entities Get Created

Entities are created during the Store stage (Stage 5) of the investigation pipeline. Here is the flow:

1. An alert arrives and passes through Ingest, Analyze, Execute, and Assess.
2. The Assess stage produces a verdict with IOCs (Indicators of Compromise) -- the IPs, domains, hashes, and usernames found during the investigation.
3. The Store stage writes the investigation result to the database.
4. As part of the Store process, each IOC is checked against the entities table. If the entity already exists, its observation_count and last_seen are updated. If it is new, a new entity row is created.
5. Relationships between entities (edges) are inferred from the investigation context and stored in entity_edges.
6. If the entity's hash matches one in cross_tenant_entities, the cross-tenant record is updated with a new sighting count.

---

## How Relationships Are Inferred

When the Store stage processes an investigation, it looks at the IOCs and their context to create edges:

- If a **source_ip** and a **username** appear together in an auth log, an edge is created: source_ip --logged_into--> username.
- If a **source_ip** and a **hostname** appear together in network traffic, an edge is created: source_ip --communicates_with--> hostname.
- If a **domain** and an **IP** appear together in a DNS resolution, an edge is created: domain --resolved_to--> IP.
- If a **process** and a **file_hash** appear together, an edge is created: process --executed--> file_hash.

Each edge carries the investigation_id that created it, so you can always trace back to the original evidence.

---

## How the Graph Gets Queried

During the Execute stage (Stage 3), the **correlate_with_history** enrichment tool queries the entity graph. Here is what happens:

1. The investigation plan runs its extraction, analysis, and detection tools.
2. Near the end of the plan, correlate_with_history receives a list of IOC values found in the current investigation.
3. It searches the entities table for any of those values.
4. For each match, it looks up which previous investigations involved that entity (via entity_edges and entity_observations).
5. It returns the prior investigation IDs, their verdicts, risk scores, and when they occurred.

This means every new investigation automatically benefits from everything Zovark has learned before. A malicious IP that appeared in 10 previous investigations will immediately raise a red flag when it appears in the 11th.

---

## A Concrete Walkthrough

Here is a real scenario showing the entity graph in action:

**Day 1 -- Investigation #1 (Supply Chain Compromise)**

An alert comes in: "Package hash mismatch detected during npm install from IP 203.0.113.50."

Zovark investigates and finds:
- Entity: IP 203.0.113.50 (threat_score: 70)
- Entity: domain "npm-packages-mirror.com" (threat_score: 60)
- Edge: 203.0.113.50 --resolved_to--> npm-packages-mirror.com
- Verdict: true_positive, risk: 75

**Day 3 -- Investigation #47 (C2 Beaconing)**

A different alert arrives: "Host 10.0.0.22 connecting to 203.0.113.50 every 60 seconds."

During the C2 investigation, the correlate_with_history tool fires. It checks IP 203.0.113.50 against the entity graph and finds:

"This IP was involved in Investigation #1 (supply chain compromise) two days ago. Verdict: true_positive. Risk: 75. It was also connected to domain npm-packages-mirror.com."

This correlation dramatically increases confidence. The C2 alert is no longer an isolated event -- it is part of a multi-stage attack. The supply chain compromise was the initial access, and the C2 beaconing is the attacker maintaining persistent control. Zovark boosts the risk score and links the two investigations.

**Day 5 -- Investigation #89 (Data Exfiltration)**

Yet another alert: "Large data transfer to 203.0.113.50 from finance server."

correlate_with_history now returns two prior hits: Investigation #1 (supply chain) and Investigation #47 (C2). The full attack chain is visible: initial access via poisoned package, persistent C2 channel established, and now data exfiltration. The risk score is near maximum.

Without the entity graph, each of these three investigations would have been analyzed in isolation. With the graph, Zovark sees the complete attack narrative.

---

## API Endpoints

The dashboard and external tools access the entity graph through 5 API endpoints:

1. **GET /api/v1/entities** -- List all entities for a tenant, with filters by type and search by value. Paginated (limit/offset). Returns entity type, value, threat score, observation count, and timestamps.

2. **GET /api/v1/entities/:id** -- Get a single entity with all its edges (connections to other entities). Returns the entity details plus a list of connected entities with edge types and confidence scores.

3. **GET /api/v1/entities/:id/graph** -- Graph traversal. Starting from one entity, follow connections outward to a configurable depth (1 to 3 hops). Returns nodes and edges in a format ready for visualization. Uses a recursive database query to efficiently traverse the graph.

4. **GET /api/v1/entities/search** -- Search entities by value. Returns matches ranked by observation count (most-seen entities first).

5. **GET /api/v1/entities/stats** -- Overview statistics: total entities, total edges, breakdown by entity type, and the top 10 most-observed entities.

There is also a cross-tenant endpoint:

6. **GET /api/v1/intelligence/top-threats** -- Returns the top 50 cross-tenant entities visible to the requesting tenant, sorted by threat score. Only shows entities that the requesting tenant has also observed (privacy-preserving).

---

## Dashboard Visualization

The dashboard renders the entity graph as an interactive, force-directed network diagram. Entities appear as nodes (colored by type -- red for malicious IPs, blue for domains, green for users), and edges appear as lines connecting them (labeled with the relationship type).

Analysts can click on any node to see its full details, expand its connections, and drill into the investigations where it appeared. The graph traversal API (depth 1-3) powers this expansion -- clicking an IP node fetches all entities within 2 hops, revealing the neighborhood of related threats.

This visualization turns abstract data into a picture that tells a story: "Here is the attacker's IP, connected to three domains, which resolved to two other IPs, which were used to log into five user accounts." In seconds, an analyst can see what would take hours to piece together from individual investigation reports.
