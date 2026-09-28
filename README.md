# BlackBox
![Static Badge](https://img.shields.io/badge/Status-Prototype-red) ![Static Badge](https://img.shields.io/badge/Track-Cybersecurity_%26_Defense-red) ![Static Badge](https://img.shields.io/badge/Event-ASYNC_2026-black)

> **Cryptography remembers. AI investigates. Humans stay in control.** 

BlackBox is a tamper-proof security gateway and verifiable flight recorder for web apps, APIs, and AI agents. It intercepts all traffic, applies strict egress/ingress rules, and writes a cryptographically sealed, hash-chained entry for every intent and outcome. If an attacker breaches your server and attempts to alter logs to cover their tracks, BlackBox mathematically proves the tampering and tells you exactly what to restore.

![Hero Screenshot Placeholder](docs/reference/hero-placeholder.png)

---

## The Problem
Three things go wrong simultaneously when a server or an AI agent is compromised:
1. **You do not know what happened.** Attackers edit or wipe logs immediately to hide their tracks.
2. **You cannot trust your own evidence.** Traditional logs live on machines the attacker now controls.
3. **You do not know what to restore or rotate.** Recovery is blind, leading to massive rollbacks and unnecessary downtime.

---

## The Complete Architecture Diagram

![Architecture Diagram](docs/architecture.svg)

### How to read this diagram
The diagram is divided into three physical and logical zones:
- **Assumed Attackable Zone (Red dashed border):** This is where your app, your agents, your database, and the BlackBox Gateway live. If an attacker breaches your infrastructure, everything in this box is compromised.
- **Trusted Zone (Crimson glow):** Physically separated infrastructure that the attacker cannot reach. It holds the Witness and the Root Keys.
- **Verifier Side (Grey solid border):** Offline and analytical tools that run after an attack to process the cryptographic proofs.

### Components
| Component | Nickname | Job | Trust level | UI Location |
| --- | --- | --- | --- | --- |
| **Client / Agent SDK** | - | Signs every request (Ed25519, timestamp, nonce). | Assumed attackable | Guided Demo |
| **GATEWAY** | Guard & Chaperone | Verifies signatures, enforces policy, brokers agent credentials, and seals logs. | Assumed attackable | Live Gateway / Agent Lane |
| **ORIGIN APP** | Demo shop | Your actual app. Reachable *only* through the gateway. | Assumed attackable | N/A |
| **PAYMENT PROVIDER** | Mock | External third-party API. The agent never holds these keys. | External | N/A |
| **LEDGER** | The diary | PostgreSQL append-only DB storing encrypted, hash-chained entries. | Assumed attackable | Ledger & Witness |
| **WITNESS** | The notary | Countersigns periodic checkpoints and verifies consistency continuously. | Trusted | Ledger & Witness |
| **RECONCILER** | Bank check | Compares the Ledger against third-party provider logs. | Verifier Side | Verify / Agent Lane |
| **VERIFIER CLI** | - | Offline tool anyone can run to generate a cryptographic verdict. | Verifier Side | Verify |
| **RECOVERY** | - | Toolkit to generate a blast-radius report and replay write journals. | Verifier Side | Recovery |
| **AI NARRATOR** | - | Generates plain-English summaries from *verified, sanitized* data only. | Verifier Side | Verify / Recovery |
| **DASHBOARD** | - | What the judge/analyst sees during the demo. | Verifier Side | Home |
| **Human Approver** | - | Evaluates high-impact agent actions held in the Approval Queue. | Trusted | Agent Lane |
| **Offline Root Key** | - | Kept in a vault with 3-of-5 holders. Certifies Gateway epoch keys. | Trusted | N/A |

### What data travels on the arrows
- **Client → Gateway:** Signed HTTP payloads (Ed25519) containing intentions or requests.
- **Gateway → Redis:** High-speed nonce lookups to prevent replay attacks.
- **Gateway → Origin / Provider:** Clean, authenticated traffic (brokered by the Gateway).
- **Gateway → Ledger:** Sealed Entries (AES-GCM encrypted payload, hashed, signed, and linked to the previous entry).
- **Ledger → Witness:** Checkpoints (the root hash of the Merkle Tree representing the chain) and Consistency Proofs.
- **Gateway → Witness:** High-frequency, cryptographically signed heartbeats.

### The Flows

#### Flow 1: Allowed Web Request
```mermaid
sequenceDiagram
    participant C as Client
    participant GW as Gateway
    participant O as Origin
    participant L as Ledger
    participant W as Witness
    C->>GW: 1. Signed request
    GW->>GW: 2. Pipeline (Sanity, Sig, Rate, Rules, Policy)
    GW->>L: 3. Seal Intent entry
    GW->>O: 4. Forward with gateway header
    O-->>GW: 5. Origin response
    GW->>L: 6. Seal Outcome entry
    GW-->>C: 7. Response to client
    L->>W: 8. Checkpoint created
    W->>W: 9. Verify consistency
    W-->>L: 10. Cosign checkpoint
```

#### Flow 2: Agent Action
```mermaid
sequenceDiagram
    participant A as Agent SDK
    participant GW as Gateway
    participant H as Human
    participant P as Provider
    participant L as Ledger
    A->>GW: 1. Action requested (no keys)
    GW->>L: 2. Seal Intent entry FIRST
    GW->>GW: 3. Policy check (requires approval)
    GW->>H: 4. Request approval
    H-->>GW: 5. Action approved
    GW->>GW: 6. Broker injects provider credentials
    GW->>P: 7. Execute call at Provider
    P-->>GW: 8. Provider response
    GW->>L: 9. Seal Outcome entry
    GW-->>A: 10. Action result
```

#### Flow 3: Attack plus tampering
```mermaid
sequenceDiagram
    participant AT as Attacker
    participant L as Ledger
    participant W as Witness
    participant V as Verifier
    participant R as Responder
    participant Rec as Reconciler
    AT->>L: 1. Gains root, edits/deletes rows
    L->>W: 2. Next checkpoint polled
    W->>W: 3. Consistency proof fails!
    W-->>V: 4. Alert triggered
    V->>V: 5. Verify run: TAMPERING DETECTED
    V-->>R: 6. Signal Responder
    R->>R: 7. Quarantines route (Tier 4)
    Rec->>P: 8. Fetch provider logs
    Rec->>L: 9. Compare with ledger
    Rec->>Rec: 10. Flag event with NO ledger entry
```

### Key Design (Forward Secrecy)
BlackBox employs a **forward-secure HKDF ratchet**. The Gateway holds a Chain Key (CK). For every entry, it derives an Encryption Key (EK), encrypts the payload, and immediately deletes CK by ratcheting it forward to the next state. A thief who steals today's key *cannot* decrypt yesterday's entries.
The root keys are offline (3-of-5 threshold signature) and only used to issue new short-lived Epoch Keys for the Gateway.

### Why the Witness is independent
If the Ledger generated its own proofs, a rooted server could simply forge an alternate history. The Witness is physically independent. By continually countersigning checkpoints (Merkle roots), it enforces an append-only property. If the Ledger attempts to alter a past entry, the new tree will not cleanly extend the old tree, and the Witness will refuse to sign, triggering an alert.

### What the diagram does NOT cover
The diagram abstracts away physical network topologies (VPCs, subnets), the specific details of the AES-GCM encryption padding, the specific consensus algorithm used if the Witness is deployed as a quorum, and the host-level eBPF capture layer (which is on the roadmap).

---

## Feature Tour

### Live Gateway
![Live Gateway Placeholder](docs/reference/gateway-placeholder.png)
- **What to click:** "Run all" in the Attack Launcher, or toggle between Bare App vs. BlackBox in the Compare section.
- **What it proves:** Real-time policy enforcement. Shows how the Gateway evaluates every step of the pipeline and safely drops or quarantines threats.

### Agent Lane
![Agent Lane Placeholder](docs/reference/agents-placeholder.png)
- **What to click:** "Run poisoned invoice attack (A11)" and watch the Approval Queue catch it. Click "Agent calls provider directly (A12)".
- **What it proves:** Safe AI delegation. Proves the agent operates empty-handed and relies on the Gateway to broker credentials, preventing direct data exfiltration.

### Ledger & Witness
![Ledger Placeholder](docs/reference/ledger-placeholder.png)
- **What to click:** Click any sealed block in the horizontally scrolling chain to see the cryptographic envelope fields.
- **What it proves:** Demonstrates the continuous Merkle tree construction and the real-time checkpoint countersigning by the Witness.

### Tamper Lab
![Tamper Lab Placeholder](docs/reference/tamper-placeholder.png)
- **What to click:** "Let a judge tamper". Edit the text of a log directly.
- **What it proves:** Proves that while a rooted database *can* be edited (Plain Log view looks clean), the cryptographic BlackBox Chain instantly breaks. 

### Verify
![Verify Placeholder](docs/reference/verify-placeholder.png)
- **What to click:** "Run Verify".
- **What it proves:** Offline verification. An 8-step cryptographic check resulting in a deterministic `TAMPERING DETECTED` verdict, complete with exact sequence numbers and a violation catalog.

### Recovery
![Recovery Placeholder](docs/reference/recovery-placeholder.png)
- **What to click:** Review the Blast-Radius report and click "Run Exploit on Patch".
- **What it proves:** Blind rollbacks are unnecessary. You can confidently replay specific good writes from the write-journal, minimizing data loss to minutes rather than days.

---

## How to run
1. Set up a Python virtual environment: `python -m venv venv`
2. Activate it: `source venv/bin/activate` (or `venv\Scripts\activate` on Windows)
3. Install requirements: `pip install -r requirements.txt`
4. Run the server: `uvicorn server.main:app --reload`
5. Open `http://localhost:8000/dashboard/` in your browser.

**Modes:** 
The application runs in **Demo Mode** by default, driven by an in-memory `MockEngine` (`dashboard/js/engine.js`) simulating the backend traffic and cryptographic state for evaluation purposes. It requires zero backend infrastructure. 

---

## Demo Script (7 Minutes)

| Time | Step | Page | Action/What to say |
| :--- | :--- | :--- | :--- |
| 0:00 | 1. Problem | Home | "When a server is breached, attackers erase logs. We fix that." |
| 0:45 | 2. Pipeline | Gateway | "The Gateway evaluates every request. I'll launch a Path Traversal attack. Blocked instantly." |
| 1:30 | 3. Compare | Gateway | "Without BlackBox, the app leaks data. With BlackBox, it's protected and recorded." |
| 2:15 | 4. AI Agents | Agent Lane | "Agents ask for actions without holding keys. A poisoned invoice asks for a $9500 refund. The Gateway holds it for human approval." |
| 3:00 | 5. Root Tamper | Tamper Lab | "The worst happens: the attacker gets root and edits the database. The plain log looks fine, but the BlackBox chain visually cracks." |
| 4:00 | 6. Judge edits | Tamper Lab | (Click 'Let a judge tamper', edit an entry). "Let's see what happens when we verify it." |
| 4:45 | 7. Verify | Verify | "We run the 8-step offline proof. It mathematically detects the tampering and gives us the exact sequence numbers." |
| 5:45 | 8. Recovery | Recovery | "Because we have a blast-radius report, we don't roll back the whole day. We lose 4 minutes, replay the good writes, and we're back." |
| 6:15 | 9. Narrator | Recovery | "Even our AI summary is safe from prompt injection because it only reads structured, verified data." |
| 6:45 | 10. Limits | Limits | "We don't prevent breaches. We guarantee they are mathematically detectable. These are our honest limits." |

**Likely Judge Questions:**
- *Q: What if the attacker deletes the Witness?*
  A: The Witness is physically separated. The Gateway will halt if it cannot heartbeat the Witness, limiting the damage window to seconds.
- *Q: What if they steal the signing keys?*
  A: They can forge *new* entries going forward, but the forward-secure ratchet prevents them from altering past entries.

---

## Folder structure
- `server/main.py`: Minimal FastAPI backend serving the static assets.
- `dashboard/index.html`: The SPA entry point.
- `dashboard/css/`: Pure CSS implementation of the design system (tokens, components, layout).
- `dashboard/js/app.js`: Client-side hash router.
- `dashboard/js/engine.js`: The MockEngine that drives all demo scenarios without a DB.
- `dashboard/js/stream.js`: The event bus connecting the UI to the engine.
- `dashboard/js/pages/`: The modular views for each page (Gateway, Ledger, Tamper, Verify, etc).
- `docs/`: Reference images, markdown docs, and Mermaid/SVG diagram files.

---

## Tech Stack
| Technology | Reason for choice |
| --- | --- |
| **HTML / CSS** | Maximum control over the aesthetic. Zero build-step requirements. Pure CSS Variables for tokens. |
| **Vanilla JS** | ES modules provide enough structure without the overhead of React/Vue for a frontend prototype. |
| **SVG** | Pixel-perfect, scalable diagramming without heavy charting libraries. |
| **FastAPI** | Lightweight, rapid server capable of serving static files and ready for future SSE/WebSocket implementation. |

---

## Honest limits
1. **Breach is not prevented.** BlackBox makes compromises cryptographically detectable.
2. **A rooted gateway can forge new entries.** Caught during reconciliation, but not prevented in real-time.
3. **Only sees traffic through the gateway.** Direct database queries or SSH access are not captured.
4. **Latency overhead.** Cryptographic sealing adds ~5ms p50 latency.
5. **Requires a trusted Witness.** You must run an independent Witness server on separate infrastructure.

## Roadmap
- Witness Quorum (BFT consensus).
- External timestamp anchoring to public blockchains.
- Machine-learning anomaly detection model for the pipeline.
- Host-level eBPF capture.

## Glossary
- **Tamper-evident:** If altered, it leaves mathematical proof.
- **Third-party verifiable:** Anyone can download the CLI and prove the logs without relying on the system owner.
- **Evidence up to the gateway boundary:** It proves what came in and what went out; it cannot prove what happened inside the origin app's memory.
