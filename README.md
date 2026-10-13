# PurpleSOAR: Autonomous Incident Response & Emulation Engine

A proactive, cross-functional incident response micro-SOAR designed to eliminate the latency between threat alert and containment. PurpleSOAR integrates automated threat intelligence enrichment, dynamic policy enforcement, and closed-loop adversary emulation to validate defensive posture in real time.

---

## Architectural Workflow

1. **Threat Intelligence Aggregation:**
   - Evaluates incoming IP indicators against AbuseIPDB and VirusTotal via unified REST APIs.
   - Computes weighted composite risk scoring based on report volume, confidence ratings, and autonomous system reputation.

2. **Policy Enforcement & Triage Playbook:**
   - **Score >= 80%:** Automated containment triggering native host firewall access control lists (ACLs).
   - **Score 30% - 79%:** Human-in-the-loop analyst prompt for manual triage.
   - **Score < 30%:** Passive telemetry ingestion.
   - **Strict Allowlisting:** Prevents denial-of-service risks against core network gateways, loopback addresses, and primary resolvers.

3. **The Purple Loop (Adversary Verification):**
   - Dispatches automated network probes directly to the isolated target immediately following rule injection.
   - Validates that traffic is dropped/unreachable at the OS boundary, ensuring true containment without assumption.

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Implementation in PurpleSOAR |
|---|---|---|---|
| Initial Access / Discovery | T1046 | Network Service Discovery | Detects inbound anomalous scanners |
| Execution / Defense Evasion | T1562.004 | Impair Defenses: Disable/Modify System Firewall | Verifies local security control enforcement |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | Blocks external C2 indicators |
| Mitigation Strategy | M1037 | Filter Network Traffic | Automated OS-level firewall rule generation |

---

## Prerequisites & Installation

```bash
git clone [https://github.com/Raihan-143/PurpleSOAR.git](https://github.com/Raihan-143/PurpleSOAR.git)
cd PurpleSOAR
python -m venv venv
venv\Scripts\activate   # On Windows
pip install -r requirements.txt

Author 
## Md. Raihan Hasan Rana - Cybersecurity Enthusiast