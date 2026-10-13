import json
import os
from datetime import datetime

class PlaybookEngine:
    @staticmethod
    def map_mitre_tactics(score, report_count):
        """Threat telemetry onujayi MITRE ATT&CK framework mapping kore"""
        if score >= 80:
            return [
                {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
                {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
                {"id": "T1071.001", "name": "Web Protocols C2", "tactic": "Command & Control"}
            ]
        elif score >= 30:
            return [
                {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
                {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"}
            ]
        return [{"id": "N/A", "name": "Benign Telemetry", "tactic": "None"}]

    @staticmethod
    def write_audit_log(entry_data):
        """Structured JSON audit trail save kore"""
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "audit_events.json")

        entry_data["timestamp"] = datetime.utcnow().isoformat() + "Z"

        records = []
        if os.path.exists(log_file):
            try:
                with open(log_file, "r") as f:
                    records = json.load(f)
            except Exception:
                records = []

        records.append(entry_data)

        with open(log_file, "w") as f:
            json.dump(records, f, indent=4)