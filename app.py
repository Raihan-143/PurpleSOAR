from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
import config
from core.intelligence import ThreatIntel
from core.firewall import FirewallManager
from core.emulator import AdversaryEmulator
from core.playbook import PlaybookEngine

console = Console()
intel = ThreatIntel()

def main():
    console.print(Panel.fit(
        "[bold cyan]PURPLE-SOAR :: Autonomous Incident Response & Emulation Engine[/bold cyan]\n"
        "[dim]Pipeline: Multi-Source TI Aggregation | MITRE ATT&CK Mapping | Dynamic Containment | Adversary Validation[/dim]",
        border_style="cyan"
    ))

    while True:
        target_ip = console.input("\n[bold cyan]target-ip@soar-engine:~$ [/bold cyan]").strip()
        if target_ip.lower() in ['exit', 'quit']:
            console.print("[dim][SYSTEM] Session terminated by security analyst.[/dim]")
            break

        if not target_ip:
            continue

        # Allowlist Protection
        if target_ip in config.ALLOWLIST_IPS:
            console.print(f"[bold green][ALLOWLIST][/bold green] Invariant check: {target_ip} is protected infrastructure. Action halted.")
            continue

        with console.status("[bold blue][PROCESSING] Querying Threat Intel Feeds (AbuseIPDB & VirusTotal)...[/bold blue]"):
            data = intel.evaluate_ip(target_ip)

        # Intelligence Table
        table = Table(title=f"TELEMETRY EVALUATION :: {target_ip}", border_style="blue")
        table.add_column("Indicator Attribute", style="cyan", no_wrap=True)
        table.add_column("Observed Value", style="white")

        table.add_row("Target Indicator", data['ip'])
        table.add_row("Consensus Risk Score", f"{data['final_score']}%")
        table.add_row("Abuse Confidence", f"{data['abuse_score']}%")
        table.add_row("VirusTotal Malicious Engines", str(data['vt_flags']))
        table.add_row("Historical Reports", str(data['reports']))
        table.add_row("Geographic Origin", data['country'])
        table.add_row("Autonomous System / ISP", data['isp'])
        console.print(table)

        # MITRE ATT&CK Assessment Table
        mitre_tags = PlaybookEngine.map_mitre_tactics(data['final_score'], data['reports'])
        mitre_table = Table(title="MITRE ATT&CK CONTEXT", border_style="magenta")
        mitre_table.add_column("Technique ID", style="yellow")
        mitre_table.add_column("Technique Name", style="white")
        mitre_table.add_column("Tactic Stage", style="magenta")

        for tag in mitre_tags:
            mitre_table.add_row(tag['id'], tag['name'], tag['tactic'])
        console.print(mitre_table)

        # Decision Execution
        score = data['final_score']
        action = None
        decision_type = "LOG_ONLY"

        if score >= config.AUTO_BLOCK_THRESHOLD:
            console.print(f"[bold red][CRITICAL THREAT][/bold red] Indicator score ({score}%) exceeds auto-block limit ({config.AUTO_BLOCK_THRESHOLD}%). Initiating containment.")
            action = "BLOCK"
            decision_type = "AUTO_CONTAINMENT"
        elif score >= config.MANUAL_REVIEW_THRESHOLD:
            console.print(f"[bold yellow][SUSPICIOUS][/bold yellow] Indicator score ({score}%) in triage threshold. Manual escalation required.")
            choice = console.input("[bold white][PROMPT] Approve host-isolation ACL injection? (y/n): [/bold white]").strip().lower()
            if choice == 'y':
                action = "BLOCK"
                decision_type = "MANUAL_APPROVAL_CONTAINMENT"
            else:
                console.print("[dim][AUDIT] Containment action suppressed by analyst.[/dim]")
                decision_type = "ANALYST_OVERRIDE_SUPPRESSED"
        else:
            console.print(f"[bold green][INFO][/bold green] Indicator score ({score}%) below operational risk baseline. Telemetry persisted.")

        # Act & Purple Loop Validation
        containment_status = "NOT_TRIGGERED"
        emulation_status = "N/A"

        if action == "BLOCK":
            success, msg = FirewallManager.block_ip(target_ip)
            if success:
                containment_status = "CONTAINED"
                console.print(f"[bold green][FIREWALL SUCCESS][/bold green] {msg}")

                console.print("[bold blue][PURPLE-LOOP][/bold blue] Dispatching verification probe to confirm barrier...")
                verified, v_msg = AdversaryEmulator.verify_containment(target_ip)
                if verified:
                    emulation_status = "VERIFIED_ISOLATED"
                    console.print(f"[bold green][VERIFICATION SUCCESS][/bold green] {v_msg}")
                else:
                    emulation_status = "FAILED_LEAK_DETECTED"
                    console.print(f"[bold red][VERIFICATION FAILED][/bold red] {v_msg}")
            else:
                containment_status = "FAILED"
                console.print(f"[bold red][FIREWALL ERROR][/bold red] {msg}")

        # Audit Trail Logging
        audit_payload = {
            "target_ip": target_ip,
            "risk_score": score,
            "decision": decision_type,
            "containment_status": containment_status,
            "purple_loop_verification": emulation_status,
            "mitre_mapping": mitre_tags
        }
        PlaybookEngine.write_audit_log(audit_payload)
        console.print("[dim][AUDIT TRAIL] Event securely indexed into logs/audit_events.json[/dim]")

if __name__ == "__main__":
    main()