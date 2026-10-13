import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import config
from core.intelligence import ThreatIntel
from core.firewall import FirewallManager
from core.emulator import AdversaryEmulator

console = Console()
intel = ThreatIntel()

def main():
    console.print(Panel.fit(
        "[bold cyan]PURPLE-SOAR :: Autonomous Incident Response & Emulation Engine[/bold cyan]\n"
        "[dim]System Architecture: Threat Intel Aggregation | Dynamic Filtering | Adversary Loop[/dim]",
        border_style="cyan"
    ))

    while True:
        target_ip = console.input("\n[bold cyan]target-ip@soar-engine:~$ [/bold cyan]").strip()
        if target_ip.lower() in ['exit', 'quit']:
            console.print("[dim][SYSTEM] Session terminated by analyst.[/dim]")
            break

        if not target_ip:
            continue

        # Check Allowlist Guardrail
        if target_ip in config.ALLOWLIST_IPS:
            console.print(f"[bold green][ALLOWLIST][/bold green] Target {target_ip} is trusted. Dynamic action aborted.")
            continue

        with console.status("[bold blue][PROCESSING] Querying Threat Intelligence APIs...[/bold blue]"):
            data = intel.evaluate_ip(target_ip)

        # Output Summary Table
        table = Table(title=f"INTELLIGENCE SUMMARY :: {target_ip}", border_style="blue")
        table.add_column("Metadata", style="cyan", no_wrap=True)
        table.add_column("Observed Value", style="white")

        table.add_row("Target IP", data['ip'])
        table.add_row("Abuse Confidence", f"{data['final_score']}%")
        table.add_row("Report Count", str(data['reports']))
        table.add_row("Origin Country", data['country'])
        table.add_row("Registered ISP", data['isp'])
        console.print(table)

        # Decision Playbook Logic
        score = data['final_score']
        action = None

        if score >= config.AUTO_BLOCK_THRESHOLD:
            console.print(f"[bold red][CRITICAL THREAT][/bold red] Score ({score}%) exceeds limit ({config.AUTO_BLOCK_THRESHOLD}%). Initiating containment.")
            action = "BLOCK"
        elif score >= config.MANUAL_REVIEW_THRESHOLD:
            console.print(f"[bold yellow][SUSPICIOUS][/bold yellow] Score ({score}%) in triage range. Manual verification required.")
            choice = console.input("[bold white][PROMPT] Execute host-isolation policy? (y/n): [/bold white]").strip().lower()
            if choice == 'y':
                action = "BLOCK"
            else:
                console.print("[dim][AUDIT] Containment rejected by security analyst.[/dim]")
        else:
            console.print(f"[bold green][INFO][/bold green] Score ({score}%) below threshold. Telemetry logged.")

        # Action Execution & Purple Loop Verification
        if action == "BLOCK":
            success, msg = FirewallManager.block_ip(target_ip)
            if success:
                console.print(f"[bold green][FIREWALL SUCCESS][/bold green] {msg}")
                
                # The Purple Loop (Adversary Verification)
                console.print("[bold blue][PURPLE-LOOP][/bold blue] Dispatching verification probe to confirm barrier...")
                verified, v_msg = AdversaryEmulator.verify_containment(target_ip)
                if verified:
                    console.print(f"[bold green][VERIFICATION SUCCESS][/bold green] {v_msg}")
                else:
                    console.print(f"[bold red][VERIFICATION FAILED][/bold red] {v_msg}")
            else:
                console.print(f"[bold red][FIREWALL ERROR][/bold red] {msg}")

if __name__ == "__main__":
    main()