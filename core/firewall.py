import subprocess
import config

class FirewallManager:
    @staticmethod
    def block_ip(ip_address):
        """Windows Firewall-e inbound block rule create kore"""
        if config.DRY_RUN:
            return True, "[DRY-RUN] Rule simulated (No change made)"

        rule_name = f"PurpleSOAR_Block_{ip_address}"
        command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}"
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            return True, f"Blocked successfully via Windows Firewall: {rule_name}"
        except subprocess.CalledProcessError as e:
            return False, f"Failed to execute netsh. Run as Administrator! Error: {e}"

    @staticmethod
    def unblock_ip(ip_address):
        """Firewall theke rule remove kore"""
        rule_name = f"PurpleSOAR_Block_{ip_address}"
        command = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        try:
            subprocess.run(command, capture_output=True, text=True, check=True)
            return True, f"Rule {rule_name} removed"
        except Exception as e:
            return False, str(e)