import subprocess
import config

class FirewallManager:
    @staticmethod
    def block_ip(ip_address):
        """Host ACL injection via Windows Firewall"""
        if config.DRY_RUN:
            return True, "[DRY-RUN] Simulation verified. Native rule bypassed."

        rule_name = f"PurpleSOAR_Block_{ip_address}"
        command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}"
        ]
        try:
            subprocess.run(command, capture_output=True, text=True, check=True)
            return True, f"Active ACL injected: {rule_name}"
        except subprocess.CalledProcessError as e:
            return False, f"Privilege escalation required. Elevation failure: {e}"

    @staticmethod
    def unblock_ip(ip_address):
        """Active ACL ejection from Windows Firewall"""
        rule_name = f"PurpleSOAR_Block_{ip_address}"
        command = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}"
        ]
        try:
            subprocess.run(command, capture_output=True, text=True, check=True)
            return True, f"ACL evicted: {rule_name}"
        except Exception as e:
            return False, f"Rule purge error: {e}"