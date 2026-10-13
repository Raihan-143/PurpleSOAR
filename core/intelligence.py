import requests
import config

class ThreatIntel:
    def __init__(self):
        self.abuse_key = config.ABUSEIPDB_API_KEY
        self.vt_key = config.VIRUSTOTAL_API_KEY

    def check_abuseipdb(self, ip_address):
        """AbuseIPDB theke telemetry pull kore"""
        if not self.abuse_key or "YOUR_" in self.abuse_key:
            return {"score": 0, "reports": 0, "country": "N/A", "isp": "Unspecified"}

        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {'Accept': 'application/json', 'Key': self.abuse_key}
        params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}

        try:
            res = requests.get(url, headers=headers, params=params, timeout=5)
            if res.status_code == 200:
                data = res.json().get('data', {})
                return {
                    "score": data.get('abuseConfidenceScore', 0),
                    "reports": data.get('totalReports', 0),
                    "country": data.get('countryCode', 'Unknown'),
                    "isp": data.get('isp', 'Unknown')
                }
        except Exception:
            pass
        return {"score": 0, "reports": 0, "country": "Error", "isp": "Error"}

    def check_virustotal(self, ip_address):
        """VirusTotal theke engine detection stats pull kore"""
        if not self.vt_key or "YOUR_" in self.vt_key:
            return {"vt_score": 0, "malicious_count": 0}

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"x-apikey": self.vt_key}

        try:
            res = requests.get(url, headers=headers, timeout=5)
            if res.status_code == 200:
                stats = res.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                vt_score = min(malicious * 12, 100)
                return {"vt_score": vt_score, "malicious_count": malicious}
        except Exception:
            pass
        return {"vt_score": 0, "malicious_count": 0}

    def evaluate_ip(self, ip_address):
        """Weighted consensus scoring engine (60% AbuseIPDB + 40% VirusTotal)"""
        abuse = self.check_abuseipdb(ip_address)
        vt = self.check_virustotal(ip_address)

        # Composite consensus calculation
        final_score = int((abuse['score'] * 0.6) + (vt['vt_score'] * 0.4))
        if abuse['score'] > 0 and vt['vt_score'] == 0:
            final_score = abuse['score']

        return {
            "ip": ip_address,
            "final_score": final_score,
            "abuse_score": abuse['score'],
            "vt_flags": vt['malicious_count'],
            "reports": abuse['reports'],
            "country": abuse['country'],
            "isp": abuse['isp']
        }