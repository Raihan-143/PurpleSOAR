import requests
import config

class ThreatIntel:
    def __init__(self):
        self.abuse_key = config.ABUSEIPDB_API_KEY
        self.vt_key = config.VIRUSTOTAL_API_KEY

    def check_abuseipdb(self, ip_address):
        """AbuseIPDB theke threat score pull kore"""
        if not self.abuse_key or "YOUR_" in self.abuse_key:
            return {"score": 0, "reports": 0, "country": "N/A", "isp": "Demo ISP"}

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

    def evaluate_ip(self, ip_address):
        """Threat Intelligence aggregate kore data return kore"""
        abuse_data = self.check_abuseipdb(ip_address)
        return {
            "ip": ip_address,
            "final_score": abuse_data['score'],
            "reports": abuse_data['reports'],
            "country": abuse_data['country'],
            "isp": abuse_data['isp']
        }