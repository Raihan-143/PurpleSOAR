import socket

class AdversaryEmulator:
    @staticmethod
    def verify_containment(target_ip, port=80, timeout=2):
        """
        Purple Loop: Attacker perspective theke probe packet pathiye
        check kore target connection dropped/blocked hocche kina.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((target_ip, port))
            s.close()
            return False, "ALERT: Packet reached! Containment verification FAILED."
        except (socket.timeout, socket.error):
            return True, "SUCCESS: Connection blocked/dropped. Containment VERIFIED!"