# 3rd party integrations
from .intelsource import VirusTotal, AbuseIPDB
from .feature_flags import ABUSEIPDB_SOURCE, VIRUSTOTAL_SOURCE

class IPEnrich:
    def __init__(self, ip_set: str):
        self.vt = VirusTotal(ip_set, 'ip')
        self.abuseipdb = AbuseIPDB(ip_set)

    def get_vt(self):
        if VIRUSTOTAL_SOURCE:
            return self.vt.get_info()
    
        return None

    def get_abuseipdb(self):
        if ABUSEIPDB_SOURCE:
            return self.abuseipdb.get_info()

        return None

    # All in this case only applied to enabled TIP
    def get_all_info(self):
        full_info = [{"AbuseIPDB": self.get_abuseipdb()}, {"VirusTotal": self.get_vt()}]

        print(full_info)
        # write to file
        return full_info