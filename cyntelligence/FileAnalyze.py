from .intelsource import VirusTotal
from .feature_flags import VIRUSTOTAL_SOURCE

class FileAnalyze:
    def __init__(self, file_hashes: list[str]):
        self.vt = VirusTotal(file_hashes, 'hash')

    def get_vt(self):
        if VIRUSTOTAL_SOURCE:
            return self.vt.get_info()
        
        return None

    def get_all_info(self):
        full_info = [{"files_VirusTotal": self.get_vt()}]

        print(full_info)
        return full_info