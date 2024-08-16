# 3rd party integrations
import vt as Vt

# access env
import os

class VirusTotal:
    def __init__(self):
        self.vt = Vt.Client(os.environ['VIRUSTOTAL_API_KEY'])

    def get_vt(self):
        return self.vt

    def close_vt(self):
        self.vt.close()