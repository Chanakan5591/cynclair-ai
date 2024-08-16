# 3rd party integrations
from .intelsource import VirusTotal

# to access env
import os

# Caching API calls
import functools

class IPEnrich:
    def __init__(self, ip: str):
        Vt = VirusTotal()

        self.ip = ip
        self.vt = Vt.get_vt()

    @functools.lru_cache(maxsize=128)
    def _get_vt_cached(self, ip):
        info = self.vt.get_object(f'/ip_addresses/{ip}')
        return info

    def get_vt(self):
        return self._get_vt_cached(self.ip)