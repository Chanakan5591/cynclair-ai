# 3rd party integrations
import vt as Vt

# API request Caching
import functools

# access env
import os

class VirusTotal:
    def __init__(self, ip_set):
        self.vt = Vt.Client(os.environ['VIRUSTOTAL_API_KEY'])
        self.ip_set = ip_set

    @functools.cache
    def _get_info_cache(self, ip):
        info = self.vt.get_object(f'/ip_addresses/{self.ip}')
        return info

    def get_info(self):
        full_info = []
        for ip in self.ip_set:
            info = self._get_info_cache(ip)

            useful_keys = ['last_analysis_stats', 'whois', 'continent']
            final_info = {}

            for key in useful_keys:
                final_info[key] = info.get(key)

            final_info['engines'] = []

            for engine_name, engine_info in info.get('last_analysis_results').items():
                final_info[f'engine_{engine_name}_method'] = engine_info['method']
                final_info[f'engine_{engine_name}_category'] = engine_info['category']
                final_info[f'engine_{engine_name}_resuilt'] = engine_info['result']
   
            full_info.append(final_info)
        return full_info


    def close_vt(self):
        self.vt.close()