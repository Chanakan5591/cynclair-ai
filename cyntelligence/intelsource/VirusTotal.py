# ----------------------------------------------------------------------
# Copyright 2024 Chanakan Moongthin <me@chanakancloud.net> on behalf of Up Up Up All Night
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------

# 3rd party integrations
import vt as Vt

# API request Caching
import functools

from .BaseSource import BaseSource

# access env
import os

# Typings
from typing import Literal

class VirusTotal(BaseSource):
    def __init__(self, targets: list[str], type: Literal['ip', 'domain', 'url', 'hash'] = 'hash'):
        self.vt = Vt.Client(os.environ['VIRUSTOTAL_API_KEY'])
        self.targets = targets
        self.type = type

    @functools.cache
    def _get_info_cache(self, target):
        info = None
        if self.type == 'ip':
            info = self.vt.get_object(f'/ip_addresses/{target}')
        elif self.type == 'domain':
            info = self.vt.get_object(f'/domains/{target}')
        elif self.type == 'url':
            info = self.vt.get_object(f'/urls/{target}')
        elif self.type == 'hash':
            info = self.vt.get_object(f'/files/{target}')
        return info

    def get_info(self):
        full_info = []
        for target in self.targets:
            info = self._get_info_cache(target)

            print(info)

            if not info:
                full_info.append({target: {}})
                continue

            useful_keys = ['whois', 'continent', 'meaningful_name', 'creation_date', 'last_submission_date']
            final_info = {}

            for key in useful_keys:
                value = info.get(key)
                if value:
                    final_info[key] = value

            final_info['last_analysis_stats'] = dict(info.get('last_analysis_stats'))

            final_info['engines'] = []

            engine_names = list(info.get('last_analysis_results').keys())
            engine_names_to_process = engine_names[:10]

            for engine_name in engine_names_to_process:
                engine_info = info.get('last_analysis_results')[engine_name]
                final_info[f'engine_{engine_name}_method'] = engine_info['method']
                final_info[f'engine_{engine_name}_category'] = engine_info['category']
                final_info[f'engine_{engine_name}_result'] = engine_info['result']

                full_info.append({target: final_info})

            return full_info


    def close_vt(self):
        self.vt.close()
