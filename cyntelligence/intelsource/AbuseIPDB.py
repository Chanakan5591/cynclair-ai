# ----------------------------------------------------------------------
# AbuseIPDB Intelligence Source File for interacting with
# AbuseIPDB via its API
#
# Copyright 2024 Chanakan Moongthin <me@chanakancloud.net>
# on behalf of Up Up Up All Night (Team of Cynclair Hackathon 2024)
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

# To access the platform's API endpoint
from typing import Any
import requests

# Cache 3rd party
import functools

from .BaseSource import BaseSource

# access env
import os

class AbuseIPDB(BaseSource):
    def __init__(self, targets: list[str]):
        self.base_url = "https://api.abuseipdb.com/api/v2/check?ipAddress={}"
        self.req_headers = {
            "Accept": "application/json",
            "Key": os.environ["ABUSEIPDB_API_KEY"]
        }
        self.ip_set = list(dict.fromkeys(targets)) # remove duplicated elements

    @functools.cache
    def _get_info_cache(self, ip) -> Any:
        response = requests.get(self.base_url.format(ip), headers=self.req_headers)

        if response.status_code == 200: # success
            body_response = response.json()
            return body_response

        # if not 200
        return False

    def get_info(self):
        full_info = []
        for ip in self.ip_set:
            response = self._get_info_cache(ip)['data']
            full_info.append({
                response['ipAddress']: {
                    'abuseConfidenceScore': response['abuseConfidenceScore'],
                    'countryCode': response['countryCode'],
                    'isp': response['isp'],
                    'domain': response['domain'],
                    'isTor': response['isTor'],
                    'totalReports': response['totalReports']
                }
            })
        return full_info
