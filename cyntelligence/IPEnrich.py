# ----------------------------------------------------------------------
# IPEnrich module for enriching IP addresses information
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

# 3rd party integrations
from .intelsource import VirusTotal, AbuseIPDB
from .feature_flags import ABUSEIPDB_SOURCE, VIRUSTOTAL_SOURCE


class IPEnrich:
    def __init__(self, ip_set: list[str]):
        self.vt = VirusTotal(ip_set, "ip")
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
        full_info = [
            {"ip_AbuseIPDB": self.get_abuseipdb()},
            {"ip_VirusTotal": self.get_vt()},
        ]
        print("CALLING VT")

        return full_info
