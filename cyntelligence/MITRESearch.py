# ----------------------------------------------------------------------
# MITRE module for looking up information from MITRE ATT&CK
#
# Copyright 2024 Chanakan Moongthin <me@chanakancloud.net>
# on behalf of Up Up Up All Night
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

from typing import Literal
from .intelsource import MITRE

class MITRESearch:
    def __init__(self, ids: list[str] = []):
        mitre = MITRE()
        self.data = mitre.get_info()
        self.ids = ids

    def get_object_by_attack_ids(self, stix_type: Literal["attack-pattern", "malware", "tool", "intrusion-set", "campaign", "course-of-action", "x-mitre-matrix", "x-mitre-tactic", "x-mitre-data-source", "x-mitre-data-component"]):
        full_info = []
        for technique_id in self.ids:
            data = self.data.get_object_by_attack_id(technique_id, stix_type)
            full_info.append(data)

        return full_info
