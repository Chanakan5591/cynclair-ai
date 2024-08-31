# ----------------------------------------------------------------------
# FileAnalyze module for sending file hashes to analyze for possible
# existing threats
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

from .intelsource import VirusTotal
from .feature_flags import VIRUSTOTAL_SOURCE


class FileAnalyze:
    def __init__(self, file_hashes: list[str]):
        self.vt = VirusTotal(file_hashes, "hash")

    def get_vt(self):
        if VIRUSTOTAL_SOURCE:
            return self.vt.get_info()

        return None

    def get_all_info(self):
        full_info = [{"files_VirusTotal": self.get_vt()}]

        return full_info
