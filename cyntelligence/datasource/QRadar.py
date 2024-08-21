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

import functools
from typing import Any

import requests
from cyntelligence.datasource import BaseSource
import os

class QRadar(BaseSource):
    def __init__(self, query):
        super().__init__(query)
        self.base_url = f"https://{os.environ['QRADAR_HOSTNAME']}/restapi/api/ariel/searches"
        self.req_headers = {
            "Accept": "application/json",
            "SEC": os.environ["QRADAR_SECURITY_TOKEN"]
        }

    @functools.cache
    def _get_info_cache(self, ip) -> list[dict]:

        # Schedule the query
        schedule_response = requests.post(self.base_url, headers=self.req_headers, json={
            "query_expression": self.query
        })

        if schedule_response.status_code == 200: # success
            body_response = schedule_response.json()
            cursor_id = body_response['cursor_id']

            status_url = f"{self.base_url}/{cursor_id}"
            status_response = requests.get(status_url, headers=self.req_headers)

            # Check query status
            if status_response.status_code == 200: # success
                body_response = status_response.json()

                if body_response['status'] == 'COMPLETED':
                    results_url = f"{self.base_url}/{cursor_id}/results"

                    # Get results
                    results_response = requests.get(results_url, headers=self.req_headers)
                    if results_response.status_code == 200: # success
                        body_response = results_response.json()
                        return body_response

        # if any of the steps failed
        return False

