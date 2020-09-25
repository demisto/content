"""Kubernetes Integration for Cortex XSOAR (aka Demisto)
Kubernete API
--------------
"""

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast
from kubernetes import client, config
from kubernetes.client import api, models, ApiClient, Configuration
from kubernetes.client.api import CoreV1Api
from kubernetes.client.models import V1PodList

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
HELLOWORLD_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']


class Client(BaseClient):
    """Client class to interact with the Kubernetes API. """
    cluster_host_url: str = ''
    cluster_token: str = ''
    ns: str = ''
    configuration: Configuration = None
    api_client: ApiClient = None
    api: CoreV1Api = None

    def __init__(self, h, t, ns):
        self.cluster_host_url = h
        self.cluster_token = t
        self.configuration = client.Configuration()
        self.configuration.host = self.cluster_host_url
        self.configuration.api_key["authorization"] = self.cluster_token
        self.configuration.api_key_prefix['authorization'] = 'Bearer'
        self.api_client = client.ApiClient(configuration=self.configuration)
        self.api = client.CoreV1Api(api_client=self.api_client)
        self.ns = ns

    def list_pods(self) -> V1PodList:
        return self.api.list_namespaced_pod(self.ns)


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # cluster_api_url = demisto.params().get('cluster_api_url')
    # cluster_user = demisto.params().get('cluster_user_url')
    

''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()