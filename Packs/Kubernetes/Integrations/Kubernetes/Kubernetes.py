"""HelloWorld Integration for Cortex XSOAR (aka Demisto)
HelloWorld API
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
from kubernetes.client import ApiClient
# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
HELLOWORLD_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']


def kubernetes_client_setup(cluster_host_url:str, cluster_token:str) -> ApiClient:
    """ Setup Kubernetes client using specified configutation

    Args:
        cluster_api_url: Json configuration file content from IAM.
    Returns:
        ClusterManagerClient: client manager.
    """
    c = client.Configuration()
    c.host = cluster_host_url
    c.api_key["authorization"] = cluster_token
    return client.ApiClient(configuration=c)


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