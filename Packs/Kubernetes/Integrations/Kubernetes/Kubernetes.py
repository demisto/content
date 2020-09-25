"""Kubernetes Integration for Cortex XSOAR.

This is an integration with the Python/REST API of a Kubernetes cluster.

Kubernetes API
--------------
"""
###########
# IMPORTS #
###########
# std packages
from typing import Any, Dict, Tuple, List, Optional, Union, cast
# local packages
import demistomock as demisto
from CommonServerPython import *  
from CommonServerUserPython import * 
# 3rd-party packages
from kubernetes import client, config
from kubernetes.client import api, models, ApiClient, Configuration
from kubernetes.client.api import CoreV1Api
from kubernetes.client.models import V1PodList, V1ServiceList

''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


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

    def list_services(self) -> V1ServiceList:
        return self.api.list_namespaced_service(self.ns)


def list_pods_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ command: Returns list of running pods in the cluster.

    :type client: ``Client``
    :param Client: Kubernetes client to use.

    :type args: ``Dict[str, Any]``
    :param args: All command arguments, usually passed from ``demisto.args()``.
    
    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains the hello world message

    :rtype: ``CommandResults``
    """
    ns = args.get('namespace', None)

    result = client.list_pods()

    # Create the human readable output.
    # It will  be in markdown format - https://www.markdownguide.org/basic-syntax/
    # More complex output can be formatted using ``tableToMarkDown()`` defined
    # in ``CommonServerPython.py``
    readable_output = f'## {result}'

    # More information about Context:
    # https://xsoar.pan.dev/docs/integrations/context-and-outputs
    # We return a ``CommandResults`` object, and we want to pass a custom
    # markdown here, so the argument ``readable_output`` is explicit. If not
    # passed, ``CommandResults``` will do a ``tableToMarkdown()`` do the data
    # to generate the readable output.
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='hello',
        outputs_key_field='',
        outputs=result
    )

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