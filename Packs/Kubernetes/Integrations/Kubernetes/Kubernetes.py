"""Kubernetes Integration for Cortex XSOAR

Integration with the Python/REST API of a Kubernetes cluster. This uses the official
Python client: https://github.com/kubernetes-client/python/

Kubernetes API
--------------
- Pods: Retrieve details of pods and their containers. Create new pods or stop running pods.
- Services: Retrieve details of services. Create new services or delete existing services.
- Routes: Retrieve details of routes Create new routes or delete existing routes.

"""

''' IMPORTS '''
# std
from typing import Any, Dict, Tuple, List, Optional, Union, cast
from datetime import date, datetime, timezone
from json import dumps
import urllib3

# internal
import demistomock as demisto
from CommonServerPython import *  
from CommonServerUserPython import * 

# 3rd-party
from kubernetes import client, config
from kubernetes.client import api, models, ApiClient, Configuration
from kubernetes.client.api import CoreV1Api
from kubernetes.client.models import V1APIVersions, V1PodList, V1ServiceList

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%d %H:%M:%SZ'

''' HELPERS '''

def json_serial(obj):
    """JSON serializer for objects not serializable by default."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError ("Type %s not serializable" % type(obj))

def dict_to_json(d: Dict[str, Any]) -> str:
    """Serialize Dict[str, Any] that includes datetime fields."""
    return json.dumps(d, indent=4, sort_keys=True, default=json_serial)

''' CLIENT '''
class Client(BaseClient):
    """Client class to interact with the Kubernetes API."""
    cluster_host_url: str = ''
    cluster_token: str = ''
    namespace = None
    configuration: Configuration = None
    api_client: ApiClient = None
    api: CoreV1Api = None

    def __init__(self, h, t):
        self.cluster_host_url = h
        self.cluster_token = t
        self.configuration = client.Configuration()
        self.configuration.host = self.cluster_host_url
        self.configuration.api_key['authorization'] = self.cluster_token
        self.configuration.api_key_prefix['authorization'] = 'Bearer'
        self.api_client = client.ApiClient(configuration=self.configuration)
        self.api = client.CoreV1Api(api_client=self.api_client)

    def get_api_versions(self) -> V1APIVersions:
        return client.CoreApi(api_client=self.api_client).get_api_versions()

    def get_pods_raw(self, ns) -> V1PodList:
        if not ns is None:
            return self.api.list_namespaced_pod(ns)
        else:
            return self.api.list_pod_for_all_namespaces()

    def list_services(self) -> V1ServiceList:
        if not self.namespace is None:
            return self.api.list_namespaced_service(self.namespace)
        else:
            return self.api.list_service_for_all_namespaces()

    def get_pods_readable(self, ret:Dict[str, Any]) -> List[Dict[str, Any]]:
        return [{
                'Name':p['metadata']['name'],
                'Status': p['status']['phase'],
                'Containers': len(p['status']['container_statuses']),
                'Ready': len ([ s for s in p['status']['container_statuses'] if s['ready'] ]),
                'Restarts': sum ([ s['restart_count'] for s in p['status']['container_statuses'] ]),
                'Started': p['status']['start_time'].strftime(DATE_FORMAT)
                } for p in ret['items']]

''' COMMAND FUNCTIONS '''
def test_module(c: Client) -> str:
    #c.list_pods_raw('victor')
    client.CoreApi(api_client=c.api_client).get_api_versions()
    return 'ok'

def get_pods_command(k8s: Client, args: Dict[str, Any]) -> CommandResults:
    """ command: Returns list of running pods in the cluster.

    :type k8s: ``Client``
    :param Client: Kubernetes client to use.

    :type args: ``Dict[str, Any]``
    :param args: All command arguments, usually passed from ``demisto.args()``.

    :return: A ``CommandResults`` object that is then passed to ``return_results``.
    :rtype: ``CommandResults``
    """
    ns = args.get('ns', None)
    results = k8s.get_pods_raw(ns).to_dict()
    return CommandResults(
        outputs_prefix='Kubernetes.Pods',
        outputs_key_field='Name',
        outputs= k8s.get_pods_readable(results)
    )

''' MAIN '''
def main() -> None:
    """main function, parses params and runs command functions.
    :return:
    :rtype:

    """
    demisto.debug(f'Command being called is {demisto.command()}')
    cluster_host_url = demisto.params().get('cluster_host_url')
    auth_token = demisto.params().get('auth_token')

    try:
        k8s = Client(cluster_host_url, auth_token)
        demisto.debug(f'Initialized k8s client for {cluster_host_url} using token {auth_token}...')
        if demisto.command() == 'test-module':
             return_results(test_module(k8s))
        if demisto.command() == 'get-pods':
            return_results(get_pods_command(k8s, demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')

''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()