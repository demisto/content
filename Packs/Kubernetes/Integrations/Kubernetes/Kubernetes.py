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
# local
import demistomock as demisto
from CommonServerPython import *  
from CommonServerUserPython import * 
# 3rd-party
from kubernetes import client, config
from kubernetes.client import api, models, ApiClient, Configuration
from kubernetes.client.api import CoreV1Api
from kubernetes.client.models import V1PodList, V1ServiceList

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

    def __init__(self, h, t, ns=None):
        self.cluster_host_url = h
        self.cluster_token = t
        self.configuration = client.Configuration()
        self.configuration.host = self.cluster_host_url
        self.configuration.api_key['authorization'] = self.cluster_token
        self.configuration.api_key_prefix['authorization'] = 'Bearer'
        self.api_client = client.ApiClient(configuration=self.configuration)
        self.api = client.CoreV1Api(api_client=self.api_client)
        self.namespace = ns

    def list_pods_raw(self) -> V1PodList:
        if not self.namespace is None:
            return self.api.list_namespaced_pod(self.namespace)
        else: 
            return self.api.list_pod_for_all_namespaces()

    def list_services(self) -> V1ServiceList:
        if not self.namespace is None:
            return self.api.list_namespaced_service(self.namespace)
        else:
            return self.api.list_service_for_all_namespaces()

    def list_pods_readable(self, ret:Dict[str, Any]) -> List[Dict[str, Any]]:
        return [{
                'Name':p['metadata']['name'], 
                'Status': p['status']['phase'], 
                'Containers': len(p['status']['container_statuses']),
                'Ready': len ([ s for s in p['status']['container_statuses'] if s['ready'] ]), 
                'Restarts': sum ([ s['restart_count'] for s in p['status']['container_statuses'] ]),
                'Started': p['status']['start_time'].strftime(DATE_FORMAT),
                'Age': "%sh" % str(datetime.now(timezone.utc) - p['status']['start_time']).split(':')[0]
                } for p in ret['items']]
        
''' COMMAND FUNCTIONS '''
def list_pods_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ command: Returns list of running pods in the cluster.

    :type client: ``Client``
    :param Client: Kubernetes client to use.

    :type args: ``Dict[str, Any]``
    :param args: All command arguments, usually passed from ``demisto.args()``.
    
    :return: A ``CommandResults`` object that is then passed to ``return_results``.
    :rtype: ``CommandResults``
    """
    ns = args.get('namespace', None)

    results = client.list_pods_raw().to_dict()
    return CommandResults(
        outputs_prefix='Kubernetes.Pods',
        outputs_key_field='Name',
        outputs=results,
        readable_output= tableToMarkdown(name="pods", t=client.list_pods_readable(results))
    )

''' MAIN ''' 
def main() -> None:
    """main function, parses params and runs command functions.
    :return:
    :rtype:
    """
    
    cluster_host_url = demisto.params().get('cluster_host_url')
    auth_token = demisto.params().get('auth_token')
    namespace = demisto.params().get('namespace')
    k8s = Client(cluster_host_url, auth_token, namespace)
    demisto.debug(f'Initialized k8s client for {cluster_host_url} using token {auth_token}...')

    command = demisto.command()
    #demisto.debug(f'Command being called is {command}')
    #if command == 'list-pods':
    #    k8s.

''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()