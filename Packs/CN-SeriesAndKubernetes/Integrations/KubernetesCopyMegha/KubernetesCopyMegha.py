import json

import dateparser
import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401
from kubernetes import client as kube_client
from kubernetes import config, watch

# IMPORTS
# from kubernetes import client, config, watch

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

NETPOL1 = """{"apiVersion": "extensions/v1beta1",
        "kind": "NetworkPolicy",
        "metadata": {
            "creationTimestamp": "2020-06-12T22:16:00Z",
            "generation": 12,
            "labels": {
                "np.panw.com/antivirus": "default",
                "np.panw.com/appid": "redis",
                "np.panw.com/datafiltering": "none",
                "np.panw.com/fileblocking": "basic",
                "np.panw.com/logprofile": "default",
                "np.panw.com/urlfiltering": "done",
                "np.panw.com/vuln-protection": "strict"
            },
            "name": "allow-black",
            "namespace": "default",
            "resourceVersion": "8288713",
            "selfLink": "/apis/extensions/v1beta1/namespaces/default/networkpolicies/allow-black",
            "uid": "4bc8129d-acfa-11ea-b163-4201c0a80005"
        },
        "spec": {
            "ingress": [
                {
                    "from": [
                        {
                            "podSelector": {
                                "matchLabels": {
                                    "color": "black"
                                }
                            }
                        }
                    ],
                    "ports": [
                        {
                            "port": 45,
                            "protocol": "TCP"
                        }
                    ]
                }
            ],
            "podSelector": {
                "matchLabels": {
                    "color": "blue",
                    "test": "more"
                }
            },
            "policyTypes": [
                "Ingress"
            ]
        }
    }"""


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any XSOAR logic.
    Should only do requests and return data.
    """

    def say_hello(self, name):
        return f'Hello {name}'

    def say_hello_http_request(self, name):
        """
        initiates a http request to a test url
        """
        data = self._http_request(
            method='GET',
            url_suffix='/hello/' + name
        )
        return data.get('result')

    def list_incidents(self):
        """
        returns dummy incident data, just for the example.
        """
        return [
            {
                'incident_id': 1,
                'description': 'Hello incident 1',
                'netpol': NETPOL1
            }
        ]


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    result = client.say_hello('DBot')
    if 'Hello DBot' == result:
        return 'ok'
    else:
        return 'Test failed because ......'


def get_netpol_command(client, args):
    """
    Returns Hello {somename}

    Args:
        client (Client): HelloWorld client.
        args (dict): all command arguments.

    Returns:
        Hello {someone}

        readable_output (str): This will be presented in the war room - should be in markdown syntax - human readable
        outputs (dict): Dictionary/JSON - saved in the incident context in order to be used as inputs
                        for other tasks in the playbook
        raw_response (dict): Used for debugging/troubleshooting purposes -
                            will be shown only if the command executed with raw-response=true
    """

    result = json.loads(NETPOL1)  # client.list_incidents()

    # readable output will be in markdown format - https://www.markdownguide.org/basic-syntax/
    readable_output = f'## {result}'
    outputs = {
        'Kubernetes.NetworkPolicy': result
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def say_hello_over_http_command(client, args):
    name = args.get('name')

    result = client.say_hello_http_request(name)

    # readable output will be in markdown format - https://www.markdownguide.org/basic-syntax/
    readable_output = f'## {result}'
    outputs = {
        'hello': result
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def fetch_incidents(client, last_run, first_fetch_time):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): HelloWorld client
        last_run (dateparser.time): The greatest incident created_time we fetched from last fetch
        first_fetch_time (dateparser.time): If last_run is None then fetch all incidents since first_fetch_time

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')

    # Handle first time fetch
    if last_fetch is None:
        last_fetch, _ = dateparser.parse(first_fetch_time)
    else:
        last_fetch = dateparser.parse(last_fetch)

    latest_created_time = last_fetch
    incidents = []
    items = client.list_incidents()
    for item in items:
        incident_created_time = dateparser.parse(item['created_time'])
        incident = {
            'name': item['description'],
            'occurred': incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'rawJSON': json.dumps(item)
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    next_run = {'last_fetch': latest_created_time.strftime(DATE_FORMAT)}
    return next_run, incidents


def long_running_command(client):
    pass


def watch_command(client):
    # demisto.createIncidents([{
    #     'name': 'K8s Policy Event',
    #     'details': 'details',
    #     'rawJSON': json.dumps({'policy': 'hi'})
    #     # 'type': '',
    #     # 'occurred': occurred
    # }])
    # return
    # Init
    v1 = kube_client.CoreV1Api()
    #  Begin watch
    v1_network = kube_client.NetworkingV1Api(kube_client.ApiClient())
    body = kube_client.V1NetworkPolicy()
    count = 0
    max = 5
    w = watch.Watch()
    for event in w.stream(v1_network.list_network_policy_for_all_namespaces, _request_timeout=120):
        policy = event['object'].to_dict()
        del policy['metadata']['creation_timestamp']
        demisto.createIncidents([{
            'name': 'Kubernetes Policy {} Changed'.format(policy['metadata']['name']),
            'details': json.dumps(policy),
            'rawJSON': json.dumps({'policy': policy})
            # 'type': '',
            # 'occurred': occurred
        }])
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': policy,
            'ReadableContentsFormat': formats['json'],
            'HumanReadable': policy,
            'EntryContext': policy
        })
        count += 1
        if count == max:
            w.stop()
    demisto.results('Done')
    return

    pretty = (
        "pretty_example"  # str | If 'true', then the output is pretty printed. (optional)
    )
    # bool | allowWatchBookmarks requests watch events with type \"BOOKMARK\". Servers that do not implement bookmarks may ignore this flag and bookmarks are sent at the server's discretion. Clients should not assume bookmarks are returned at any specific interval, nor may they assume the server will send any BOOKMARK event during a session. If this is not a watch, this field is ignored. If the feature gate WatchBookmarks is not enabled in apiserver, this field is ignored.  This field is beta. (optional)
    allow_watch_bookmarks = True
    _continue = "_continue_example"  # str | The continue option should be set when retrieving more results from the server. Since this value is server defined, kubernetes.clients may only use the continue value from a previous query result with identical query parameters (except for the value of continue) and the server may reject a continue value it does not recognize. If the specified continue value is no longer valid whether due to expiration (generally five to fifteen minutes) or a configuration change on the server, the server will respond with a 410 ResourceExpired error together with a continue token. If the kubernetes.client needs a consistent list, it must restart their list without the continue field. Otherwise, the kubernetes.client may send another list request with the token received with the 410 error, the server will respond with a list starting from the next key, but from the latest snapshot, which is inconsistent from the previous list results - objects that are created, modified, or deleted after the first list request will be included in the response, as long as their keys are after the \"next key\".  This field is not supported when watch is true. Clients may start a watch from the last resourceVersion value returned by the server and not miss any modifications. (optional)
    limit = 1  # int | limit is a maximum number of responses to return for a list call. If more items exist, the server will set the `continue` field on the list metadata to a value that can be used with the same initial query to retrieve the next set of results. Setting a limit may return fewer than the requested amount of items (up to zero items) in the event all requested objects are filtered out and kubernetes.clients should only use the presence of the continue field to determine whether more results are available. Servers may choose not to support the limit argument and will return all of the available results. If limit is specified and the continue field is empty, kubernetes.clients may assume that no more results are available. This field is not supported if watch is true.  The server guarantees that the objects returned when using continue will be identical to issuing a single list call without a limit - that is, no objects created, modified, or deleted after the first request is issued will be included in any subsequent continued requests. This is sometimes referred to as a consistent snapshot, and ensures that a kubernetes.client that is using limit to receive smaller chunks of a very large result can ensure they see all possible objects. If objects are updated during a chunked list the version of the object that was present at the time the first list result was calculated is returned. (optional)
    # str | When specified with a watch call, shows changes that occur after that particular version of a resource. Defaults to changes from the beginning of history. When specified for list: - if unset, then the result is returned from remote storage based on quorum-read flag; - if it's 0, then we simply return what we currently have in cache, no guarantee; - if set to non zero, then the result is at least as fresh as given rv. (optional)
    resource_version = "resource_version_example"
    # int | Timeout for the list/watch call. This limits the duration of the call, regardless of any activity or inactivity. (optional)
    timeout_seconds = 20
    # api_response = v1_network.list_network_policy_for_all_namespaces(
    api_response = v1_network.list_network_policy_for_all_namespaces(
        pretty="true",
        allow_watch_bookmarks=True,
        limit=limit,
        timeout_seconds=timeout_seconds,
        watch=False)

    demisto.results(api_response.to_str())

    incidents = []
    for policy in api_response['items']:
        incidents.append({
            'name': 'K8s Policy Event',
            'details': str(policy),
            'rawJSON': json.dumps({'policy': str(policy)})
            # 'type': '',
            # 'occurred': occurred
        })
    demisto.results(demisto.createIncidents(incidents))


def watch1_command(client):
    # Init
    v1 = kube_client.CoreV1Api()
    #  Begin watch
    v1_network = kube_client.NetworkingV1Api(kube_client.ApiClient())
    body = kube_client.V1NetworkPolicy()
    count = 2
    out = ""
    incidents = []
    w = watch.Watch()

    for event in w.stream(v1.list_namespace, _request_timeout=300):
        out += "Event: %s %s\n" % (event['type'], event['object'].metadata.name)
        incidents.append({
            'name': 'created',
            'details': 'details',
            'rawJSON': json.dumps({'type': event['type'], 'name': event['object'].metadata.name})
            # 'type': '',
            # 'occurred': occurred
        })
        # demisto.addEntry(id=8, entry={'Contents': 'Adding entry! %d' % count})
        count -= 1
        if not count:
            w.stop()

    demisto.results(demisto.createIncidents(incidents))
    demisto.info('test')
    demisto.results(out)


def k8s_delete_pod_ip(client, args):
    """
        Delete the pod matching the IP in the args
    """
    try:
        v1 = kube_client.CoreV1Api()
        pods = v1.list_pod_for_all_namespaces(watch=False)
        for pod in pods.items:
            # TBD: is this the right arg
            if pod.status.pod_ip == args['threat_ip']:
                demisto.results('Deleting pod %s.%s' % (pod.metadata.namespace, pod.metadata.name))
                try:
                    #body = client.V1DeleteOptions()
                    api_response = v1.delete_namespaced_pod(pod.metadata.name, pod.metadata.namespace)
                    break
                except kube_client.rest.ApiException as e:
                    demisto.results('Exception in  pod delete API %s' % e)
    except Exception as ee:
        demisto.results('Exception in deleting pod with ip %s %s' % (threat_ip, ee))


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/v1/suffix')

    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()

    proxy = demisto.params().get('proxy', False)
    with open('./kubeconfig.tmp', 'wt') as kubeconfig_file:
        kubeconfig_file.write(demisto.params().get('kubeconfig', ''))

    config.load_kube_config('./kubeconfig.tmp')

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'k8s-list-network-policies':
            return_outputs(*get_netpol_command(client, demisto.args()))
        elif demisto.command() == 'k8s-get-network-policy':
            # Get individual if arg provided, else list all. --namespace=all
            demisto.args().get('policy_name', '')
            return_outputs(*get_netpol_command(client, demisto.args()))
        elif demisto.command() == 'k8s-watch':
            watch_command(client)
        elif demisto.command() == 'k8s-show-pods':
            v1 = kube_client.CoreV1Api()
            v1.api_client.configuration.verify_ssl = False
            out = "Listing pods with their IPs:\n"
            ret = v1.list_pod_for_all_namespaces(watch=False)
            for i in ret.items:
                out += "%s\t%s\t%s\n" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name)
            demisto.results(out)
        elif command == 'long-running-execution':
            long_running_command(client)
        elif demisto.command() == 'k8s-delete-pod-ip':
            k8s_delete_pod_ip(client, demisto.args())

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
