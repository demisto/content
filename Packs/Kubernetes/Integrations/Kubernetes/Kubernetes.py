from datetime import date, datetime, timezone
from json import dumps
from typing import Any, Dict, List, Optional, Tuple, Union, cast

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from kubernetes import client, config
from kubernetes.client import ApiClient, Configuration, api, models
from kubernetes.client.api import CoreV1Api
from kubernetes.client.models import (V1APIVersions, V1Pod, V1PodList,
                                      V1ServiceList)
from kubernetes.stream import stream

"""Kubernetes Integration for Cortex XSOAR

Integration with the Python/REST API of a Kubernetes cluster. This uses the official
Python client: https://github.com/kubernetes-client/python/. Includes optional OS package vulnerability
scanning from the Vulners.com vulnerability scanner: https://vulners.com

Kubernetes API
--------------
- Pods: Retrieve details of pods and their containers. Create new pods or stop running pods.
- Services: Retrieve details of services. Create new services or delete existing services.
- Routes: Retrieve details of routes Create new routes or delete existing routes.
- Scan: Scan container packages for vulnerabilities.

"""

''' IMPORTS '''
# std

# 3rd-party

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%d %H:%M:%SZ'

''' HELPERS '''


def json_serial(obj):
    """JSON serializer for objects not serializable by default."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError("Type %s not serializable" % type(obj))


def dict_to_json(d: Dict[str, Any]) -> str:
    """Serialize Dict[str, Any] that includes datetime fields."""
    return json.dumps(d, indent=4, sort_keys=True, default=json_serial)


''' CLIENT '''


class Client(BaseClient):
    """Client class to interact with the Kubernetes API."""
    cluster_host_url: str = ''
    cluster_token: str = ''
    vulners_api_key = None
    namespace = None
    configuration: Configuration = None
    api_client: ApiClient = None
    api: CoreV1Api = None

    def __init__(self, h, t, ns=None, k=None):
        super().__init__('https://vulners.com')
        self.cluster_host_url = h
        self.cluster_token = t
        self.vulners_api_key = k
        self.configuration = client.Configuration()
        self.configuration.host = self.cluster_host_url
        self.configuration.api_key['authorization'] = self.cluster_token
        self.configuration.api_key_prefix['authorization'] = 'Bearer'
        self.api_client = client.ApiClient(configuration=self.configuration)
        self.api = client.CoreV1Api(api_client=self.api_client)
        self.namespace = ns

    def get_api_versions(self) -> V1APIVersions:
        return client.CoreApi(api_client=self.api_client).get_api_versions()

    def get_pods_raw(self, ns=None) -> V1PodList:
        if not ns is None:
            return self.api.list_namespaced_pod(ns)
        else:
            return self.api.list_pod_for_all_namespaces()

    def try_get_pod(self, ns: str, pod_name: str) -> V1Pod:
        try:
            return self.api.read_namespaced_pod(pod_name, ns)
        except:
            return None

    def pod_exec(self, ns, pod_name, cmd) -> str:
        pod = self.try_get_pod(ns, pod_name)
        if not pod:
            raise ValueError(f'The pod {pod_name} in namespace {ns} does not exist.')
        exec_command = [
            '/bin/sh',
            '-c',
            cmd
        ]
        resp = stream(self.api.connect_get_namespaced_pod_exec,
                      pod_name,
                      ns,
                      command=exec_command,
                      stderr=True, stdin=False,
                      stdout=True, tty=False)
        return resp

    def pod_detect_os(self, ns, pod_name) -> str:
        version = self.pod_exec(ns, pod_name, "cat /etc/os-release")
        if version:
            reFamily = re.search("^ID=\"?(\w+)\"?", version, re.MULTILINE)
            if reFamily:
                osFamily = reFamily.group(1).lower()
            else:
                return ''
            reVersion = re.search("^VERSION_ID=\"?(\w+)(.\w+)?\"?", version, re.MULTILINE)
            if reVersion:
                osVersion = ''.join([s.lower() for s in reVersion.groups()])
            else:
                return osFamily
            return f'{osFamily}:{osVersion}'

    def pod_get_os_packages_raw(self, ns, pod_name) -> Dict[str, Any]:
        osinfo = self.pod_detect_os(ns, pod_name)
        if osinfo == '':
            return []
        name, version = osinfo.split(':')[0], osinfo.split(':')[1]
        cmd = ''
        if name in ('rhel', 'centos', 'oraclelinux', 'suse', 'fedora'):
            cmd = """rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n'"""
        elif name in ('debian', 'ubuntu', 'kali', 'linuxmint'):
            cmd = """dpkg-query -W -f='${Status} ${Package} ${Version} ${Architecture}\\n'|awk '($1 == "install") && ($2 == "ok") {print $4" "$5" "$6}'"""
        else:
            return []
        active_kernel = self.pod_exec(ns, pod_name, "uname -r")
        package_list = self.pod_exec(ns, pod_name, cmd).splitlines()
        packages = [package for package in package_list if not (
            package == '0' or package == '' or package.startswith("kernel-") or package == "kernel-%s" % active_kernel)]
        return {'os': name, 'version': version, 'package': packages}

    def pod_scan_os_packages_raw(self, ns, pod_name) -> Dict[str, Any]:
        if self.vulners_api_key is None:
            raise ValueError("You must first set a Vulners API key in the integration configuration.")
        packages = self.pod_get_os_packages_raw(ns, pod_name)
        packages['apiKey'] = self.vulners_api_key
        resp = self._http_request(
            method='POST',
            url_suffix='api/v3/audit/audit/',
            json_data=packages
        )
        if resp['result'] != 'OK':
            raise ValueError("Did not receive data from Vulners.com server.")
        else:
            return resp['data']

    def get_vulns_readable(self, ret: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [{
                'Package': r['package'],
                'BulletinID': r.get('bulletinID', ''),
                'BulletinPackage': r.get('bulletinPackage', ''),
                'CVE': str(r.get('cvelist', '')),
                'CVSS': str(r.get('cvss', '')),
                'Fix': r.get('fix', '')
                } for r in ret['reasons']]

    def list_services(self) -> V1ServiceList:
        if not self.namespace is None:
            return self.api.list_namespaced_service(self.namespace)
        else:
            return self.api.list_service_for_all_namespaces()

    def get_pods_readable(self, ret: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [{
                'Name': p['metadata']['name'],
                'Status': p['status']['phase'],
                'Containers': len(p['status']['container_statuses']),
                'Ready': len([s for s in p['status']['container_statuses'] if s['ready']]),
                'Restarts': sum([s['restart_count'] for s in p['status']['container_statuses']]),
                'Started': p['status']['start_time'].strftime(DATE_FORMAT)
                } for p in ret['items']]


''' COMMAND FUNCTIONS '''


def test_module(c: Client) -> str:
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
    ns = args.get('ns', k8s.namespace)
    results = k8s.get_pods_raw(ns).to_dict()
    return CommandResults(
        outputs_prefix='Kubernetes.Pods',
        outputs_key_field='Name',
        outputs=k8s.get_pods_readable(results)
    )


def pod_exec_command(k8s: Client, args: Dict[str, Any]) -> CommandResults:
    """ command: Execute a command in a pod.

    :type k8s: ``Client``
    :param Client: Kubernetes client to use.

    :type args: ``Dict[str, Any]``
    :param args: All command arguments, usually passed from ``demisto.args()``.

    :return: A ``CommandResults`` object that is then passed to ``return_results``.
    :rtype: ``CommandResults``
    """
    ns = args.get('ns', k8s.namespace)
    pod_name = args['pod_name']
    cmd = args['cmd']
    resp = k8s.pod_exec(ns, pod_name, cmd)
    return CommandResults(
        outputs_prefix='Kubernetes.Pod.Exec',
        outputs_key_field='',
        outputs=resp,
        readable_output=resp)


def pod_detect_os_command(k8s: Client, args: Dict[str, Any]) -> CommandResults:
    """ command: Detect pod's operating system.

    :type k8s: ``Client``
    :param Client: Kubernetes client to use.

    :type args: ``Dict[str, Any]``
    :param args: All command arguments, usually passed from ``demisto.args()``.

    :return: A ``CommandResults`` object that is then passed to ``return_results``.
    :rtype: ``CommandResults``
    """
    ns = args.get('ns', k8s.namespace)
    pod_name = args['pod_name']
    resp = k8s.pod_detect_os(ns, pod_name)
    return CommandResults(
        outputs_prefix='Kubernetes.Pod.OS',
        outputs_key_field='',
        outputs=resp,
        readable_output=resp)


def pod_get_os_packages_command(k8s: Client, args: Dict[str, Any]) -> CommandResults:
    """ command: Get a list of a pod's container's operating system packages.

    :type k8s: ``Client``
    :param Client: Kubernetes client to use.

    :type args: ``Dict[str, Any]``
    :param args: All command arguments, usually passed from ``demisto.args()``.

    :return: A ``CommandResults`` object that is then passed to ``return_results``.
    :rtype: ``CommandResults``
    """
    ns = args.get('ns', k8s.namespace)
    pod_name = args['pod_name']
    r = k8s.pod_get_os_packages_raw(ns, pod_name)
    return CommandResults(
        outputs_prefix='Kubernetes.Pod.OS.Packages',
        outputs_key_field='',
        outputs=r,
        readable_output=dict_to_json(r))


def pod_scan_os_packages_command(k8s: Client, args: Dict[str, Any]) -> CommandResults:
    """ command: Scan a pod's container's operating system packages for vulnerabilities.

    :type k8s: ``Client``
    :param Client: Kubernetes client to use.

    :type args: ``Dict[str, Any]``
    :param args: All command arguments, usually passed from ``demisto.args()``.

    :return: A ``CommandResults`` object that is then passed to ``return_results``.
    :rtype: ``CommandResults``
    """
    ns = args.get('ns', k8s.namespace)
    pod_name = args['pod_name']
    r = k8s.pod_scan_os_packages_raw(ns, pod_name)
    return CommandResults(
        outputs_prefix='Kubernetes.Pod.OS.Packages.Vulnerabilities',
        outputs_key_field='Package',
        outputs=k8s.get_vulns_readable(r)
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
    vulners_api_key = demisto.params().get('vulners_api_key')
    namespace = demisto.params().get('namespace')

    try:
        k8s = Client(cluster_host_url, auth_token, namespace, vulners_api_key)
        demisto.debug(f'Initialized k8s client for {cluster_host_url}.')
        if demisto.command() == 'test-module':
            return_results(test_module(k8s))
        elif demisto.command() == 'get-pods':
            return_results(get_pods_command(k8s, demisto.args()))
        elif demisto.command() == 'pod-exec':
            return_results(pod_exec_command(k8s, demisto.args()))
        elif demisto.command() == 'pod-detect-os':
            return_results(pod_detect_os_command(k8s, demisto.args()))
        elif demisto.command() == 'pod-get-os-packages':
            return_results(pod_get_os_packages_command(k8s, demisto.args()))
        elif demisto.command() == 'pod-scan-os-packages':
            return_results(pod_scan_os_packages_command(k8s, demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command in cluster {cluster_host_url}.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
