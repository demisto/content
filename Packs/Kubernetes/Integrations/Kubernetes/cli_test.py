import os

from kubernetes import client, config
from kubernetes.client import ApiClient

from Kubernetes import Client

cluster_host_url = os.environ['KUBERNETES_CLUSTER_HOST_URL']
token = os.environ['KUBERNETES_CLUSTER_TOKEN']
cs = Client(cluster_host_url, token, "victor")
ret = cs.list_pods()
for i in ret.items:
    print("%s\t%s\t%s" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name))
#test_kubernetes_client_setup()
