import os
from kubernetes import client, config
from kubernetes.client import ApiClient

cluster_host_url = os.environ['KUBERNETES_CLUSTER_HOST_URL']
token = os.environ['KUBERNETES_CLUSTER_TOKEN']
def test_kubernetes_client_setup():
    from Kubernetes import kubernetes_client_setup
    c = kubernetes_client_setup(cluster_host_url, token)
    print(c.configuration)
    v1 = client.CoreV1Api(api_client=c)
    ret = v1.list_namespace(watch=False)
    for i in ret.items:
        print("%s\t%s\t%s" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name))


test_kubernetes_client_setup()
