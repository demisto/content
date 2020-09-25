import os
import argparse

from Kubernetes import Client

parser = argparse.ArgumentParser()
parser.add_argument("namespace", help="The Kubernetes namespace to use.")
parser.add_argument("--pods", help="List pods in name", action="store_true")
args = parser.parse_args()
ns = args.namespace
cluster_host_url = os.environ['KUBERNETES_CLUSTER_HOST_URL']
token = os.environ['KUBERNETES_CLUSTER_TOKEN']
k8s = Client(cluster_host_url, token, "victor")

if (args.pods):
    print ("Pods in namespace %s:" % ns)
    ret = k8s.list_pods()
    for i in ret.items:
        print("%s\t%s\t%s" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name))