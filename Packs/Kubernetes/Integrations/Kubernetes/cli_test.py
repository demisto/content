import os
import argparse

from Kubernetes import Client

parser = argparse.ArgumentParser()
parser.add_argument("namespace", help="The Kubernetes namespace to use.")
parser.add_argument("--pods", help="List pods in namespace.", action="store_true")
parser.add_argument("--services", help="List services in namespace.", action="store_true")
parser.add_argument("--spec", help="List all properties of an object's specification.", action="store_true")
parser.add_argument("--prop", type=str, help="Print a specific property.")
args = parser.parse_args()
ns = args.namespace
cluster_host_url = os.environ['KUBERNETES_CLUSTER_HOST_URL']
token = os.environ['KUBERNETES_CLUSTER_TOKEN']
k8s = Client(cluster_host_url, token, ns)

if args.pods:
    ret = k8s.list_pods()
    if len(ret.items) > 0:
        if args.spec:            
            if args.prop is None:
                print ("Pod spec: %s" % dir(ret.items[0].spec))
            else:
                print ("Pod %s: %s" % (args.prop, getattr(ret.items[0].spec, args.prop)))            
        else:
            print ("Pods in namespace %s:" % ns)
            for i in ret.items:
                print("%s\t%s" % (i.metadata.name, i.status.pod_ip))
    else: print ("No pods returned.")

elif (args.services):
    print ("Services in namespace %s:" % ns)
    ret = k8s.list_services()
    for i in ret.items:
        print("%st%s" % (i.spec, i.metadata))