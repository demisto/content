import os
import argparse

from Kubernetes import *

parser = argparse.ArgumentParser()
parser.add_argument("namespace", help="The Kubernetes namespace to use.")
parser.add_argument("--pods", help="List pods in namespace.", action="store_true")
parser.add_argument("--podscmd", help="Command: list pods in namespace.", action="store_true")
parser.add_argument("--services", help="List services in namespace.", action="store_true")
parser.add_argument("--spec", help="List all properties of an object's specification.", action="store_true")
parser.add_argument("--meta", help="List all properties of an object's metadata.", action="store_true")
parser.add_argument("--status", help="List all properties of an object's status.", action="store_true")
parser.add_argument("--prop", type=str, help="Print a specific property.")
args = parser.parse_args()
ns = args.namespace

cluster_host_url = os.environ['KUBERNETES_CLUSTER_HOST_URL']
token = os.environ['KUBERNETES_CLUSTER_TOKEN']
k8s = Client(cluster_host_url, token, ns)

if args.podscmd:
    print(k8s.list_pods_readable())
    exit()
obj = ''
ret = None
if args.pods:
    obj = "Pod"
    ret = k8s.list_pods()
elif args.services:
    obj = "Service"
    ret = k8s.list_services()
else: exit()

if len(ret.items) > 0:
    if args.spec:            
        if args.prop is None:
            print ("%s spec: %s" % (obj, [ x for x in dir(ret.items[0].spec) if not x.startswith('_')]))
        else:
            print ("%ss %s:" % (obj, args.prop))
            for i in ret.items:
                print ("%s" % (getattr(i.spec, args.prop)))            
    elif args.meta:
        if args.prop is None:
            print ("%s metadata: %s" % (obj, [ x for x in dir(ret.items[0].metadata) if not x.startswith('_')]))
        else:
            print ("%ss %s:" % (obj, args.prop))
            for i in ret.items:
                print ("%s" % (getattr(i.metadata, args.prop)))
    elif args.status:
        if args.prop is None:
            print ("%s status: %s" % (obj, [ x for x in dir(ret.items[0].status) if not x.startswith('_')]))
        else:
            print ("%ss %s:" % (obj, args.prop))
            for i in ret.items:
                print ("%s" % (getattr(i.status, args.prop)))
    else:
        print ("%ss in namespace %s:" % (obj, ns))
        for i in ret.items:
            print([ x for x in dir(i) if not x.startswith('_')])
else: print ("No %ss returned." % obj)