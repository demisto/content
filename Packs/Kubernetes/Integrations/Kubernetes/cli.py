import os
import argparse
import json
import logging

from Kubernetes import *

parser = argparse.ArgumentParser()
parser.add_argument("namespace", help="The Kubernetes namespace to use.")
parser.add_argument("--pods", help="List pods in namespace.", action="store_true")
parser.add_argument("--getpods", help="Command: list pods in namespace.", action="store_true")
parser.add_argument("--services", help="List services in namespace.", action="store_true")
parser.add_argument("--spec", help="List all properties of an object's specification.", action="store_true")
parser.add_argument("--meta", help="List all properties of an object's metadata.", action="store_true")
parser.add_argument("--status", help="List all properties of an object's status.", action="store_true")
parser.add_argument("--json", help="Print an object as JSON.", action="store_true")
parser.add_argument("--prop", type=str, help="Print a specific property.")
parser.add_argument("--podname", type=str, help="Select a pod for an operation.")
parser.add_argument("--podexec", type=str, help="Execute a command inside a pod.")
args = parser.parse_args()
ns = args.namespace

cluster_host_url = os.environ['KUBERNETES_CLUSTER_HOST_URL']
token = os.environ['KUBERNETES_CLUSTER_TOKEN']
k8s = Client(cluster_host_url, token)

if args.getpods:
    print(k8s.get_pods_readable(k8s.get_pods_raw(ns).to_dict()))
    exit()
elif args.podexec:
    if args.podname is None:
        raise ValueError(f'Pod name must be specified.')
    else:
        print(k8s.pod_exec(ns, args.podname, args.podexec))
    exit()
obj = ''
ret = None
if args.pods:
    obj = "Pod"
    ret = k8s.get_pods_raw(ns)
elif args.services:
    obj = "Service"
    ret = k8s.list_services(ns)
else: exit()

if len(ret.items) > 0:
    if args.json:
        print(dict_to_json(ret.to_dict()))
        exit()
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