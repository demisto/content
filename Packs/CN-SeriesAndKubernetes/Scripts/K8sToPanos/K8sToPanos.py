import datetime
import hashlib

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from dateutil.tz import tzutc

# M4d Propz @Richie


def gen_svc_obj_name(cluster_name, port):
    # service, address, and inbound nat rule object name for K8s service
    #    13 chars  13 chars  4 chars  6 chars   10 chars
    # <namespace>-<svc_name>-<type>-<port_value>-<hash>
    # "kube-system-kube-dns-tgt-53-4e5c971725"
    port_type = ""
    if port["port_type"] == "node_port":
        port_type = "np"
    elif port["port_type"] == "load_balancer":
        port_type = "port"
    elif port["port_type"] == "target_port":
        port_type = "tgt"
    else:
        port_type = "port"
    temp_hash_name = "%s-%s-%s-%s-%s-%s" % (
        cluster_name,
        port["namespace"],
        port["svc_name"],
        port_type,
        port["port"],
        port["protocol"],
    )
    temp_hash_val = hashlib.md5(str(temp_hash_name)).hexdigest()
    hash_val = temp_hash_val[0:10]
    temp_namespace = port["namespace"][0:13]
    temp_svc_name = port["svc_name"][0:13]
    res_name = "%s-%s-%s-%s-%s" % (
        temp_namespace,
        temp_svc_name,
        port_type,
        port["port"],
        hash_val,
    )
    return res_name


def gen_security_policy_rule_name(k8s_rule_name):
    # example : xsoar.k8s.namespace.key-value
    # Longest label supported is 253 + 63 chars or 316
    # https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
    if len(k8s_rule_name) <= 53:
        return k8s_rule_name
    hex_digest = hashlib.md5(
        k8s_rule_name.encode("utf8")
    ).hexdigest()  # always 32 bytes
    label = k8s_rule_name.split(".")[-1]
    if len(label) <= 30:
        return f"{label}-{hex_digest}"
    return hex_digest


def gen_dag_match_criteria(network_policy, direction, namespace):
    """Extract a list of DAG tags from Network Policy."""
    tags = []
    if direction == "src":
        try:
            ingress_spec = network_policy["raw_object"]["spec"]["ingress"]
            from_ = ingress_spec[0].get("from", '')
            if not from_:
                from_ = ingress_spec[0]["_from"]
            for selector in from_:
                for k, v in selector.items():
                    if k in ["namespaceSelector", "podSelector"]:
                        labels = v["matchLabels"]
                        for k_, v_ in labels.items():
                            tags.append(f"{namespace}.{k_}.{v_}")
        except KeyError:
            pass
    if direction == "dst":
        try:
            labels = network_policy["raw_object"]["spec"]["podSelector"]["matchLabels"]
            for k_, v_ in labels.items():
                tags.append(f"{namespace}.{k_}.{v_}")
        except KeyError:
            pass
    match = " OR ".join(tags)
    return match


def gen_service_objects(network_policy):
    services = []
    try:
        ports = network_policy["raw_object"]["spec"]["ingress"][0]["ports"]
        for port in ports:
            port_number = port.get("port")
            protocol = port.get("protocol", "tcp").lower()
            name = f"{protocol}-{port_number}"
            services.append({"Name": name, "Port": port_number, "Protocol": protocol})
    except KeyError:
        pass
    return services


def get_ip_blocks(network_policy, direction):
    ip_blocks = []
    if direction == "src":
        try:
            from_ = network_policy["raw_object"]["spec"]["ingress"][0]["from"]
            for selector in from_:
                for k, v in selector.items():
                    if k in ["ipBlock"]:
                        cidr = v["cidr"]
                        if isinstance(cidr, list):
                            return cidr
                        else:
                            ip_blocks.append(cidr)
        except KeyError:
            pass
    return ip_blocks


def get_appid(network_policy):
    labels = network_policy["raw_object"]["metadata"].get("labels")
    if labels:
        appid = labels.get("np.panw.com/appid")
        return appid
    return


# XSOAR Code
def analyzeIngress(specIngress):
    pass


def analyzeEgress(specEgress):
    pass


def setApplication():
    pass


def setDynamicAddressGroups():
    pass


def AnalyzePolicy(cluster_name: str, net_policy_json: dict):
    services = []
    sources = []
    destinations = []
    applications = []

    # Does it
    namespace = net_policy_json["raw_object"]["metadata"]["namespace"]
    policy_name = net_policy_json["raw_object"]["metadata"]["name"]

    # Up to 63 characters total
    namespace = f"xsoar.k8s.cl_{cluster_name}.ns_{namespace}"
    fqrn = f"{namespace}.{policy_name}"
    rule_name = gen_security_policy_rule_name(fqrn)
    rule_description = fqrn

    # Get CIDR addresses
    dst_ip_blocks = []
    src_ip_blocks = get_ip_blocks(net_policy_json, "src")

    # Generate DAG objects
    src_dag_name = f"{rule_name}.src"
    src_dag_description = fqrn
    src_dag_match = gen_dag_match_criteria(net_policy_json, "src", namespace)
    src_dag = {
        "Name": src_dag_name,
        "Match": src_dag_match,
        "Description": src_dag_description,
    }
    dst_dag_name = f"{rule_name}.dst"
    dst_dag_description = fqrn
    dst_dag_match = gen_dag_match_criteria(net_policy_json, "dst", namespace)
    dst_dag = {
        "Name": dst_dag_name,
        "Match": dst_dag_match,
        "Description": dst_dag_description,
    }

    # Generate service objects
    service_objects = gen_service_objects(net_policy_json)

    # Get NGFW metadata labels
    appid = get_appid(net_policy_json)

    src = ", ".join([src_dag_name] + src_ip_blocks)
    dst = ", ".join([dst_dag_name] + dst_ip_blocks)

    results = {
        "ConvertedPolicy": {
            "Rule": {
                "Name": rule_name,
                "Service": [
                    service["Name"] for service in services
                ],  # Service object name,
                "FromZone": "any",
                "ToZone": "any",
                "Application": appid,
                "Src": src,
                "Dst": dst
            },
            "DAG": [src_dag, dst_dag],
            "Services": service_objects,
        }
    }
    return results


def main():
    # network_policy = demisto.args()["KubernetesNetworkPolicy"]

    # There can be multiple clusters defined in Panorama, which one(s) do we care about?
    DEFAULT_CLUSTER = "dev-cluster"

   # results = AnalyzePolicy(DEFAULT_CLUSTER, NET_POL2)

    arg_network_policy = demisto.args().get('KubernetesNetworkPolicy', '')
    arg_cluster_name = demisto.args().get('ClusterName', '')
    # Some sources provide only the raw_object
    try:
        network_policy = json.loads(arg_network_policy)
    except Exception as e:
        raise

    if not network_policy.get('raw_object', ''):
        json_annotation = json.loads(network_policy.get('metadata').get(
            'annotations').get('kubectl.kubernetes.io/last-applied-configuration'))
        network_policy = {'raw_object': json_annotation}
    results = AnalyzePolicy(arg_cluster_name, network_policy)

    # demisto.results(results)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': results,
        'ReadableContentsFormat': formats['json'],
        'HumanReadable': results,
        'EntryContext': results
    })


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
