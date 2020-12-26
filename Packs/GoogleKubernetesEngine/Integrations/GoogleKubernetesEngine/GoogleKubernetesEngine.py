###########
# IMPORTS #
###########
# STD packages
from typing import Dict, Callable, Tuple, Any, Optional, List
# 3-rd party packages
from google.cloud.container_v1 import ClusterManagerClient
from google.protobuf.json_format import MessageToDict
from google.protobuf.message import Message
from google.cloud.container_v1 import enums
from google.oauth2 import service_account
# Local packages
import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

#########
# Notes #
#########
"""
    Development info:
    1.This integration implements the gke cli of google cloud platform, For more info -
        https://cloud.google.com/sdk/gcloud/reference/container/clusters
    2.In the implementation we use the official "google-cloud-container" sdk, For more info -
        https://googleapis.dev/python/container/latest/gapic/v1/types.html#google.cloud.container_v1
    3. Authentication done by Google service account, For more info -
        https://cloud.google.com/iam/docs/service-accounts
    Notice - Between updates GKE will not allow to perform new update until the last one finished, check the status in
             operation entry.           
"""  # noqa W291
####################
# GLOBAL CONSTUNTS #
####################
INTEGRATION_NAME = 'Google Kubernetes Engine'
INTEGRATION_CONTEXT_NAME = 'GKE'
CLUSTER_CONTEXT = f'{INTEGRATION_CONTEXT_NAME}.Cluster(val.Name && val.Name == obj.Name)'
NODE_POOL_CONTEXT = f'{INTEGRATION_CONTEXT_NAME}.NodePool(val.Name && val.Name == obj.Name)'
OPERATION_CONTEXT = f'{INTEGRATION_CONTEXT_NAME}.Operation(val.Name && val.Name == obj.Name)'
OPERATION_TABLE = ['Name', 'Zone', 'Status', 'StartTime']
COMMAND_OUTPUT = Tuple[str, Dict[str, Any], Dict[str, Any]]
API_TIMEOUT = 90


####################
# HELPER FUNCTIONS #
####################

def handle_default_configuration():
    """ Handle - default configuration if args not configured.

    Returns:
        dict: arguments filled with default configuration if args not configured.
    """
    command_arguments = demisto.args()
    integration_parameters = demisto.params()
    default_parameters = ['project', 'zone']
    for param in default_parameters:
        if param not in command_arguments:
            command_arguments[param] = integration_parameters.get(f'default_{param}')

    return command_arguments


def google_client_setup(json_configuration: str) -> ClusterManagerClient:
    """ Setup client for service acount in google cloud - For more information:
        https://cloud.google.com/iam/docs/service-accounts

    Args:
        json_configuration: Json configuration file content from IAM.

    Returns:
        ClusterManagerClient: client manager.
    """
    credentials = service_account.Credentials.from_service_account_info(json.loads(json_configuration))
    client = ClusterManagerClient(credentials=credentials)

    return client


def parse_cluster(cluster: dict) -> dict:
    """ Build entry contect entry for a cluster entry.

    Args:
        cluster: Cluster raw response from google API.

    Returns:
        dict: Cluster as defined entry context.
    """
    return {
        "Name": dict_safe_get(cluster, ["name"]),
        "MasterAuth": {
            "ClusterCaCertificate": dict_safe_get(cluster, ["masterAuth", "clusterCaCertificate"]),
        },
        "LoggingService": dict_safe_get(cluster, ["loggingService"]),
        "MonitoringService": dict_safe_get(cluster, ["monitoringService"]),
        "Network": dict_safe_get(cluster, ["network"]),
        "ClusterIpv4Cidr": dict_safe_get(cluster, ["clusterIpv4Cidr"]),
        "AddonsConfig": {
            "HttpLoadBalancing": {
                "Disbaled": dict_safe_get(cluster, ["addonsConfig", "httpLoadBalancing"]),
            },
            "HorizontalPodAutoscaling": {
                "Disabled": dict_safe_get(cluster, ["addonsConfig", "horizontalPodAutoscaling"]),
            },
            "KubernetesDashboard": {
                "Disabled": dict_safe_get(cluster, ["addonsConfig", "kubernetesDashboard", "disabled"]),
            },
            "NetworkPolicyConfig": {
                "Disabled": dict_safe_get(cluster, ["addonsConfig", "networkPolicyConfig", "disabled"]),
            }
        },
        "SubNetwork": dict_safe_get(cluster, ["subnetwork"]),
        "NodePools": [parse_node_pool(node_pool) for node_pool in cluster.get("nodePools", [])],
        "Locations": dict_safe_get(cluster, ["locations"]),
        "LabelFingerprint": dict_safe_get(cluster, ["labelFingerprint"]),
        "LegacyAbac": {
            "Enabled": dict_safe_get(cluster, ["legacyAbac", "enabled"]),
        },
        "NetworkPolicy": dict_safe_get(cluster, ["networkPolicy"]),
        "IpAllocationPolicy": {
            "UseIpAliases": dict_safe_get(cluster, ["ipAllocationPolicy", "useIpAliases"]),
            "ClusterIpv4Cidr": dict_safe_get(cluster, ["ipAllocationPolicy", "clusterIpv4Cidr"]),
            "ServicesIpv4Cidr": dict_safe_get(cluster, ["ipAllocationPolicy", "servicesIpv4Cidr"]),
            "ClusterSecondaryRangeName": dict_safe_get(cluster, ["ipAllocationPolicy", "clusterSecondaryRangeName"]),
            "ServicesSecondaryRangeName": dict_safe_get(cluster, ["ipAllocationPolicy", "servicesSecondaryRangeName"]),
            "ClusterIpv4CidrBlock": dict_safe_get(cluster, ["ipAllocationPolicy", "clusterIpv4CidrBlock"]),
            "ServicesIpv4CidrBlock": dict_safe_get(cluster, ["ipAllocationPolicy", "servicesIpv4CidrBlock"]),
        },
        "MasterAuthorizedNetworksConfig": {
            "CIDR": [cidr.get('cidrBlock') for cidr in dict_safe_get(cluster,
                                                                     keys=["masterAuthorizedNetworksConfig", "cidrBlocks"],
                                                                     default_return_value={})],
            "Enabled": dict_safe_get(cluster, ["masterAuthorizedNetworksConfig", "enabled"]),
        },
        "MaintenancePolicy": {
            "ResourceVersion": dict_safe_get(cluster, ["maintenancePolicy", "resourceVersion"]),
        },
        "NetworkConfig": {
            "Network": dict_safe_get(cluster, ["networkConfig", "network"]),
            "Subnetwork": dict_safe_get(cluster, ["networkConfig", "subnetwork"]),
        },
        "DefaultMaxPodsConstraint": {
            "MaxPodsPerNode": dict_safe_get(cluster, ["defaultMaxPodsConstraint", "maxPodsPerNode"]),
        },
        "AuthenticatorGroupsConfig": dict_safe_get(cluster, ["authenticatorGroupsConfig"]),
        "DatabaseEncryption": {
            "State": dict_safe_get(cluster, ["databaseEncryption", "state"]),
        },
        "SelfLink": dict_safe_get(cluster, ["selfLink"]),
        "Endpoint": dict_safe_get(cluster, ["endpoint"]),
        "InitialClusterVersion": dict_safe_get(cluster, ["initialClusterVersion"]),
        "CurrentMasterVersion": dict_safe_get(cluster, ["currentMasterVersion"]),
        "CreateTime": dict_safe_get(cluster, ["createTime"]),
        "Status": dict_safe_get(cluster, ["status"]),
        "ServicesIpv4Cidr": dict_safe_get(cluster, ["servicesIpv4Cidr"]),
        "Location": dict_safe_get(cluster, ["location"]),
    }


def parse_cluster_table(entry: dict) -> dict:
    """ Build human readable structue

    Args:
        entry: Cluster entry of context entry

    Returns:
        dict: dict object as required for table markdown.
    """
    return {
        'Name': dict_safe_get(entry, ["Name"]),
        'Location': dict_safe_get(entry, ["Location"]),
        'Master version': dict_safe_get(entry, ["CurrentMasterVersion"]),
        'Master IP': dict_safe_get(entry, ["Endpoint"]),
        'Status': dict_safe_get(entry, ["Status"])
    }


def parse_node_pool(node_pool: dict) -> dict:
    """ Build entry contect entry for a node pools entry.

    Args:
        node_pool: Node pool raw response from google API.

    Returns:
        dict: Node pool as defined entry context.
    """
    return {
        "Name": dict_safe_get(node_pool, ["name"]),
        "Config": {
            "MachineType": dict_safe_get(node_pool, ["config", "machineType"]),
            "DiskSizeGb": dict_safe_get(node_pool, ["config", "diskSizeGb"]),
            "OauthScopes": dict_safe_get(node_pool, ["config", "oauthScopes"]),
            "Metadata": {
                "DisableLegacyEndpoints": dict_safe_get(node_pool, ["config", "metadata", "disable-legacy-endpoints"])
            },
            "ImageType": dict_safe_get(node_pool, ["config", "imageType"]),
            "ServiceAccount": dict_safe_get(node_pool, ["config", "serviceAccount"]),
            "DiskType": dict_safe_get(node_pool, ["config", "diskType"]),
            "ShieldedInstanceConfig": {
                "EnableIntegrityMonitoring": dict_safe_get(node_pool, ["config",
                                                                       "shieldedInstanceConfig",
                                                                       "enableIntegrityMonitoring"])
            }
        },
        "InitialNodeCount": dict_safe_get(node_pool, ["initialNodeCount"]),
        "Autoscaling": {
            "Enabled": dict_safe_get(node_pool, ["autoscaling", "enabled"]),
            "MinNodeCount": dict_safe_get(node_pool, ["autoscaling", "minNodeCount"]),
            "MaxNodeCount": dict_safe_get(node_pool, ["autoscaling", "maxNodeCount"])
        },
        "Management": {
            "AutoRepair": dict_safe_get(node_pool, ["management", "autoRepair"])
        },
        "MaxPodsConstraint": {
            "MaxPodsPerNode": dict_safe_get(node_pool, ["maxPodsConstraint", "maxPodsPerNode"])
        },
        "PodIpv4CidrSize": dict_safe_get(node_pool, ["podIpv4CidrSize"]),
        "SelfLink": dict_safe_get(node_pool, ["selfLink"]),
        "Version": dict_safe_get(node_pool, ["version"]),
        "InstanceGroupUrls": dict_safe_get(node_pool, ["instanceGroupUrls"]),
        "Status": dict_safe_get(node_pool, ["status"])
    }


def parse_node_pool_table(entry: dict) -> dict:
    """ Build human readable structue

    Args:
        entry: Node pool entry of context entry

    Returns:
        dict: dict object as required for table markdown.
    """
    return {
        'Name': dict_safe_get(entry, ["Name"]),
        'Machine Type': dict_safe_get(entry, ["Config", "MachineType"]),
        'Disk size': dict_safe_get(entry, ["Config", "DiskSizeGb"]),
        'Node version': dict_safe_get(entry, ["Version"])
    }


def parse_operation(response_dict: dict):
    return {
        'Name': response_dict.get('name'),
        'Zone': response_dict.get('zone'),
        'OperationType': response_dict.get('operationType'),
        'Status': response_dict.get('status'),
        'SelfLink': response_dict.get('selfLink'),
        'TargetLink': response_dict.get('targetLink'),
        'StartTime': response_dict.get('startTime')
    }


######################
# COMMANDS FUNCTIONS #
######################

def test_module_command(client: ClusterManagerClient, project: str, zone: str):
    """ Test Google Kubernetes Engine client connection using gcloud-clusters-list command:
            1. project.
            2. zone.

    Args:
        client: Google container client.
        project: GCP project from console.
        zone: Project query zone, e.g. "europe-west2-a".

    Returns:
        str: Human readable.
        dict: Cluster entry context.
        dict: Cluster raw response.
    """
    # Query and gPRC unpack - will raise exception if not succeed
    try:
        client.list_clusters(project_id=project,
                             zone=zone,
                             timeout=API_TIMEOUT)
    except Exception:
        raise DemistoException('Unsuccessfull integration test - check configuration...')

    return 'ok', {}, {}


def gcloud_clusters_list_command(client: ClusterManagerClient, project: str, zone: str) -> COMMAND_OUTPUT:
    """ Lists all clusters owned by a project in either the specified zone or all zones.
        Original command - https://cloud.google.com/sdk/gcloud/reference/container/clusters/list

    Args:
        client: Google container client.
        project: GCP project from console.
        zone: Project query zone, e.g. "europe-west2-a".

    Returns:
        str: Human readable.
        dict: Cluster entry context.
        dict: Cluster raw response.
    """
    # Query and gPRC unpack
    raw_response_msg: Message = client.list_clusters(project_id=project,
                                                     zone=zone,
                                                     timeout=API_TIMEOUT)
    raw_response_dict: dict = MessageToDict(raw_response_msg)

    # Entry context
    clusters_ec: List[dict] = [parse_cluster(cluster) for cluster in raw_response_dict.get('clusters', [])]
    entry_context = {
        CLUSTER_CONTEXT: clusters_ec,
    }
    # Human readable
    human_readable: str = tableToMarkdown(t=[parse_cluster_table(entry) for entry in clusters_ec],
                                          name=f'Clusters (Project={project}, Zone={zone})')

    return human_readable, entry_context, raw_response_dict


def gcloud_clusters_describe_command(client: ClusterManagerClient, project: str = "", cluster: str = "",
                                     zone: str = "") -> COMMAND_OUTPUT:
    """ Gets the details of a specific cluster.
        https://cloud.google.com/sdk/gcloud/reference/container/clusters/describe

    Args:
        client: Google container client.
        project: GCP project from console.
        cluster: Cluster ID, e.g. "dmst-gcloud-cluster-1".
        zone: Project query zone, e.g. "europe-west2-a".

    Returns:
        str: Human readable.
        dict: Cluster entry context.
        dict: Cluster raw response.
    """
    # Query and gPRC unpack
    raw_response_msg: Message = client.get_cluster(cluster_id=cluster,
                                                   project_id=project,
                                                   zone=zone,
                                                   timeout=API_TIMEOUT)
    # Entry context
    raw_response_dict: dict = MessageToDict(raw_response_msg)
    cluster_ec = parse_cluster(raw_response_dict)
    entry_context = {
        CLUSTER_CONTEXT: cluster_ec,
    }
    # Human readable
    human_readable: str = tableToMarkdown(t=parse_cluster_table(cluster_ec),
                                          name=f'Clusters (Project={project}, Zone={zone}, Cluster={cluster})', )

    return human_readable, entry_context, raw_response_dict


def gcloud_clusters_set_master_auth(client: ClusterManagerClient, project: str, cluster: str, zone: str,
                                    basic_auth: Optional[str] = None) -> COMMAND_OUTPUT:
    """ Enable basic (username/password) auth for the cluster. Enable will create user admin with generated password.
        https://cloud.google.com/sdk/gcloud/reference/container/clusters/update#--enable-basic-auth

    Args:
        client: Google container client.
        project: GCP project from console.
        zone: Project query zone, e.g. "europe-west2-a".
        cluster: Cluster ID, e.g. "dmst-gcloud-cluster-1".
        basic_auth: "enable" or "disable".

    Returns:
        str: Human readable.
        dict: Operation entry context.
        dict: Operation raw response.
    """
    # Perform cluster update
    upadte = {
        "username": "admin" if basic_auth == "enable" else ""
    }
    raw_response_msg: Message = client.set_master_auth(action=enums.SetMasterAuthRequest.Action.SET_USERNAME,
                                                       project_id=project,
                                                       zone=zone,
                                                       cluster_id=cluster,
                                                       update=upadte,
                                                       timeout=API_TIMEOUT)
    raw_response_dict: dict = MessageToDict(raw_response_msg)
    # Entry context
    operation: dict = parse_operation(raw_response_dict)
    entry_context = {
        OPERATION_CONTEXT: operation
    }
    # Human readable
    human_readable: str = tableToMarkdown(t=operation,
                                          headers=OPERATION_TABLE,
                                          name=f'Set master-auth operation - {operation.get("Name")}')

    return human_readable, entry_context, raw_response_dict


def gcloud_clusters_set_addons_command(client: ClusterManagerClient, project: str, cluster: str, zone: str,
                                       http_load_balancing: Optional[str] = None,
                                       kubernetes_dashboard: Optional[str] = None,
                                       network_policy: Optional[str] = None) -> COMMAND_OUTPUT:
    """ Sets the addons for a specific cluster.
        https://cloud.google.com/sdk/gcloud/reference/container/clusters/update#--update-addons

    Args:
        client: Google container client.
        project: GCP project from console.
        zone: Project query zone, e.g. "europe-west2-a".
        cluster: Cluster ID, e.g. "dmst-gcloud-cluster-1".
        http_load_balancing: "enable" or "disable".
        kubernetes_dashboard: "enable" or "disable".
        network_policy: "enable" or "disable".

    Returns:
        str: Human readable.
        dict: Operation entry context.
        dict: Operation raw response.
    """
    # Perform cluster update
    update = {}
    if http_load_balancing:
        update['http_load_balancing'] = {
            "disabled": http_load_balancing != 'enable'
        }
    if kubernetes_dashboard:
        update['kubernetes_dashboard'] = {
            "disabled": kubernetes_dashboard != 'enable'
        }
    if network_policy:
        update['network_policy_config'] = {
            "disabled": network_policy != 'enable'
        }
    raw_response_msg: Message = client.set_addons_config(project_id=project,
                                                         zone=zone,
                                                         cluster_id=cluster,
                                                         addons_config=update,
                                                         timeout=API_TIMEOUT)
    raw_response_dict: dict = MessageToDict(raw_response_msg)
    # Entry context
    operation: dict = parse_operation(raw_response_dict)
    entry_context = {
        OPERATION_CONTEXT: operation,
    }
    # Human readable
    human_readable: str = tableToMarkdown(t=operation,
                                          headers=OPERATION_TABLE,
                                          name=f'Set addons - Operation: {operation.get("Name")}')

    return human_readable, entry_context, raw_response_dict


def gcloud_clusters_set_legacy_auth_command(client: ClusterManagerClient, project: str, cluster: str, zone: str,
                                            enable: Optional[str] = None) -> COMMAND_OUTPUT:
    """ Enable or Disable legacy ABAC auth.
        https://cloud.google.com/sdk/gcloud/reference/container/clusters/update#--enable-legacy-authorization

    Args:
        client: Google container client.
        project: GCP project from console.
        zone: Project query zone, e.g. "europe-west2-a".
        cluster: Cluster ID, e.g. "dmst-gcloud-cluster-1".
        enable: "true" or "false"

    Returns:
        str: Human readable.
        dict: Operation entry context.
        dict: Operation raw response.
    """
    # Perform cluster update
    raw_response_msg: Message = client.set_legacy_abac(project_id=project,
                                                       zone=zone,
                                                       cluster_id=cluster,
                                                       enabled=(enable == 'true'),
                                                       timeout=API_TIMEOUT)
    raw_response_dict: dict = MessageToDict(raw_response_msg)
    # Entry context
    operation: dict = parse_operation(raw_response_dict)
    entry_context = {
        OPERATION_CONTEXT: operation,
    }
    # Human readable
    human_readable: str = tableToMarkdown(t=operation,
                                          headers=OPERATION_TABLE,
                                          name=f'Set legacy auth - Operation: {operation.get("Name")}')

    return human_readable, entry_context, raw_response_dict


def gcloud_clusters_set_master_authorized_network_command(client: ClusterManagerClient, project: str, cluster: str,
                                                          zone: str,
                                                          enable: Optional[str] = None,
                                                          cidrs: Optional[str] = None) -> COMMAND_OUTPUT:
    """ Enable or Disable authorized CIDRs to master node and add cidrs.
        https://cloud.google.com/sdk/gcloud/reference/container/clusters/update#--master-authorized-networks

    Args:
        client: Google container client.
        project: GCP project from console.
        zone: Project query zone, e.g. "europe-west2-a".
        cluster: Cluster ID, e.g. "dmst-gcloud-cluster-1".
        enable: "true" or "false"
        cidrs: Comma seprated list of CIDRs 192.160.0.0/24,10.0.0.0/24,

    Returns:
        str: Human readable.
        dict: Operation entry context.
        dict: Operation raw response.
    """
    # Perform cluster update
    update = {
        'desired_master_authorized_networks_config': {
            'enabled': enable == 'true',
            'cidr_blocks': [{'cidr_block': cidr_block} for cidr_block in argToList(cidrs)]
        }
    }

    raw_response_msg: Message = client.update_cluster(project_id=project,
                                                      zone=zone,
                                                      cluster_id=cluster,
                                                      update=update,
                                                      timeout=API_TIMEOUT)
    raw_response_dict: dict = MessageToDict(raw_response_msg)
    # Entry context
    operation: dict = parse_operation(raw_response_dict)
    entry_context = {
        OPERATION_CONTEXT: operation,
    }
    # Human readable
    human_readable: str = tableToMarkdown(t=operation,
                                          headers=OPERATION_TABLE,
                                          name=f'Set master authorized networks - Operation: {operation.get("Name")}')

    return human_readable, entry_context, raw_response_dict


def gcloud_clusters_set_k8s_stackdriver_command(client: ClusterManagerClient, project: str, cluster: str, zone: str,
                                                enable: Optional[str] = None) -> COMMAND_OUTPUT:
    """ Enable or Disable k8s stackdriver.
        https://cloud.google.com/sdk/gcloud/reference/container/clusters/update#--enable-stackdriver-kubernetes

    Args:
        client: Google container client.
        project: GCP project from console.
        zone: Project query zone, e.g. "europe-west2-a".
        cluster: Cluster ID, e.g. "dmst-gcloud-cluster-1".
        enable: "true" or "false"

    Returns:
        str: Human readable.
        dict: Operation entry context.
        dict: Operation raw response.

    Notes:
        1. The monitoring and logging should be configured to same resource and it can done only via gcp console.
    """
    # Perform cluster update
    update = "monitoring.googleapis.com/kubernetes" if enable == 'true' else ''
    raw_response_msg: Message = client.set_monitoring_service(project_id=project,
                                                              zone=zone,
                                                              cluster_id=cluster,
                                                              monitoring_service=update,
                                                              timeout=API_TIMEOUT)

    raw_response_dict: dict = MessageToDict(raw_response_msg)
    # Entry context
    operation: dict = parse_operation(raw_response_dict)
    entry_context = {
        OPERATION_CONTEXT: operation,
    }
    # Human readable
    human_readable: str = tableToMarkdown(t=operation,
                                          headers=OPERATION_TABLE,
                                          name=f'Set kubernetes stackdriver - Operation: {operation.get("Name")}')

    return human_readable, entry_context, raw_response_dict


def gcloud_clusters_set_binary_auth(client: ClusterManagerClient, project: str, cluster: str, zone: str,
                                    enable: Optional[str] = None) -> COMMAND_OUTPUT:
    """ Enable or Disable binary authorize.
        https://cloud.google.com/sdk/gcloud/reference/container/clusters/update#--enable-binauthz

    Args:
        client: Google container client.
        project: GCP project from console.
        zone: Project query zone, e.g. "europe-west2-a".
        cluster: Cluster ID, e.g. "dmst-gcloud-cluster-1".
        enable: "true" or "false"

    Returns:
        str: Human readable.
        dict: Operation entry context.
        dict: Operation raw response.
    """
    # Perform cluster update
    update = {
        'desired_binary_authorization': {
            'enabled': enable == 'enable',
        }
    }
    raw_response_msg: Message = client.update_cluster(project_id=project,
                                                      zone=zone,
                                                      cluster_id=cluster,
                                                      update=update,
                                                      timeout=API_TIMEOUT)
    raw_response_dict: dict = MessageToDict(raw_response_msg)
    # Entry context
    operation: dict = parse_operation(raw_response_dict)
    entry_context = {
        OPERATION_CONTEXT: operation,
    }
    # Human readable
    human_readable: str = tableToMarkdown(t=operation,
                                          headers=OPERATION_TABLE,
                                          name=f'Set kubernetes binary authorization - Operation: {operation.get("Name")}')

    return human_readable, entry_context, raw_response_dict


def gcloud_clusters_set_intra_node_visibility(client: ClusterManagerClient, project: str, cluster: str, zone: str,
                                              enable: Optional[str] = None) -> COMMAND_OUTPUT:
    """ Enable or Disable for intra node visibility in cluster.
        https://cloud.google.com/sdk/gcloud/reference/container/clusters/update#--enable-intra-node-visibility

    Args:
        client: Google container client.
        project: GCP project from console.
        zone: Project query zone, e.g. "europe-west2-a".
        cluster: Cluster ID, e.g. "dmst-gcloud-cluster-1".
        enable: "true" or "false"

    Returns:
        str: Human readable.
        dict: Operation entry context.
        dict: Operation raw response.
    """
    # Perform cluster update
    update = {
        'desired_intra_node_visibility_config': {
            'enabled': enable == 'enable',
        }
    }

    raw_response_msg: Message = client.update_cluster(project_id=project,
                                                      zone=zone,
                                                      cluster_id=cluster,
                                                      update=update,
                                                      timeout=API_TIMEOUT)
    raw_response_dict: dict = MessageToDict(raw_response_msg)
    # Entry context
    operation: dict = parse_operation(raw_response_dict)
    entry_context = {
        OPERATION_CONTEXT: operation,
    }
    # Human readable
    human_readable: str = tableToMarkdown(t=operation,
                                          headers=OPERATION_TABLE,
                                          name=f'Set intra node visibility - Operation: {operation.get("Name")}')

    return human_readable, entry_context, raw_response_dict


def gcloud_node_pool_list_command(client: ClusterManagerClient, project: str, zone: str,
                                  cluster: str) -> COMMAND_OUTPUT:
    """ gcloud container node-pools list - list existing node pools for a cluster
        https://cloud.google.com/sdk/gcloud/reference/container/node-pools/list

    Args:
        client: Google container client.
        project: GCP project from console.
        zone: Project query zone, e.g. "europe-west2-a".
        cluster: Cluster ID, e.g. "dmst-gcloud-cluster-1".

    Returns:
        str: Human readable.
        dict: Cluster entry context.
        dict: Cluster raw response.
    """
    # Query and gPRC unpack
    raw_response_msg: Message = client.list_node_pools(project_id=project,
                                                       zone=zone,
                                                       cluster_id=cluster,
                                                       timeout=API_TIMEOUT)
    raw_response_dict: dict = MessageToDict(raw_response_msg)
    # Entry context
    node_pools_ec: List[dict] = [parse_node_pool(node_pool) for node_pool in raw_response_dict.get('nodePools', [])]
    entry_context = {
        NODE_POOL_CONTEXT: node_pools_ec
    }
    # Human readable
    human_readable: str = tableToMarkdown(t=[parse_node_pool_table(entry) for entry in node_pools_ec],
                                          name=f'Node-pools (Project={project}, Zone={zone}, Cluster={cluster})')

    return human_readable, entry_context, raw_response_dict


def gcloud_node_pool_describe_command(client: ClusterManagerClient, project: str, zone: str, cluster: str,
                                      node_pool: str) -> COMMAND_OUTPUT:
    """ gcloud container node-pools list - list existing node pools for a cluster
        https://cloud.google.com/sdk/gcloud/reference/container/node-pools/describe

    Args:
        client: Google container client.
        project: GCP project from console.
        zone: Project query zone, e.g. "europe-west2-a".
        cluster: Cluster ID, e.g. "dmst-gcloud-cluster-1".
        node_pool: Node pool id, e.g. "dmst-gke-pool-1".

    Returns:
        str: Human readable.
        dict: Cluster entry context.
        dict: Cluster raw response.
    """
    # Query and gPRC unpack
    raw_response_msg: Message = client.get_node_pool(project_id=project,
                                                     zone=zone,
                                                     cluster_id=cluster,
                                                     node_pool_id=node_pool,
                                                     timeout=API_TIMEOUT)
    raw_response_dict: dict = MessageToDict(raw_response_msg)
    # Entry context
    node_pools_ec: dict = parse_node_pool(raw_response_dict)
    entry_context = {
        NODE_POOL_CONTEXT: node_pools_ec
    }
    # Human readable
    human_readable: str = tableToMarkdown(t=parse_node_pool_table(node_pools_ec),
                                          name=f'Node-pools (Project={project}, Zone={zone},'
                                               f' Cluster={cluster}, Node pool={node_pool})')

    return human_readable, entry_context, raw_response_dict


def gcloud_set_node_pool_management(client: ClusterManagerClient, project: str, zone: str, cluster: str,
                                    node_pool: str, auto_repair: Optional[str] = None,
                                    auto_upgrade: Optional[str] = None) -> COMMAND_OUTPUT:
    """ Disbale or Enable node-pool functionallity:
            1. auto-repair.
            2. auto-upgrade.
        https://cloud.google.com/sdk/gcloud/reference/container/node-pools/update

    Args:
        client: Google container client.
        project: GCP project from console.
        zone: Project query zone, e.g. "europe-west2-a".
        cluster: Cluster ID, e.g. "dmst-gcloud-cluster-1".
        node_pool: Node pool id, e.g. "dmst-gke-pool-1".
        auto_repair: A flag that specifies whether the node auto-repair is enabled for the node pool.
        auto_upgrade: A flag that specifies whether node auto-upgrade is enabled for the node pool.

    Returns:
        str: Human readable.
        dict: Operation entry context.
        dict: Operation raw response.
    """
    # Perform node pools update
    update = {}
    if auto_repair:
        update['auto_repair'] = auto_repair == 'enable'
    if auto_upgrade:
        update['auto_upgrade'] = auto_upgrade == 'enable'

    raw_response_msg: Message = client.set_node_pool_management(project_id=project,
                                                                zone=zone,
                                                                cluster_id=cluster,
                                                                node_pool_id=node_pool,
                                                                management=update,
                                                                timeout=API_TIMEOUT)
    raw_response_dict: dict = MessageToDict(raw_response_msg)
    # Entry context
    operation: dict = parse_operation(raw_response_dict)
    entry_context = {
        OPERATION_CONTEXT: operation,
    }
    # Human readable
    human_readable: str = tableToMarkdown(t=operation,
                                          headers=OPERATION_TABLE,
                                          name=f'Project {project} - Zone {zone} - Cluster {cluster} - {operation.get("Name")}')

    return human_readable, entry_context, raw_response_dict


def gcloud_operations_list_command(client: ClusterManagerClient, project: str, zone: str) -> COMMAND_OUTPUT:
    """ List operations in project-zone.
        https://cloud.google.com/sdk/gcloud/reference/container/operations/list

    Args:
        client: Google container client.
        project: GCP project from console.
        zone: Project query zone, e.g. "europe-west2-a".

    Returns:
        str: Human readable.
        dict: Operation entry context.
        dict: Operation raw response.
    """
    # Query operation status

    raw_response_msg: Message = client.list_operations(project_id=project,
                                                       zone=zone,
                                                       timeout=API_TIMEOUT)
    raw_response_dict: dict = MessageToDict(raw_response_msg)
    # Entry context
    operations: List[dict] = [parse_operation(operation) for operation in raw_response_dict.get('operations', [])]
    entry_context = {
        OPERATION_CONTEXT: operations,
    }
    # Human readable
    human_readable: str = tableToMarkdown(t=operations,
                                          headers=OPERATION_TABLE,
                                          name=f'Project {project} - Zone {zone} - Operations')

    return human_readable, entry_context, raw_response_dict


def gcloud_operations_describe_command(client: ClusterManagerClient, project: str, zone: str,
                                       operation: str) -> COMMAND_OUTPUT:
    """ Retrieve operation information by name.
        https://cloud.google.com/sdk/gcloud/reference/container/operations/describe

    Args:
        client: Google container client.
        project: GCP project from console.
        zone: Project query zone, e.g. "europe-west2-a".
        operation: Operation name.

    Returns:
        str: Human readable.
        dict: Operation entry context.
        dict: Operation raw response.
    """
    # Query operation status
    raw_response_msg: Message = client.get_operation(project_id=project,
                                                     zone=zone,
                                                     operation_id=operation,
                                                     timeout=API_TIMEOUT)
    raw_response_dict: dict = MessageToDict(raw_response_msg)
    # Entry context
    operations: dict = parse_operation(raw_response_dict)
    entry_context = {
        OPERATION_CONTEXT: operations,
    }
    # Human readable
    human_readable: str = tableToMarkdown(t=operations,
                                          headers=OPERATION_TABLE,
                                          name=f'Project {project} - Zone {zone} - Operation {operation}')

    return human_readable, entry_context, raw_response_dict


def gcloud_operations_cancel_command(client: ClusterManagerClient, project: str, zone: str,
                                     operation: str) -> COMMAND_OUTPUT:
    """ Cancel operation by operation name.

    Args:
        client: Google container client.
        project: GCP project from console.
        zone: Project query zone, e.g. "europe-west2-a".
        operation: Operation name.

    Returns:
        str: Human readable.
        dict: Operation entry context - will be empty.
        dict: Operation raw response - will be empty.
    """
    # Query operation status
    client.cancel_operation(project_id=project,
                            zone=zone,
                            operation_id=operation,
                            timeout=API_TIMEOUT)
    # Human readable
    human_readable: str = f'Project {project} - Zone {zone} - Operation {operation} canceled'

    return human_readable, {}, {}


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # Execute command
    command = demisto.command()
    LOG(f'Command being called is {command}')
    commands: Dict[str, Callable] = {
        # Clusters
        "test-module": test_module_command,
        "gcloud-clusters-list": gcloud_clusters_list_command,
        "gcloud-clusters-describe": gcloud_clusters_describe_command,
        "gcloud-clusters-set-muster-auth": gcloud_clusters_set_master_auth,
        "gcloud-clusters-set-addons": gcloud_clusters_set_addons_command,
        "gcloud-clusters-set-legacy-auth": gcloud_clusters_set_legacy_auth_command,
        "gcloud-clusters-set-master-authorized-network":
            gcloud_clusters_set_master_authorized_network_command,
        "gcloud-clusters-set-k8s-stackdriver": gcloud_clusters_set_k8s_stackdriver_command,
        "gcloud-clusters-set-binary-auth": gcloud_clusters_set_binary_auth,
        "gcloud-clusters-set-intra-node-visibility": gcloud_clusters_set_intra_node_visibility,
        # Node pools
        "gcloud-node-pool-list": gcloud_node_pool_list_command,
        "gcloud-node-pool-describe": gcloud_node_pool_describe_command,
        "gcloud-node-pool-set-management": gcloud_set_node_pool_management,
        # Operation handling
        "gcloud-operations-list": gcloud_operations_list_command,
        "gcloud-operations-describe": gcloud_operations_describe_command,
        "gcloud-operations-cancel": gcloud_operations_cancel_command,
    }
    try:
        client: ClusterManagerClient = google_client_setup(json_configuration=demisto.getParam('credentials_json'))
        command_arguments = handle_default_configuration()
        readable_output, context_entry, raw_response = commands[command](client=client, **command_arguments)

        return_outputs(readable_output=readable_output,
                       outputs=context_entry,
                       raw_response=raw_response)
    except Exception as e:
        # Log exceptions
        return_error(f'Integration {INTEGRATION_NAME} Failed to execute {command} command.\n Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
