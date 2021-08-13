import shutil
import tempfile
import json
import os
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from requests import Session
from zeep import Client as zClient
from zeep import Settings, helpers
from zeep.cache import SqliteCache
from zeep.transports import Transport
from datetime import datetime


''' HELPER FUNCTIONS '''


class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        output = {}
        for key in o:
            if isinstance(o[key], datetime):
                output[key] = o[key].isoformat()
            else:
                output[key] = helpers.serialize_object(o[key])

        return json.dumps(output, default=lambda o: '_not_serializable_')


def serialize_object_list(input) -> List:
    output = []
    tmp_output = json.loads(json.dumps(input, cls=DateTimeEncoder))
    for element in tmp_output:
        output.append(json.loads(element))
    return output


def serialize_object_dict(input) -> Dict:
    return json.loads(json.loads(json.dumps(input, cls=DateTimeEncoder)))


def resolve_datetime(input) -> Dict:
    output = {}
    for key in input:
        if isinstance(input[key], datetime):
            output[key] = input[key].isoformat()
        else:
            output[key] = input[key]
    return output

def get_cache_path():
    path = tempfile.gettempdir() + "/zeepcache"
    try:
        os.makedirs(path)
    except OSError:
        if os.path.isdir(path):
            pass
        else:
            raise
    db_path = os.path.join(path, "cache.db")
    try:
        if not os.path.isfile(db_path):
            static_init_db = os.getenv('ZEEP_STATIC_CACHE_DB', '/zeep/static/cache.db')
            if os.path.isfile(static_init_db):
                demisto.debug(f'copying static init db: {static_init_db} to: {db_path}')
                shutil.copyfile(static_init_db, db_path)
    except Exception as ex:
        # non fatal
        demisto.error(f'Failed copying static init db to: {db_path}. Error: {ex}')
    return db_path

def findObjectAffectedAccessRulesV2_command(client, args):
    hostId = args.get('hostId')
    objectName = args.get('objectName')
    subRange_size = args.get('subRange_size')
    subRange_start = args.get('subRange_start')
    chainFilterMode = args.get('chainFilterMode')
    chainNames = args.get('chainNames')

    response = client.service.servicefindObjectAffectedAccessRulesV2(
        hostId, objectName, subRange_size, subRange_start, chainFilterMode, chainNames)
    command_results = CommandResults(
        outputs_prefix='Skybox.findObjectAffectedAccessRulesV2',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def deleteFirewallException_command(client, args):
    firewallException_destinationAddress = args.get('firewallException_destinationAddress')
    firewallException_expirationDate = args.get('firewallException_expirationDate')
    firewallException_firewall_id = args.get('firewallException_firewall_id')
    firewallException_firewall_name = args.get('firewallException_firewall_name')
    firewallException_firewall_path = args.get('firewallException_firewall_path')
    firewallException_id = args.get('firewallException_id')
    firewallException_isDestinationNegated = args.get('firewallException_isDestinationNegated')
    firewallException_isServicesNegated = args.get('firewallException_isServicesNegated')
    firewallException_isSourceNegated = args.get('firewallException_isSourceNegated')
    firewallException_originalRuleId = args.get('firewallException_originalRuleId')
    firewallException_originalRuleText = args.get('firewallException_originalRuleText')
    firewallException_policy = args.get('firewallException_policy')
    firewallException_services = args.get('firewallException_services')
    firewallException_sourceAddress = args.get('firewallException_sourceAddress')
    firewallException_tag = args.get('firewallException_tag')
    firewallException_ticketId = args.get('firewallException_ticketId')
    firewallException_userComments = args.get('firewallException_userComments')

    response = client.service.deleteFirewallException(firewallException_destinationAddress, firewallException_expirationDate, firewallException_firewall_id, firewallException_firewall_name, firewallException_firewall_path, firewallException_id, firewallException_isDestinationNegated, firewallException_isServicesNegated,
                                                      firewallException_isSourceNegated, firewallException_originalRuleId, firewallException_originalRuleText, firewallException_policy, firewallException_services, firewallException_sourceAddress, firewallException_tag, firewallException_ticketId, firewallException_userComments)
    command_results = CommandResults(
        outputs_prefix='Skybox.deleteFirewallException',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getAccessRuleAttributesV2_command(client, args):
    id_ = args.get('id')

    response = client.service.getAccessRuleAttributesV2(id_)
    command_results = CommandResults(
        outputs_prefix='Skybox.getAccessRuleAttributesV2',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getNetInterfacesByNetworkId_command(client, args):
    networkId = args.get('networkId')

    response = client.service.getNetInterfacesByNetworkId(networkId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getNetInterfacesByNetworkId',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getHostAttributes_command(client, args):
    id_ = args.get('id')

    response = client.service.getHostAttributes(id_)
    command_results = CommandResults(
        outputs_prefix='Skybox.getHostAttributes',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findNetworksForIPRange_command(client, args):
    ipRange = args.get('ipRange')

    response = client.service.findNetworksForIPRange(ipRange)
    command_results = CommandResults(
        outputs_prefix='Skybox.findNetworksForIPRange',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def deleteRulePolicyException_command(client, args):
    rulePolicyException_comment = args.get('rulePolicyException_comment')
    rulePolicyException_expirationAccessRuleModification = args.get(
        'rulePolicyException_expirationAccessRuleModification')
    rulePolicyException_expirationDate = args.get('rulePolicyException_expirationDate')
    rulePolicyException_firewall_id = args.get('rulePolicyException_firewall_id')
    rulePolicyException_firewall_name = args.get('rulePolicyException_firewall_name')
    rulePolicyException_firewall_path = args.get('rulePolicyException_firewall_path')
    rulePolicyException_id = args.get('rulePolicyException_id')
    rulePolicyException_ruleGuid = args.get('rulePolicyException_ruleGuid')
    rulePolicyException_rulePolicyScope = args.get('rulePolicyException_rulePolicyScope')

    response = client.service.deleteRulePolicyException(rulePolicyException_comment, rulePolicyException_expirationAccessRuleModification, rulePolicyException_expirationDate, rulePolicyException_firewall_id,
                                                        rulePolicyException_firewall_name, rulePolicyException_firewall_path, rulePolicyException_id, rulePolicyException_ruleGuid, rulePolicyException_rulePolicyScope)
    command_results = CommandResults(
        outputs_prefix='Skybox.deleteRulePolicyException',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findFirewallObjectByIP_command(client, args):
    hostId = args.get('hostId')
    objectIP = args.get('objectIP')

    response = client.service.findFirewallObjectByIP(hostId, objectIP)
    command_results = CommandResults(
        outputs_prefix='Skybox.findFirewallObjectByIP',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def updateHostAttributes_command(client, args):
    updateInfo_hostAttributes_businessFunction = args.get('updateInfo_hostAttributes_businessFunction')
    updateInfo_hostAttributes_customFields = args.get('updateInfo_hostAttributes_customFields')
    updateInfo_hostAttributes_email = args.get('updateInfo_hostAttributes_email')
    updateInfo_hostAttributes_owner = args.get('updateInfo_hostAttributes_owner')
    updateInfo_hostAttributes_site = args.get('updateInfo_hostAttributes_site')
    updateInfo_hostAttributes_userComment = args.get('updateInfo_hostAttributes_userComment')
    updateInfo_hostAttributes_userNameTag = args.get('updateInfo_hostAttributes_userNameTag')
    updateInfo_hostIds = args.get('updateInfo_hostIds')

    response = client.service.updateHostAttributes(updateInfo_hostAttributes_businessFunction, updateInfo_hostAttributes_customFields, updateInfo_hostAttributes_email,
                                                   updateInfo_hostAttributes_owner, updateInfo_hostAttributes_site, updateInfo_hostAttributes_userComment, updateInfo_hostAttributes_userNameTag, updateInfo_hostIds)
    command_results = CommandResults(
        outputs_prefix='Skybox.updateHostAttributes',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def modifyFirewallException_command(client, args):
    firewallException_destinationAddress = args.get('firewallException_destinationAddress')
    firewallException_expirationDate = args.get('firewallException_expirationDate')
    firewallException_firewall_id = args.get('firewallException_firewall_id')
    firewallException_firewall_name = args.get('firewallException_firewall_name')
    firewallException_firewall_path = args.get('firewallException_firewall_path')
    firewallException_id = args.get('firewallException_id')
    firewallException_isDestinationNegated = args.get('firewallException_isDestinationNegated')
    firewallException_isServicesNegated = args.get('firewallException_isServicesNegated')
    firewallException_isSourceNegated = args.get('firewallException_isSourceNegated')
    firewallException_originalRuleId = args.get('firewallException_originalRuleId')
    firewallException_originalRuleText = args.get('firewallException_originalRuleText')
    firewallException_policy = args.get('firewallException_policy')
    firewallException_services = args.get('firewallException_services')
    firewallException_sourceAddress = args.get('firewallException_sourceAddress')
    firewallException_tag = args.get('firewallException_tag')
    firewallException_ticketId = args.get('firewallException_ticketId')
    firewallException_userComments = args.get('firewallException_userComments')

    response = client.service.modifyFirewallException(firewallException_destinationAddress, firewallException_expirationDate, firewallException_firewall_id, firewallException_firewall_name, firewallException_firewall_path, firewallException_id, firewallException_isDestinationNegated, firewallException_isServicesNegated,
                                                      firewallException_isSourceNegated, firewallException_originalRuleId, firewallException_originalRuleText, firewallException_policy, firewallException_services, firewallException_sourceAddress, firewallException_tag, firewallException_ticketId, firewallException_userComments)
    command_results = CommandResults(
        outputs_prefix='Skybox.modifyFirewallException',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getHostCluster_command(client, args):
    hostId = args.get('hostId')

    response = client.service.getHostCluster(hostId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getHostCluster',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def checkAccessCompliance_command(client, args):
    req_destinationAddress = args.get('req_destinationAddress')
    req_destinationZone = args.get('req_destinationZone')
    req_ports = args.get('req_ports')
    req_sourceAddress = args.get('req_sourceAddress')
    req_sourceZone = args.get('req_sourceZone')

    response = client.service.checkAccessCompliance(
        req_destinationAddress, req_destinationZone, req_ports, req_sourceAddress, req_sourceZone)
    command_results = CommandResults(
        outputs_prefix='Skybox.checkAccessCompliance',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findFirewallsByObjectName_command(client, args):
    objectName = args.get('objectName')

    response = client.service.findFirewallsByObjectName(objectName)
    command_results = CommandResults(
        outputs_prefix='Skybox.findFirewallsByObjectName',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def updateAccessRuleAttributesV2_command(client, args):
    updateInfo_accessRuleIds = args.get('updateInfo_accessRuleIds')
    updateInfo_ruleAttributes_businessFunction = args.get('updateInfo_ruleAttributes_businessFunction')
    updateInfo_ruleAttributes_comment = args.get('updateInfo_ruleAttributes_comment')
    updateInfo_ruleAttributes_customFields = args.get('updateInfo_ruleAttributes_customFields')
    updateInfo_ruleAttributes_docOwners = args.get('updateInfo_ruleAttributes_docOwners')
    updateInfo_ruleAttributes_nextReviewDate = args.get('updateInfo_ruleAttributes_nextReviewDate')
    updateInfo_ruleAttributes_status = args.get('updateInfo_ruleAttributes_status')
    updateInfo_ruleAttributes_ticketId = args.get('updateInfo_ruleAttributes_ticketId')

    response = client.service.updateAccessRuleAttributesV2(updateInfo_accessRuleIds, updateInfo_ruleAttributes_businessFunction, updateInfo_ruleAttributes_comment, updateInfo_ruleAttributes_customFields,
                                                           updateInfo_ruleAttributes_docOwners, updateInfo_ruleAttributes_nextReviewDate, updateInfo_ruleAttributes_status, updateInfo_ruleAttributes_ticketId)
    command_results = CommandResults(
        outputs_prefix='Skybox.updateAccessRuleAttributesV2',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getHostNetworkInterfaces_command(client, args):
    hostId = args.get('hostId')

    response = client.service.getHostNetworkInterfaces(hostId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getHostNetworkInterfaces',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def checkAccessV3_command(client, args):
    query_destinationAddresses = args.get('query_destinationAddresses')
    query_destinationElements_IPAddress = args.get('query_destinationElements_IPAddress')
    query_destinationElements_id = args.get('query_destinationElements_id')
    query_destinationElements_name = args.get('query_destinationElements_name')
    query_destinationElements_netMask = args.get('query_destinationElements_netMask')
    query_destinationElements_path = args.get('query_destinationElements_path')
    query_destinationElements_type = args.get('query_destinationElements_type')
    query_firewall_id = args.get('query_firewall_id')
    query_firewall_name = args.get('query_firewall_name')
    query_firewall_path = args.get('query_firewall_path')
    query_mode = args.get('query_mode')
    query_ports = args.get('query_ports')
    query_sourceAddresses = args.get('query_sourceAddresses')
    query_sourceElements_IPAddress = args.get('query_sourceElements_IPAddress')
    query_sourceElements_id = args.get('query_sourceElements_id')
    query_sourceElements_name = args.get('query_sourceElements_name')
    query_sourceElements_netMask = args.get('query_sourceElements_netMask')
    query_sourceElements_path = args.get('query_sourceElements_path')
    query_sourceElements_type = args.get('query_sourceElements_type')
    query_useAccessRules = args.get('query_useAccessRules')
    query_useRoutingRules = args.get('query_useRoutingRules')
    query_routesPerService = args.get('query_routesPerService')
    query_sendTo_destinationAddress = args.get('query_sendTo_destinationAddress')
    query_sendTo_ports = args.get('query_sendTo_ports')
    routeOutputType = args.get('routeOutputType')

    response = client.service.checkAccessV3(query_destinationAddresses, query_destinationElements_IPAddress, query_destinationElements_id, query_destinationElements_name, query_destinationElements_netMask, query_destinationElements_path, query_destinationElements_type, query_firewall_id, query_firewall_name, query_firewall_path, query_mode,
                                            query_ports, query_sourceAddresses, query_sourceElements_IPAddress, query_sourceElements_id, query_sourceElements_name, query_sourceElements_netMask, query_sourceElements_path, query_sourceElements_type, query_useAccessRules, query_useRoutingRules, query_routesPerService, query_sendTo_destinationAddress, query_sendTo_ports, routeOutputType)
    command_results = CommandResults(
        outputs_prefix='Skybox.checkAccessV3',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findNetworkElementZone_command(client, args):
    networkElements_IPAddress = args.get('networkElements_IPAddress')
    networkElements_id = args.get('networkElements_id')
    networkElements_name = args.get('networkElements_name')
    networkElements_netMask = args.get('networkElements_netMask')
    networkElements_path = args.get('networkElements_path')
    networkElements_type = args.get('networkElements_type')

    response = client.service.findNetworkElementZone(
        networkElements_IPAddress, networkElements_id, networkElements_name, networkElements_netMask, networkElements_path, networkElements_type)
    command_results = CommandResults(
        outputs_prefix='Skybox.findNetworkElementZone',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def checkAccessV2_command(client, args):
    query_destinationAddresses = args.get('query_destinationAddresses')
    query_destinationElements_IPAddress = args.get('query_destinationElements_IPAddress')
    query_destinationElements_id = args.get('query_destinationElements_id')
    query_destinationElements_name = args.get('query_destinationElements_name')
    query_destinationElements_netMask = args.get('query_destinationElements_netMask')
    query_destinationElements_path = args.get('query_destinationElements_path')
    query_destinationElements_type = args.get('query_destinationElements_type')
    query_firewall_id = args.get('query_firewall_id')
    query_firewall_name = args.get('query_firewall_name')
    query_firewall_path = args.get('query_firewall_path')
    query_mode = args.get('query_mode')
    query_ports = args.get('query_ports')
    query_sourceAddresses = args.get('query_sourceAddresses')
    query_sourceElements_IPAddress = args.get('query_sourceElements_IPAddress')
    query_sourceElements_id = args.get('query_sourceElements_id')
    query_sourceElements_name = args.get('query_sourceElements_name')
    query_sourceElements_netMask = args.get('query_sourceElements_netMask')
    query_sourceElements_path = args.get('query_sourceElements_path')
    query_sourceElements_type = args.get('query_sourceElements_type')
    query_useAccessRules = args.get('query_useAccessRules')
    query_useRoutingRules = args.get('query_useRoutingRules')
    routeOutputType = args.get('routeOutputType')

    response = client.service.checkAccessV2(query_destinationAddresses, query_destinationElements_IPAddress, query_destinationElements_id, query_destinationElements_name, query_destinationElements_netMask, query_destinationElements_path, query_destinationElements_type, query_firewall_id, query_firewall_name,
                                            query_firewall_path, query_mode, query_ports, query_sourceAddresses, query_sourceElements_IPAddress, query_sourceElements_id, query_sourceElements_name, query_sourceElements_netMask, query_sourceElements_path, query_sourceElements_type, query_useAccessRules, query_useRoutingRules, routeOutputType)
    command_results = CommandResults(
        outputs_prefix='Skybox.checkAccessV2',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findAssetsByNames_command(client, args):
    names = args.get('names')
    subRange_size = args.get('subRange_size')
    subRange_start = args.get('subRange_start')

    response = client.service.findAssetsByNames(names, subRange_size, subRange_start)
    command_results = CommandResults(
        outputs_prefix='Skybox.findAssetsByNames',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getAccessRule_command(client, args):
    accessRuleId = args.get('accessRuleId')

    response = client.service.getAccessRule(accessRuleId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getAccessRule',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def checkAccessV1_command(client, args):
    query_destinationAddresses = args.get('query_destinationAddresses')
    query_destinationElements_IPAddress = args.get('query_destinationElements_IPAddress')
    query_destinationElements_id = args.get('query_destinationElements_id')
    query_destinationElements_name = args.get('query_destinationElements_name')
    query_destinationElements_netMask = args.get('query_destinationElements_netMask')
    query_destinationElements_path = args.get('query_destinationElements_path')
    query_destinationElements_type = args.get('query_destinationElements_type')
    query_firewall_id = args.get('query_firewall_id')
    query_firewall_name = args.get('query_firewall_name')
    query_firewall_path = args.get('query_firewall_path')
    query_mode = args.get('query_mode')
    query_ports = args.get('query_ports')
    query_sourceAddresses = args.get('query_sourceAddresses')
    query_sourceElements_IPAddress = args.get('query_sourceElements_IPAddress')
    query_sourceElements_id = args.get('query_sourceElements_id')
    query_sourceElements_name = args.get('query_sourceElements_name')
    query_sourceElements_netMask = args.get('query_sourceElements_netMask')
    query_sourceElements_path = args.get('query_sourceElements_path')
    query_sourceElements_type = args.get('query_sourceElements_type')
    routeOutputType = args.get('routeOutputType')

    response = client.service.checkAccessV1(query_destinationAddresses, query_destinationElements_IPAddress, query_destinationElements_id, query_destinationElements_name, query_destinationElements_netMask, query_destinationElements_path, query_destinationElements_type, query_firewall_id,
                                            query_firewall_name, query_firewall_path, query_mode, query_ports, query_sourceAddresses, query_sourceElements_IPAddress, query_sourceElements_id, query_sourceElements_name, query_sourceElements_netMask, query_sourceElements_path, query_sourceElements_type, routeOutputType)
    command_results = CommandResults(
        outputs_prefix='Skybox.checkAccessV1',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findNetworks_command(client, args):
    ipRange = args.get('ipRange')

    response = client.service.findNetworks(ipRange)
    command_results = CommandResults(
        outputs_prefix='Skybox.findNetworks',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getAccessRuleEntityFields_command(client, args):

    response = client.service.getAccessRuleEntityFields()
    command_results = CommandResults(
        outputs_prefix='Skybox.getAccessRuleEntityFields',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def countAssetsByIps_command(client, args):
    ipRanges = args.get('ipRanges')

    response = client.service.countAssetsByIps(ipRanges)
    command_results = CommandResults(
        outputs_prefix='Skybox.countAssetsByIps',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findFirewallElementFAFolderPath_command(client, args):
    firewallElements_id = args.get('firewallElements_id')
    firewallElements_name = args.get('firewallElements_name')
    firewallElements_path = args.get('firewallElements_path')

    response = client.service.findFirewallElementFAFolderPath(
        firewallElements_id, firewallElements_name, firewallElements_path)
    command_results = CommandResults(
        outputs_prefix='Skybox.findFirewallElementFAFolderPath',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getZoneFromNetwork_command(client, args):
    network_IPAddress = args.get('network_IPAddress')
    network_id = args.get('network_id')
    network_name = args.get('network_name')
    network_netMask = args.get('network_netMask')
    network_path = args.get('network_path')
    network_type = args.get('network_type')

    response = client.service.getZoneFromNetwork(
        network_IPAddress, network_id, network_name, network_netMask, network_path, network_type)
    command_results = CommandResults(
        outputs_prefix='Skybox.getZoneFromNetwork',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findAccessRules_command(client, args):
    accessRuleSearchFilter_description = args.get('accessRuleSearchFilter_description')
    accessRuleSearchFilter_destination = args.get('accessRuleSearchFilter_destination')
    accessRuleSearchFilter_findMode = args.get('accessRuleSearchFilter_findMode')
    accessRuleSearchFilter_firewallScope_fwFolders = args.get('accessRuleSearchFilter_firewallScope_fwFolders')
    accessRuleSearchFilter_firewallScope_fwList = args.get('accessRuleSearchFilter_firewallScope_fwList')
    accessRuleSearchFilter_ignoreRulesWithAny = args.get('accessRuleSearchFilter_ignoreRulesWithAny')
    accessRuleSearchFilter_matchCriteria = args.get('accessRuleSearchFilter_matchCriteria')
    accessRuleSearchFilter_originalRuleId = args.get('accessRuleSearchFilter_originalRuleId')
    accessRuleSearchFilter_originalText = args.get('accessRuleSearchFilter_originalText')
    accessRuleSearchFilter_services = args.get('accessRuleSearchFilter_services')
    accessRuleSearchFilter_source = args.get('accessRuleSearchFilter_source')

    response = client.service.findAccessRules(accessRuleSearchFilter_description, accessRuleSearchFilter_destination, accessRuleSearchFilter_findMode, accessRuleSearchFilter_firewallScope_fwFolders, accessRuleSearchFilter_firewallScope_fwList,
                                              accessRuleSearchFilter_ignoreRulesWithAny, accessRuleSearchFilter_matchCriteria, accessRuleSearchFilter_originalRuleId, accessRuleSearchFilter_originalText, accessRuleSearchFilter_services, accessRuleSearchFilter_source)
    command_results = CommandResults(
        outputs_prefix='Skybox.findAccessRules',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def isBackwardRouteExist_command(client, args):
    sourceEntity_IPRange_endIP = args.get('sourceEntity_IPRange_endIP')
    sourceEntity_IPRange_startIP = args.get('sourceEntity_IPRange_startIP')
    sourceEntity_networkOrHost_comment = args.get('sourceEntity_networkOrHost_comment')
    sourceEntity_networkOrHost_createdBy = args.get('sourceEntity_networkOrHost_createdBy')
    sourceEntity_networkOrHost_creationTimeAsDate = args.get('sourceEntity_networkOrHost_creationTimeAsDate')
    sourceEntity_networkOrHost_creationTimeInMillis = args.get('sourceEntity_networkOrHost_creationTimeInMillis')
    sourceEntity_networkOrHost_creationTimeInSeconds = args.get('sourceEntity_networkOrHost_creationTimeInSeconds')
    sourceEntity_networkOrHost_description = args.get('sourceEntity_networkOrHost_description')
    sourceEntity_networkOrHost_lastModificationTimeAsDate = args.get(
        'sourceEntity_networkOrHost_lastModificationTimeAsDate')
    sourceEntity_networkOrHost_lastModificationTimeInMillis = args.get(
        'sourceEntity_networkOrHost_lastModificationTimeInMillis')
    sourceEntity_networkOrHost_lastModificationTimeInSeconds = args.get(
        'sourceEntity_networkOrHost_lastModificationTimeInSeconds')
    sourceEntity_networkOrHost_modifiedBy = args.get('sourceEntity_networkOrHost_modifiedBy')
    sourceEntity_networkOrHost_discoveryMethod = args.get('sourceEntity_networkOrHost_discoveryMethod')
    sourceEntity_networkOrHost_discoveryMethodAsString = args.get('sourceEntity_networkOrHost_discoveryMethodAsString')
    sourceEntity_networkOrHost_lastScanTimeAsDate = args.get('sourceEntity_networkOrHost_lastScanTimeAsDate')
    sourceEntity_networkOrHost_lastScanTimeInMillis = args.get('sourceEntity_networkOrHost_lastScanTimeInMillis')
    sourceEntity_networkOrHost_lastScanTimeInSeconds = args.get('sourceEntity_networkOrHost_lastScanTimeInSeconds')
    sourceEntity_networkOrHost_scannedBy = args.get('sourceEntity_networkOrHost_scannedBy')
    sourceEntity_networkOrHost_netStatus = args.get('sourceEntity_networkOrHost_netStatus')
    sourceEntity_networkOrHost_threatGroupExposures = args.get('sourceEntity_networkOrHost_threatGroupExposures')
    sourceEntity_networkOrHost_threatGroupRisks = args.get('sourceEntity_networkOrHost_threatGroupRisks')
    sourceEntity_networkOrHost_threatTotalRisk = args.get('sourceEntity_networkOrHost_threatTotalRisk')
    sourceEntity_networkOrHost_totalExposure = args.get('sourceEntity_networkOrHost_totalExposure')
    sourceEntity_networkOrHost_vulnerabilityTotalRisk = args.get('sourceEntity_networkOrHost_vulnerabilityTotalRisk')
    sourceEntity_networkOrHost_criticalRelevantVulCount = args.get(
        'sourceEntity_networkOrHost_criticalRelevantVulCount')
    sourceEntity_networkOrHost_criticalVulCount = args.get('sourceEntity_networkOrHost_criticalVulCount')
    sourceEntity_networkOrHost_exposedVulCount = args.get('sourceEntity_networkOrHost_exposedVulCount')
    sourceEntity_networkOrHost_fixedCriticalVulCount = args.get('sourceEntity_networkOrHost_fixedCriticalVulCount')
    sourceEntity_networkOrHost_fixedHighVulCount = args.get('sourceEntity_networkOrHost_fixedHighVulCount')
    sourceEntity_networkOrHost_fixedInfoVulCount = args.get('sourceEntity_networkOrHost_fixedInfoVulCount')
    sourceEntity_networkOrHost_fixedLowVulCount = args.get('sourceEntity_networkOrHost_fixedLowVulCount')
    sourceEntity_networkOrHost_fixedMediumVulCount = args.get('sourceEntity_networkOrHost_fixedMediumVulCount')
    sourceEntity_networkOrHost_fixedVulCount = args.get('sourceEntity_networkOrHost_fixedVulCount')
    sourceEntity_networkOrHost_highRelevantVulCount = args.get('sourceEntity_networkOrHost_highRelevantVulCount')
    sourceEntity_networkOrHost_highVulCount = args.get('sourceEntity_networkOrHost_highVulCount')
    sourceEntity_networkOrHost_hostCount = args.get('sourceEntity_networkOrHost_hostCount')
    sourceEntity_networkOrHost_ignoredVulCount = args.get('sourceEntity_networkOrHost_ignoredVulCount')
    sourceEntity_networkOrHost_infoRelevantVulCount = args.get('sourceEntity_networkOrHost_infoRelevantVulCount')
    sourceEntity_networkOrHost_infoVulCount = args.get('sourceEntity_networkOrHost_infoVulCount')
    sourceEntity_networkOrHost_lowRelevantVulCount = args.get('sourceEntity_networkOrHost_lowRelevantVulCount')
    sourceEntity_networkOrHost_lowVulCount = args.get('sourceEntity_networkOrHost_lowVulCount')
    sourceEntity_networkOrHost_mediumRelevantVulCount = args.get('sourceEntity_networkOrHost_mediumRelevantVulCount')
    sourceEntity_networkOrHost_mediumVulCount = args.get('sourceEntity_networkOrHost_mediumVulCount')
    sourceEntity_networkOrHost_nonForwardingHostCount = args.get('sourceEntity_networkOrHost_nonForwardingHostCount')
    sourceEntity_networkOrHost_owner = args.get('sourceEntity_networkOrHost_owner')
    sourceEntity_networkOrHost_reachableVulCount = args.get('sourceEntity_networkOrHost_reachableVulCount')
    sourceEntity_networkOrHost_vulCount = args.get('sourceEntity_networkOrHost_vulCount')
    sourceEntity_network_IPAddress = args.get('sourceEntity_network_IPAddress')
    sourceEntity_network_id = args.get('sourceEntity_network_id')
    sourceEntity_network_name = args.get('sourceEntity_network_name')
    sourceEntity_network_netMask = args.get('sourceEntity_network_netMask')
    sourceEntity_network_path = args.get('sourceEntity_network_path')
    sourceEntity_network_type = args.get('sourceEntity_network_type')
    destinationEntity_IPRange_endIP = args.get('destinationEntity_IPRange_endIP')
    destinationEntity_IPRange_startIP = args.get('destinationEntity_IPRange_startIP')
    destinationEntity_networkOrHost_comment = args.get('destinationEntity_networkOrHost_comment')
    destinationEntity_networkOrHost_createdBy = args.get('destinationEntity_networkOrHost_createdBy')
    destinationEntity_networkOrHost_creationTimeAsDate = args.get('destinationEntity_networkOrHost_creationTimeAsDate')
    destinationEntity_networkOrHost_creationTimeInMillis = args.get(
        'destinationEntity_networkOrHost_creationTimeInMillis')
    destinationEntity_networkOrHost_creationTimeInSeconds = args.get(
        'destinationEntity_networkOrHost_creationTimeInSeconds')
    destinationEntity_networkOrHost_description = args.get('destinationEntity_networkOrHost_description')
    destinationEntity_networkOrHost_lastModificationTimeAsDate = args.get(
        'destinationEntity_networkOrHost_lastModificationTimeAsDate')
    destinationEntity_networkOrHost_lastModificationTimeInMillis = args.get(
        'destinationEntity_networkOrHost_lastModificationTimeInMillis')
    destinationEntity_networkOrHost_lastModificationTimeInSeconds = args.get(
        'destinationEntity_networkOrHost_lastModificationTimeInSeconds')
    destinationEntity_networkOrHost_modifiedBy = args.get('destinationEntity_networkOrHost_modifiedBy')
    destinationEntity_networkOrHost_discoveryMethod = args.get('destinationEntity_networkOrHost_discoveryMethod')
    destinationEntity_networkOrHost_discoveryMethodAsString = args.get(
        'destinationEntity_networkOrHost_discoveryMethodAsString')
    destinationEntity_networkOrHost_lastScanTimeAsDate = args.get('destinationEntity_networkOrHost_lastScanTimeAsDate')
    destinationEntity_networkOrHost_lastScanTimeInMillis = args.get(
        'destinationEntity_networkOrHost_lastScanTimeInMillis')
    destinationEntity_networkOrHost_lastScanTimeInSeconds = args.get(
        'destinationEntity_networkOrHost_lastScanTimeInSeconds')
    destinationEntity_networkOrHost_scannedBy = args.get('destinationEntity_networkOrHost_scannedBy')
    destinationEntity_networkOrHost_netStatus = args.get('destinationEntity_networkOrHost_netStatus')
    destinationEntity_networkOrHost_threatGroupExposures = args.get(
        'destinationEntity_networkOrHost_threatGroupExposures')
    destinationEntity_networkOrHost_threatGroupRisks = args.get('destinationEntity_networkOrHost_threatGroupRisks')
    destinationEntity_networkOrHost_threatTotalRisk = args.get('destinationEntity_networkOrHost_threatTotalRisk')
    destinationEntity_networkOrHost_totalExposure = args.get('destinationEntity_networkOrHost_totalExposure')
    destinationEntity_networkOrHost_vulnerabilityTotalRisk = args.get(
        'destinationEntity_networkOrHost_vulnerabilityTotalRisk')
    destinationEntity_networkOrHost_criticalRelevantVulCount = args.get(
        'destinationEntity_networkOrHost_criticalRelevantVulCount')
    destinationEntity_networkOrHost_criticalVulCount = args.get('destinationEntity_networkOrHost_criticalVulCount')
    destinationEntity_networkOrHost_exposedVulCount = args.get('destinationEntity_networkOrHost_exposedVulCount')
    destinationEntity_networkOrHost_fixedCriticalVulCount = args.get(
        'destinationEntity_networkOrHost_fixedCriticalVulCount')
    destinationEntity_networkOrHost_fixedHighVulCount = args.get('destinationEntity_networkOrHost_fixedHighVulCount')
    destinationEntity_networkOrHost_fixedInfoVulCount = args.get('destinationEntity_networkOrHost_fixedInfoVulCount')
    destinationEntity_networkOrHost_fixedLowVulCount = args.get('destinationEntity_networkOrHost_fixedLowVulCount')
    destinationEntity_networkOrHost_fixedMediumVulCount = args.get(
        'destinationEntity_networkOrHost_fixedMediumVulCount')
    destinationEntity_networkOrHost_fixedVulCount = args.get('destinationEntity_networkOrHost_fixedVulCount')
    destinationEntity_networkOrHost_highRelevantVulCount = args.get(
        'destinationEntity_networkOrHost_highRelevantVulCount')
    destinationEntity_networkOrHost_highVulCount = args.get('destinationEntity_networkOrHost_highVulCount')
    destinationEntity_networkOrHost_hostCount = args.get('destinationEntity_networkOrHost_hostCount')
    destinationEntity_networkOrHost_ignoredVulCount = args.get('destinationEntity_networkOrHost_ignoredVulCount')
    destinationEntity_networkOrHost_infoRelevantVulCount = args.get(
        'destinationEntity_networkOrHost_infoRelevantVulCount')
    destinationEntity_networkOrHost_infoVulCount = args.get('destinationEntity_networkOrHost_infoVulCount')
    destinationEntity_networkOrHost_lowRelevantVulCount = args.get(
        'destinationEntity_networkOrHost_lowRelevantVulCount')
    destinationEntity_networkOrHost_lowVulCount = args.get('destinationEntity_networkOrHost_lowVulCount')
    destinationEntity_networkOrHost_mediumRelevantVulCount = args.get(
        'destinationEntity_networkOrHost_mediumRelevantVulCount')
    destinationEntity_networkOrHost_mediumVulCount = args.get('destinationEntity_networkOrHost_mediumVulCount')
    destinationEntity_networkOrHost_nonForwardingHostCount = args.get(
        'destinationEntity_networkOrHost_nonForwardingHostCount')
    destinationEntity_networkOrHost_owner = args.get('destinationEntity_networkOrHost_owner')
    destinationEntity_networkOrHost_reachableVulCount = args.get('destinationEntity_networkOrHost_reachableVulCount')
    destinationEntity_networkOrHost_vulCount = args.get('destinationEntity_networkOrHost_vulCount')
    destinationEntity_network_IPAddress = args.get('destinationEntity_network_IPAddress')
    destinationEntity_network_id = args.get('destinationEntity_network_id')
    destinationEntity_network_name = args.get('destinationEntity_network_name')
    destinationEntity_network_netMask = args.get('destinationEntity_network_netMask')
    destinationEntity_network_path = args.get('destinationEntity_network_path')
    destinationEntity_network_type = args.get('destinationEntity_network_type')

    response = client.service.isBackwardRouteExist(sourceEntity_IPRange_endIP, sourceEntity_IPRange_startIP, sourceEntity_networkOrHost_comment, sourceEntity_networkOrHost_createdBy, sourceEntity_networkOrHost_creationTimeAsDate, sourceEntity_networkOrHost_creationTimeInMillis, sourceEntity_networkOrHost_creationTimeInSeconds, sourceEntity_networkOrHost_description, sourceEntity_networkOrHost_lastModificationTimeAsDate, sourceEntity_networkOrHost_lastModificationTimeInMillis, sourceEntity_networkOrHost_lastModificationTimeInSeconds, sourceEntity_networkOrHost_modifiedBy, sourceEntity_networkOrHost_discoveryMethod, sourceEntity_networkOrHost_discoveryMethodAsString, sourceEntity_networkOrHost_lastScanTimeAsDate, sourceEntity_networkOrHost_lastScanTimeInMillis, sourceEntity_networkOrHost_lastScanTimeInSeconds, sourceEntity_networkOrHost_scannedBy, sourceEntity_networkOrHost_netStatus, sourceEntity_networkOrHost_threatGroupExposures, sourceEntity_networkOrHost_threatGroupRisks, sourceEntity_networkOrHost_threatTotalRisk, sourceEntity_networkOrHost_totalExposure, sourceEntity_networkOrHost_vulnerabilityTotalRisk, sourceEntity_networkOrHost_criticalRelevantVulCount, sourceEntity_networkOrHost_criticalVulCount, sourceEntity_networkOrHost_exposedVulCount, sourceEntity_networkOrHost_fixedCriticalVulCount, sourceEntity_networkOrHost_fixedHighVulCount, sourceEntity_networkOrHost_fixedInfoVulCount, sourceEntity_networkOrHost_fixedLowVulCount, sourceEntity_networkOrHost_fixedMediumVulCount, sourceEntity_networkOrHost_fixedVulCount, sourceEntity_networkOrHost_highRelevantVulCount, sourceEntity_networkOrHost_highVulCount, sourceEntity_networkOrHost_hostCount, sourceEntity_networkOrHost_ignoredVulCount, sourceEntity_networkOrHost_infoRelevantVulCount, sourceEntity_networkOrHost_infoVulCount, sourceEntity_networkOrHost_lowRelevantVulCount, sourceEntity_networkOrHost_lowVulCount, sourceEntity_networkOrHost_mediumRelevantVulCount, sourceEntity_networkOrHost_mediumVulCount, sourceEntity_networkOrHost_nonForwardingHostCount, sourceEntity_networkOrHost_owner, sourceEntity_networkOrHost_reachableVulCount, sourceEntity_networkOrHost_vulCount, sourceEntity_network_IPAddress, sourceEntity_network_id, sourceEntity_network_name, sourceEntity_network_netMask, sourceEntity_network_path, sourceEntity_network_type, destinationEntity_IPRange_endIP, destinationEntity_IPRange_startIP, destinationEntity_networkOrHost_comment,
                                                   destinationEntity_networkOrHost_createdBy, destinationEntity_networkOrHost_creationTimeAsDate, destinationEntity_networkOrHost_creationTimeInMillis, destinationEntity_networkOrHost_creationTimeInSeconds, destinationEntity_networkOrHost_description, destinationEntity_networkOrHost_lastModificationTimeAsDate, destinationEntity_networkOrHost_lastModificationTimeInMillis, destinationEntity_networkOrHost_lastModificationTimeInSeconds, destinationEntity_networkOrHost_modifiedBy, destinationEntity_networkOrHost_discoveryMethod, destinationEntity_networkOrHost_discoveryMethodAsString, destinationEntity_networkOrHost_lastScanTimeAsDate, destinationEntity_networkOrHost_lastScanTimeInMillis, destinationEntity_networkOrHost_lastScanTimeInSeconds, destinationEntity_networkOrHost_scannedBy, destinationEntity_networkOrHost_netStatus, destinationEntity_networkOrHost_threatGroupExposures, destinationEntity_networkOrHost_threatGroupRisks, destinationEntity_networkOrHost_threatTotalRisk, destinationEntity_networkOrHost_totalExposure, destinationEntity_networkOrHost_vulnerabilityTotalRisk, destinationEntity_networkOrHost_criticalRelevantVulCount, destinationEntity_networkOrHost_criticalVulCount, destinationEntity_networkOrHost_exposedVulCount, destinationEntity_networkOrHost_fixedCriticalVulCount, destinationEntity_networkOrHost_fixedHighVulCount, destinationEntity_networkOrHost_fixedInfoVulCount, destinationEntity_networkOrHost_fixedLowVulCount, destinationEntity_networkOrHost_fixedMediumVulCount, destinationEntity_networkOrHost_fixedVulCount, destinationEntity_networkOrHost_highRelevantVulCount, destinationEntity_networkOrHost_highVulCount, destinationEntity_networkOrHost_hostCount, destinationEntity_networkOrHost_ignoredVulCount, destinationEntity_networkOrHost_infoRelevantVulCount, destinationEntity_networkOrHost_infoVulCount, destinationEntity_networkOrHost_lowRelevantVulCount, destinationEntity_networkOrHost_lowVulCount, destinationEntity_networkOrHost_mediumRelevantVulCount, destinationEntity_networkOrHost_mediumVulCount, destinationEntity_networkOrHost_nonForwardingHostCount, destinationEntity_networkOrHost_owner, destinationEntity_networkOrHost_reachableVulCount, destinationEntity_networkOrHost_vulCount, destinationEntity_network_IPAddress, destinationEntity_network_id, destinationEntity_network_name, destinationEntity_network_netMask, destinationEntity_network_path, destinationEntity_network_type)
    command_results = CommandResults(
        outputs_prefix='Skybox.isBackwardRouteExist',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getAccessRulesSections_command(client, args):
    hostId = args.get('hostId')
    chain = args.get('chain')

    response = client.service.getAccessRulesSections(hostId, chain)
    command_results = CommandResults(
        outputs_prefix='Skybox.getAccessRulesSections',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getAccessRuleAttributes_command(client, args):
    id_ = args.get('id')

    response = client.service.getAccessRuleAttributes(id_)
    command_results = CommandResults(
        outputs_prefix='Skybox.getAccessRuleAttributes',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getZoneFromFW_command(client, args):
    firewall_id = args.get('firewall_id')
    firewall_name = args.get('firewall_name')
    firewall_path = args.get('firewall_path')
    ipRange = args.get('ipRange')

    response = client.service.getZoneFromFW(firewall_id, firewall_name, firewall_path, ipRange)
    command_results = CommandResults(
        outputs_prefix='Skybox.getZoneFromFW',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getHostEntityFields_command(client, args):

    response = client.service.getHostEntityFields()
    command_results = CommandResults(
        outputs_prefix='Skybox.getHostEntityFields',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findAssetsByIps_command(client, args):
    ipRanges = args.get('ipRanges')
    subRange_size = args.get('subRange_size')
    subRange_start = args.get('subRange_start')

    response = client.service.findAssetsByIps(ipRanges, subRange_size, subRange_start)
    command_results = CommandResults(
        outputs_prefix='Skybox.findAssetsByIps',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findFirewallObjectsIdentifications_command(client, args):
    hostId = args.get('hostId')
    objectNameFilter = args.get('objectNameFilter')

    response = client.service.findFirewallObjectsIdentifications(hostId, objectNameFilter)
    command_results = CommandResults(
        outputs_prefix='Skybox.findFirewallObjectsIdentifications',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def modifyRulePolicyException_command(client, args):
    rulePolicyException_comment = args.get('rulePolicyException_comment')
    rulePolicyException_expirationAccessRuleModification = args.get(
        'rulePolicyException_expirationAccessRuleModification')
    rulePolicyException_expirationDate = args.get('rulePolicyException_expirationDate')
    rulePolicyException_firewall_id = args.get('rulePolicyException_firewall_id')
    rulePolicyException_firewall_name = args.get('rulePolicyException_firewall_name')
    rulePolicyException_firewall_path = args.get('rulePolicyException_firewall_path')
    rulePolicyException_id = args.get('rulePolicyException_id')
    rulePolicyException_ruleGuid = args.get('rulePolicyException_ruleGuid')
    rulePolicyException_rulePolicyScope = args.get('rulePolicyException_rulePolicyScope')

    response = client.service.modifyRulePolicyException(rulePolicyException_comment, rulePolicyException_expirationAccessRuleModification, rulePolicyException_expirationDate, rulePolicyException_firewall_id,
                                                        rulePolicyException_firewall_name, rulePolicyException_firewall_path, rulePolicyException_id, rulePolicyException_ruleGuid, rulePolicyException_rulePolicyScope)
    command_results = CommandResults(
        outputs_prefix='Skybox.modifyRulePolicyException',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getAccessRuleV5_command(client, args):
    accessRuleId = args.get('accessRuleId')

    response = client.service.getAccessRuleV5(accessRuleId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getAccessRuleV5',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getAccessRules_command(client, args):
    fw_id = args.get('fw_id')
    fw_name = args.get('fw_name')
    fw_path = args.get('fw_path')
    range_from = args.get('range_from')
    range_to = args.get('range_to')
    chainName = args.get('chainName')

    response = client.service.getAccessRules(fw_id, fw_name, fw_path, range_from, range_to, chainName)
    command_results = CommandResults(
        outputs_prefix='Skybox.getAccessRules',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findFirewallObjectByName_command(client, args):
    hostId = args.get('hostId')
    objectName = args.get('objectName')

    response = client.service.findFirewallObjectByName(hostId, objectName)
    command_results = CommandResults(
        outputs_prefix='Skybox.findFirewallObjectByName',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findAccessRulesV2_command(client, args):
    accessRuleSearchFilter_description = args.get('accessRuleSearchFilter_description')
    accessRuleSearchFilter_destination = args.get('accessRuleSearchFilter_destination')
    accessRuleSearchFilter_findMode = args.get('accessRuleSearchFilter_findMode')
    accessRuleSearchFilter_firewallScope_fwFolders = args.get('accessRuleSearchFilter_firewallScope_fwFolders')
    accessRuleSearchFilter_firewallScope_fwList = args.get('accessRuleSearchFilter_firewallScope_fwList')
    accessRuleSearchFilter_ignoreRulesWithAny = args.get('accessRuleSearchFilter_ignoreRulesWithAny')
    accessRuleSearchFilter_matchCriteria = args.get('accessRuleSearchFilter_matchCriteria')
    accessRuleSearchFilter_originalRuleId = args.get('accessRuleSearchFilter_originalRuleId')
    accessRuleSearchFilter_originalText = args.get('accessRuleSearchFilter_originalText')
    accessRuleSearchFilter_services = args.get('accessRuleSearchFilter_services')
    accessRuleSearchFilter_source = args.get('accessRuleSearchFilter_source')

    response = client.service.findAccessRulesV2(accessRuleSearchFilter_description, accessRuleSearchFilter_destination, accessRuleSearchFilter_findMode, accessRuleSearchFilter_firewallScope_fwFolders, accessRuleSearchFilter_firewallScope_fwList,
                                                accessRuleSearchFilter_ignoreRulesWithAny, accessRuleSearchFilter_matchCriteria, accessRuleSearchFilter_originalRuleId, accessRuleSearchFilter_originalText, accessRuleSearchFilter_services, accessRuleSearchFilter_source)
    command_results = CommandResults(
        outputs_prefix='Skybox.findAccessRulesV2',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findFirewallsByName_command(client, args):
    name = args.get('name')

    response = client.service.findFirewallsByName(name)
    command_results = CommandResults(
        outputs_prefix='Skybox.findFirewallsByName',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findObjectAffectedAccessRules_command(client, args):
    hostId = args.get('hostId')
    objectName = args.get('objectName')
    subRange_size = args.get('subRange_size')
    subRange_start = args.get('subRange_start')
    chainFilterMode = args.get('chainFilterMode')
    chainNames = args.get('chainNames')

    response = client.service.findObjectAffectedAccessRules(
        hostId, objectName, subRange_size, subRange_start, chainFilterMode, chainNames)
    command_results = CommandResults(
        outputs_prefix='Skybox.findObjectAffectedAccessRules',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def updateFwAccessRuleAttributes_command(client, args):
    updateInfo_hostId = args.get('updateInfo_hostId')
    updateInfo_originalRuleIds = args.get('updateInfo_originalRuleIds')
    updateInfo_ruleAttributes_businessFunction = args.get('updateInfo_ruleAttributes_businessFunction')
    updateInfo_ruleAttributes_comment = args.get('updateInfo_ruleAttributes_comment')
    updateInfo_ruleAttributes_customFields = args.get('updateInfo_ruleAttributes_customFields')
    updateInfo_ruleAttributes_email = args.get('updateInfo_ruleAttributes_email')
    updateInfo_ruleAttributes_nextReviewDate = args.get('updateInfo_ruleAttributes_nextReviewDate')
    updateInfo_ruleAttributes_owner = args.get('updateInfo_ruleAttributes_owner')
    updateInfo_ruleAttributes_status = args.get('updateInfo_ruleAttributes_status')
    updateInfo_ruleAttributes_ticketId = args.get('updateInfo_ruleAttributes_ticketId')

    response = client.service.updateFwAccessRuleAttributes(updateInfo_hostId, updateInfo_originalRuleIds, updateInfo_ruleAttributes_businessFunction, updateInfo_ruleAttributes_comment, updateInfo_ruleAttributes_customFields,
                                                           updateInfo_ruleAttributes_email, updateInfo_ruleAttributes_nextReviewDate, updateInfo_ruleAttributes_owner, updateInfo_ruleAttributes_status, updateInfo_ruleAttributes_ticketId)
    command_results = CommandResults(
        outputs_prefix='Skybox.updateFwAccessRuleAttributes',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findAccessRulesV3_command(client, args):
    accessRuleSearchFilter_description = args.get('accessRuleSearchFilter_description')
    accessRuleSearchFilter_destination = args.get('accessRuleSearchFilter_destination')
    accessRuleSearchFilter_findMode = args.get('accessRuleSearchFilter_findMode')
    accessRuleSearchFilter_firewallScope_fwFolders = args.get('accessRuleSearchFilter_firewallScope_fwFolders')
    accessRuleSearchFilter_firewallScope_fwList = args.get('accessRuleSearchFilter_firewallScope_fwList')
    accessRuleSearchFilter_ignoreRulesWithAny = args.get('accessRuleSearchFilter_ignoreRulesWithAny')
    accessRuleSearchFilter_matchCriteria = args.get('accessRuleSearchFilter_matchCriteria')
    accessRuleSearchFilter_originalRuleId = args.get('accessRuleSearchFilter_originalRuleId')
    accessRuleSearchFilter_originalText = args.get('accessRuleSearchFilter_originalText')
    accessRuleSearchFilter_services = args.get('accessRuleSearchFilter_services')
    accessRuleSearchFilter_source = args.get('accessRuleSearchFilter_source')

    response = client.service.findAccessRulesV3(accessRuleSearchFilter_description, accessRuleSearchFilter_destination, accessRuleSearchFilter_findMode, accessRuleSearchFilter_firewallScope_fwFolders, accessRuleSearchFilter_firewallScope_fwList,
                                                accessRuleSearchFilter_ignoreRulesWithAny, accessRuleSearchFilter_matchCriteria, accessRuleSearchFilter_originalRuleId, accessRuleSearchFilter_originalText, accessRuleSearchFilter_services, accessRuleSearchFilter_source)
    command_results = CommandResults(
        outputs_prefix='Skybox.findAccessRulesV3',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def checkAccess_command(client, args):
    query_destinationAddresses = args.get('query_destinationAddresses')
    query_destinationElements_IPAddress = args.get('query_destinationElements_IPAddress')
    query_destinationElements_id = args.get('query_destinationElements_id')
    query_destinationElements_name = args.get('query_destinationElements_name')
    query_destinationElements_netMask = args.get('query_destinationElements_netMask')
    query_destinationElements_path = args.get('query_destinationElements_path')
    query_destinationElements_type = args.get('query_destinationElements_type')
    query_firewall_id = args.get('query_firewall_id')
    query_firewall_name = args.get('query_firewall_name')
    query_firewall_path = args.get('query_firewall_path')
    query_mode = args.get('query_mode')
    query_ports = args.get('query_ports')
    query_sourceAddresses = args.get('query_sourceAddresses')
    query_sourceElements_IPAddress = args.get('query_sourceElements_IPAddress')
    query_sourceElements_id = args.get('query_sourceElements_id')
    query_sourceElements_name = args.get('query_sourceElements_name')
    query_sourceElements_netMask = args.get('query_sourceElements_netMask')
    query_sourceElements_path = args.get('query_sourceElements_path')
    query_sourceElements_type = args.get('query_sourceElements_type')

    response = client.service.checkAccess(query_destinationAddresses, query_destinationElements_IPAddress, query_destinationElements_id, query_destinationElements_name, query_destinationElements_netMask, query_destinationElements_path, query_destinationElements_type, query_firewall_id,
                                          query_firewall_name, query_firewall_path, query_mode, query_ports, query_sourceAddresses, query_sourceElements_IPAddress, query_sourceElements_id, query_sourceElements_name, query_sourceElements_netMask, query_sourceElements_path, query_sourceElements_type)
    command_results = CommandResults(
        outputs_prefix='Skybox.checkAccess',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def countObjectAffectedAccessRules_command(client, args):
    hostId = args.get('hostId')
    objectName = args.get('objectName')
    chainFilterMode = args.get('chainFilterMode')
    chainNames = args.get('chainNames')

    response = client.service.countObjectAffectedAccessRules(hostId, objectName, chainFilterMode, chainNames)
    command_results = CommandResults(
        outputs_prefix='Skybox.countObjectAffectedAccessRules',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getAccessRulesV5_command(client, args):
    fw_id = args.get('fw_id')
    fw_name = args.get('fw_name')
    fw_path = args.get('fw_path')
    range_from = args.get('range_from')
    range_to = args.get('range_to')
    chainName = args.get('chainName')

    response = client.service.getAccessRulesV5(fw_id, fw_name, fw_path, range_from, range_to, chainName)
    command_results = CommandResults(
        outputs_prefix='Skybox.getAccessRulesV5',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getAccessRulesV3_command(client, args):
    fw_id = args.get('fw_id')
    fw_name = args.get('fw_name')
    fw_path = args.get('fw_path')
    range_from = args.get('range_from')
    range_to = args.get('range_to')
    chainName = args.get('chainName')

    response = client.service.getAccessRulesV3(fw_id, fw_name, fw_path, range_from, range_to, chainName)
    command_results = CommandResults(
        outputs_prefix='Skybox.getAccessRulesV3',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getAccessRulesV4_command(client, args):
    fw_id = args.get('fw_id')
    fw_name = args.get('fw_name')
    fw_path = args.get('fw_path')
    range_from = args.get('range_from')
    range_to = args.get('range_to')
    chainName = args.get('chainName')

    response = client.service.getAccessRulesV4(fw_id, fw_name, fw_path, range_from, range_to, chainName)
    command_results = CommandResults(
        outputs_prefix='Skybox.getAccessRulesV4',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def doCheckRuleCompliance_command(client, args):
    req_destinationAddress = args.get('req_destinationAddress')
    req_firewallId = args.get('req_firewallId')
    req_port = args.get('req_port')
    req_rulePolicy = args.get('req_rulePolicy')
    req_sourceAddress = args.get('req_sourceAddress')

    response = client.service.doCheckRuleCompliance(
        req_destinationAddress, req_firewallId, req_port, req_rulePolicy, req_sourceAddress)
    command_results = CommandResults(
        outputs_prefix='Skybox.doCheckRuleCompliance',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findNetworkEntitiesBySourceAndDestination_command(client, args):
    sourceIPRangeElem_endIP = args.get('sourceIPRangeElem_endIP')
    sourceIPRangeElem_startIP = args.get('sourceIPRangeElem_startIP')
    destinationIPRangeElem_endIP = args.get('destinationIPRangeElem_endIP')
    destinationIPRangeElem_startIP = args.get('destinationIPRangeElem_startIP')
    checkBackwardRoute = args.get('checkBackwardRoute')

    response = client.service.findNetworkEntitiesBySourceAndDestination(
        sourceIPRangeElem_endIP, sourceIPRangeElem_startIP, destinationIPRangeElem_endIP, destinationIPRangeElem_startIP, checkBackwardRoute)
    command_results = CommandResults(
        outputs_prefix='Skybox.findNetworkEntitiesBySourceAndDestination',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getAccessRulesV2_command(client, args):
    fw_id = args.get('fw_id')
    fw_name = args.get('fw_name')
    fw_path = args.get('fw_path')
    range_from = args.get('range_from')
    range_to = args.get('range_to')
    chainName = args.get('chainName')

    response = client.service.getAccessRulesV2(fw_id, fw_name, fw_path, range_from, range_to, chainName)
    command_results = CommandResults(
        outputs_prefix='Skybox.getAccessRulesV2',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getNetInterfacesByAssetId_command(client, args):
    assetId = args.get('assetId')

    response = client.service.getNetInterfacesByAssetId(assetId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getNetInterfacesByAssetId',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def countAssetsByNames_command(client, args):
    names = args.get('names')

    response = client.service.countAssetsByNames(names)
    command_results = CommandResults(
        outputs_prefix='Skybox.countAssetsByNames',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findFirewallsByLocation_command(client, args):
    locationName = args.get('locationName')

    response = client.service.findFirewallsByLocation(locationName)
    command_results = CommandResults(
        outputs_prefix='Skybox.findFirewallsByLocation',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def testService_command(client, args):
    anyValue = args.get('anyValue')

    response = client.service.testService(anyValue)
    command_results = CommandResults(
        outputs_prefix='Skybox.testService',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getAllFirewallObjects_command(client, args):
    hostId = args.get('hostId')
    objectName = args.get('objectName')
    pageNum = args.get('pageNum')
    itemInPage = args.get('itemInPage')

    response = client.service.getAllFirewallObjects(hostId, objectName, pageNum, itemInPage)
    command_results = CommandResults(
        outputs_prefix='Skybox.getAllFirewallObjects',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def createFirewallException_command(client, args):
    firewallException_destinationAddress = args.get('firewallException_destinationAddress')
    firewallException_expirationDate = args.get('firewallException_expirationDate')
    firewallException_firewall_id = args.get('firewallException_firewall_id')
    firewallException_firewall_name = args.get('firewallException_firewall_name')
    firewallException_firewall_path = args.get('firewallException_firewall_path')
    firewallException_id = args.get('firewallException_id')
    firewallException_isDestinationNegated = args.get('firewallException_isDestinationNegated')
    firewallException_isServicesNegated = args.get('firewallException_isServicesNegated')
    firewallException_isSourceNegated = args.get('firewallException_isSourceNegated')
    firewallException_originalRuleId = args.get('firewallException_originalRuleId')
    firewallException_originalRuleText = args.get('firewallException_originalRuleText')
    firewallException_policy = args.get('firewallException_policy')
    firewallException_services = args.get('firewallException_services')
    firewallException_sourceAddress = args.get('firewallException_sourceAddress')
    firewallException_tag = args.get('firewallException_tag')
    firewallException_ticketId = args.get('firewallException_ticketId')
    firewallException_userComments = args.get('firewallException_userComments')

    response = client.service.createFirewallException(firewallException_destinationAddress, firewallException_expirationDate, firewallException_firewall_id, firewallException_firewall_name, firewallException_firewall_path, firewallException_id, firewallException_isDestinationNegated, firewallException_isServicesNegated,
                                                      firewallException_isSourceNegated, firewallException_originalRuleId, firewallException_originalRuleText, firewallException_policy, firewallException_services, firewallException_sourceAddress, firewallException_tag, firewallException_ticketId, firewallException_userComments)
    command_results = CommandResults(
        outputs_prefix='Skybox.createFirewallException',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def updateAccessRuleAttributes_command(client, args):
    updateInfo_accessRuleIds = args.get('updateInfo_accessRuleIds')
    updateInfo_ruleAttributes_businessFunction = args.get('updateInfo_ruleAttributes_businessFunction')
    updateInfo_ruleAttributes_comment = args.get('updateInfo_ruleAttributes_comment')
    updateInfo_ruleAttributes_customFields = args.get('updateInfo_ruleAttributes_customFields')
    updateInfo_ruleAttributes_email = args.get('updateInfo_ruleAttributes_email')
    updateInfo_ruleAttributes_nextReviewDate = args.get('updateInfo_ruleAttributes_nextReviewDate')
    updateInfo_ruleAttributes_owner = args.get('updateInfo_ruleAttributes_owner')
    updateInfo_ruleAttributes_status = args.get('updateInfo_ruleAttributes_status')
    updateInfo_ruleAttributes_ticketId = args.get('updateInfo_ruleAttributes_ticketId')

    response = client.service.updateAccessRuleAttributes(updateInfo_accessRuleIds, updateInfo_ruleAttributes_businessFunction, updateInfo_ruleAttributes_comment, updateInfo_ruleAttributes_customFields,
                                                         updateInfo_ruleAttributes_email, updateInfo_ruleAttributes_nextReviewDate, updateInfo_ruleAttributes_owner, updateInfo_ruleAttributes_status, updateInfo_ruleAttributes_ticketId)
    command_results = CommandResults(
        outputs_prefix='Skybox.updateAccessRuleAttributes',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def createRulePolicyException_command(client, args):
    rulePolicyException_comment = args.get('rulePolicyException_comment')
    rulePolicyException_expirationAccessRuleModification = args.get(
        'rulePolicyException_expirationAccessRuleModification')
    rulePolicyException_expirationDate = args.get('rulePolicyException_expirationDate')
    rulePolicyException_firewall_id = args.get('rulePolicyException_firewall_id')
    rulePolicyException_firewall_name = args.get('rulePolicyException_firewall_name')
    rulePolicyException_firewall_path = args.get('rulePolicyException_firewall_path')
    rulePolicyException_id = args.get('rulePolicyException_id')
    rulePolicyException_ruleGuid = args.get('rulePolicyException_ruleGuid')
    rulePolicyException_rulePolicyScope = args.get('rulePolicyException_rulePolicyScope')

    response = client.service.createRulePolicyException(rulePolicyException_comment, rulePolicyException_expirationAccessRuleModification, rulePolicyException_expirationDate, rulePolicyException_firewall_id,
                                                        rulePolicyException_firewall_name, rulePolicyException_firewall_path, rulePolicyException_id, rulePolicyException_ruleGuid, rulePolicyException_rulePolicyScope)
    command_results = CommandResults(
        outputs_prefix='Skybox.createRulePolicyException',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findFirewalls_command(client, args):
    sourceIpRange = args.get('sourceIpRange')
    destinationIpRange = args.get('destinationIpRange')

    response = client.service.findFirewalls(sourceIpRange, destinationIpRange)
    command_results = CommandResults(
        outputs_prefix='Skybox.findFirewalls',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def test_module(client):
    response = client.service.testService(111000111)
    if response == 111000111:
        return_results('ok')
    else:
        return_results(str(response))


def main():
    handle_proxy()
    params = demisto.params()
    args = demisto.args()
    url = params.get('url')
    verify_certificate = not params.get('insecure', False)

    wsdl = url + "/skybox/webservice/jaxws/network?wsdl"

    username = params['credentials']['identifier']
    password = params['credentials']['password']

    session: Session = Session()
    session.auth = (username, password)
    session.verify = verify_certificate
    cache: SqliteCache = SqliteCache(path=get_cache_path(), timeout=None)
    transport: Transport = Transport(session=session, cache=cache)
    settings: Settings = Settings(strict=False, xsd_ignore_sequence_order=True)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client = zClient(wsdl=wsdl, transport=transport, settings=settings)

        commands = {
            'skybox-findObjectAffectedAccessRulesV2': findObjectAffectedAccessRulesV2_command,
            'skybox-deleteFirewallException': deleteFirewallException_command,
            'skybox-getAccessRuleAttributesV2': getAccessRuleAttributesV2_command,
            'skybox-getNetInterfacesByNetworkId': getNetInterfacesByNetworkId_command,
            'skybox-getHostAttributes': getHostAttributes_command,
            'skybox-findNetworksForIPRange': findNetworksForIPRange_command,
            'skybox-deleteRulePolicyException': deleteRulePolicyException_command,
            'skybox-findFirewallObjectByIP': findFirewallObjectByIP_command,
            'skybox-updateHostAttributes': updateHostAttributes_command,
            'skybox-modifyFirewallException': modifyFirewallException_command,
            'skybox-getHostCluster': getHostCluster_command,
            'skybox-checkAccessCompliance': checkAccessCompliance_command,
            'skybox-findFirewallsByObjectName': findFirewallsByObjectName_command,
            'skybox-updateAccessRuleAttributesV2': updateAccessRuleAttributesV2_command,
            'skybox-getHostNetworkInterfaces': getHostNetworkInterfaces_command,
            'skybox-checkAccessV3': checkAccessV3_command,
            'skybox-findNetworkElementZone': findNetworkElementZone_command,
            'skybox-checkAccessV2': checkAccessV2_command,
            'skybox-findAssetsByNames': findAssetsByNames_command,
            'skybox-getAccessRule': getAccessRule_command,
            'skybox-checkAccessV1': checkAccessV1_command,
            'skybox-findNetworks': findNetworks_command,
            'skybox-getAccessRuleEntityFields': getAccessRuleEntityFields_command,
            'skybox-countAssetsByIps': countAssetsByIps_command,
            'skybox-findFirewallElementFAFolderPath': findFirewallElementFAFolderPath_command,
            'skybox-getZoneFromNetwork': getZoneFromNetwork_command,
            'skybox-findAccessRules': findAccessRules_command,
            'skybox-isBackwardRouteExist': isBackwardRouteExist_command,
            'skybox-getAccessRulesSections': getAccessRulesSections_command,
            'skybox-getAccessRuleAttributes': getAccessRuleAttributes_command,
            'skybox-getZoneFromFW': getZoneFromFW_command,
            'skybox-getHostEntityFields': getHostEntityFields_command,
            'skybox-findAssetsByIps': findAssetsByIps_command,
            'skybox-findFirewallObjectsIdentifications': findFirewallObjectsIdentifications_command,
            'skybox-modifyRulePolicyException': modifyRulePolicyException_command,
            'skybox-getAccessRuleV5': getAccessRuleV5_command,
            'skybox-getAccessRules': getAccessRules_command,
            'skybox-findFirewallObjectByName': findFirewallObjectByName_command,
            'skybox-findAccessRulesV2': findAccessRulesV2_command,
            'skybox-findFirewallsByName': findFirewallsByName_command,
            'skybox-findObjectAffectedAccessRules': findObjectAffectedAccessRules_command,
            'skybox-updateFwAccessRuleAttributes': updateFwAccessRuleAttributes_command,
            'skybox-findAccessRulesV3': findAccessRulesV3_command,
            'skybox-checkAccess': checkAccess_command,
            'skybox-countObjectAffectedAccessRules': countObjectAffectedAccessRules_command,
            'skybox-getAccessRulesV5': getAccessRulesV5_command,
            'skybox-getAccessRulesV3': getAccessRulesV3_command,
            'skybox-getAccessRulesV4': getAccessRulesV4_command,
            'skybox-doCheckRuleCompliance': doCheckRuleCompliance_command,
            'skybox-findNetworkEntitiesBySourceAndDestination': findNetworkEntitiesBySourceAndDestination_command,
            'skybox-getAccessRulesV2': getAccessRulesV2_command,
            'skybox-getNetInterfacesByAssetId': getNetInterfacesByAssetId_command,
            'skybox-countAssetsByNames': countAssetsByNames_command,
            'skybox-findFirewallsByLocation': findFirewallsByLocation_command,
            'skybox-testService': testService_command,
            'skybox-getAllFirewallObjects': getAllFirewallObjects_command,
            'skybox-createFirewallException': createFirewallException_command,
            'skybox-updateAccessRuleAttributes': updateAccessRuleAttributes_command,
            'skybox-createRulePolicyException': createRulePolicyException_command,
            'skybox-findFirewalls': findFirewalls_command,
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
