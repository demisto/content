import shutil
import tempfile

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from requests import Session
from zeep import Client as zClient
from zeep import Settings, helpers
from zeep.cache import SqliteCache
from zeep.transports import Transport
from datetime import date, datetime


''' HELPER FUNCTIONS '''

class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        output = {}
        for key in o:
            if isinstance(o[key], datetime):
                output[key] = o[key].isoformat()
            else:
                output[key] = helpers.serialize_object(o[key])

        return json.dumps(output, default=lambda o: '<not serializable>')


def serialize_object_list(input) -> Dict:
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


def getTicketWorkflow_command(client, args):
    ticketId = args.get('ticketId')

    response = client.service.getTicketWorkflow(ticketId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getTicketWorkflow',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getOriginalChangeRequestRouteInfoV1_command(client, args):
    ticketId = args.get('ticketId')
    changeRequestId = args.get('changeRequestId')

    response = client.service.getOriginalChangeRequestRouteInfoV1(ticketId, changeRequestId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getOriginalChangeRequestRouteInfoV1',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getTicketTypePhasesByTicketType_command(client, args):
    ticketType = args.get('ticketType')

    response = client.service.getTicketTypePhasesByTicketType(ticketType)
    command_results = CommandResults(
        outputs_prefix='Skybox.getTicketTypePhasesByTicketType',
        outputs_key_field='id',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getOriginalChangeRequestV7_command(client, args):
    ticketId = args.get('ticketId')

    response = client.service.getOriginalChangeRequestV7(ticketId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getOriginalChangeRequestV7',
        outputs_key_field='',
        readable_output=tableToMarkdown("Original Change Request", serialize_object(response)),
        outputs=serialize_object_list(response),
        raw_response=serialize_object_list(response)
    )

    return command_results


def setTicketFields_command(client, args):
    ticketId = args.get('ticketId')
    ticketIdType = args.get('ticketIdType')
    ticketFields_typeCode = args.get('ticketFields_typeCode')
    ticketFields_value = args.get('ticketFields_value')

    ticketFields_type = client.get_type('ns0:ticketField')
    ticketFields = ticketFields_type(
        typeCode=ticketFields_typeCode,
        value=ticketFields_value,
    )

    response = client.service.setTicketFields(ticketId, ticketIdType, [ticketFields])
    command_results = CommandResults(
        outputs_prefix='Skybox.setTicketFields',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def createAccessChangeTicket_command(client, args):
    accessChangeTicket_id = args.get('accessChangeTicket_id')
    accessChangeTicket_comment = args.get('accessChangeTicket_comment')
    accessChangeTicket_description = args.get('accessChangeTicket_description')
    accessChangeTicket_createdBy = args.get('accessChangeTicket_createdBy')
    accessChangeTicket_creationTime = args.get('accessChangeTicket_creationTime')
    accessChangeTicket_lastModifiedBy = args.get('accessChangeTicket_lastModifiedBy')
    accessChangeTicket_lastModificationTime = args.get('accessChangeTicket_lastModificationTime')
    accessChangeTicket_externalTicketId = args.get('accessChangeTicket_externalTicketId')
    accessChangeTicket_externalTicketStatus = args.get('accessChangeTicket_externalTicketStatus')
    accessChangeTicket_status = args.get('accessChangeTicket_status')
    accessChangeTicket_title = args.get('accessChangeTicket_title')
    accessChangeTicket_changeDetails = args.get('accessChangeTicket_changeDetails')
    accessChangeTicket_priority = args.get('accessChangeTicket_priority')
    accessChangeTicket_owner = args.get('accessChangeTicket_owner')
    accessChangeTicket_dueDate = args.get('accessChangeTicket_dueDate')
    accessChangeTicket_doneDate = args.get('accessChangeTicket_doneDate')
    accessChangeTicket_likelihood = args.get('accessChangeTicket_likelihood')
    accessChangeTicket_ccList_email = args.get('accessChangeTicket_ccList_email')
    accessChangeTicket_ccList_userName = args.get('accessChangeTicket_ccList_userName')
    accessChangeTicket_customFields_comment = args.get('accessChangeTicket_customFields_comment')
    accessChangeTicket_customFields_createdBy = args.get('accessChangeTicket_customFields_createdBy')
    accessChangeTicket_customFields_creationTime = args.get('accessChangeTicket_customFields_creationTime')
    accessChangeTicket_customFields_description = args.get('accessChangeTicket_customFields_description')
    accessChangeTicket_customFields_id = args.get('accessChangeTicket_customFields_id')
    accessChangeTicket_customFields_lastModificationTime = args.get(
        'accessChangeTicket_customFields_lastModificationTime')
    accessChangeTicket_customFields_lastModifiedBy = args.get('accessChangeTicket_customFields_lastModifiedBy')
    accessChangeTicket_customFields_name = args.get('accessChangeTicket_customFields_name')
    accessChangeTicket_customFields_typeCode = args.get('accessChangeTicket_customFields_typeCode')
    accessChangeTicket_customFields_value = args.get('accessChangeTicket_customFields_value')
    accessChangeTicket_currentPhaseName = args.get('accessChangeTicket_currentPhaseName')
    phases_comment = args.get('phases_comment')
    phases_createdBy = args.get('phases_createdBy')
    phases_creationTime = args.get('phases_creationTime')
    phases_current = args.get('phases_current')
    phases_demotionsCount = args.get('phases_demotionsCount')
    phases_description = args.get('phases_description')
    phases_dueDate = args.get('phases_dueDate')
    phases_endDate = args.get('phases_endDate')
    phases_id = args.get('phases_id')
    phases_lastModificationTime = args.get('phases_lastModificationTime')
    phases_lastModifiedBy = args.get('phases_lastModifiedBy')
    phases_owner = args.get('phases_owner')
    phases_revisedDueDate = args.get('phases_revisedDueDate')
    phases_startDate = args.get('phases_startDate')
    phases_ticketTypePhase_defaultOwner = args.get('phases_ticketTypePhase_defaultOwner')
    phases_ticketTypePhase_id = args.get('phases_ticketTypePhase_id')
    phases_ticketTypePhase_name = args.get('phases_ticketTypePhase_name')
    phases_ticketTypePhase_order = args.get('phases_ticketTypePhase_order')
    phases_ticketTypePhase_ticketType = args.get('phases_ticketTypePhase_ticketType')
    phases_ticketTypePhase_waitingForClosure = args.get('phases_ticketTypePhase_waitingForClosure')

    ticketTypePhase_type = client.get_type('ns0:ticketTypePhase')
    ticketTypePhase = ticketTypePhase_type(
        defaultOwner=phases_ticketTypePhase_defaultOwner,
        id=phases_ticketTypePhase_id,
        name=phases_ticketTypePhase_name,
        order=phases_ticketTypePhase_order,
        ticketType=phases_ticketTypePhase_ticketType,
        waitingForClosure=phases_ticketTypePhase_waitingForClosure
    )

    phases_type = client.get_type('ns0:phase')
    phases = phases_type(
        comment=phases_comment,
        createdBy=phases_createdBy,
        creationTime=phases_creationTime,
        current=phases_current,
        demotionsCount=phases_demotionsCount,
        description=phases_description,
        dueDate=phases_dueDate,
        endDate=phases_endDate,
        id=phases_id,
        lastModificationTime=phases_lastModificationTime,
        lastModifiedBy=phases_lastModifiedBy,
        owner=phases_owner,
        revisedDueDate=phases_revisedDueDate,
        startDate=phases_startDate,
        ticketTypePhase=ticketTypePhase
    )

    customField_type = client.get_type('ns0:customField')
    customField = customField_type(
        comment=accessChangeTicket_customFields_comment,
        createdBy=accessChangeTicket_customFields_createdBy,
        creationTime=accessChangeTicket_customFields_creationTime,
        description=accessChangeTicket_customFields_description,
        id=accessChangeTicket_customFields_id,
        lastModificationTime=accessChangeTicket_customFields_lastModificationTime,
        lastModifiedBy=accessChangeTicket_customFields_lastModifiedBy,
        name=accessChangeTicket_customFields_name,
        typeCode=accessChangeTicket_customFields_typeCode,
        value=accessChangeTicket_customFields_value
    )

    emailRecipient_type = client.get_type('ns0:emailRecipient')
    emailRecipient = emailRecipient_type(
        email=accessChangeTicket_ccList_email,
        userName=accessChangeTicket_ccList_userName
    )

    accessChangeTicket_type = client.get_type('ns0:accessChangeTicket')
    accessChangeTicket = accessChangeTicket_type(
        id=accessChangeTicket_id,
        status=accessChangeTicket_status,
        likelihood=accessChangeTicket_likelihood,
        priority=accessChangeTicket_priority,
        title=accessChangeTicket_title,
        comment=accessChangeTicket_comment,
        externalTicketId=accessChangeTicket_externalTicketId,
        externalTicketStatus=accessChangeTicket_externalTicketStatus,
        changeDetails=accessChangeTicket_changeDetails,
        owner=accessChangeTicket_owner,
        description=accessChangeTicket_description,
        ccList=[emailRecipient],
        customFields=[customField],
        createdBy=accessChangeTicket_createdBy,
        creationTime=accessChangeTicket_creationTime,
        lastModifiedBy=accessChangeTicket_lastModifiedBy,
        lastModificationTime=accessChangeTicket_lastModificationTime,
        dueDate=accessChangeTicket_dueDate,
        doneDate=accessChangeTicket_doneDate,
        currentPhaseName=accessChangeTicket_currentPhaseName,
    )

    response = client.service.createAccessChangeTicket(
        accessChangeTicket=accessChangeTicket,
    )

    command_results = CommandResults(
        outputs_prefix='Skybox.createAccessChangeTicket',
        outputs_key_field='id',
        outputs=serialize_object_dict(response),
        raw_response=serialize_object_dict(response),
        readable_output=tableToMarkdown("Access Change Ticket Created", serialize_object_dict(response), ['id',
                                                                                                          'title',
                                                                                                          'priority'])
    )

    return command_results


def getAttachmentFile_command(client, args):
    attachmentId = args.get('attachmentId')
    output_filename = args.get('output_filename')

    response = client.service.getAttachmentFile(attachmentId)
    file = fileResult(filename=output_filename, data=response, file_type=EntryType.ENTRY_INFO_FILE)

    return file


def createRecertifyTicketV2_command(client, args):
    accessChangeTicket_id = args.get('accessChangeTicket_id')
    accessChangeTicket_comment = args.get('accessChangeTicket_comment')
    accessChangeTicket_description = args.get('accessChangeTicket_description')
    accessChangeTicket_createdBy = args.get('accessChangeTicket_createdBy')
    accessChangeTicket_creationTime = args.get('accessChangeTicket_creationTime')
    accessChangeTicket_lastModifiedBy = args.get('accessChangeTicket_lastModifiedBy')
    accessChangeTicket_lastModificationTime = args.get('accessChangeTicket_lastModificationTime')
    accessChangeTicket_externalTicketId = args.get('accessChangeTicket_externalTicketId')
    accessChangeTicket_externalTicketStatus = args.get('accessChangeTicket_externalTicketStatus')
    accessChangeTicket_status = args.get('accessChangeTicket_status')
    accessChangeTicket_title = args.get('accessChangeTicket_title')
    accessChangeTicket_changeDetails = args.get('accessChangeTicket_changeDetails')
    accessChangeTicket_priority = args.get('accessChangeTicket_priority')
    accessChangeTicket_owner = args.get('accessChangeTicket_owner')
    accessChangeTicket_dueDate = args.get('accessChangeTicket_dueDate')
    accessChangeTicket_doneDate = args.get('accessChangeTicket_doneDate')
    accessChangeTicket_likelihood = args.get('accessChangeTicket_likelihood')
    accessChangeTicket_ccList_email = args.get('accessChangeTicket_ccList_email')
    accessChangeTicket_ccList_userName = args.get('accessChangeTicket_ccList_userName')
    accessChangeTicket_customFields_comment = args.get('accessChangeTicket_customFields_comment')
    accessChangeTicket_customFields_createdBy = args.get('accessChangeTicket_customFields_createdBy')
    accessChangeTicket_customFields_creationTime = args.get('accessChangeTicket_customFields_creationTime')
    accessChangeTicket_customFields_description = args.get('accessChangeTicket_customFields_description')
    accessChangeTicket_customFields_id = args.get('accessChangeTicket_customFields_id')
    accessChangeTicket_customFields_lastModificationTime = args.get(
        'accessChangeTicket_customFields_lastModificationTime')
    accessChangeTicket_customFields_lastModifiedBy = args.get('accessChangeTicket_customFields_lastModifiedBy')
    accessChangeTicket_customFields_name = args.get('accessChangeTicket_customFields_name')
    accessChangeTicket_customFields_typeCode = args.get('accessChangeTicket_customFields_typeCode')
    accessChangeTicket_customFields_value = args.get('accessChangeTicket_customFields_value')
    accessChangeTicket_currentPhaseName = args.get('accessChangeTicket_currentPhaseName')
    accessRuleElements_action = args.get('accessRuleElements_action')
    accessRuleElements_comment = args.get('accessRuleElements_comment')
    accessRuleElements_description = args.get('accessRuleElements_description')
    accessRuleElements_destinationAddresses = args.get('accessRuleElements_destinationAddresses')
    accessRuleElements_direction = args.get('accessRuleElements_direction')
    accessRuleElements_disabled = args.get('accessRuleElements_disabled')
    accessRuleElements_firewall_id = args.get('accessRuleElements_firewall_id')
    accessRuleElements_firewall_name = args.get('accessRuleElements_firewall_name')
    accessRuleElements_firewall_path = args.get('accessRuleElements_firewall_path')
    accessRuleElements_globalUniqueId = args.get('accessRuleElements_globalUniqueId')
    accessRuleElements_id = args.get('accessRuleElements_id')
    accessRuleElements_implied = args.get('accessRuleElements_implied')
    accessRuleElements_isAuthenticated = args.get('accessRuleElements_isAuthenticated')
    accessRuleElements_netInterfaces = args.get('accessRuleElements_netInterfaces')
    accessRuleElements_orgDestinationText = args.get('accessRuleElements_orgDestinationText')
    accessRuleElements_orgPortsText = args.get('accessRuleElements_orgPortsText')
    accessRuleElements_orgRuleNumber = args.get('accessRuleElements_orgRuleNumber')
    accessRuleElements_orgRuleText = args.get('accessRuleElements_orgRuleText')
    accessRuleElements_orgSourceText = args.get('accessRuleElements_orgSourceText')
    accessRuleElements_ports = args.get('accessRuleElements_ports')
    accessRuleElements_ruleChain = args.get('accessRuleElements_ruleChain')
    accessRuleElements_sbOrder = args.get('accessRuleElements_sbOrder')
    accessRuleElements_services = args.get('accessRuleElements_services')
    accessRuleElements_sourceAddresses = args.get('accessRuleElements_sourceAddresses')
    accessRuleElements_sourceNetInterfaces = args.get('accessRuleElements_sourceNetInterfaces')
    workflowId = args.get('workflowId')

    customField_type = client.get_type('ns0:customField')
    customField = customField_type(
        comment=accessChangeTicket_customFields_comment,
        createdBy=accessChangeTicket_customFields_createdBy,
        creationTime=accessChangeTicket_customFields_creationTime,
        description=accessChangeTicket_customFields_description,
        id=accessChangeTicket_customFields_id,
        lastModificationTime=accessChangeTicket_customFields_lastModificationTime,
        lastModifiedBy=accessChangeTicket_customFields_lastModifiedBy,
        name=accessChangeTicket_customFields_name,
        typeCode=accessChangeTicket_customFields_typeCode,
        value=accessChangeTicket_customFields_value
    )

    emailRecipient_type = client.get_type('ns0:emailRecipient')
    emailRecipient = emailRecipient_type(
        email=accessChangeTicket_ccList_email,
        userName=accessChangeTicket_ccList_userName
    )

    accessChangeTicket_type = client.get_type('ns0:accessChangeTicket')
    accessChangeTicket = accessChangeTicket_type(
        id=accessChangeTicket_id,
        status=accessChangeTicket_status,
        likelihood=accessChangeTicket_likelihood,
        priority=accessChangeTicket_priority,
        title=accessChangeTicket_title,
        comment=accessChangeTicket_comment,
        externalTicketId=accessChangeTicket_externalTicketId,
        externalTicketStatus=accessChangeTicket_externalTicketStatus,
        changeDetails=accessChangeTicket_changeDetails,
        owner=accessChangeTicket_owner,
        description=accessChangeTicket_description,
        ccList=[emailRecipient],
        # customFields=[customField],
        createdBy=accessChangeTicket_createdBy,
        creationTime=accessChangeTicket_creationTime,
        lastModifiedBy=accessChangeTicket_lastModifiedBy,
        lastModificationTime=accessChangeTicket_lastModificationTime,
        dueDate=accessChangeTicket_dueDate,
        doneDate=accessChangeTicket_doneDate,
        currentPhaseName=accessChangeTicket_currentPhaseName
    )

    accessRuleElements_type = client.get_type('ns0:accessRuleElementV2')
    accessRuleElements = accessRuleElements_type(
        action=accessRuleElements_action,
        comment=accessRuleElements_comment,
        description=accessRuleElements_description,
        destinationAddresses=accessRuleElements_destinationAddresses,
        direction=accessRuleElements_direction,
        disabled=accessRuleElements_disabled,
        # firewall=firewall,
        globalUniqueId=accessRuleElements_globalUniqueId,
        id=accessRuleElements_id,
        implied=accessRuleElements_implied,
        isAuthenticated=accessRuleElements_isAuthenticated,
        netInterfaces=accessRuleElements_netInterfaces,
        orgDestinationText=accessRuleElements_orgDestinationText,
        orgPortsText=accessRuleElements_orgPortsText,
        orgRuleNumber=accessRuleElements_orgRuleNumber,
        orgRuleText=accessRuleElements_orgRuleText,
        orgSourceText=accessRuleElements_orgSourceText,
        ports=accessRuleElements_ports,
        ruleChain=accessRuleElements_ruleChain,
        sbOrder=accessRuleElements_sbOrder,
        services=accessRuleElements_services,
        sourceAddresses=accessRuleElements_sourceAddresses,
        sourceNetInterfaces=accessRuleElements_sourceNetInterfaces
    )

    response = client.service.createRecertifyTicketV2(
        accessChangeTicket=accessChangeTicket,
        accessRuleElements=accessRuleElements,
        workflowId=workflowId
    )

    command_results = CommandResults(
        outputs_prefix='Skybox.createRecertifyTicketV2',
        outputs_key_field='',
        outputs=helpers.serialize_object(resolve_datetime(response)),
        raw_response=helpers.serialize_object(resolve_datetime(response))
    )

    return command_results


def getAccessChangeTicket_command(client, args):
    ticketId = args.get('ticketId')

    response = client.service.getAccessChangeTicket(ticketId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getAccessChangeTicket',
        outputs_key_field='',
        outputs=serialize_object_dict(response),
        raw_response=serialize_object_dict(response)
    )

    return command_results


def getAccessRequests_command(client, args):
    accessRequestIds = args.get('accessRequestIds')

    response = client.service.getAccessRequests(accessRequestIds)
    command_results = CommandResults(
        outputs_prefix='Skybox.getAccessRequests',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getPotentialVulnerabilitiesV2_command(client, args):
    ticketId = args.get('ticketId')
    changeRequestId = args.get('changeRequestId')

    response = client.service.getPotentialVulnerabilitiesV2(ticketId, changeRequestId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getPotentialVulnerabilitiesV2',
        outputs_key_field='',
        outputs=helpers.serialize_object(resolve_datetime(response)),
        raw_response=helpers.serialize_object(resolve_datetime(response))
    )

    return command_results


def deleteChangeRequests_command(client, args):
    ticketId = args.get('ticketId')
    changeRequestIds = args.get('changeRequestIds')

    response = client.service.deleteChangeRequests(ticketId, changeRequestIds)
    command_results = CommandResults(
        outputs_prefix='Skybox.deleteChangeRequests',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def deleteAccessChangeTicket_command(client, args):
    ticketId = args.get('ticketId')

    response = client.service.deleteAccessChangeTicket(ticketId)
    command_results = CommandResults(
        outputs_prefix='Skybox.deleteAccessChangeTicket',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getNotImplementedChangeRequestsV2_command(client, args):

    response = client.service.getNotImplementedChangeRequestsV2()
    command_results = CommandResults(
        outputs_prefix='Skybox.getNotImplementedChangeRequestsV2',
        outputs_key_field='',
        outputs=serialize_object_list(response),
        raw_response=serialize_object_list(response)
    )

    return command_results


def getTicketEvents_command(client, args):
    ticketId = args.get('ticketId')

    response = client.service.getTicketEvents(ticketId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getTicketEvents',
        outputs_key_field='',
        outputs=serialize_object_list(response),
        raw_response=serialize_object_list(response)
    )

    return command_results


def getChangeRequestReviewers_command(client, args):
    ticketId = args.get('ticketId')
    changeRequestId = args.get('changeRequestId')

    response = client.service.getChangeRequestReviewers(ticketId, changeRequestId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getChangeRequestReviewers',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getChangeRequestRuleAttributes_command(client, args):
    ticketId = args.get('ticketId')
    changeRequestId = args.get('changeRequestId')

    response = client.service.getChangeRequestRuleAttributes(ticketId, changeRequestId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getChangeRequestRuleAttributes',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getGeneratedCommands_command(client, args):
    ticketId = args.get('ticketId')
    changeRequestId = args.get('changeRequestId')

    response = client.service.getGeneratedCommands(ticketId, changeRequestId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getGeneratedCommands',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getImplementedChangeRequests_command(client, args):

    response = client.service.getImplementedChangeRequests()
    command_results = CommandResults(
        outputs_prefix='Skybox.getImplementedChangeRequests',
        outputs_key_field='',
        outputs=serialize_object_list(response),
        raw_response=serialize_object_list(response)
    )

    return command_results


def operateOnVulnerabilityDefinitionTicket_command(client, args):
    ticketId = args.get('ticketId')
    phaseOperation_phaseId = args.get('phaseOperation_phaseId')
    phaseOperation_phaseOwner = args.get('phaseOperation_phaseOwner')
    phaseOperation_reject = args.get('phaseOperation_reject')
    phaseOperation_type_var = args.get('phaseOperation_type')

    phaseOperation_type = client.get_type('ns0:phaseOperation')
    phaseOperation = phaseOperation_type(
        phaseId=phaseOperation_phaseId,
        phaseOwner=phaseOperation_phaseOwner,
        reject=phaseOperation_reject,
        type=phaseOperation_type_var
    )

    response = client.service.operateOnVulnerabilityDefinitionTicket(ticketId, phaseOperation)

    command_results = CommandResults(
        outputs_prefix='Skybox.operateOnVulnerabilityDefinitionTicket',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def createChangeManagerTicket_command(client, args):
    accessChangeTicket_id = args.get('accessChangeTicket_id', -1)
    accessChangeTicket_comment = args.get('accessChangeTicket_comment')
    accessChangeTicket_description = args.get('accessChangeTicket_description')
    accessChangeTicket_createdBy = args.get('accessChangeTicket_createdBy')
    accessChangeTicket_creationTime = args.get('accessChangeTicket_creationTime')
    accessChangeTicket_lastModifiedBy = args.get('accessChangeTicket_lastModifiedBy')
    accessChangeTicket_lastModificationTime = args.get('accessChangeTicket_lastModificationTime')
    accessChangeTicket_externalTicketId = args.get('accessChangeTicket_externalTicketId')
    accessChangeTicket_externalTicketStatus = args.get('accessChangeTicket_externalTicketStatus', 'Pending')
    accessChangeTicket_status = args.get('accessChangeTicket_status', 'New')
    accessChangeTicket_title = args.get('accessChangeTicket_title')
    accessChangeTicket_changeDetails = args.get('accessChangeTicket_changeDetails')
    accessChangeTicket_priority = args.get('accessChangeTicket_priority', 'P5')
    accessChangeTicket_owner = args.get('accessChangeTicket_owner')
    accessChangeTicket_dueDate = args.get('accessChangeTicket_dueDate')
    accessChangeTicket_doneDate = args.get('accessChangeTicket_doneDate')
    accessChangeTicket_likelihood = args.get('accessChangeTicket_likelihood', 'Unknown')
    accessChangeTicket_ccList_email = args.get('accessChangeTicket_ccList_email')
    accessChangeTicket_ccList_userName = args.get('accessChangeTicket_ccList_userName')
    accessChangeTicket_customFields_comment = args.get('accessChangeTicket_customFields_comment')
    accessChangeTicket_customFields_createdBy = args.get('accessChangeTicket_customFields_createdBy')
    accessChangeTicket_customFields_creationTime = args.get('accessChangeTicket_customFields_creationTime')
    accessChangeTicket_customFields_description = args.get('accessChangeTicket_customFields_description')
    accessChangeTicket_customFields_id = args.get('accessChangeTicket_customFields_id', 0)
    accessChangeTicket_customFields_lastModificationTime = args.get(
        'accessChangeTicket_customFields_lastModificationTime')
    accessChangeTicket_customFields_lastModifiedBy = args.get('accessChangeTicket_customFields_lastModifiedBy')
    accessChangeTicket_customFields_name = args.get('accessChangeTicket_customFields_name')
    accessChangeTicket_customFields_typeCode = args.get('accessChangeTicket_customFields_typeCode')
    accessChangeTicket_customFields_value = args.get('accessChangeTicket_customFields_value')
    accessChangeTicket_currentPhaseName = args.get('accessChangeTicket_currentPhaseName')
    phases_comment = args.get('phases_comment')
    phases_createdBy = args.get('phases_createdBy')
    phases_creationTime = args.get('phases_creationTime')
    phases_current = args.get('phases_current')
    phases_demotionsCount = args.get('phases_demotionsCount')
    phases_description = args.get('phases_description')
    phases_dueDate = args.get('phases_dueDate')
    phases_endDate = args.get('phases_endDate')
    phases_id = args.get('phases_id')
    phases_lastModificationTime = args.get('phases_lastModificationTime')
    phases_lastModifiedBy = args.get('phases_lastModifiedBy')
    phases_owner = args.get('phases_owner')
    phases_revisedDueDate = args.get('phases_revisedDueDate')
    phases_startDate = args.get('phases_startDate')
    phases_ticketTypePhase_defaultOwner = args.get('phases_ticketTypePhase_defaultOwner')
    phases_ticketTypePhase_id = args.get('phases_ticketTypePhase_id')
    phases_ticketTypePhase_name = args.get('phases_ticketTypePhase_name')
    phases_ticketTypePhase_order = args.get('phases_ticketTypePhase_order')
    phases_ticketTypePhase_ticketType = args.get('phases_ticketTypePhase_ticketType')
    phases_ticketTypePhase_waitingForClosure = args.get('phases_ticketTypePhase_waitingForClosure')
    workflowId = args.get('workflowId', 1)

    demisto.debug("ticketTYPEPHASE")

    ticketTypePhase_type = client.get_type('ns0:ticketTypePhase')
    ticketTypePhase = ticketTypePhase_type(
        defaultOwner=phases_ticketTypePhase_defaultOwner,
        id=phases_ticketTypePhase_id,
        name=phases_ticketTypePhase_name,
        order=phases_ticketTypePhase_order,
        ticketType=phases_ticketTypePhase_ticketType,
        waitingForClosure=phases_ticketTypePhase_waitingForClosure
    )

    customField_type = client.get_type('ns0:customField')
    customField = customField_type(
        comment=accessChangeTicket_customFields_comment,
        createdBy=accessChangeTicket_customFields_createdBy,
        creationTime=accessChangeTicket_customFields_creationTime,
        description=accessChangeTicket_customFields_description,
        id=accessChangeTicket_customFields_id,
        lastModificationTime=accessChangeTicket_customFields_lastModificationTime,
        lastModifiedBy=accessChangeTicket_customFields_lastModifiedBy,
        name=accessChangeTicket_customFields_name,
        typeCode=accessChangeTicket_customFields_typeCode,
        value=accessChangeTicket_customFields_value
    )

    emailRecipient_type = client.get_type('ns0:emailRecipient')
    emailRecipient = emailRecipient_type(
        email=accessChangeTicket_ccList_email,
        userName=accessChangeTicket_ccList_userName
    )

    accessChangeTicket_type = client.get_type('ns0:accessChangeTicket')
    accessChangeTicket = accessChangeTicket_type(
        id=accessChangeTicket_id,
        status=accessChangeTicket_status,
        likelihood=accessChangeTicket_likelihood,
        priority=accessChangeTicket_priority,
        title=accessChangeTicket_title,
        comment=accessChangeTicket_comment,
        externalTicketId=accessChangeTicket_externalTicketId,
        externalTicketStatus=accessChangeTicket_externalTicketStatus,
        changeDetails=accessChangeTicket_changeDetails,
        owner=accessChangeTicket_owner,
        description=accessChangeTicket_description,
        ccList=[emailRecipient],
        # customFields=[customField],
        createdBy=accessChangeTicket_createdBy,
        creationTime=accessChangeTicket_creationTime,
        lastModifiedBy=accessChangeTicket_lastModifiedBy,
        lastModificationTime=accessChangeTicket_lastModificationTime,
        dueDate=accessChangeTicket_dueDate,
        doneDate=accessChangeTicket_doneDate,
        currentPhaseName=accessChangeTicket_currentPhaseName
    )

    response = client.service.createChangeManagerTicket(
        accessChangeTicket=accessChangeTicket,
        workflowId=workflowId
    )

    readable_output = {}
    readable_output['id'] = response['id']
    readable_output['title'] = response['title']
    readable_output['priority'] = response['priority']

    command_results = CommandResults(
        outputs_prefix='Skybox.createChangeManagerTicket',
        outputs_key_field='id',
        outputs=serialize_object_dict(response),
        raw_response=serialize_object_dict(response),
        readable_output=tableToMarkdown('Created Ticket', serialize_object_dict(response),['id', 'priority', 'title'])
    )

    return command_results


def getTicketsNotImplementedChangeRequestsV2_command(client, args):
    ticketIds = args.get('ticketIds')

    response = client.service.getTicketsNotImplementedChangeRequestsV2(ticketIds)
    command_results = CommandResults(
        outputs_prefix='Skybox.getTicketsNotImplementedChangeRequestsV2',
        outputs_key_field='',
        outputs=serialize_object_list(response),
        raw_response=serialize_object_list(response)
    )

    return command_results


def findAccessRequests_command(client, args):
    hostId = args.get('hostId')
    dateRange_endDate = args.get('dateRange_endDate')
    dateRange_startDate = args.get('dateRange_startDate')

    dateRange_type = client.get_type('ns0:dateRange')
    dateRange = dateRange_type(
        startDate=dateRange_startDate,
        endDate=dateRange_endDate
    )

    response = client.service.findAccessRequests(hostId, dateRange)
    command_results = CommandResults(
        outputs_prefix='Skybox.findAccessRequests',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def expandFirewallsForAccessChangeTicket_command(client, args):
    ticketId = args.get('ticketId')
    accessRequestIds = args.get('accessRequestIds')
    recalculate = args.get('recalculate')

    response = client.service.expandFirewallsForAccessChangeTicket(ticketId, accessRequestIds, recalculate)
    command_results = CommandResults(
        outputs_prefix='Skybox.expandFirewallsForAccessChangeTicket',
        outputs_key_field='',
        outputs=serialize_object_dict(response),
        raw_response=serialize_object_dict(response)
    )

    return command_results


def addAttachmentFile_command(client, args):
    entry_id = demisto.args()['EntryID']
    attachmentDesc = args.get('attachmentDesc')
    sourceFileName = args.get('sourceFileName')
    ticketId = args.get('ticketId')
    phaseName = args.get('phaseName')

    file_path = demisto.getFilePath(entry_id).get('path')

    f = open(file_path, "rb")
    data = f.read()

    response = client.service.addAttachmentFile(
        attachmentDesc=attachmentDesc, sourceFileName=sourceFileName, attachmentData=data, ticketId=ticketId,
        phaseName=phaseName)
    attachment = {}
    attachment['id'] = response
    attachment['ticketId'] = ticketId
    attachment['EntryID'] = entry_id

    command_results = CommandResults(
        outputs_prefix='Skybox.addAttachmentFile',
        outputs_key_field='',
        outputs=attachment,
        raw_response=attachment
    )

    return command_results


def countAccessChangeTickets_command(client, args):
    filter_createdBy = args.get('filter_createdBy')
    filter_freeTextFilter = args.get('filter_freeTextFilter')
    filter_modifiedBy = args.get('filter_modifiedBy')
    filter_myGroups = args.get('filter_myGroups')
    filter_owner = args.get('filter_owner')
    filter_phaseName = args.get('filter_phaseName')
    filter_statusFilter = args.get('filter_statusFilter')
    filter_ticketIdsFilter = args.get('filter_ticketIdsFilter')

    filter_type = client.get_type('ns0:ticketsSearchFilter')
    filter = filter_type(
        createdBy=filter_createdBy,
        freeTextFilter=filter_freeTextFilter,
        modifiedBy=filter_modifiedBy,
        myGroups=filter_myGroups,
        owner=filter_owner,
        phaseName=filter_phaseName,
        statusFilter=filter_statusFilter,
        ticketIdsFilter=filter_ticketIdsFilter
    )

    response = client.service.countAccessChangeTickets(filter)
    command_results = CommandResults(
        outputs_prefix='Skybox.countAccessChangeTickets',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getDerivedChangeRequestsV7_command(client, args):
    ticketId = args.get('ticketId')
    changeRequestId = args.get('changeRequestId')

    response = client.service.getDerivedChangeRequestsV7(ticketId, changeRequestId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getDerivedChangeRequestsV7',
        outputs_key_field='',
        outputs=serialize_object_list(response),
        raw_response=serialize_object_list(response)
    )

    return command_results


def setTicketAccessRequests_command(client, args):
    """
    setTicketAccessRequests": {
                         "input": {
                              "ticketId": {
                                   "optional": false,
                                   "type": "Int(value)"
                              },
                              "accessRequests": {
                                   "optional": true,
                                   "type": {
                                        "accessQuery": {
                                             "optional": true,
                                             "type": {
                                                  "destinationAddresses": {
                                                       "optional": true,
                                                       "type": "String(value)"
                                                  },
                                                  "destinationElements": {
                                                       "optional": true,
                                                       "type": {
                                                            "IPAddress": {
                                                                 "optional": true,
                                                                 "type": "String(value)"
                                                            },
                                                            "id": {
                                                                 "optional": false,
                                                                 "type": "Int(value)"
                                                            },
                                                            "name": {
                                                                 "optional": true,
                                                                 "type": "String(value)"
                                                            },
                                                            "netMask": {
                                                                 "optional": false,
                                                                 "type": "Int(value)"
                                                            },
                                                            "path": {
                                                                 "optional": true,
                                                                 "type": "String(value)"
                                                            },
                                                            "type": {
                                                                 "optional": false,
                                                                 "type": "Int(value)"
                                                            }
                                                       }
                                                  },
                                                  "firewall": {
                                                       "optional": true,
                                                       "type": {
                                                            "id": {
                                                                 "optional": false,
                                                                 "type": "Int(value)"
                                                            },
                                                            "name": {
                                                                 "optional": true,
                                                                 "type": "String(value)"
                                                            },
                                                            "path": {
                                                                 "optional": true,
                                                                 "type": "String(value)"
                                                            }
                                                       }
                                                  },
                                                  "mode": {
                                                       "optional": false,
                                                       "type": "Int(value)"
                                                  },
                                                  "ports": {
                                                       "optional": true,
                                                       "type": "String(value)"
                                                  },
                                                  "sourceAddresses": {
                                                       "optional": true,
                                                       "type": "String(value)"
                                                  },
                                                  "sourceElements": {
                                                       "optional": true,
                                                       "type": {
                                                            "IPAddress": {
                                                                 "optional": true,
                                                                 "type": "String(value)"
                                                            },
                                                            "id": {
                                                                 "optional": false,
                                                                 "type": "Int(value)"
                                                            },
                                                            "name": {
                                                                 "optional": true,
                                                                 "type": "String(value)"
                                                            },
                                                            "netMask": {
                                                                 "optional": false,
                                                                 "type": "Int(value)"
                                                            },
                                                            "path": {
                                                                 "optional": true,
                                                                 "type": "String(value)"
                                                            },
                                                            "type": {
                                                                 "optional": false,
                                                                 "type": "Int(value)"
                                                            }
                                                       }
                                                  }
                                             }
                                        },
                                        "accessQueryMode": {
                                             "optional": true,
                                             "type": "String(value)"
                                        },
                                        "accessStatus": {
                                             "optional": true,
                                             "type": "String(value)"
                                        },
                                        "accessType": {
                                             "optional": true,
                                             "type": "String(value)"
                                        },
                                        "comment": {
                                             "optional": true,
                                             "type": "String(value)"
                                        },
                                        "complianceStatus": {
                                             "optional": true,
                                             "type": "String(value)"
                                        },
                                        "complianceViolations": {
                                             "optional": true,
                                             "type": {
                                                  "aprName": {
                                                       "optional": true,
                                                       "type": "String(value)"
                                                  },
                                                  "aprPath": {
                                                       "optional": true,
                                                       "type": "String(value)"
                                                  },
                                                  "importance": {
                                                       "optional": false,
                                                       "type": "Int(value)"
                                                  },
                                                  "portsViolating": {
                                                       "optional": true,
                                                       "type": "String(value)"
                                                  }
                                             }
                                        },
                                        "createdBy": {
                                             "optional": true,
                                             "type": "String(value)"
                                        },
                                        "creationTime": {
                                             "optional": true,
                                             "type": "DateTime(value)"
                                        },
                                        "description": {
                                             "optional": true,
                                             "type": "String(value)"
                                        },
                                        "destinationZones": {
                                             "optional": true,
                                             "type": "String(value)"
                                        },
                                        "disabled": {
                                             "optional": false,
                                             "type": "Boolean(value)"
                                        },
                                        "id": {
                                             "optional": false,
                                             "type": "Int(value)"
                                        },
                                        "lastModificationTime": {
                                             "optional": true,
                                             "type": "DateTime(value)"
                                        },
                                        "lastModifiedBy": {
                                             "optional": true,
                                             "type": "String(value)"
                                        },
                                        "potentialVulnerabilities": {
                                             "optional": true,
                                             "type": {
                                                  "catalogId": {
                                                       "optional": true,
                                                       "type": "String(value)"
                                                  },
                                                  "cveId": {
                                                       "optional": true,
                                                       "type": "String(value)"
                                                  },
                                                  "hostIp": {
                                                       "optional": true,
                                                       "type": "String(value)"
                                                  },
                                                  "hostName": {
                                                       "optional": true,
                                                       "type": "String(value)"
                                                  },
                                                  "id": {
                                                       "optional": false,
                                                       "type": "Int(value)"
                                                  },
                                                  "severity": {
                                                       "optional": true,
                                                       "type": "String(value)"
                                                  },
                                                  "title": {
                                                       "optional": true,
                                                       "type": "String(value)"
                                                  }
                                             }
                                        },
                                        "sourceZones": {
                                             "optional": true,
                                             "type": "String(value)"
                                        }
                                   }
                              }
                         }
                    },
    """
    ticketId = args.get('ticketId')
    accessRequests_accessQuery_destinationAddresses = args.get('accessRequests_accessQuery_destinationAddresses')
    accessRequests_accessQuery_destinationElements_IPAddress = args.get(
        'accessRequests_accessQuery_destinationElements_IPAddress')
    accessRequests_accessQuery_destinationElements_id = args.get('accessRequests_accessQuery_destinationElements_id')
    accessRequests_accessQuery_destinationElements_name = args.get('accessRequests_accessQuery_destinationElements_name')
    accessRequests_accessQuery_destinationElements_netMask = args.get('accessRequests_accessQuery_destinationElements_netMask')
    accessRequests_accessQuery_destinationElements_path = args.get('accessRequests_accessQuery_destinationElements_path')
    accessRequests_accessQuery_destinationElements_type = args.get('accessRequests_accessQuery_destinationElements_type')
    accessRequests_accessQuery_firewall_id = args.get('accessRequests_accessQuery_firewall_id')
    accessRequests_accessQuery_firewall_name = args.get('accessRequests_accessQuery_firewall_name')
    accessRequests_accessQuery_firewall_path = args.get('accessRequests_accessQuery_firewall_path')
    accessRequests_accessQuery_mode = args.get('accessRequests_accessQuery_mode')
    accessRequests_accessQuery_ports = args.get('accessRequests_accessQuery_ports')
    accessRequests_accessQuery_sourceAddresses = args.get('accessRequests_accessQuery_sourceAddresses')
    accessRequests_accessQuery_sourceElements_IPAddress = args.get('accessRequests_accessQuery_sourceElements_IPAddress')
    accessRequests_accessQuery_sourceElements_id = args.get('accessRequests_accessQuery_sourceElements_id')
    accessRequests_accessQuery_sourceElements_name = args.get('accessRequests_accessQuery_sourceElements_name')
    accessRequests_accessQuery_sourceElements_netMask = args.get('accessRequests_accessQuery_sourceElements_netMask')
    accessRequests_accessQuery_sourceElements_path = args.get('accessRequests_accessQuery_sourceElements_path')
    accessRequests_accessQuery_sourceElements_type = args.get('accessRequests_accessQuery_sourceElements_type')
    accessRequests_accessStatus = args.get('accessRequests_accessStatus')
    accessRequests_accessType = args.get('accessRequests_accessType')
    accessRequests_comment = args.get('accessRequests_comment')
    accessRequests_complianceStatus = args.get('accessRequests_complianceStatus')
    accessRequests_complianceViolations_aprName = args.get('accessRequests_complianceViolations_aprName')
    accessRequests_complianceViolations_aprPath = args.get('accessRequests_complianceViolations_aprPath')
    accessRequests_complianceViolations_importance = args.get('accessRequests_complianceViolations_importance')
    accessRequests_complianceViolations_portsViolating = args.get('accessRequests_complianceViolations_portsViolating')
    accessRequests_createdBy = args.get('accessRequests_createdBy')
    accessRequests_creationTime = args.get('accessRequests_creationTime')
    accessRequests_description = args.get('accessRequests_description')
    accessRequests_destinationZones = args.get('accessRequests_destinationZones')
    accessRequests_disabled = args.get('accessRequests_disabled')
    accessRequests_id = args.get('accessRequests_id')
    accessRequests_lastModificationTime = args.get('accessRequests_lastModificationTime')
    accessRequests_lastModifiedBy = args.get('accessRequests_lastModifiedBy')
    accessRequests_potentialVulnerabilities_catalogId = args.get('accessRequests_potentialVulnerabilities_catalogId')
    accessRequests_potentialVulnerabilities_cveId = args.get('accessRequests_potentialVulnerabilities_cveId')
    accessRequests_potentialVulnerabilities_hostIp = args.get('accessRequests_potentialVulnerabilities_hostIp')
    accessRequests_potentialVulnerabilities_hostName = args.get('accessRequests_potentialVulnerabilities_hostName')
    accessRequests_potentialVulnerabilities_id = args.get('accessRequests_potentialVulnerabilities_id')
    accessRequests_potentialVulnerabilities_severity = args.get('accessRequests_potentialVulnerabilities_severity')
    accessRequests_potentialVulnerabilities_title = args.get('accessRequests_potentialVulnerabilities_title')
    accessRequests_sourceZones = args.get('accessRequests_sourceZones')

    destinationElements_type = client.get_type('ns0:networkElement')
    destinationElements = destinationElements_type(
        IPAddress=accessRequests_accessQuery_destinationElements_IPAddress,
        id=accessRequests_accessQuery_destinationElements_id,
        name=accessRequests_accessQuery_destinationElements_name,
        netMask=accessRequests_accessQuery_destinationElements_netMask,
        path=accessRequests_accessQuery_destinationElements_path,
        type=accessRequests_accessQuery_destinationElements_type
    )

    firewall_type = client.get_type('ns0:firewallElement')
    firewall = firewall_type(
        id=accessRequests_accessQuery_firewall_id,
        name=accessRequests_accessQuery_firewall_name,
        path=accessRequests_accessQuery_firewall_path
    )

    sourceElements_type = client.get_type('ns0:networkElement')
    sourceElements = sourceElements_type(
        IPAddress=accessRequests_accessQuery_sourceElements_IPAddress,
        id=accessRequests_accessQuery_sourceElements_id,
        name=accessRequests_accessQuery_sourceElements_name,
        netMask=accessRequests_accessQuery_sourceElements_netMask,
        path=accessRequests_accessQuery_sourceElements_path,
        type=accessRequests_accessQuery_sourceElements_type
    )

    complianceViolations_type = client.get_type('ns0:complianceViolationElement')
    complianceViolations = complianceViolations_type(
        aprName=accessRequests_complianceViolations_aprName,
        aprPath=accessRequests_complianceViolations_aprPath,
        importance=accessRequests_complianceViolations_importance,
        portsViolating=accessRequests_complianceViolations_portsViolating,
    )

    accessQuery_type = client.get_type('ns0:accessQueryElement')
    accessQuery = accessQuery_type(
        destinationAddresses=accessRequests_accessQuery_destinationAddresses,
        destinationElements=destinationElements,
        firewall=firewall,
        mode=accessRequests_accessQuery_mode,
        ports=accessRequests_accessQuery_ports,
        sourceAddresses=accessRequests_accessQuery_sourceAddresses,
        sourceElements=sourceElements,
    )

    potentialVulnerabilities_type = client.get_type('ns0:potentialVulnerability')
    potentialVulnerabilities = potentialVulnerabilities_type(
        catalogId=accessRequests_potentialVulnerabilities_catalogId,
        cveId=accessRequests_potentialVulnerabilities_cveId,
        hostIp=accessRequests_potentialVulnerabilities_hostIp,
        hostName=accessRequests_potentialVulnerabilities_hostName,
        id=accessRequests_potentialVulnerabilities_id,
        severity=accessRequests_potentialVulnerabilities_severity,
        title=accessRequests_potentialVulnerabilities_title
    )

    accessRequests_type = client.get_type('ns0:accessRequest')
    accessRequests = accessRequests_type(
        accessStatus=accessRequests_accessStatus,
        accessType=accessRequests_accessType,
        comment=accessRequests_comment,
        complianceStatus=accessRequests_complianceStatus,
        createdBy=accessRequests_createdBy,
        creationTime=accessRequests_creationTime,
        description=accessRequests_description,
        destinationZones=accessRequests_destinationZones,
        disabled=accessRequests_disabled,
        id=accessRequests_id,
        lastModificationTime=accessRequests_lastModificationTime,
        lastModifiedBy=accessRequests_lastModifiedBy,
        sourceZones=accessRequests_sourceZones,
        complianceViolations=complianceViolations,
        accessQuery=accessQuery,
        potentialVulnerabilities=potentialVulnerabilities
    )

    response = client.service.setTicketAccessRequests(
        ticketId=ticketId,
        accessRequests=[accessRequests]
    )

    command_results = CommandResults(
        outputs_prefix='Skybox.setTicketAccessRequests',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def updateAccessChangeTicket_command(client, args):
    accessChangeTicket_id = args.get('accessChangeTicket_id')
    accessChangeTicket_comment = args.get('accessChangeTicket_comment')
    accessChangeTicket_description = args.get('accessChangeTicket_description')
    accessChangeTicket_createdBy = args.get('accessChangeTicket_createdBy')
    accessChangeTicket_creationTime = args.get('accessChangeTicket_creationTime')
    accessChangeTicket_lastModifiedBy = args.get('accessChangeTicket_lastModifiedBy')
    accessChangeTicket_lastModificationTime = args.get('accessChangeTicket_lastModificationTime')
    accessChangeTicket_externalTicketId = args.get('accessChangeTicket_externalTicketId')
    accessChangeTicket_externalTicketStatus = args.get('accessChangeTicket_externalTicketStatus')
    accessChangeTicket_status = args.get('accessChangeTicket_status')
    accessChangeTicket_title = args.get('accessChangeTicket_title')
    accessChangeTicket_changeDetails = args.get('accessChangeTicket_changeDetails')
    accessChangeTicket_priority = args.get('accessChangeTicket_priority')
    accessChangeTicket_owner = args.get('accessChangeTicket_owner')
    accessChangeTicket_dueDate = args.get('accessChangeTicket_dueDate')
    accessChangeTicket_doneDate = args.get('accessChangeTicket_doneDate')
    accessChangeTicket_likelihood = args.get('accessChangeTicket_likelihood')
    accessChangeTicket_ccList_email = args.get('accessChangeTicket_ccList_email')
    accessChangeTicket_ccList_userName = args.get('accessChangeTicket_ccList_userName')
    accessChangeTicket_customFields_comment = args.get('accessChangeTicket_customFields_comment')
    accessChangeTicket_customFields_createdBy = args.get('accessChangeTicket_customFields_createdBy')
    accessChangeTicket_customFields_creationTime = args.get('accessChangeTicket_customFields_creationTime')
    accessChangeTicket_customFields_description = args.get('accessChangeTicket_customFields_description')
    accessChangeTicket_customFields_id = args.get('accessChangeTicket_customFields_id')
    accessChangeTicket_customFields_lastModificationTime = args.get(
        'accessChangeTicket_customFields_lastModificationTime')
    accessChangeTicket_customFields_lastModifiedBy = args.get('accessChangeTicket_customFields_lastModifiedBy')
    accessChangeTicket_customFields_name = args.get('accessChangeTicket_customFields_name')
    accessChangeTicket_customFields_typeCode = args.get('accessChangeTicket_customFields_typeCode')
    accessChangeTicket_customFields_value = args.get('accessChangeTicket_customFields_value')
    accessChangeTicket_currentPhaseName = args.get('accessChangeTicket_currentPhaseName')

    customField_type = client.get_type('ns0:customField')
    customField = customField_type(
        comment=accessChangeTicket_customFields_comment,
        createdBy=accessChangeTicket_customFields_createdBy,
        creationTime=accessChangeTicket_customFields_creationTime,
        description=accessChangeTicket_customFields_description,
        id=accessChangeTicket_customFields_id,
        lastModificationTime=accessChangeTicket_customFields_lastModificationTime,
        lastModifiedBy=accessChangeTicket_customFields_lastModifiedBy,
        name=accessChangeTicket_customFields_name,
        typeCode=accessChangeTicket_customFields_typeCode,
        value=accessChangeTicket_customFields_value
    )

    emailRecipient_type = client.get_type('ns0:emailRecipient')
    emailRecipient = emailRecipient_type(
        email=accessChangeTicket_ccList_email,
        userName=accessChangeTicket_ccList_userName
    )

    accessChangeTicket_type = client.get_type('ns0:accessChangeTicket')
    accessChangeTicket = accessChangeTicket_type(
        id=accessChangeTicket_id,
        status=accessChangeTicket_status,
        likelihood=accessChangeTicket_likelihood,
        priority=accessChangeTicket_priority,
        title=accessChangeTicket_title,
        comment=accessChangeTicket_comment,
        externalTicketId=accessChangeTicket_externalTicketId,
        externalTicketStatus=accessChangeTicket_externalTicketStatus,
        changeDetails=accessChangeTicket_changeDetails,
        owner=accessChangeTicket_owner,
        description=accessChangeTicket_description,
        ccList=[emailRecipient],
        # customFields=[customField],
        createdBy=accessChangeTicket_createdBy,
        creationTime=accessChangeTicket_creationTime,
        lastModifiedBy=accessChangeTicket_lastModifiedBy,
        lastModificationTime=accessChangeTicket_lastModificationTime,
        dueDate=accessChangeTicket_dueDate,
        doneDate=accessChangeTicket_doneDate,
        currentPhaseName=accessChangeTicket_currentPhaseName
    )

    response = client.service.createChangeManagerTicket(
        accessChangeTicket=accessChangeTicket,
    )

    command_results = CommandResults(
        outputs_prefix='Skybox.updateAccessChangeTicket',
        outputs_key_field='',
        outputs=serialize_object_dict(response),
        raw_response=serialize_object_dict(response)
    )

    return command_results


def addDerivedChangeRequests_command(client, args):
    ticketId = args.get('ticketId')
    changeRequestId = args.get('changeRequestId')
    firewalls_accessRules = args.get('firewalls_accessRules')
    firewalls_id = args.get('firewalls_id')
    firewalls_interfaces = args.get('firewalls_interfaces')
    firewalls_name = args.get('firewalls_name')
    firewalls_netInterface_description = args.get('firewalls_netInterface_description')
    firewalls_netInterface_id = args.get('firewalls_netInterface_id')
    firewalls_netInterface_ipAddress = args.get('firewalls_netInterface_ipAddress')
    firewalls_netInterface_name = args.get('firewalls_netInterface_name')
    firewalls_netInterface_type = args.get('firewalls_netInterface_type')
    firewalls_netInterface_zoneName = args.get('firewalls_netInterface_zoneName')
    firewalls_netInterface_zoneType = args.get('firewalls_netInterface_zoneType')
    firewalls_os = args.get('firewalls_os')
    firewalls_osVendor = args.get('firewalls_osVendor')
    firewalls_osVersion = args.get('firewalls_osVersion')
    firewalls_primaryIp = args.get('firewalls_primaryIp')
    firewalls_routingRules = args.get('firewalls_routingRules')
    firewalls_services = args.get('firewalls_services')
    firewalls_status = args.get('firewalls_status')
    firewalls_type_var = args.get('firewalls_type')
    firewalls_vulnerabilities = args.get('firewalls_vulnerabilities')

    netInterface_type = client.get_type('ns0:netInterfaceElement')
    netInterface = netInterface_type(
        description=firewalls_netInterface_description,
        id=firewalls_netInterface_id,
        ipAddress=firewalls_netInterface_ipAddress,
        name=firewalls_netInterface_name,
        type=firewalls_netInterface_type,
        zoneName=firewalls_netInterface_zoneName,
        zoneType=firewalls_netInterface_zoneType
    )

    firewalls_type = client.get_type('ns0:asset')
    firewalls = firewalls_type(
        accessRules=firewalls_accessRules,
        id=firewalls_id,
        interfaces=firewalls_interfaces,
        name=firewalls_name,
        os=firewalls_os,
        osVendor=firewalls_osVendor,
        osVersion=firewalls_osVersion,
        primaryIp=firewalls_primaryIp,
        routingRules=firewalls_routingRules,
        services=firewalls_services,
        status=firewalls_status,
        type=firewalls_type_var,
        vulnerabilities=firewalls_vulnerabilities,
        netInterface=netInterface
    )

    response = client.service.addDerivedChangeRequests(
        ticketId=ticketId,
        changeRequestId=changeRequestId,
        firewalls=firewalls
    )

    command_results = CommandResults(
        outputs_prefix='Skybox.addDerivedChangeRequests',
        outputs_key_field='',
        outputs=serialize_object_dict(response),
        raw_response=serialize_object_dict(response)
    )

    return command_results


def getPolicyViolations_command(client, args):
    ticketId = args.get('ticketId')
    changeRequestId = args.get('changeRequestId')

    response = client.service.getPolicyViolations(ticketId, changeRequestId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getPolicyViolations',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def removeAttachmentFile_command(client, args):
    attachmentId = args.get('attachmentId')

    response = client.service.removeAttachmentFile(attachmentId)
    command_results = CommandResults(
        outputs_prefix='Skybox.removeAttachmentFile',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getTicketWorkflows_command(client, args):

    response = client.service.getTicketWorkflows()
    command_results = CommandResults(
        outputs_prefix='Skybox.getTicketWorkflows',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def recalculateTicketChangeRequests_command(client, args):
    ticketId = args.get('ticketId')

    response = client.service.recalculateTicketChangeRequests(ticketId)
    command_results = CommandResults(
        outputs_prefix='Skybox.recalculateTicketChangeRequests',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findConfigurationItems_command(client, args):
    filter_ancestorOf = args.get('filter_ancestorOf')
    filter_childrenOf = args.get('filter_childrenOf')
    filter_configurationItemTypes = args.get('filter_configurationItemTypes')
    filter_freeTextFilter = args.get('filter_freeTextFilter')
    filter_ids = args.get('filter_ids')
    filter_ignoreEmptyGroups = args.get('filter_ignoreEmptyGroups')
    filter_isEnabled = args.get('filter_isEnabled')
    filter_nameFilter = args.get('filter_nameFilter')
    subRange_size = args.get('subRange_size')
    subRange_start = args.get('subRange_start')

    filter_type = client.get_type('ns0:configurationItemFilter')
    filter = filter_type(
        ancestorOf=filter_ancestorOf,
        childrenOf=filter_childrenOf,
        configurationItemTypes=filter_configurationItemTypes,
        freeTextFilter=filter_freeTextFilter,
        ids=filter_ids,
        ignoreEmptyGroups=filter_ignoreEmptyGroups,
        isEnabled=filter_isEnabled,
        nameFilter=filter_nameFilter
    )

    subRange_type = client.get_type('ns0:subRange')
    subRange = subRange_type(
        size=subRange_size,
        start=subRange_start
    )

    response = client.service.findConfigurationItems(filter, subRange)

    command_results = CommandResults(
        outputs_prefix='Skybox.findConfigurationItems',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getSponsoringApplication_command(client, args):
    ticketId = args.get('ticketId')

    response = client.service.getSponsoringApplication(ticketId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getSponsoringApplication',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def addOriginalChangeRequestsV7_command(client, args):
    ticketId = args.get('ticketId')
    changeRequests_comment = args.get('changeRequests_comment')
    changeRequests_complianceStatus = args.get('changeRequests_complianceStatus')
    changeRequests_createdBy = args.get('changeRequests_createdBy')
    changeRequests_creationTime = args.get('changeRequests_creationTime')
    changeRequests_description = args.get('changeRequests_description')
    changeRequests_id = args.get('changeRequests_id')
    changeRequests_isRequiredStatus = args.get('changeRequests_isRequiredStatus')
    changeRequests_lastModificationTime = args.get('changeRequests_lastModificationTime')
    changeRequests_lastModifiedBy = args.get('changeRequests_lastModifiedBy')
    changeRequests_messages_args = args.get('changeRequests_messages_args')
    changeRequests_messages_formatedMessage = args.get('changeRequests_messages_formatedMessage')
    changeRequests_messages_key = args.get('changeRequests_messages_key')
    changeRequests_messages_level = args.get('changeRequests_messages_level')
    changeRequests_originalChangeRequestId = args.get('changeRequests_originalChangeRequestId')
    changeRequests_verificationStatus = args.get('changeRequests_verificationStatus')

    messages_type = client.get_type('ns0:changeRequestMessage')
    messages = messages_type(
        args=changeRequests_messages_args,
        formatedMessage=changeRequests_messages_formatedMessage,
        key=changeRequests_messages_key,
        level=changeRequests_messages_level,
    )

    changeRequests_type = client.get_type('ns0:changeRequestV3')
    changeRequests = changeRequests_type(
        comment=changeRequests_comment,
        complianceStatus=changeRequests_complianceStatus,
        createdBy=changeRequests_createdBy,
        creationTime=changeRequests_creationTime,
        description=changeRequests_description,
        id=changeRequests_id,
        isRequiredStatus=changeRequests_isRequiredStatus,
        lastModificationTime=changeRequests_lastModificationTime,
        lastModifiedBy=changeRequests_lastModifiedBy,
        originalChangeRequestId=changeRequests_originalChangeRequestId,
        verificationStatus=changeRequests_verificationStatus,
        messages=messages
    )

    response = client.service.addOriginalChangeRequestsV7(ticketId, [changeRequests])

    command_results = CommandResults(
        outputs_prefix='Skybox.addOriginalChangeRequestsV7',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def createTicketAccessRequestsForObjectChange_command(client, args):
    ticketId = args.get('ticketId')
    hostId = args.get('hostId')
    objectName = args.get('objectName')
    changeType = args.get('changeType')
    addressChange = args.get('addressChange')
    portChange = args.get('portChange')
    maxAccessRequestsToCreate = args.get('maxAccessRequestsToCreate')
    chainFilterMode = args.get('chainFilterMode')
    chainNames = args.get('chainNames')

    response = client.service.createTicketAccessRequestsForObjectChange(
        ticketId, hostId, objectName, changeType, addressChange, portChange,
        maxAccessRequestsToCreate, chainFilterMode, chainNames)

    command_results = CommandResults(
        outputs_prefix='Skybox.createTicketAccessRequestsForObjectChange',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getDerivedChangeRequestRouteInfoV1_command(client, args):
    ticketId = args.get('ticketId')
    changeRequestId = args.get('changeRequestId')

    response = client.service.getDerivedChangeRequestRouteInfoV1(ticketId, changeRequestId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getDerivedChangeRequestRouteInfoV1',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def implementChangeRequests_command(client, args):
    changeRequests_id = args.get('changeRequests_id')
    changeRequests_ticketId = args.get('changeRequests_ticketId')
    changeRequests_dueDate = args.get('changeRequests_dueDate')
    changeRequests_ticketPriority = args.get('changeRequests_ticketPriority')
    changeRequests_changeType = args.get('changeRequests_changeType')
    changeRequests_firewallName = args.get('changeRequests_firewallName')
    changeRequests_firewallManagementName = args.get('changeRequests_firewallManagementName')
    changeRequests_globalUniqueId = args.get('changeRequests_globalUniqueId')
    changeRequests_changeDetails = args.get('changeRequests_changeDetails')
    changeRequests_additionalDetails = args.get('changeRequests_additionalDetails')
    changeRequests_isRequiredStatus = args.get('changeRequests_isRequiredStatus')
    changeRequests_owner = args.get('changeRequests_owner')
    changeRequests_completeStatus = args.get('changeRequests_completeStatus')
    changeRequests_completeDate = args.get('changeRequests_completeDate')
    changeRequests_workflowName = args.get('changeRequests_workflowName')
    changeRequests_comment = args.get('changeRequests_comment')
    changeRequests_lastModificationTime = args.get('changeRequests_lastModificationTime')
    changeRequests_implementationStatus = args.get('changeRequests_implementationStatus')
    comment = args.get('comment')

    changeRequests_type = client.get_type('ns0:changeRequestImplementation')
    changeRequests = changeRequests_type(
        id=changeRequests_id,
        ticketId=changeRequests_ticketId,
        dueDate=changeRequests_dueDate,
        ticketPriority=changeRequests_ticketPriority,
        changeType=changeRequests_changeType,
        firewallName=changeRequests_firewallName,
        firewallManagementName=changeRequests_firewallManagementName,
        globalUniqueId=changeRequests_globalUniqueId,
        changeDetails=changeRequests_changeDetails,
        additionalDetails=changeRequests_additionalDetails,
        isRequiredStatus=changeRequests_isRequiredStatus,
        owner=changeRequests_owner,
        completeStatus=changeRequests_completeStatus,
        completeDate=changeRequests_completeDate,
        workflowName=changeRequests_workflowName,
        comment=changeRequests_comment,
        lastModificationTime=changeRequests_lastModificationTime,
        implementationStatus=changeRequests_implementationStatus
    )

    response = client.service.implementChangeRequests(changeRequests, comment)

    command_results = CommandResults(
        outputs_prefix='Skybox.implementChangeRequests',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getAnalysisTree_command(client, args):
    type_ = args.get('type')

    response = client.service.getAnalysisTree(type_)
    command_results = CommandResults(
        outputs_prefix='Skybox.getAnalysisTree',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def operateOnAccessChangeTicket_command(client, args):
    ticketId = args.get('ticketId')
    phaseOperation_phaseId = args.get('phaseOperation_phaseId')
    phaseOperation_phaseOwner = args.get('phaseOperation_phaseOwner')
    phaseOperation_reject = args.get('phaseOperation_reject')
    phaseOperation_type_var = args.get('phaseOperation_type')

    phaseOperation_type = client.get_type('ns0:phaseOperation')
    phaseOperation = phaseOperation_type(
        phaseId=phaseOperation_phaseId,
        phaseOwner=phaseOperation_phaseOwner,
        reject=phaseOperation_reject,
        type=phaseOperation_type_var
    )

    response = client.service.operateOnAccessChangeTicket(ticketId, phaseOperation)

    command_results = CommandResults(
        outputs_prefix='Skybox.operateOnAccessChangeTicket',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def analyzeAccessChangeTicket_command(client, args):
    ticketId = args.get('ticketId')
    accessRequests = args.get('accessRequests')
    mode = args.get('mode')

    response = client.service.analyzeAccessChangeTicket(ticketId, accessRequests, mode)
    command_results = CommandResults(
        outputs_prefix='Skybox.analyzeAccessChangeTicket',
        outputs_key_field='',
        outputs=serialize_object_dict(response),
        raw_response=serialize_object_dict(response)
    )

    return command_results


def getVerificationDetails_command(client, args):
    ticketId = args.get('ticketId')
    changeRequestId = args.get('changeRequestId')

    response = client.service.getVerificationDetails(ticketId, changeRequestId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getVerificationDetails',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getTicketPhases_command(client, args):
    ticketId = args.get('ticketId')

    response = client.service.getTicketPhases(ticketId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getTicketPhases',
        outputs_key_field='',
        outputs=serialize_object_list(response),
        raw_response=serialize_object_list(response)
    )

    return command_results


def findTickets_command(client, args):
    analysis_id = args.get('analysis_id')
    analysis_name = args.get('analysis_name')
    analysis_path = args.get('analysis_path')
    analysis_type_var = args.get('analysis_type')
    subRange_size = args.get('subRange_size')
    subRange_start = args.get('subRange_start')

    analysis_type = client.get_type('ns0:analysis')
    analysis = analysis_type(
        id=analysis_id,
        name=analysis_name,
        path=analysis_path,
        type=analysis_type_var
    )

    subRange_type = client.get_type('ns0:subRange')
    subRange = subRange_type(
        size=subRange_size,
        start=subRange_start
    )

    response = client.service.findTickets(analysis, subRange)

    command_results = CommandResults(
        outputs_prefix='Skybox.findTickets',
        outputs_key_field='',
        outputs=serialize_object_list(response),
        raw_response=serialize_object_list(response)
    )

    return command_results


def setChangeRequestRuleAttributes_command(client, args):
    ticketId = args.get('ticketId')
    changeRequestId = args.get('changeRequestId')
    ruleAttributes_businessFunction = args.get('ruleAttributes_businessFunction')
    ruleAttributes_comment = args.get('ruleAttributes_comment')
    ruleAttributes_customFields_defId = args.get('ruleAttributes_customFields_defId')
    ruleAttributes_customFields_entityType = args.get('ruleAttributes_customFields_entityType')
    ruleAttributes_customFields_id = args.get('ruleAttributes_customFields_id')
    ruleAttributes_customFields_name = args.get('ruleAttributes_customFields_name')
    ruleAttributes_customFields_value = args.get('ruleAttributes_customFields_value')
    ruleAttributes_email = args.get('ruleAttributes_email')
    ruleAttributes_nextReviewDate = args.get('ruleAttributes_nextReviewDate')
    ruleAttributes_owner = args.get('ruleAttributes_owner')
    ruleAttributes_status = args.get('ruleAttributes_status')
    ruleAttributes_ticketId = args.get('ruleAttributes_ticketId')

    customFields_type = client.get_type('ns0:entityField')
    customFields = customFields_type(
        defId=ruleAttributes_customFields_defId,
        entityType=ruleAttributes_customFields_entityType,
        id=ruleAttributes_customFields_id,
        name=ruleAttributes_customFields_name,
        value=ruleAttributes_customFields_value,
    )

    ruleAttributes_type = client.get_type('ns0:ruleAttributes')
    ruleAttributes = ruleAttributes_type(
        businessFunction=ruleAttributes_businessFunction,
        comment=ruleAttributes_comment,
        customFields=customFields,
        email=ruleAttributes_email,
        nextReviewDate=ruleAttributes_nextReviewDate,
        owner=ruleAttributes_owner,
        status=ruleAttributes_status,
        ticketId=ruleAttributes_ticketId
    )

    response = client.service.setChangeRequestRuleAttributes(ticketId, changeRequestId, ruleAttributes)
    command_results = CommandResults(
        outputs_prefix='Skybox.setChangeRequestRuleAttributes',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getAttachmentList_command(client, args):
    ticketId = args.get('ticketId')

    response = client.service.getAttachmentList(ticketId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getAttachmentList',
        outputs_key_field='',
        readable_output=tableToMarkdown("Attachement List", serialize_object_list(response), headers=['id', 'filename', 'description']),
        outputs=serialize_object_list(response),
        raw_response=serialize_object_list(response)
    )

    return command_results


def setAddRuleChangeRequestFields_command(client, args):
    ticketId = args.get('ticketId')
    changeRequestId = args.get('changeRequestId')
    fields = json.loads(args.get('fields'))

    response = client.service.setAddRuleChangeRequestFields(ticketId, changeRequestId, fields)

    command_results = CommandResults(
        outputs_prefix='Skybox.setAddRuleChangeRequestFields',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def setTicketPhases_command(client, args):
    ticketId = args.get('ticketId')
    phases_comment = args.get('phases_comment')
    phases_createdBy = args.get('phases_createdBy')
    phases_creationTime = args.get('phases_creationTime')
    phases_current = args.get('phases_current')
    phases_demotionsCount = args.get('phases_demotionsCount')
    phases_description = args.get('phases_description')
    phases_dueDate = args.get('phases_dueDate')
    phases_endDate = args.get('phases_endDate')
    phases_id = args.get('phases_id')
    phases_lastModificationTime = args.get('phases_lastModificationTime')
    phases_lastModifiedBy = args.get('phases_lastModifiedBy')
    phases_owner = args.get('phases_owner')
    phases_revisedDueDate = args.get('phases_revisedDueDate')
    phases_startDate = args.get('phases_startDate')
    phases_ticketTypePhase_defaultOwner = args.get('phases_ticketTypePhase_defaultOwner')
    phases_ticketTypePhase_id = args.get('phases_ticketTypePhase_id')
    phases_ticketTypePhase_name = args.get('phases_ticketTypePhase_name')
    phases_ticketTypePhase_order = args.get('phases_ticketTypePhase_order')
    phases_ticketTypePhase_ticketType = args.get('phases_ticketTypePhase_ticketType')
    phases_ticketTypePhase_waitingForClosure = args.get('phases_ticketTypePhase_waitingForClosure')
    phaseOperation_phaseId = args.get('phaseOperation_phaseId')
    phaseOperation_phaseOwner = args.get('phaseOperation_phaseOwner')
    phaseOperation_reject = args.get('phaseOperation_reject')
    phaseOperation_type_var = args.get('phaseOperation_type')

    ticketTypePhase_type = client.get_type('ns0:ticketTypePhase')
    ticketTypePhase = ticketTypePhase_type(
        defaultOwner=phases_ticketTypePhase_defaultOwner,
        id=phases_ticketTypePhase_id,
        name=phases_ticketTypePhase_name,
        order=phases_ticketTypePhase_order,
        ticketType=phases_ticketTypePhase_ticketType,
        waitingForClosure=phases_ticketTypePhase_waitingForClosure
    )

    phases_type = client.get_type('ns0:phase')
    phases = phases_type(
        comment=phases_comment,
        createdBy=phases_createdBy,
        creationTime=phases_creationTime,
        current=phases_current,
        demotionsCount=phases_demotionsCount,
        description=phases_description,
        dueDate=phases_dueDate,
        endDate=phases_endDate,
        id=phases_id,
        lastModificationTime=phases_lastModificationTime,
        lastModifiedBy=phases_lastModifiedBy,
        owner=phases_owner,
        revisedDueDate=phases_revisedDueDate,
        startDate=phases_startDate,
        ticketTypePhase=ticketTypePhase
    )

    phaseOperation_type = client.get_type('ns0:phaseOperation')
    phaseOperation = phaseOperation_type(
        phaseId=phaseOperation_phaseId,
        phaseOwner=phaseOperation_phaseOwner,
        reject=phaseOperation_reject,
        type=phaseOperation_type_var
    )

    response = client.service.setTicketPhases(ticketId, phases, phaseOperation)

    command_results = CommandResults(
        outputs_prefix='Skybox.setTicketPhases',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getTicketAccessRequests_command(client, args):
    ticketId = args.get('ticketId')

    response = client.service.getTicketAccessRequests(ticketId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getTicketAccessRequests',
        outputs_key_field='',
        outputs=serialize_object_list(response),
        raw_response=serialize_object_list(response)
    )

    return command_results


def testService_command(client, args):
    anyValue = args.get('anyValue')

    response = str(client.service.testService(anyValue))

    command_results = CommandResults(
        outputs_prefix='Skybox.testService',
        outputs_key_field='',
        outputs=response,
        raw_response=response,
        readable_output=response
    )

    return command_results


def setRecertificationStatus_command(client, args):
    ticketId = args.get('ticketId')
    changeRequestIds = args.get('changeRequestIds')
    ruleAttributes_businessFunction = args.get('ruleAttributes_businessFunction')
    ruleAttributes_comment = args.get('ruleAttributes_comment')
    ruleAttributes_customFields_dataType = args.get('ruleAttributes_customFields_dataType')
    ruleAttributes_customFields_defId = args.get('ruleAttributes_customFields_defId')
    ruleAttributes_customFields_entityType = args.get('ruleAttributes_customFields_entityType')
    ruleAttributes_customFields_id = args.get('ruleAttributes_customFields_id')
    ruleAttributes_customFields_name = args.get('ruleAttributes_customFields_name')
    ruleAttributes_customFields_value = args.get('ruleAttributes_customFields_value')
    ruleAttributes_email = args.get('ruleAttributes_email')
    ruleAttributes_nextReviewDate = args.get('ruleAttributes_nextReviewDate')
    ruleAttributes_owner = args.get('ruleAttributes_owner')
    ruleAttributes_status = args.get('ruleAttributes_status')
    ruleAttributes_ticketId = args.get('ruleAttributes_ticketId')

    customFields_type = client.get_type('ns0:entityField')
    customFields = customFields_type(
        dataType=ruleAttributes_customFields_dataType,
        defId=ruleAttributes_customFields_defId,
        entityType=ruleAttributes_customFields_entityType,
        id=ruleAttributes_customFields_id,
        name=ruleAttributes_customFields_name,
        value=ruleAttributes_customFields_value,
    )

    ruleAttributes_type = client.get_type('ns0:ruleAttributes')
    ruleAttributes = ruleAttributes_type(
        businessFunction=ruleAttributes_businessFunction,
        comment=ruleAttributes_comment,
        #customFields=customFields,
        email=ruleAttributes_email,
        nextReviewDate=ruleAttributes_nextReviewDate,
        owner=ruleAttributes_owner,
        status=ruleAttributes_status,
        ticketId=ruleAttributes_ticketId
    )

    response = client.service.setRecertificationStatus(ticketId, changeRequestIds, ruleAttributes)

    command_results = CommandResults(
        outputs_prefix='Skybox.setRecertificationStatus',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def setTicketDeferChangeRequestsCalculationStatus_command(client, args):
    ticketId = args.get('ticketId')
    deferChangeRequestsCalculation = args.get('deferChangeRequestsCalculation')

    response = client.service.setTicketDeferChangeRequestsCalculationStatus(ticketId, deferChangeRequestsCalculation)
    command_results = CommandResults(
        outputs_prefix='Skybox.setTicketDeferChangeRequestsCalculationStatus',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def setSponsoringApplication_command(client, args):
    ticketId = args.get('ticketId')
    sponsoringApplicationId = args.get('sponsoringApplicationId')

    response = client.service.setSponsoringApplication(ticketId, sponsoringApplicationId)
    command_results = CommandResults(
        outputs_prefix='Skybox.setSponsoringApplication',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def findAccessChangeTickets_command(client, args):
    filter_createdBy = args.get('filter_createdBy')
    filter_freeTextFilter = args.get('filter_freeTextFilter')
    filter_modifiedBy = args.get('filter_modifiedBy')
    filter_myGroups = args.get('filter_myGroups')
    filter_owner = args.get('filter_owner')
    filter_phaseName = args.get('filter_phaseName')
    filter_statusFilter = args.get('filter_statusFilter')
    filter_ticketIdsFilter = args.get('filter_ticketIdsFilter')
    subRange_size = args.get('subRange_size')
    subRange_start = args.get('subRange_start')

    filter_type = client.get_type('ns0:filter')
    filter = filter_type(
        createdBy=filter_createdBy,
        freeTextFilter=filter_freeTextFilter,
        modifiedBy=filter_modifiedBy,
        myGroups=filter_myGroups,
        owner=filter_owner,
        phaseName=filter_phaseName,
        statusFilter=filter_statusFilter,
        ticketIdsFilter=filter_ticketIdsFilter,
    )

    subRange_type = client.get_type('ns0:subRange')
    subRange = subRange_type(
        size=subRange_size,
        start=subRange_start
    )

    response = client.service.findAccessChangeTickets(filter, subRange)

    command_results = CommandResults(
        outputs_prefix='Skybox.findAccessChangeTickets',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getTicketFields_command(client, args):
    ticketId = args.get('ticketId')
    ticketIdType = args.get('ticketIdType')

    response = client.service.getTicketFields(ticketId, ticketIdType)
    command_results = CommandResults(
        outputs_prefix='Skybox.getTicketFields',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getTicketsImplementedChangeRequests_command(client, args):
    ticketIds = args.get('ticketIds')

    response = client.service.getTicketsImplementedChangeRequests(ticketIds)
    command_results = CommandResults(
        outputs_prefix='Skybox.getTicketsImplementedChangeRequests',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getTicketDeferChangeRequestsCalculationStatus_command(client, args):
    ticketId = args.get('ticketId')

    response = client.service.getTicketDeferChangeRequestsCalculationStatus(ticketId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getTicketDeferChangeRequestsCalculationStatus',
        outputs_key_field='',
        outputs=helpers.serialize_object(response),
        raw_response=helpers.serialize_object(response)
    )

    return command_results


def getPotentialVulnerabilities_command(client, args):
    ticketId = args.get('ticketId')
    changeRequestId = args.get('changeRequestId')

    response = client.service.getPotentialVulnerabilities(ticketId, changeRequestId)
    command_results = CommandResults(
        outputs_prefix='Skybox.getPotentialVulnerabilities',
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
    params = demisto.params()
    args = demisto.args()
    url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    wsdl = url + "/skybox/webservice/jaxws/tickets?wsdl"

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
            'skybox-getTicketWorkflow': getTicketWorkflow_command,
            'skybox-getOriginalChangeRequestRouteInfoV1': getOriginalChangeRequestRouteInfoV1_command,
            'skybox-getTicketTypePhasesByTicketType': getTicketTypePhasesByTicketType_command,
            'skybox-getOriginalChangeRequestV7': getOriginalChangeRequestV7_command,
            'skybox-setTicketFields': setTicketFields_command,
            'skybox-createAccessChangeTicket': createAccessChangeTicket_command,
            'skybox-getAttachmentFile': getAttachmentFile_command,
            'skybox-createRecertifyTicketV2': createRecertifyTicketV2_command,
            'skybox-getAccessChangeTicket': getAccessChangeTicket_command,
            'skybox-getAccessRequests': getAccessRequests_command,
            'skybox-getPotentialVulnerabilitiesV2': getPotentialVulnerabilitiesV2_command,
            'skybox-deleteChangeRequests': deleteChangeRequests_command,
            'skybox-deleteAccessChangeTicket': deleteAccessChangeTicket_command,
            'skybox-getNotImplementedChangeRequestsV2': getNotImplementedChangeRequestsV2_command,
            'skybox-getTicketEvents': getTicketEvents_command,
            'skybox-getChangeRequestReviewers': getChangeRequestReviewers_command,
            'skybox-getChangeRequestRuleAttributes': getChangeRequestRuleAttributes_command,
            'skybox-getGeneratedCommands': getGeneratedCommands_command,
            'skybox-getImplementedChangeRequests': getImplementedChangeRequests_command,
            'skybox-operateOnVulnerabilityDefinitionTicket': operateOnVulnerabilityDefinitionTicket_command,
            'skybox-createChangeManagerTicket': createChangeManagerTicket_command,
            'skybox-getTicketsNotImplementedChangeRequestsV2': getTicketsNotImplementedChangeRequestsV2_command,
            'skybox-findAccessRequests': findAccessRequests_command,
            'skybox-expandFirewallsForAccessChangeTicket': expandFirewallsForAccessChangeTicket_command,
            'skybox-addAttachmentFile': addAttachmentFile_command,
            'skybox-countAccessChangeTickets': countAccessChangeTickets_command,
            'skybox-getDerivedChangeRequestsV7': getDerivedChangeRequestsV7_command,
            'skybox-setTicketAccessRequests': setTicketAccessRequests_command,
            'skybox-updateAccessChangeTicket': updateAccessChangeTicket_command,
            'skybox-addDerivedChangeRequests': addDerivedChangeRequests_command,
            'skybox-getPolicyViolations': getPolicyViolations_command,
            'skybox-removeAttachmentFile': removeAttachmentFile_command,
            'skybox-getTicketWorkflows': getTicketWorkflows_command,
            'skybox-recalculateTicketChangeRequests': recalculateTicketChangeRequests_command,
            'skybox-findConfigurationItems': findConfigurationItems_command,
            'skybox-getSponsoringApplication': getSponsoringApplication_command,
            'skybox-addOriginalChangeRequestsV7': addOriginalChangeRequestsV7_command,
            'skybox-createTicketAccessRequestsForObjectChange': createTicketAccessRequestsForObjectChange_command,
            'skybox-getDerivedChangeRequestRouteInfoV1': getDerivedChangeRequestRouteInfoV1_command,
            'skybox-implementChangeRequests': implementChangeRequests_command,
            'skybox-getAnalysisTree': getAnalysisTree_command,
            'skybox-operateOnAccessChangeTicket': operateOnAccessChangeTicket_command,
            'skybox-analyzeAccessChangeTicket': analyzeAccessChangeTicket_command,
            'skybox-getVerificationDetails': getVerificationDetails_command,
            'skybox-getTicketPhases': getTicketPhases_command,
            'skybox-findTickets': findTickets_command,
            'skybox-setChangeRequestRuleAttributes': setChangeRequestRuleAttributes_command,
            'skybox-getAttachmentList': getAttachmentList_command,
            'skybox-setAddRuleChangeRequestFields': setAddRuleChangeRequestFields_command,
            'skybox-setTicketPhases': setTicketPhases_command,
            'skybox-getTicketAccessRequests': getTicketAccessRequests_command,
            'skybox-testService': testService_command,
            'skybox-setRecertificationStatus': setRecertificationStatus_command,
            'skybox-setTicketDeferChangeRequestsCalculationStatus': setTicketDeferChangeRequestsCalculationStatus_command,
            'skybox-setSponsoringApplication': setSponsoringApplication_command,
            'skybox-findAccessChangeTickets': findAccessChangeTickets_command,
            'skybox-getTicketFields': getTicketFields_command,
            'skybox-getTicketsImplementedChangeRequests': getTicketsImplementedChangeRequests_command,
            'skybox-getTicketDeferChangeRequestsCalculationStatus': getTicketDeferChangeRequestsCalculationStatus_command,
            'skybox-getPotentialVulnerabilities': getPotentialVulnerabilities_command,
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
