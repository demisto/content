import json
from copy import deepcopy
from datetime import datetime
import requests
from requests.exceptions import HTTPError
from CommonServerPython import *

''' GLOBAL VARIABLES '''
SERVER = demisto.params()['url']
CREDENTIALS = demisto.params().get('credentials')
USERNAME = CREDENTIALS['identifier'] if CREDENTIALS else ''
PASSWORD = CREDENTIALS['password'] if CREDENTIALS else ''
APP_ID = demisto.params()['appID']
USE_SSL = not demisto.params().get('insecure', True) == 'True'

handle_proxy()

''' ID -> Label maps for Oceane '''

TYPE_TYPE_ENUM = {
    '1': 'Failure',
    '2': 'Assistance',
    '3': 'Installation',
    '4': 'Maintenance',
    '5': 'Parametrization',
    '6': 'Other',
    '8': 'Information request',
    '9': 'Scheduled maintenance',
    '10': 'Long period assistance',
    '12': 'Production',
    '14': 'Contradictory expertise',
    '15': 'QS Alert',
    '16': 'Problem',
    '17': 'Problem Notification',
    '18': 'Work order',
    '19': 'Alarm',
    '20': 'Crisis',
    '21': 'Critical failure',
    '22': 'External Failure info',
    '23': 'Customer complaint',
    '24': 'Service degradation',
    '25': 'Permanent alarm',
    '26': 'Management CONF&DB',
    '27': 'Problem Verification',
    '28': 'Neutral expertise',
    '29': 'User support',
    '30': 'Incident User',
    '31': 'User settings',
    '32': 'User installation',
    '33': 'Recurrent Problem',
    '34': 'Reason for Outage',
    '35': 'Data Trouble Ticket',
    '36': 'Measurements',
    '37': 'Emergency Report',
    '38': 'Trouble Report',
    '39': 'Failure Results & Risk Repair',
    '40': 'Failure VIP sites',
    '41': 'SAV+',
    '42': 'SAV+ PC',
    '43': 'Diagnostic',
    '44': 'SAV+ Contradictoire',
    '45': 'Technical',
    '46': 'Property',
    '47': 'SAV+ Contradictoire PC',
    '48': 'disruptive',
    '49': 'Fut interne',
    '50': 'Fut externe',
    '51': 'PC Informations',
    '52': 'Anomaly',
    '53': 'Activation',
    '54': 'Suspension',
    '55': 'Request Fulfillment',
    '56': 'Security',
    '57': 'Notification noticed Incident',
    '58': 'SAV+ GTR4H',
    '59': 'SAV+ Contradictory GTR4H',
    '60': 'Customer trouble ticket',
    '62': 'Recurrent',
    '63': 'Faults',
    '64': 'Event',
    '65': 'Ano Missing mandatory field',
    '66': 'Ano Pos file not corresponding',
    '67': 'Ano Delivery missing',
    '68': 'Ano Delivery mgt agent missing',
    '69': 'Ano Pb adress',
    '70': 'Ano Pb Number of housing',
    '71': 'Ano Pb Ref PM',
    '72': 'Chronic',
    '73': 'Action Plan',
    '74': 'Incident Report',
    '75': 'VIP Customer\'s complaint',
    '76': '4G customer\'s complaint',
    '77': 'Company\'s complaint',
    '78': 'request for information',
    '79': 'Incident Identification',
    '80': 'Incident Souscription',
    '81': 'Production access',
    '82': 'Production service'
}

SEVERITY_TYPE_ENUM = {
    '1': 'Minor',
    '2': 'Major',
    '3': 'Blocking',
    '4': 'Blocking/Major',
    '5': 'Major/Minor',
    '6': 'Failure severity 1',
    '7': 'Failure severity 2',
    '8': 'Failure severity 3',
    '9': 'Failure severity 4'
}

CRITICITY_TYPE_ENUM = {
    '2': 'Interrupted service',
    '3': 'No interference',
    '6': 'Isolated customer site',
    '7': 'Corrupted service',
    '8': 'Working backup',
    '11': 'To be Qualified',
    '12': 'Voice-Not calling-Movistar',
    '13': 'Voice-Not calling-Vodafone',
    '14': 'Voice-Not calling-Orange',
    '15': 'Voice-Not calling-All',
    '16': 'Voice-Not calling- (indicate)',
    '17': 'Voice-Not receiving-Movistar',
    '18': 'Voice-Not receiving-Vodafone',
    '19': 'Voice-Not receiving-Orange',
    '20': 'Voice-Not receiving-All',
    '21': 'Voice-Not receive- (indicate)',
    '22': 'Voice-Not call/receive-Movist',
    '23': 'Voice-Not call/receive-Vodafon',
    '24': 'Voice-Not call/receive-Orange',
    '25': 'Voice-Not call/receive-Only112',
    '26': 'Voice-Not call/receive-Others',
    '27': 'Voice-Congestion/retries',
    '28': 'Voice-Call drop',
    '29': 'Voice-Line switch',
    '30': 'Data-No connection 2G/GPRS',
    '31': 'Data-No connection 3G/UMTS',
    '32': 'Data-No connection 3G/HSDPA',
    '33': 'Data-No connection 2G and 3G',
    '34': ' Data-Connection OK, Navigatio',
    '35': 'Data-Conn OK Navig KO 2G/GPRS',
    '36': 'Data-Conn OK Navig KO 3G/UMTS',
    '37': 'Data-Conn OK Navig KO 3G/HSDPA',
    '38': 'Data-Conn OK Navig KO 2G + 3G',
    '39': 'Data-connection drop 2G/GPRS',
    '40': 'Data-connection drop 3G/UMTS',
    '41': 'Data-connection drop 3G/HSDPA',
    '42': 'Data-connection drop 2G and 3G',
    '43': ' Voice/Data-no serv some techn',
    '44': 'Voice/Data-no coverage 2G/GPR',
    '45': 'Voice/Data-no coverage 3G/UMT',
    '46': 'Voice/Data-no coverag 3G/HSDPA',
    '47': 'Voice/Data-no coverage 2G + 3G',
    '48': 'Services',
    '49': 'Mobile service not affected',
    '50': 'Data-slow navigation 2G/GPRS',
    '51': 'Data-slow navigation 3G/UMTS',
    '52': 'Data-slow navigation 3G/HSDPA',
    '53': 'Data-slow navigation 2G and 3G',
    '54': 'Voice/Data-no coverage 2G/GPRS',
    '55': 'Voice/Data-no coverage 3G/UMTS',
    '56': 'Datos-Conecta,no naveg-4G',
    '57': 'Datos-Cortes en-4G',
    '58': 'Datos-Navega lento en-4G',
    '59': 'Datos-Sin cobertura 4G',
    '60': 'Retardos emisión/recep 4G',
    '61': 'Voz-No llama/No recibe 4G',
    '62': 'Voz-No llama/No recibe-WIFI',
    '63': 'Retardos emisión/recep WIFI',
}

PRIORITY_TYPE_ENUM = {
    '0': 'P0',
    '1': 'P1',
    '2': 'P2',
    '3': 'P3',
    '4': 'P4',
    '5': 'P5',
    '6': 'P6'
}

ORIGIN_TYPE_ENUM = {
    '1': 'Customer',
    '2': 'Supervision',
    '3': 'Internal',
    '4': 'Other',
    '5': 'Carrier',
    '6': 'User',
    '7': 'Partners',
    '8': 'Proactive',
    '9': 'Reactive',
    'A': 'Audit',
    'B': 'SMC',
    'C': 'Quality Analysis',
    'D': 'Customer GP (General Public)',
    'E': 'Customer PRO (Professional)',
    'F': 'NetWorkS',
    'G': 'Commercial',
    'H': 'Self-care',
    'I': 'GAQ',
    'J': 'Incident',
    'K': 'Reporting ',
    'L': 'TMC',
    'M': 'IOBSP Vendor',
    'N': 'Non-IOBSP Vendor',
    'O': 'ELITE'
}

URGENCY_TYPE_ENUM = {
    '0': 'NULL',
    '1': 'Immediate intervention',
    '2': 'Deferred Intervention',
    '3': '(State of) Emergency',
    '4': 'No intervention',
    '5': '-',
    '6': '1',
    '7': '2',
    '8': '3',
    '9': '4',
    '10': 'Class 1',
    '11': 'Class 2',
    '12': 'Class 3',
    '13': 'Premium program'
}

CATEGORY_TYPE_ENUM = {
    '0': 'Isolated customer site',
    '1': 'Interrupted service',
    '2': 'Corrupted service',
    '3': 'Request for information',
    '4': 'Working backup',
    '5': 'No interference',
    '6': 'freeze incident',
    '7': 'Isolated customer(s)',
    '8': 'Total breakdown',
    '9': 'Inaccessible route/destination',
    '10': 'Incoherence SI',
    '11': 'Grouping problem',
    '12': 'Failling map',
    '13': 'Number of flat',
    '14': 'Interrupted resource',
    '15': 'Degraded resource',
    '16': 'CR MAD',
    '17': 'PLANMAD',
    '18': 'IPE',
    '19': 'PM non mutualisable',
    '20': 'STAS',
    '21': 'Not corresponding connecting',
    '22': 'Refusal Management agent',
    '23': 'Refusal co-owners',
    '24': 'Pb access privative parts',
    '25': 'Change of management agent',
    '26': 'Dégats, Fault',
    '27': 'Financial compensation',
    '28': 'Problem block OC',
    '29': 'Problem piece joined',
    '30': 'INCOH RGPT',
    '31': 'Error',
    '32': 'Circuit failure',
    '33': 'Loss of supervision',
    '34': 'Polling failure',
    '35': 'Site isolation',
    '36': 'NNI failure Interconnection',
    '37': 'Country isolation',
    '38': 'High RTD on circuit',
    '39': 'Packet Loss',
    '40': 'Security',
    '41': 'Hardware replacement',
    '42': 'Remote software operations',
    '43': 'Client failure',
    '44': 'Local SW operations',
    '45': 'Parameters changed',
    '46': 'Solution changed',
    '47': 'AR Order unit rent',
    '48': 'Fiber constraint',
    '49': 'Mail of Kindness',
    '50': 'CR MAD',
    '51': 'Busy dedicated fiber',
    '52': 'Position file',
    '53': 'Flow CR info management agent',
    '54': 'IPE',
    '55': 'IPE and CR MAD',
    '56': 'MAD Plan',
    '57': 'Several impacted supports',
    '58': 'Not corresponding PM',
    '59': 'Rising column or PM missing',
    '60': 'PM or fiber HS or inaccessible',
    '61': 'Refusal of Mutualization',
    '62': 'PTO',
    '63': 'CONNECTING LANDING',
    '64': 'PBO',
    '65': 'RISING COLUMN',
    '66': 'CRAWLING COLUMN',
    '67': 'PM',
    '68': 'HORIZONTAL NETWORK',
    '69': 'Wiring problem Access',
    '70': 'Wiring problem PM',
    '71': 'Wiring problem PB',
    '72': 'circuit unstable',
    '73': 'PM-PBO',
    '74': 'Planned Outage',
    '75': 'Unplanned Outage',
    '76': 'Unplanned Outage caused by PW',
    '77': 'No service affected',
    '78': 'Planned Outage',
    '79': 'Unplanned Outage',
    '80': 'Unplanned Outage caused by PW',
    '81': 'No service affected',
    '82': 'Degradations',
    '83': 'Various',
    '84': 'Not applicable',
    '85': 'POST PROD ORT',
    '86': 'Security',
    'A': 'Downgrading equipment',
    'B': 'No interference',
    'C': 'Corrupted service',
    'D': 'Other',
    'E': 'Interrupted service',
    'F': 'Voice Stop/Visio',
    'G': 'Data Stop',
    'H': 'Counting anomaly',
    'I': 'To be Qualified',
    'J': 'To be Qualified',
    'K': 'Major corrupted service',
    'L': 'Anomaly detected',
    'M': 'No Traffic',
    'N': 'Equipment failure',
    'O': 'Node isolated',
    'P': 'Anomaly detected',
    'Q': 'No Traffic',
    'R': 'Equipment failure',
    'S': 'Node isolated',
    'T': 'Change operations fault',
    'U': 'Change parameters fault',
    'V': 'FNI impact',
    'W': 'Software failure',
    'X': 'PM to move',
    'Y': 'Access problem',
    'Z': 'Piping problem'
}

NOTE_COMMENT_TYPE_ENUM = {
    'CLT': 'Customer',
    'ENT': 'Group',
    'INT': 'Internal',
    'SYS': 'System'
}

NOTE_OPERATION_TYPE_ENUM = {
    '1': 'Inward customer comments',
    '2': 'Outward customer comments',
    '3': 'Local customer call back',
    '4': 'Organization contact',
    '5': 'Tests and measurements',
    '6': 'Diagnosis',
    '7': 'Appointment',
    '8': 'Escalation',
    '9': 'Comments',
    '10': 'Restoration',
    '11': 'Closure',
    '12': 'Restitution',
    '13': 'Freeze/unfreeze',
    '14': 'Freeze/unfreeze Request',
    '15': 'Activation',
    '16': 'Transfer refusal',
    '17': 'IRLT/CRLT',
    '18': 'Affected technician',
    '19': 'Technician on site',
    '20': 'Add file attachment',
    '21': 'TIC contact',
    '22': 'Alert',
    '23': 'Intervention',
    '24': 'Decrease Bonus',
    '25': 'Get Assignment',
    '26': 'Acknowledge Assignment',
    '27': 'Assign',
    '28': 'To be Allocated',
    '29': 'Never Allocated',
    '30': 'Assignment End',
    '31': 'Assignment Error',
    '32': 'Over planned restor. reminder',
    '33': 'Synthesis ticket',
    '35': 'End of intervention',
    '36': 'Tests and measurement',
    '37': 'Undertaking',
    '38': 'Follow-up',
    '39': 'Information request',
    '40': 'Information',
    '41': 'Threshold crossed',
    '42': 'CRM Closure',
    '43': 'End of alarm',
    '44': 'Genergy comments',
    '45': 'Notification',
    '46': 'Pilot Problem Comments',
    '47': 'Selected Unit',
    '48': 'Affected',
    '49': 'Communicated',
    '50': 'Closed',
    '51': 'Cancelled',
    '52': 'Cancellation requested',
    '53': 'Current',
    '54': 'Sent',
    '55': 'IR in error',
    '56': 'Monitoring Mode',
    '57': 'Answer to Customer',
    '58': 'Description updated',
    '60': 'Follow-up intervention',
    '61': 'Transmitted intervention',
    '62': 'Declarative form',
    '63': 'Transfer request',
    '64': 'Transfer acceptance',
    '65': 'Alarm association',
    '66': 'End of alarm association',
    '67': 'Last ONETM Status',
    '68': 'Supplier transfer',
    '69': 'Problem root cause',
    '70': 'Request of meeting',
    '71': 'Modification of meeting',
    '72': 'ESCALATION E MAIL',
    '73': 'Cust first Tech Resp',
    '74': 'Customer Status',
    '75': 'Cust given ETA',
    '76': 'Cust given RFO ',
    '77': 'Telco status',
    '78': 'Acknowledge',
    '79': 'Choice of resolution',
    '80': 'Chronic',
    '81': 'Crisis bridge',
    '82': 'Remote assistance',
    '83': 'Workaround',
    '84': 'ENO-ORO-Parameters',
    '85': 'Operator relationship',
    '86': 'First technical information',
    '87': 'Partner engagement',
    '88': 'Cancel appointment requested'
}

PROBLEM_DETAIL_TYPE_ENUM = {
    '10005590': 'Forensic - Analysis request',
    '10005591': 'Forensic - Information request',
    '10005592': 'Forensic - Duplicate',
    '10005596': 'DDOS - Anomaly with impact',
    '10005597': 'DDOS - Anomaly without impact',
    '10005598': 'DDOS - False positive Orange responsibility',
    '10005599': 'DDOS - False positive customer responsibility',
    '10005600': 'DDOS - Analysis request',
    '10005601': 'DDOS - Information request',
    '10005602': 'DDOS - Duplicate',
    '10005610': 'IPS - Anomaly with impact',
    '10005611': 'IPS - Anomaly without impact',
    '10005612': 'IPS - False positive Orange responsibility',
    '10005613': 'IPS - False positive customer responsibility',
    '10005614': 'IPS - Information request',
    '10005615': 'IPS - Duplicate',
    '10005622': 'SIEM - Incident with impact',
    '10005623': 'SIEM - Incident without impact',
    '10005624': 'SIEM - False positive with improvement',
    '10005625': 'SIEM - False positive',
    '10005626': 'SIEM - Analysis request',
    '10005627': 'SIEM - Information request',
    '10005628': 'SIEM - Duplicate',
    '10005636': 'VOC - Emergency scan',
    '10005637': 'VOC - Vulnerability detected',
    '10005638': 'VOC - False positive',
    '10005639': 'VOC - Analysis request',
    '10005640': 'VOC - Information request',
    '10005641': 'VOC - Duplicate'
}


def get_enum_label(enum, id):
    if id not in enum:
        return 'INTEGRATION: Unrecognized enum value (' + id + ').'
    return enum[id]


def get_enum_id(enum, label):
    for id, value in enum.items():
        if value == label:
            return id
    return 'INTEGRATION: Unrecognized enum key (' + label + ').'


def now():
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')


class Ticket:
    def __init__(self):
        args = demisto.args()
        self.body = {}
        if 'externalId' in args:
            self.body['externalId'] = args['externalId']
        if 'description' in args:
            self.body['description'] = args['description']
        if 'severity' in args:
            self.body['severity'] = {'id': get_enum_id(SEVERITY_TYPE_ENUM, args['severity'])}
        if 'ticketType' in args:
            self.body['ticketType'] = {'id': get_enum_id(TYPE_TYPE_ENUM, args['ticketType'])}
        if 'customerTicketId' in args:
            self.body['customerTicketId'] = args['customerTicketId']
        if 'criticity' in args:
            self.body['criticity'] = {'id': get_enum_id(CRITICITY_TYPE_ENUM, args['criticity'])}
        if 'priority' in args:
            self.body['priority'] = {'id': get_enum_id(PRIORITY_TYPE_ENUM, args['priority'])}
        if 'origin' in args:
            self.body['originId'] = {'id': get_enum_id(ORIGIN_TYPE_ENUM, args['origin'])}
        if 'urgency' in args:
            self.body['urgencyId'] = {'id': get_enum_id(URGENCY_TYPE_ENUM, args['urgency'])}
        if 'supervisionTool' in args:
            self.body['supervisionTool'] = args['supervisionTool']
        if 'category' in args:
            self.body['category'] = {'id': get_enum_id(CATEGORY_TYPE_ENUM, args['category'])}
        # if 'detectionDateTime' in args:
        # ??????????????
        if 'targetRestorationDateTime' in args:
            self.body['targetRestorationDateTime'] = args['targetRestorationDateTime']
        if 'plannedRestorationDateTime' in args:
            self.body['plannedRestorationDateTime'] = args['plannedRestorationDateTime']

    def set_status(self, status):
        self.body['status'] = status

    def set_note(self, note):
        self.body['note'] = note

    def set_related_service(self, related_service):
        self.body['relatedService'] = related_service

    def set_related_party(self, related_party):
        self.body['relatedParty'] = [related_party]

    def set_attachment(self, attachment):
        self.body['attachment'] = [attachment]

    def set_related_object(self, related_object):
        self.body['relatedObject'] = [related_object]

    def set_trouble_cause(self, trouble_cause):
        self.body['troubleCause'] = [trouble_cause]

    def json(self):
        clone = deepcopy(self.body)
        return json.dump(clone, separators=(',', ':'))


def create_status_object():
    args = demisto.args()
    status = {
        'code': args['status'],
        'isCurrentStatus': args.get('isCurrent', True) == 'True',
        'startDateTime': args.get('startTime', now())
    }
    if 'reason' in args:
        status['reason'] = args['reason']
    return status


def create_note_object():
    args = demisto.args()
    note = {
        'recordingDate': args.get('commentRecordingDate', args.get('recordingDate'), now())
    }
    if 'commentAuthor' in args or 'author' in args:
        note['author'] = args.get('commentAuthor', args['author'])
    if 'commentGroupId' in args or 'groupId' in args:
        note['groupId'] = args.get('commentGroupId', args['groupId'])
    if 'commentText' in args or 'text' in args:
        note['text'] = args.get('commentText', args['text'])
    if 'commentType' in args:
        note['commentType'] = {'id': get_enum_id(NOTE_COMMENT_TYPE_ENUM, args['commentType'])}
    if 'commentOperationType' in args or 'operationType' in args:
        note['operationType'] = {
            'id': get_enum_id(NOTE_OPERATION_TYPE_ENUM, args.get('commentOperationType', args['operationType']))
        }
    return note


def create_related_service_object():
    related_service = {}
    if 'id' in demisto.args() or 'relatedServiceId' in demisto.args():
        related_service['id'] = demisto.args().get('id', demisto.args()['relatedServiceId'])
    return related_service


def create_related_party_object():
    related_party = {}
    if 'id' in demisto.args():
        related_party['id'] = demisto.args()['id']
    if 'role' in demisto.args():
        related_party['role'] = demisto.args()['role']
    return related_party


def create_attachment_object():
    args = demisto.args()
    attachment = {}
    if 'attachmentId' in args:
        attachment['id'] = args['attachmentId']
    if 'attachmentLabel' in args:
        attachment['label'] = args['attachmentLabel']
    if 'attachmentType' in args:
        attachment['type'] = args['attachmentType']
    if 'attachmentUrl' in args:
        attachment['url'] = args['attachmentUrl']
    return attachment


def create_related_object_object():
    related_object = {}
    if 'involvement' in demisto.args():
        related_object['involvement'] = demisto.args()['involvement']
    if 'reference' in demisto.args():
        related_object['reference'] = demisto.args()['reference']
    return related_object


def create_trouble_cause_object():
    trouble_cause_object = {}
    if 'problemDetails' in demisto.args():
        trouble_cause_object.problemDetail = {
            'id': get_enum_id(PROBLEM_DETAIL_TYPE_ENUM, demisto.args()['problemDetails'])
        }
    if 'problemCategory' in demisto.args():
        trouble_cause_object['problemCategory'] = {
            id: get_enum_id(CATEGORY_TYPE_ENUM, demisto.args()['problemCategory'])
        }
    return trouble_cause_object


def send_request(method, path, body=None):
    # Validate required parameters
    if body is None:
        body = {}
    if USERNAME == '' or PASSWORD == '':
        raise Exception('Invalid credentials')
    if SERVER == '':
        raise Exception('Invalid server URL')
    if 'userId' not in demisto.args() or demisto.args()['userId'] == '':
        raise Exception('Invalid Oceane user ID')
    if APP_ID == '':
        raise Exception('Invalid application ID')

    # Extract parameters
    user_id = demisto.args()['user_id']
    request_url = SERVER + path
    headers = {
        'X-OAPI-User-Id': [user_id],
        'X-OAPI-Application-Id': [APP_ID]
    }
    if method == 'PUT':
        headers['X-HTTP-Method-Override'] = ['PATCH']

    try:
        # Make the request to the service
        res = requests.request(method, request_url, data=body, headers=headers, auth=(USERNAME, PASSWORD),
                               verify=USE_SSL)
    except HTTPError:
        err = 'Request Failed.'
        if res:
            err += ' Status Code: {0}. Body: {1}.'.format(res.status_code, res.json())
        raise Exception(err)

    return res.json()


def build_response(object, title, headers):
    def capitalize_fields(obj):
        if isinstance(obj, list):
            objs = []
            for value in obj:
                objs += capitalize_fields(value)
            return objs
        obj = deepcopy(obj)
        for key in obj.keys():
            # Capitalize the whole Id field.
            if key == 'id':
                obj['ID'] = obj.pop(key)
            else:
                capitalized = key.capitalize
                if key != capitalized:
                    obj[capitalized] = obj.pop(key)
        return obj

    def translate_enums(obj, new_field_prefix=''):
        if isinstance(obj, list):
            if isinstance(obj, list):
                objs = []
                for value in obj:
                    objs += translate_enums(value, new_field_prefix)
                return objs
        obj = deepcopy(obj)
        for key, value in obj:
            fieldName = key + new_field_prefix
            lc_key = key.lower()
            if lc_key is 'severity':
                obj[fieldName] = get_enum_label(SEVERITY_TYPE_ENUM, value)
            elif lc_key is 'type':
                obj[fieldName] = get_enum_label(TYPE_TYPE_ENUM, value)
            elif lc_key is 'criticity':
                obj[fieldName] = get_enum_label(CRITICITY_TYPE_ENUM, value)
            elif lc_key is 'originid':
                obj[fieldName] = get_enum_label(ORIGIN_TYPE_ENUM, value)
            elif lc_key is 'urgencyid':
                obj[fieldName] = get_enum_label(URGENCY_TYPE_ENUM, value)
            elif lc_key is 'category':
                obj[fieldName] = get_enum_label(CATEGORY_TYPE_ENUM, value)
            elif lc_key is 'priority':
                obj[fieldName] = get_enum_label(PRIORITY_TYPE_ENUM, value)
            elif lc_key is 'operationtype':
                obj[fieldName] = get_enum_label(NOTE_OPERATION_TYPE_ENUM, value)
            elif lc_key is 'commenttypeid':
                obj[fieldName] = get_enum_label(NOTE_COMMENT_TYPE_ENUM, value)
        return obj

    def build_entry_context(obj):
        obj = deepcopy(obj)
        obj = capitalize_fields(obj)
        obj = translate_enums(obj, 'Name')
        return obj

    def build_human_readable(obj, title, headers):
        obj = deepcopy(obj)
        if not obj:
            return 'No results'
        obj = capitalize_fields(obj)
        obj = translate_enums(obj)

        if isinstance(obj, list):
            return tblToMd(title, obj)
        else:
            text = '### ' + title + '\n\n'

            # Print general fields
            if not headers or 'General' in headers:
                text += '#### General\n'
                general_fields = [
                    'ID',
                    'CorrelationId',
                    'Type',
                    'Severity',
                    'UrgencyId',
                    'Priority',
                    'CreationDateTime',
                    'DetectionDateTime',
                    'Category',
                    'OriginId',
                    'SupervisionTool'
                ]
                text += tblToMd('', obj, general_fields) + '\n\n'

            # Print related service
            if not headers or 'Related service' in headers:
                text += '#### Related service\n'
                related_service = {}
                if 'RelatedService' in obj and 'serviceSpecCharacteristic' in obj['RelatedService']:
                    for spec in obj['RelatedService']['serviceSpecCharacteristic']:
                        if 'id' not in spec:
                            continue
                        lc_id = spec['id'].lower()
                        if lc_id is 'csuid':
                            related_service['CSUID'] = spec.get('value', 'N/A')
                        elif lc_id is 'csuname':
                            related_service['CSU Name'] = spec.get('value', 'N/A')
                        elif lc_id is 'srchkey':
                            related_service['Search Key'] = spec.get('value', 'N/A')
                text += tblToMd('', related_service, [
                    'CSUID',
                    'CSU Name',
                    'Search Key'
                ])

            # Print status
            if not headers or 'Status' in headers:
                text += '#### Status\n'
                status = obj['Status']
                status = capitalize_fields(status)
                text += tblToMd('', status)

            # Print related party
            if not headers or 'Related party' in headers:
                text += '#### Related party\n'
                related_party = obj['RelatedParty']
                related_party = capitalize_fields(related_party)
                text += tblToMd('', related_party)

            # Print notes
            if not headers or 'Notes' in headers:
                text += '#### Notes\n'
                notes = obj['Note']
                notes = capitalize_fields(notes)
                notes = translate_enums(notes)
                text += tblToMd('', notes)

            return text

    if headers:
        headers = headers.split(',')

    return {
        'Type': entryTypes['note'],
        'Contents': object,
        'ContentsFormat': formats['json'],
        'EntryContext': {
            'Oceane.Ticket(val.ID==obj.ID)': build_entry_context(object)
        },
        'HumanReadable': build_human_readable(object, title, headers)
    }


def test_module():
    try:
        send_request('GET', '', '');
    except Exception as err:
        if 'Trouble Ticket ID must be provided' in str(err):
            return True
        return err
    return False


def command_create_ticket():
    ticket = Ticket()
    if 'status' in demisto.args():
        ticket.set_status(create_status_object())
    if 'relatedServiceId' in demisto.args():
        ticket.set_related_service(create_related_service_object())
    res = send_request('POST', '/', ticket.json())
    return build_response(res, 'Oceane create ticket', demisto.args().get('headers'))


def command_create_ticket_raw():
    res = send_request('POST', '/', demisto.args().get('payload'))
    return build_response(res, 'Oceane create ticket', demisto.args().get('headers'))


def command_update_ticket():
    ticket = Ticket()
    if 'status' in demisto.args():
        ticket.set_status(create_status_object())
    if 'relatedServiceId' in demisto.args():
        ticket.set_related_service(create_related_service_object())
    res = send_request('PUT', '/' + demisto.args().get('ticketId'), ticket.json())
    return build_response(res, 'Oceane update ticket', demisto.args().get('headers'))


def command_update_ticket_raw():
    res = send_request('PUT', '/' + demisto.args().get('ticketId'), demisto.args().get('payload'))
    return build_response(res, 'Oceane update ticket', demisto.args().get('headers'))


def command_update_ticket_status():
    ticket = Ticket()
    ticket.set_status(create_status_object())
    ticket.set_trouble_cause(create_trouble_cause_object())
    ticket.set_note(create_note_object())
    res = send_request('PUT', '/' + demisto.args().get('ticketId'), ticket.json())
    return build_response(res, 'Oceane update ticket status', demisto.args().get('headers'))


def command_add_ticket_comment():
    ticket = Ticket()
    ticket.set_note(create_note_object())
    res = send_request('PUT', '/' + demisto.args().get('ticketId'), ticket.json())
    return build_response(res, 'Oceane add ticket comment', demisto.args().get('headers'))


def command_add_ticket_attachment():
    ticket = Ticket()
    ticket.set_attachment(create_attachment_object())
    res = send_request('PUT', '/' + demisto.args().get('ticketId'), ticket.json())
    return build_response(res, 'Oceane add ticket attachment', demisto.args().get('headers'))


def command_get_ticket():
    res = send_request('GET', '/' + demisto.args().get('ticketId'))
    return build_response(res, 'Oceane get ticket', demisto.args().get('headers'))


def command_search_tickets():
    params = []
    if 'resultsOffset' in demisto.args():
        params.append('offset=' + demisto.args().get('resultsOffset'))
    if 'resultsLimit' in demisto.args():
        params.append('limit=' + demisto.args().get('resultsLimit'))
    query = '?' + '&'.join(params) if len(params) else ''
    res = send_request('POST', '/search' + query, demisto.args().get('payload'))
    return build_response(res, 'Oceane search tickets', demisto.args().get('headers'))


def command_add_ticket_related_object():
    ticket = Ticket()
    ticket.set_related_object(create_related_object_object())
    res = send_request('PUT', '/' + demisto.args().get('ticketId'), ticket.json())
    return build_response(res, 'Oceane add ticket related object', demisto.args().get('headers'))


def command_add_ticket_related_party():
    ticket = Ticket()
    ticket.set_related_party(create_related_party_object())
    res = send_request('PUT', '/' + demisto.args().get('ticketId'), ticket.json())
    return build_response(res, 'Oceane add ticket related party', demisto.args().get('headers'))


if demisto.command() is 'test-module':
    demisto.results(test_module())
elif demisto.command() is 'oceane-create-ticket':
    demisto.results(command_create_ticket())
elif demisto.command() is 'oceane-update-ticket':
    demisto.results(command_update_ticket())
elif demisto.command() is 'oceane-update-ticket-status':
    demisto.results(command_update_ticket_status())
elif demisto.command() is 'oceane-add-ticket-comment':
    demisto.results(command_add_ticket_comment())
elif demisto.command() is 'oceane-add-ticket-attachment':
    demisto.results(command_add_ticket_attachment())
elif demisto.command() is 'oceane-add-ticket-relatedobject':
    demisto.results(command_add_ticket_related_object())
elif demisto.command() is 'oceane-add-ticket-relatedparty':
    demisto.results(command_add_ticket_related_party())
elif demisto.command() is 'oceane-get-ticket':
    demisto.results(command_get_ticket())
