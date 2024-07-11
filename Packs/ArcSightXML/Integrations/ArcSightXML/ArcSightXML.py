import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import os
import glob
import datetime
import json


SECURITY_EVENT_START_TAG = '<SecurityEvent id="%s"'
SECURITY_EVENT_END_TAG = '</SecurityEvent>'

LIST_CASE_ENTRIES = ['caseEvents', 'childOf', 'ownedBy']
TIME_CASE_ENTRIES = ['detectionTime', 'estimatedStartTime']

SYSTEM = ''
URI_PREFIX = ''
TOREPLACE = '\\"\\<\\>\\(\\)'

XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE archive SYSTEM "../../schema/xml/archive/arcsight-archive.dtd">
<archive buildVersion="6.9.1.2195.0" buildTime="2-9-2016_19:0:8" createTime="{0}">
    <ArchiveCreationParameters>
        <action>insert</action>
        <format>xml.external.case</format>
        <include>
            <list>
                <ref type="Case" uri="{2}" id="{1}"/>
            </list>
        </include>
    </ArchiveCreationParameters>
    <Case id="{1}" name="{3}" action="insert" >
        <stage>{4}</stage>
    </Case>
</archive>"""

FILENAME_TEMPLATE = 'ExternalEventTrackingData_{0}.xml'


def ref_to_dict(item):
    return {'type': item.get('type'), 'uri': item.get('uri'), 'id': item.get('id')}


def build_case_data(case):
    case_data = {case_child.tag: case_child.text for case_child in case}

    # fix timestamp entries
    for name in TIME_CASE_ENTRIES:
        if name in case_data:
            case_data[name] = str(datetime.datetime.fromtimestamp(int(case_data[name]) / 1000))

    # fix list entries
    for name in LIST_CASE_ENTRIES:
        list_entry = case.find(name)
        if list_entry is not None:
            case_data[name] = json.dumps([ref_to_dict(item) for item in list_entry[0]])

    # convert to a list of 'type' and 'value'
    case_data = [{'type': key, 'value': value} for key, value in case_data.iteritems()]

    return case_data


def parse_arcsight_xml(filepath):
    with open(filepath, 'rb') as f:
        xml_content = f.read()

    root_json = json.loads(xml2json(xml_content))
    archive_cases = root_json.get('archive', {}).get('Case')
    if archive_cases is not None and not isinstance(archive_cases, list):
        archive_cases = [archive_cases]

    cases = root_json.get('Case')
    if cases is not None and not isinstance(cases, list):
        cases = [cases]

    all_cases = []
    if cases:
        all_cases = cases
    if archive_cases:
        all_cases = archive_cases + all_cases

    archive_security_events = root_json.get('archive', {}).get('SecurityEvent')
    if archive_security_events is not None and not isinstance(archive_security_events, list):
        archive_security_events = [archive_security_events]

    security_events = root_json.get('SecurityEvent')
    if security_events is not None and not isinstance(security_events, list):
        security_events = [security_events]

    all_security_events = []
    if security_events:
        all_security_events = security_events
    if archive_security_events:
        all_security_events = archive_security_events + all_security_events

    incidents = []
    for case in all_cases:
        case_event_ids = demisto.dt(case, 'caseEvents.list.ref.@id')
        case_events = []

        for security_event in all_security_events:
            event_id = security_event.get('@id')
            if event_id in case_event_ids:
                case_events.append(security_event)

        incident = {
            'name': '#{} - {}'.format(case.get('@id'), case.get('@name')),
            'details': json.dumps(case_events, indent=4),
            'rawJSON': json.dumps(case)
        }
        incidents.append(incident)

    os.remove(filepath)

    return incidents


def get_incidents_from_xmls():
    filepaths = glob.glob(os.path.join(demisto.params()['inputDirPath'], '*.xml'))
    incidents = []
    for filepath in filepaths:
        incidents += parse_arcsight_xml(filepath)

    return incidents


def create_file_locally(data, filepath):
    with open(filepath, 'w') as f:
        f.write(data)


def update_case():
    case_id = demisto.args()['caseId']
    name = demisto.args()['name']
    stage = demisto.args()['stage']
    uri = URI_PREFIX + demisto.args()['name']
    now = time.strftime('%m-%d-%Y_%H-%M-%S.000')

    filename = FILENAME_TEMPLATE.format(now)
    filepath = os.path.join(demisto.params()['commandsDirPath'], filename)
    data = XML_TEMPLATE.format(now, case_id, uri, name, stage)

    create_file_locally(data, filepath)

    demisto.results('Modified stage to %s in case %s.' % (stage, case_id))


if demisto.command() == 'test-module':
    demisto.results('ok')
    sys.exit(0)

elif demisto.command() == 'fetch-incidents' or demisto.command() == 'arcsight-fetch-xml':
    incidents = get_incidents_from_xmls()
    demisto.incidents(incidents)
    sys.exit(0)

elif demisto.command() == 'arcsight-update-case':
    update_case()
