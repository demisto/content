import glob
import json
import os
from typing import List, Dict, Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def parse_arcsight_xml(filepath) -> List[Dict[str, Any]]:
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


def get_incidents_from_xmls(dir: str) -> List[Dict[str, Any]]:
    """
    Parse all XMLs in specified directory as incidents
    """
    filepaths = glob.glob(os.path.join(dir, '*.xml'))
    incidents = []
    for filepath in filepaths:
        incidents += parse_arcsight_xml(filepath)

    return incidents


def create_xml(time: str, id: str, name: str, stage: str):
    """
    Returns the contents of the XML to be written to the fs
    """
    uri = name
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE archive SYSTEM "../../schema/xml/archive/arcsight-archive.dtd">
<archive buildVersion="6.9.1.2195.0" buildTime="2-9-2016_19:0:8" createTime="{time}">
    <ArchiveCreationParameters>
        <action>insert</action>
        <format>xml.external.case</format>
        <include>
            <list>
                <ref type="Case" uri="{uri}" id="{id}"/>
            </list>
        </include>
    </ArchiveCreationParameters>
    <Case id="{id}" name="{name}" action="insert" >
        <stage>{stage}</stage>
    </Case>
</archive>"""


def create_file_locally(cmds_dir, id, name, stage, time: str = time.strftime('%m-%d-%Y_%H-%M-%S.000')):
    """
    Creates the XML file in the container fs
    """
    filepath = os.path.join(cmds_dir, f"ExternalEventTrackingData_{time}.xml")
    data = create_xml(time, id, name, stage)

    demisto.debug(f"Writing data to file '{filepath}'...")
    demisto.debug(f"Data:\n\t\t{data}")
    with open(filepath, 'w') as f:
        f.write(data)


def update_case(id: str, name: str, stage: str, cmds_dir: str) -> CommandResults:
    """
    Creates an XML containing a case update request
    Args:
        - `id` (`str`): The ID of the case
        - `name` (`str`): The name of the case
        - `stage` (`str`): The stage of the case
        - `cmd_dir` (`str`): Where to save the XML
    Outputs:
        - `CommandResults`
    """
    create_file_locally(cmds_dir, id, name, stage)
    return CommandResults(readable_output=f"Updated case {id} to stage {stage}.")


def is_dir_exists(dir: str) -> bool:
    return os.path.isdir(dir)


def main():  # pragma: no cover

    args = demisto.args()
    params = demisto.params()

    try:
        if demisto.command() == 'test-module':
            return_results('ok')

        elif demisto.command() == 'fetch-incidents' or demisto.command() == 'arcsight-fetch-xml':

            input_dir = params.get("inputDirPath")
            if not is_dir_exists(input_dir):
                raise FileNotFoundError(f"{input_dir}: No such file or directory")

            incidents = get_incidents_from_xmls(input_dir)
            demisto.incidents(incidents)

        elif demisto.command() == 'arcsight-update-case':

            cmds_dir = params.get("commandsDirPath")
            if not is_dir_exists(cmds_dir):
                raise FileNotFoundError(f"{cmds_dir}: No such file or directory")

            case_id: str = args.get("caseId")
            name: str = args.get('name')
            stage: str = args.get('stage')
            cmd_res = update_case(case_id, name, stage, cmds_dir)

        return_results(cmd_res)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
