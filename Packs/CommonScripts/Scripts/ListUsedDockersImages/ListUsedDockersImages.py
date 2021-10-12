"""ListUsedDockerImages Script for Cortex XSOAR (aka Demisto)

This is a script that lists all the docker images used by installed integrations and/or automations.


"""

import demistomock as demisto
from CommonServerPython import *

import traceback
import json

'''REST API HTTP COMMANDS'''
POST_COMMAND = "POST"

'''REST API CALL BODY'''
REQUEST_INTEGRATION_SEARCH_BODY = "{\"size\":500}"

'''REST API HTTP ENTRY POINTS'''
SETTING_INTEGRATION_SEARCH = "/settings/integration/search"
AUTOMATION_SEARCH = "/automation/search"

'''Constants used to filter out the result'''
CONFIGURATIONS = 'configurations'
INTEGRATION_SCRIPT = 'integrationScript'

PYTHON_SCRIPT = 'python'
POWERSHELL_SCRIPT = 'powershell'

INTEGRATION_SCRIPT_TYPE = 'type'
INTEGRATION_ID = 'id'

DOCKER_IMAGE = 'dockerImage'
DEFAULT_DOCKER_IMAGE = 'Default Docker Image'

SCRIPT_TYPE = 'type'
SCRIPT_ID = 'id'
SCRIPTS = 'scripts'

MAX_PER_DOCKER = 5


''' STANDALONE FUNCTION '''


def extract_dockers_from_integration_search_result(content: str) -> dict:
    """Returns a simple python dict of used dockerImages by integration

    :type content: ``str``
    :param content: string representation for the /settings/integrations/search API result response

    :return: dict as {"integration_id":"dockername"}
    :rtype: ``dict``

    """
    json_content = json.loads(content)
    dockers = {}
    for conf in json_content[CONFIGURATIONS]:
        if (INTEGRATION_SCRIPT not in conf) or (conf[INTEGRATION_SCRIPT] is None):
            continue
        else:
            if INTEGRATION_SCRIPT_TYPE in conf[INTEGRATION_SCRIPT] and conf[INTEGRATION_SCRIPT][SCRIPT_TYPE] in (
                    PYTHON_SCRIPT, POWERSHELL_SCRIPT):
                if DOCKER_IMAGE not in conf[INTEGRATION_SCRIPT] or conf[INTEGRATION_SCRIPT][DOCKER_IMAGE] in (None, ''):
                    docker_image = 'Default Image Name'
                else:
                    docker_image = conf[INTEGRATION_SCRIPT][DOCKER_IMAGE]
                dockers[conf[INTEGRATION_ID]] = docker_image
    return dockers


def extract_dockers_from_automation_search_result(content: str) -> dict:
    """Returns a simple python dict of used dockerImages by automations

    :type content: ``str``
    :param content: string representation for the /automation/search API result response

    :return: dict as {"integration_id":"dockername"}
    :rtype: dict

    """
    json_content = json.loads(content)
    dockers = {}
    for script in json_content[SCRIPTS]:
        if (SCRIPT_TYPE not in script) or \
                ((script[SCRIPT_TYPE] != PYTHON_SCRIPT) and (script[SCRIPT_TYPE] != POWERSHELL_SCRIPT)):
            continue
        else:
            if DOCKER_IMAGE in script and script[DOCKER_IMAGE] in (None, ''):
                docker_image = 'Default Image Name'
            else:
                docker_image = script[DOCKER_IMAGE]
            dockers[script[SCRIPT_ID]] = docker_image

    return dockers


def merge_result(docker_list: dict, result_dict: dict = {}, max_entries_per_docker: int = 5) -> dict:
    """Returns a python dict of the merge result

    :type docker_list: ``dict``
    :param docker_list: dictionary representation for the docker image used by integration or script

    :type result_dict: ``dict``
    :param result_dict: dictionary representation for the docker image and the integration/scripts belongs to it
                       merge the current result to it

    :type max_entries_per_docker: ``int``
    :param max_entries_per_docker: max number of integration or script to show per docker image entry

    :return: dict as {'docker_image':['integration/scripts', 'integration/scripts',...]}
    :rtype: dict

    """
    result = result_dict or {}
    for integration_script, docker_image in docker_list.items():
        if integration_script in ['CommonServerUserPowerShell', 'CommonServerUserPython']:
            continue
        if docker_image in result:
            if len(result[docker_image]) < max_entries_per_docker:
                result[docker_image].append(integration_script)
        else:
            result[docker_image] = [integration_script]

    return result


def format_result_for_markdown(result_dict) -> list:
    result_output = []
    for docker_image, integration_script in result_dict.items():
        result_output.append({
            'Docker Image': docker_image,
            'Integrations/Automations': integration_script
        })
    return result_output


''' COMMAND FUNCTION '''


def get_used_dockers_images() -> CommandResults:
    md = None
    active_docker_list_integration = {}
    active_docker_list_automation = {}
    result_dict: Dict[str, List[str]] = {}

    active_integration_instances = demisto.internalHttpRequest(POST_COMMAND, "%s" % SETTING_INTEGRATION_SEARCH,
                                                               REQUEST_INTEGRATION_SEARCH_BODY)
    demisto.debug(
        f"called demisto.internalHttpRequest(\"{POST_COMMAND}\", \"{SETTING_INTEGRATION_SEARCH}\", "
        f"\"{REQUEST_INTEGRATION_SEARCH_BODY}\")")

    demisto.debug(f'respose code = {0}', active_integration_instances['statusCode'])
    if active_integration_instances and active_integration_instances['statusCode'] == 200:
        active_docker_list_integration = extract_dockers_from_integration_search_result(
            active_integration_instances['body'])

    active_automation_instances = demisto.internalHttpRequest(POST_COMMAND, "%s" % AUTOMATION_SEARCH,
                                                              REQUEST_INTEGRATION_SEARCH_BODY)
    demisto.debug(f"called demisto.internalHttpRequest(\"{POST_COMMAND}\", \"{AUTOMATION_SEARCH}\", "
                  f"\"{REQUEST_INTEGRATION_SEARCH_BODY}\")")
    demisto.debug(f'respose code = {0}', active_automation_instances['statusCode'])
    if active_automation_instances and active_automation_instances['statusCode'] == 200:
        active_docker_list_automation = extract_dockers_from_automation_search_result(
            active_automation_instances['body'])

    result_dict = merge_result(active_docker_list_integration, result_dict, MAX_PER_DOCKER)
    result_dict = merge_result(active_docker_list_automation, result_dict, MAX_PER_DOCKER)

    ''' format the result for Markdown view'''
    result_output = []
    result_output = format_result_for_markdown(result_dict)

    md = tableToMarkdown('Dockers Images In use:', result_output, )

    return CommandResults(readable_output=md)


''' MAIN FUNCTION '''


def main():
    try:
        demisto.debug("running get_used_dockers_images()")
        return_results(get_used_dockers_images())
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ListUsedDockersImages. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
