import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""ListUsedDockerImages Script for Cortex XSOAR (aka Demisto)

This is a script that list all the dockers images that are in ues in the integrations and automations

"""

import json
from typing import Dict

'''REST API HTTP COMMANDS'''
POST_COMMAND = "POST"

'''REST API CALL BODY'''
REQUEST_INTEGRATION_SEARCH_BODY = "{\"size\":500}"

'''Constants used to filter out the result'''
CONFIGURATIONS = 'configurations'
INTEGRATION_SCRIPT = 'integrationScript'

PYTHON_SCRIPT = 'python'
POWERSHELL_SCRIPT = 'powershell'
JAVA_SCRIPT = 'javascript'

INTEGRATION_SCRIPT_TYPE = 'type'
INTEGRATION_ID = 'id'
INTEGRATION_DISPLAY = 'display'

DOCKER_IMAGE = 'dockerImage'
DEFAULT_DOCKER_IMAGE = 'Default Docker Image'

SCRIPT_TYPE = 'type'
SCRIPT_NAME = 'name'
SCRIPTS = 'scripts'

ENABLED = 'enabled'
DEPRECATED = 'deprecated'
IS_INTEGRATION_SCRIPT = 'isIntegrationScript'

''' HELPER FUNCTION '''


def get_docker_from_conf(conf: Dict) -> str:
    """
    :type conf: ``json object``
    :param conf: json represents integration configuration

    Returns:
        docker image if it is in used
    """

    docker_image = ''
    if SCRIPT_TYPE in conf[INTEGRATION_SCRIPT] and conf[INTEGRATION_SCRIPT][SCRIPT_TYPE] in (
            PYTHON_SCRIPT, POWERSHELL_SCRIPT):
        if DOCKER_IMAGE not in conf[INTEGRATION_SCRIPT] or conf[INTEGRATION_SCRIPT][DOCKER_IMAGE] in (None, ''):
            docker_image = 'Default Image Name'
        else:
            docker_image = conf[INTEGRATION_SCRIPT][DOCKER_IMAGE]
    return docker_image


def get_integration_conf(integration_search_json: Dict, instance_brand: str,
                         ignore_deprecated: bool = False) -> Any:
    """ returns the corresponding integration_configuration json object for the given instance_brand
    Args:
        :type integration_search_json: ``json object``
        :param integration_search_json: j son object represents XSOAR integrations configuration.

        :type instance_brand: ``str``
        :param instance_brand: the configured instance brand value.

        :type ignore_deprecated: ``bool``
        :param ignore_deprecated: a boolean indicates if to ignore deprecated integration

    Returns:
        json object for the corresponding
    """

    for conf in integration_search_json[CONFIGURATIONS]:
        if 'id' in conf and conf['id'] != instance_brand:
            continue
        if ignore_deprecated and (DEPRECATED in conf) and conf[DEPRECATED] is True:
            continue
        if (INTEGRATION_SCRIPT not in conf) or (conf[INTEGRATION_SCRIPT] is None):
            continue
        else:
            return conf


def extract_dockers_from_integration_search_result(content: str, ignore_deprecated_integrations: bool = False,
                                                   ignore_disabled_integrations: bool = True) -> dict:
    """Returns a simple python dict of used dockerImages by integration
    Args:

        :type content: ``str``
        :param content: string representation for the /settings/integrations/search API result response

        :type ignore_deprecated_integrations: ``bool``
        :param ignore_deprecated_integrations: a boolean indicates if to ignore deprecated integration

        :type ignore_disabled_integrations: ``bool``
        :param ignore_disabled_integrations: a boolean indicates if to ignore integration instances that are disabled
    Returns:
        :rtype: ``dict``
        :return: dict as {"integration_id":"dockername"}
    """

    integration_search_json = json.loads(content)
    dockers = {}
    for instance in integration_search_json['instances']:
        if ignore_disabled_integrations and (ENABLED in instance and instance[ENABLED] == "false"):
            continue
        if IS_INTEGRATION_SCRIPT in instance and instance[IS_INTEGRATION_SCRIPT] is False:
            continue
        instance_brand = instance['brand']
        if instance_brand == '':
            continue
        else:
            conf_json = get_integration_conf(integration_search_json, instance_brand, ignore_deprecated_integrations)
            if conf_json:
                docker_image = get_docker_from_conf(conf_json)
                if docker_image and docker_image != '':
                    dockers[conf_json[INTEGRATION_DISPLAY]] = docker_image
    return dockers


def extract_dockers_from_automation_search_result(content: str, ignore_deprecated: bool = True) -> dict:
    """Returns a simple python dict of used dockerImages by automations
    Args:
        :type content: ``str``
        :param content: string representation for the /automation/search API result response

        :type ignore_deprecated: ``bool``
        :param ignore_deprecated: string representation for the /automation/search API result response

    Returns:
        :return: dict as {"integration_id":"dockername"}
        :rtype: dict
    """
    json_content = json.loads(content)
    dockers = {}
    for script in json_content[SCRIPTS]:
        if (ignore_deprecated and (DEPRECATED in script and script[DEPRECATED] is True)) or \
                (ENABLED in script and script[ENABLED] is False) or \
                (SCRIPT_TYPE in script and script[SCRIPT_TYPE] == JAVA_SCRIPT):
            continue
        else:
            if DOCKER_IMAGE in script and script[DOCKER_IMAGE] in (None, ''):
                docker_image = 'Default Image Name'
            else:
                docker_image = script[DOCKER_IMAGE]
            dockers[script[SCRIPT_NAME]] = docker_image

    return dockers


def merge_result(docker_list: dict, result_dict: dict = {}) -> dict:
    """Returns a python dict of the merge result

    Args:
        :type docker_list: ``dict``
        :param docker_list: dictionary representation for the docker image used by integration or script

        :type result_dict: ``dict``
        :param result_dict: dictionary representation for the docker image and the integration/scripts belongs to it
                           merge the current result to it

        :type max_entries_per_docker: ``int``
        :param max_entries_per_docker: max number of integration or script to show per docker image entry

    Returns:
        :return: dict as {'docker_image':['integration/scripts', 'integration/scripts',...]}
        :rtype: dict
    """

    result = result_dict or {}
    for integration_script, docker_image in docker_list.items():
        if integration_script in ['CommonServerUserPowerShell', 'CommonServerUserPython']:
            continue
        if docker_image in result:
            result[docker_image].append(integration_script)
        else:
            result[docker_image] = [integration_script]

    return result


def format_result_for_markdown(result_dict: dict) -> list:
    result_output = []
    for docker_image, integration_script in result_dict.items():
        result_output.append({
            'DockerImage': docker_image,
            'ContentItem': integration_script
        })
    return result_output


''' COMMAND FUNCTION '''


def list_used_docker_images(export_to_context: bool = True,
                            ignore_deprecated_automations: bool = True) -> CommandResults:
    md = None
    active_docker_list_integration = {}
    active_docker_list_automation = {}

    ''' Examples for output: { 'demisto/python3:3.9.7.24076' : ['ListUsedDockerImage', 'VirusTotal',...]}'''
    result_dict: Dict[str, List[str]] = {}

    active_integration_instances = demisto.internalHttpRequest(POST_COMMAND, '/settings/integration/search',
                                                               '{\"size\":500}')
    demisto.debug(f'response code = {0}', active_integration_instances['statusCode'])
    if active_integration_instances and active_integration_instances['statusCode'] == 200:
        active_docker_list_integration = extract_dockers_from_integration_search_result(
            active_integration_instances['body'], False, True)

    active_automation = demisto.internalHttpRequest(POST_COMMAND, '/automation/search',
                                                    '{\"size\":500}')
    demisto.debug(f'response code = {0}', active_automation['statusCode'])
    if active_automation and active_automation['statusCode'] == 200:
        active_docker_list_automation = extract_dockers_from_automation_search_result(
            active_automation['body'], ignore_deprecated_automations)

    result_dict = merge_result(active_docker_list_integration, result_dict)
    result_dict = merge_result(active_docker_list_automation, result_dict)

    ''' format the result for Markdown view'''
    result_output = []
    result_output = format_result_for_markdown(result_dict)

    md = tableToMarkdown('Docker Images In use:', result_output, headers=['DockerImage', 'ContentItem'],
                         headerTransform=pascalToSpace)

    if export_to_context:
        return CommandResults(
            outputs_prefix='UsedDockerImages',
            outputs_key_field='DockerImage',
            outputs=result_output,
            raw_response=result_dict,
            readable_output=md)
    else:
        return CommandResults(readable_output=md)


''' MAIN FUNCTION '''


def main():
    demisto.debug("running list_used_docker_images()")
    export_to_context = demisto.args().get('export_to_context') == 'true'
    ignore_deprecated_automations = demisto.args().get('ignore_deprecated_automations') == 'true'

    try:
        return_results(list_used_docker_images(export_to_context, ignore_deprecated_automations))
    except Exception as e:
        return_error(f'Failed to execute ListUserDockerImages Script. Error: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
