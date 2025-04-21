import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_custom_scripts_playbooks():
    results = {}
    final_results = []
    req_response = demisto.executeCommand(
        "demisto-api-post", {"uri": "automation/search", "body": "{\"query\":\"system:F AND hidden:F AND deprecated:F\"}"})
    list_scripts = req_response[0].get('Contents', {}).get('response', {}).get('scripts')
    if not list_scripts:
        return_error("No custom scripts found.")
    else:
        for item in list_scripts:
            results['ScriptName'] = item['name']
            results['Type'] = item['type']
            results['User'] = item['user']
            results['Modified'] = item['modified']
            query = {"query": "script.name:" + str(item['name']) + " AND hidden:F AND deprecated:F"}
            playbooksUsingScripts = (
                demisto.executeCommand(
                    "demisto-api-post", {"uri": "playbook/search", "body": query}
                )[0]
                .get("Contents", {})
                .get("response", {})
                .get("playbooks")
            )
            if not playbooksUsingScripts:
                pbnamelist = []
                for item in playbooksUsingScripts:
                    pbnamelist.append(item['name'])
                results['playbooksUsingScript'] = pbnamelist
            else:
                results['playbooksUsingScript'] = "Not used in any playbooks"
            final_results.append(results.copy())
        markdown = ''
        markdown = tableToMarkdown('Custom scripts Used in Playbooks', final_results)
        command_results_results = CommandResults(
            readable_output=markdown,
            outputs_prefix='CustomScripts',
            outputs_key_field='CustomDependencies.Info',
            outputs=final_results
        )
        return_results(command_results_results)


def get_integrations_playbooks() -> None:
    results = {}
    final_results = []
    incident = demisto.incidents()[0]
    accountName = incident.get('account')
    accountName = f"acc_{accountName}" if accountName != "" else ""
    EnabledIntegrations = demisto.executeCommand(
        "demisto-api-post",
        {
            "uri": f"{accountName}/settings/integration/search",
            "body": {
                "preferences": "true"
            },
        })[0]["Contents"]["response"]["instances"]
    if EnabledIntegrations is not None:
        integrations_list = []
        for item in EnabledIntegrations:
            integrations_list.append(item['brand'])
        integrations_list = list(set(integrations_list))
        for brand in integrations_list:
            results['IntegrationBrands'] = brand
            string_brand = (f'"{str(brand)}"')
            query = {"query": "brands:" + str(string_brand) + " AND hidden:F AND deprecated:F"}
            playbooksUsingIntegrations = (
                demisto.executeCommand(
                    "demisto-api-post", {"uri": "playbook/search", "body": query}
                )[0]
                .get("Contents", {})
                .get("response", {})
                .get("playbooks")
            )
            if playbooksUsingIntegrations is not None:
                pbnamelist = []
                for item in playbooksUsingIntegrations:
                    pbnamelist.append(item['name'])
                results['playbooksUsingIntegrations'] = pbnamelist
            else:
                results['playbooksUsingIntegrations'] = "Not used in any playbooks"
            final_results.append(results.copy())
        markdown = ''
        markdown = tableToMarkdown('Integrations Used in Playbooks', final_results)
        command_results_results = CommandResults(
            readable_output=markdown,
            outputs_prefix='Integrations',
            outputs_key_field='Info',
            outputs=final_results
        )
        return_results(command_results_results)
    else:
        return_results("No integrations are enabled")


def main():
    Mode = str(demisto.args()['mode'])
    if Mode == 'scripts':
        get_custom_scripts_playbooks()
    elif Mode == 'integrations':
        get_integrations_playbooks()
    else:
        return_error("Please enter a valid mode. Available modes: scripts, integrations.")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
