from CommonServerPython import *
import demistomock as demisto
import sys
import jinja2

"""
GenerateAsBuilt

Uses the XSOAR API to query for custom content, configuration, and statistics, then generates
a HTML and Markdown output based on this.
"""
DEMISTO_INTEGRATIONS_PATH = "/settings/integration/search"
DEMISTO_INSTALLED_PATH = "/contentpacks/metadata/installed"
DEMISTO_PLAYBOOKS_PATH = "/playbook/search"
DEMISTO_AUTOMATIONS_PATH = "/automation/search"
DEMISTO_CONFIG_PATH = "/system/config"
MAX_REQUEST_SIZE = demisto.args().get("size", 500)
HTML_TABLE_TEMPLATE = """
<table>
    <tr>
        {% for header in headers %}
        <th>{{ header }}</th>
        {% endfor %}
    </tr>
    {% for row in rows %}
    <tr>
        {% for header in headers %}
        <td>{{ row[header] }}</td>
        {% endfor %}
    </tr>
    {% endfor %}
</table>
"""
MD_DOCUMENT_TEMPLATE = """
{{ integrations_table }}

{{ installed_packs_table }}

{{ playbooks_table }}

{{ automations_table }}
"""


class ReturnedAPIData:
    def __init__(self, data, name):
        self.data = data
        self.name = name

    def as_markdown(self, headers):
        return tableToMarkdown(self.name, self.data, headers=headers)

    def as_html(self, headers):
        template = jinja2.Template(HTML_TABLE_TEMPLATE)
        return template.render(headers=headers, rows=self.data)

    def total(self):
        return len(self.data)


def build_md_document(
        integrations_table,
        installed_packs_table,
        playbooks_table,
        automations_table
):
    template = jinja2.Template(MD_DOCUMENT_TEMPLATE)
    return template.render(
        integrations_table=integrations_table,
        installed_packs_table=installed_packs_table,
        playbooks_table=playbooks_table,
        automations_table=automations_table
    )


def post_api_request(url, body):
    api_args = {
        "uri": url,
        "body": body
    }
    raw_res = demisto.executeCommand("demisto-api-post", api_args)
    try:
        res = raw_res[0]['Contents']['response']
        return res
    except KeyError:
        return_error(f'API Request failed, no response from API call to {url}')


def get_api_request(url):
    api_args = {
        "uri": url
    }
    raw_res = demisto.executeCommand("demisto-api-get", api_args)
    try:
        res = raw_res[0]['Contents']['response']
        return res
    except KeyError:
        return_error(f'API Request failed, no response from API call to {url}')


def get_enabled_integrations():
    """
    Retrieve all the running instances.
    :return: ReturnedAPIData
    """
    r = post_api_request(DEMISTO_INTEGRATIONS_PATH, {"size": MAX_REQUEST_SIZE})
    instances = r.get("instances")
    enabled_instances = []
    for instance in instances:
        if instance.get("enabled"):
            enabled_instances.append(instance)

    rd = ReturnedAPIData(enabled_instances, "Enabled Instances")
    # return_results(rd.as_markdown(headers=["name", "brand"]))
    return rd


def get_installed_packs():
    """
    Get all the installed Content Packs
    :return: ReturnedAPIData
    """
    r = get_api_request(DEMISTO_INSTALLED_PATH)
    rd = ReturnedAPIData(r, "Installed Content Packs")
    return rd


def get_custom_playbooks():
    """
    Return all the custom playbooks installed in XSOAR>
    :return: ReturnedAPIData
    """
    r = post_api_request(DEMISTO_PLAYBOOKS_PATH, {"query": "system:F AND hidden:F"}).get("playbooks")
    for pb in r:
        pb["TotalTasks"] = len(pb.get("tasks", []))
    rd = ReturnedAPIData(r, "Custom Playbooks")
    return rd


def get_custom_automations():
    r = post_api_request(DEMISTO_AUTOMATIONS_PATH, {"query": "system:F AND hidden:F"}).get("scripts")
    rd = ReturnedAPIData(r, "Custom Automations")
    return rd


def get_system_config():
    r = get_api_request(DEMISTO_CONFIG_PATH).get("defaultMap")
    rd = ReturnedAPIData(r, "System Configuration")
    return rd


def main():
    system_config = get_system_config()
    integrations = get_enabled_integrations()
    installed_packs = get_installed_packs()
    playbooks = get_custom_playbooks()
    automations = get_custom_automations()
    hr = build_md_document(
        integrations.as_markdown(["name", "brand"]),
        installed_packs.as_markdown(["name", "currentVersion"]),
        playbooks.as_markdown(["name", "TotalTasks"]),
        automations.as_markdown(["name", "comment"])
    )
    return_results(hr)


if __name__ in ('__builtin__', 'builtins'):
    main()
