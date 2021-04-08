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


def build_md_document(integrations_table, installed_packs_table, playbooks_table):
    template = jinja2.Template(MD_DOCUMENT_TEMPLATE)
    return template.render(
        integrations_table=integrations_table,
        installed_packs_table=installed_packs_table,
        playbooks_table=playbooks_table
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


def main():
    integrations = get_enabled_integrations()
    installed_packs = get_installed_packs()
    playbooks = get_custom_playbooks()
    hr = build_md_document(
        integrations.as_markdown(["name", "brand"]),
        installed_packs.as_markdown(["name", "currentVersion"]),
        playbooks.as_markdown(["name", "TotalTasks"])
    )
    return_results(hr)


if __name__ in ('__builtin__', 'builtins'):
    main()
