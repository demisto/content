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
MAX_REQUEST_SIZE = demisto.args().get("size", 500)
HTML_TABLE_TEMPLATE = """
<table>
    <tr>
        {% for header in headers %}
        <th>{{ header }}</th>
        {% endfor %}
    </tr>
</table>
"""
class ReturnedAPIData:
    def __init__(self, data, name):
        self.data = data
        self.name = name

    def as_markdown(self, headers):
        tableToMarkdown(self.name, self.data, headers=headers)

    def as_html(self, headers):
        template = jinja2.Template(HTML_TABLE_TEMPLATE)
        return template.render(headers=headers)

def api_request(url, body, command):
    api_args = {
        "uri": url,
        "body": body
    }
    raw_res = demisto.executeCommand(command, api_args)
    try:
        res = raw_res[0]['Contents']['response']
        return res
    except KeyError:
        return_error(f'API Request failed, no response from API call to {url}')


def get_enabled_integrations():
    """
    Retrieve all the running instances.
    :return:
    """
    r = api_request(DEMISTO_INTEGRATIONS_PATH, {"size": MAX_REQUEST_SIZE}, "demisto-api-post")
    instances = r.get("instances")
    total_instances = len(instances)
    enabled_instances = []
    for instance in instances:
        if instance.get("enabled"):
            enabled_instances.append(instance)

    return_results(tableToMarkdown("Enabled Instances", enabled_instances, headers=["brand","name"]))

def main():
    get_enabled_integrations()


if __name__ in ('__builtin__', 'builtins'):
    main()
