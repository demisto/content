import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

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
DEMISTO_INCIDENTS_PATH = "/incidents/search"
DEMISTO_INCIDENT_TYPE_PATH = "/incidenttype"
MAX_REQUEST_SIZE = demisto.args().get("size", 500)
HTML_TABLE_TEMPLATE = """
<h3>{{ name }}</h3>
<table class="table">
    {% if headers %}
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
    {% else %}
    {% for row in rows %}
        {% for k,v in row.items() %}
        <tr>
            <td>{{ k }}</td>
            <td>{{ v }}</td>
        </tr>
        {% endfor %}
    {% endfor %}
    {% endif %}

</table>
"""

MD_DOCUMENT_TEMPLATE = """
{{ open_incidents }}

{{ closed_incidents }}

{{ playbook_stats }}

{{ integrations_table }}

{{ installed_packs_table }}

{{ playbooks_table }}

{{ automations_table }}

{{ system_config }} 
"""

HTML_DOCUMENT_TEMPLATE = """
<head>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta3/dist/css/bootstrap.min.css" rel="stylesheet"
          integrity="sha384-eOJMYsd53ii+scO/bJGFsiCZc+5NDVN2yr8+0RDqr0Ql0h+rP48ckxlpbzKgwra6" crossorigin="anonymous"
    media='all'>
</head>
<style>
    td {
        font-size: small;
    }
</style>
<body>
<div class="container">
    <header class="d-flex flex-wrap justify-content-center py-3 mb-4 border-bottom">
        <div class="d-flex align-items-center mb-3 mb-md-0 me-md-auto text-dark text-decoration-none"
        style="min-width:500px;">
            <span class="fs-4">XSOAR as built</span>
        </div>
        <div>
            <img src="https://www.paloaltonetworks.com/content/dam/pan/en_US/images/logos/brand/primary-company-logo/PANW_Parent_Brand_Primary_Logo_RGB.png?imbypass=on"
                 height="35px">
        </div>
    </header>
    <div class="row mb-2">
        <div class="col">
            <small class="text-secondary">Prepared by: {{ author }}</small>
        </div>
        <div class="col text-center">
            <small class="text-secondary">Prepared For: {{ customer }}</small>
        </div>
        <div class="col text-end">
            <small class="text-secondary">Prepared at: {{ date }}</small>
        </div>
    </div>
    <div class="row mb-2">
        <div class="col text-center p-2 border-bottom">
            {{ open_incidents }}
        </div>
        <div class="col text-center p-2 border-bottom">
            {{ closed_incidents }}
        </div>
    </div>
    <div class="row mb-2">
        <div class="col">
            <h1 class="text-primary">Purpose</h1>
            <p>This Document covers all of the custom configuration and content that has been deployed following
            the engagement of Palo Alto professional services.<br>
            </p>
            <h1 class="text-primary">Document Overview</h1>
            <p>
                This document has been auto-generated using the XSOAR Automation <i>!GenerateAsBuilt</i>.
            </p>
            <h1 class="text-primary">
                Project Details
            </h1>
            <textarea style="width:100%;border:none;"
                  placeholder="Click here to complete this section with any relevant details, for example customer
contat details, project scope, etc."></textarea>
        </div>
    </div>
    <p style="page-break-after: always;"></p>


    {{ integrations_table }}
    <p>The system configuration above represents the server configuration of XSOAR, including advanced
        server config parameters such as HTTP proxy. This configuration is accessible via
        settings->about->troubleshooting.</p>
    <p style="page-break-after: always;"></p>

    {{ installed_packs_table }}
    <p>The installed packs are all the content packs currently installed on the server. Content packs
    include playbooks, automations, and in some cases, integrations.</p>
    <p style="page-break-after: always;"></p>


    {{ playbooks_table }}
    <p>
        Custom playbooks are written specifically for this deployment, or adapted from existing OOTB playbooks.
        The tasks in each playbook represent the overall size and complexity of each developed playbook.
    </p>
    <p style="page-break-after: always;"></p>

    {{ automations_table }}
    <p>
        Custom automations are used to add additional logic and support to playbooks and use cases.
    </p>
    <p style="page-break-after: always;"></p>

    {{ system_config }}
    <p>
        The system configuration changes the behavior of the XSOAR server/application itself, including
        keys and the published hostname.
    </p>
    <p style="page-break-after: always;"></p>
</div>
</body>
"""


class TableData:
    def __init__(self, data, name):
        self.data = data
        self.name = name

    def as_markdown(self, headers=None):
        if not headers:
            return tableToMarkdown(self.name, self.data, removeNull=True)
        else:
            return tableToMarkdown(self.name, self.data, headers=headers, removeNull=True)

    def as_html(self, headers=None):
        template = jinja2.Template(HTML_TABLE_TEMPLATE)
        rows = self.data
        if type(self.data) is dict:
            rows = []
            for k, v in self.data.items():
                rows.append({k: v})
        return template.render(headers=headers, rows=rows, name=self.name)

    def total(self):
        return len(self.data)


class SingleFieldData:
    def __init__(self, name, data):
        self.data = data
        self.name = name

    def as_markdown(self):
        return f"### {self.name}\n{self.data}"

    def as_html(self):
        return f"""<h3>{self.name}</h3><span class="display-5">{self.data}</span>"""


class Document:
    def __init__(
            self,
            template,
            integrations_table,
            installed_packs_table,
            playbooks_table,
            automations_table,
            system_config,
            open_incidents,
            closed_incidents,
            playbook_stats
    ):
        self.template = template
        self.integrations_table = integrations_table
        self.installed_packs_table = installed_packs_table
        self.playbooks_table = playbooks_table
        self.automations_table = automations_table
        self.system_config = system_config
        self.open_incidents = open_incidents
        self.closed_incidents = closed_incidents
        self.playbook_stats = playbook_stats
        self.author = demisto.args().get("author")
        self.date = datetime.now().strftime("%m/%d/%Y")
        self.customer = demisto.args().get("customer")

    def html(self):
        template = jinja2.Template(HTML_DOCUMENT_TEMPLATE)
        return template.render(
            integrations_table=self.integrations_table.as_html(["name", "brand"]),
            installed_packs_table=self.installed_packs_table.as_html(["name", "currentVersion"]),
            playbooks_table=self.playbooks_table.as_html(["name", "TotalTasks"]),
            automations_table=self.automations_table.as_html(["name", "comment"]),
            system_config=self.system_config.as_html(),
            open_incidents=self.open_incidents.as_html(),
            closed_incidents=self.closed_incidents.as_html(),
            author=self.author,
            date=self.date,
            customer=self.customer,
            playbook_stats=self.playbook_stats.as_html()
        )

    def markdown(self):
        template = jinja2.Template(MD_DOCUMENT_TEMPLATE)
        return template.render(
            integrations_table=self.integrations_table.as_markdown(["name", "brand"]),
            installed_packs_table=self.installed_packs_table.as_markdown(["name", "currentVersion"]),
            playbooks_table=self.playbooks_table.as_markdown(["name", "TotalTasks"]),
            automations_table=self.automations_table.as_markdown(["name", "comment"]),
            system_config=self.system_config.as_markdown(),
            open_incidents=self.open_incidents.as_markdown(),
            closed_incidents=self.closed_incidents.as_markdown(),
            playbook_stats=self.playbook_stats.as_markdown(headers=["playbook", "incidents"])
        )


def build_document(
        template,
        integrations_table,
        installed_packs_table,
        playbooks_table,
        automations_table,
        system_config
):
    template = jinja2.Template(template)
    return template.render(
        integrations_table=integrations_table.as_html(),
        installed_packs_table=installed_packs_table,
        playbooks_table=playbooks_table,
        automations_table=automations_table,
        system_config=system_config
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
    except TypeError:
        return_error(f'API Request failed, failedto {raw_res}')


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


def get_all_incidents(days=7, size=1000):
    body = {
        "userFilter": False,
        "filter": {
            "page": 0,
            "size": size,
            "query": "-category:job",
            "sort": [
                {
                    "field": "id",
                    "asc": False
                }
            ],
            "period": {
                "by": "day",
                "fromValue": days
            }
        }
    }
    r = post_api_request(DEMISTO_INCIDENTS_PATH, body)
    return r.get("data")


def get_open_incidents(days=7, size=1000):
    body = {
        "userFilter": False,
        "filter": {
            "page": 0,
            "size": size,
            "query": "-status:closed -category:job",
            "sort": [
                {
                    "field": "id",
                    "asc": False
                }
            ],
            "period": {
                "by": "day",
                "fromValue": days
            }
        }
    }
    r = post_api_request(DEMISTO_INCIDENTS_PATH, body)
    total = r.get("total")
    rd = SingleFieldData(f"Open Incidents {days} days", total)
    return rd


def get_closed_incidents(days=7, size=1000):
    body = {
        "userFilter": False,
        "filter": {
            "page": 0,
            "size": size,
            "query": "status:closed -category:job",
            "sort": [
                {
                    "field": "id",
                    "asc": False
                }
            ],
            "period": {
                "by": "day",
                "fromValue": days
            }
        }
    }
    r = post_api_request(DEMISTO_INCIDENTS_PATH, body)
    total = r.get("total")
    rd = SingleFieldData(f"Closed Incidents {days} days", total)
    return rd


def get_enabled_integrations():
    """
    Retrieve all the running instances.
    :return: TableData
    """
    r = post_api_request(DEMISTO_INTEGRATIONS_PATH, {"size": MAX_REQUEST_SIZE})
    instances = r.get("instances")
    enabled_instances = []
    for instance in instances:
        if instance.get("enabled"):
            enabled_instances.append(instance)

    rd = TableData(enabled_instances, "Enabled Instances")
    # return_results(rd.as_markdown(headers=["name", "brand"]))
    return rd


def get_installed_packs():
    """
    Get all the installed Content Packs
    :return: TableData
    """
    r = get_api_request(DEMISTO_INSTALLED_PATH)
    rd = TableData(r, "Installed Content Packs")
    return rd


def get_custom_playbooks():
    """
    Return all the custom playbooks installed in XSOAR>
    :return: TableData
    """
    r = post_api_request(DEMISTO_PLAYBOOKS_PATH, {"query": "system:F AND hidden:F"}).get("playbooks")
    for pb in r:
        pb["TotalTasks"] = len(pb.get("tasks", []))
    rd = TableData(r, "Custom Playbooks")
    return rd


def get_playbook_stats():
    """
    Pull all the incident types and assoociated playbooks,
    then join this with the incident stats to determine how often each playbook has been used.
    """
    # incident_types = get_api_request(DEMISTO_INCIDENT_TYPE_PATH)
    incidents = get_all_incidents()
    playbook_stats = {}
    for incident in incidents:
        playbook = incident.get("playbookId")
        if playbook not in playbook_stats:
            playbook_stats[playbook] = 0

        playbook_stats[playbook] = playbook_stats[playbook] + 1

    table = []
    for playbook, count in playbook_stats.items():
        table.append({
            "playbook": playbook,
            "incidents": count
        })
    td = TableData(table, "Playbook Stats")
    return td


def get_custom_automations():
    r = post_api_request(DEMISTO_AUTOMATIONS_PATH, {"query": "system:F AND hidden:F"}).get("scripts")
    rd = TableData(r, "Custom Automations")
    return rd


def get_system_config():
    r = get_api_request(DEMISTO_CONFIG_PATH).get("defaultMap")
    rd = TableData(r, "System Configuration")
    return rd


def main():
    open_incidents = get_open_incidents()
    closed_incidents = get_closed_incidents()

    system_config = get_system_config()
    integrations = get_enabled_integrations()
    installed_packs = get_installed_packs()
    playbooks = get_custom_playbooks()
    automations = get_custom_automations()
    playbook_stats = get_playbook_stats()
    d = Document(
        MD_DOCUMENT_TEMPLATE,
        system_config=system_config,
        integrations_table=integrations,
        installed_packs_table=installed_packs,
        playbooks_table=playbooks,
        automations_table=automations,
        open_incidents=open_incidents,
        closed_incidents=closed_incidents,
        playbook_stats=playbook_stats
    )
    fr = fileResult("asbuilt.html", d.html())
    return_results(CommandResults(
        readable_output=d.markdown(),
    ))
    return_results(fr)


if __name__ in ('__builtin__', 'builtins'):
    main()
