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
DEMISTO_DEPENDENCIES_PATH = "/itemsdependencies"
DEMISTO_REPORTS_PATH = "/reports"
DEMISTO_DASHBOARDS_PATH = "/dashboards"
MAX_REQUEST_SIZE = demisto.args().get("size", 1000)
MAX_DAYS = demisto.args().get("days", 7)
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

USECASE_MD_DOCUMENT_TEMPLATE = """
# {{ playbook_name }}

{{ data.playbooks.as_markdown() }}

{{ data.integrations.as_markdown() }}

{{ data.incidentfields.as_markdown() }}

{{ data.automations.as_markdown() }}
"""

MD_DOCUMENT_TEMPLATE = """
{{ open_incidents }}

{{ closed_incidents }}

{{ reports }}

{{ dashboards }}

{{ playbook_stats }}

{{ integrations_table }}

{{ installed_packs_table }}

{{ playbooks_table }}

{{ automations_table }}

{{ system_config }}
"""

USECASE_HTML_DOCUMENT_TEMPLATE = """
<head>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta3/dist/css/bootstrap.min.css" rel="stylesheet"
          integrity="sha384-eOJMYsd53ii+scO/bJGFsiCZc+5NDVN2yr8+0RDqr0Ql0h+rP48ckxlpbzKgwra6" crossorigin="anonymous"
          media='all'>
</head>
<style>
    td {
        font-size: small;
    }
    .border-cortex {
        border-color: #fa582d!important;
    }
    .text-cortex {
        color: #fa582d!important;
    }

</style>
<body>
<div class="container">
    <header class="d-flex flex-wrap justify-content-center py-3 mb-4 border-bottom border-cortex">
        <div class="d-flex align-items-center mb-3 mb-md-0 me-md-auto text-dark text-decoration-none"
             style="min-width:500px;">
            <span class="fs-4">{{ playbook_name }}</span>
        </div>
        <div>
            <img src="https://www.paloaltonetworks.com/content/dam/pan/en_US/images/logos/brand/primary-company-logo/PANW_Parent_Brand_Primary_Logo_RGB.png?imbypass=on"
                 height="35px">
        </div>
    </header>
    <div class="row mb-2">
        <div class="col">
            <small class="text-secondary">Prepared by: {{ data.author }}</small>
        </div>
        <div class="col text-center">
            <small class="text-secondary">Prepared For: {{ data.customer }}</small>
        </div>
        <div class="col text-end">
            <small class="text-secondary">Prepared at: {{ data.date }}</small>
        </div>
    </div>
    <div class="row mb-2">
        <div class="col">
            <h1 class="text-cortex">Purpose</h1>
            <p>This Document covers all of the custom configuration and content that has been deployed following
                the engagement of Palo Alto professional services.<br><br>
                This document specifically covers the implementation of the provided use case/playbook, and collates
                the dependencies and artefacts implemented to complete it.
                <br><br>
                This document only includes the dependencies used by the playbook, which may not include other configurations
                such as:
            </p>
            <ul>
                <li>Incident Classifiers</li>
                <li>Incident Mappers</li>
            </ul>
            <h1 class="text-cortex">Document Overview</h1>
            <p>
                This document has been auto-generated using the XSOAR Automation <i>!GenerateAsBuilt</i>, with a
                specific
                playbook ({{ playbook_name }}) provided.
            </p>
            <h1 class="text-cortex">
                Project Details
            </h1>
            <textarea style="width:100%;border:none;"
                      placeholder="Click here to complete this section with any relevant details, for example customer
contat details, project scope, etc."></textarea>
            <h1 class="text-cortex">
                Contact Details
            </h1>
            <p>
                <b>Corporate Headquarters</b><br>
                Palo Alto Networks<br>
                3000 Tannery Way<br>
                Santa Clara, CA 95054<br>
            </p>
        </div>
    </div>
    <p style="page-break-after: always;"></p>

    {{ data.playbooks.as_html(["name","pack"]) }}
    <p>
        Playbook dependencies are subplaybooks consumed by the parent use case.
    </p>
    <p style="page-break-after: always;"></p>

    {% if data.integrations %}
    {{ data.integrations.as_html(["name","pack"]) }}
    <p>
        Integration dependencies are those that implement commands required by this use case.
        <br><br>
        The above integrations may not all be configured in this environment, but are referenced by the use case.
    </p>
    <p style="page-break-after: always;"></p>
    {% endif %}

    {% if data.incidenttypes %}
    {{ data.incidenttypes.as_html(["name","pack"]) }}
    <p>
        Incident types are the types of incidents generated or used by this use-case.
    </p>
    <p style="page-break-after: always;"></p>
    {% endif %}

    {% if data.automations %}
    {{ data.automations.as_html(["name","pack"]) }}
    <p>
        Automations are scripts used to perform tasks. They may be custom, or OOTB.
    </p>
    <p style="page-break-after: always;"></p>
    {% endif %}

    {% if data.incidentfields %}
    {{ data.incidentfields.as_html(["name","pack"]) }}
    <p>
        Incident fields are the fields that this use case relies on to populate or consume information.
    </p>
    <p style="page-break-after: always;"></p>
    {% endif %}
</div>
</body>
"""  # noqa: E501

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
    .border-cortex {
        border-color: #fa582d!important;
    }
    .text-cortex {
        color: #fa582d!important;
    }
</style>
<body>
<div class="container">
    <header class="d-flex flex-wrap justify-content-center py-3 mb-4 border-bottom border-cortex">
        <div class="d-flex align-items-center mb-3 mb-md-0 me-md-auto text-dark text-decoration-none"
             style="min-width:500px;">
            <span class="fs-4 display-1">XSOAR as built</span>
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
        <div class="col">
            <h1 class="text-cortex">Purpose</h1>
            <p>This Document covers all of the custom configuration and content that has been deployed following
                the engagement of Palo Alto professional services.<br>
            </p>
            <h1 class="text-cortex">Document Overview</h1>
            <p>
                This document has been auto-generated using the XSOAR Automation <i>!GenerateAsBuilt</i>.
            </p>
            <h1 class="text-cortex">
                Project Details
            </h1>
            <textarea style="width:100%;border:none;"
                      placeholder="Click here to complete this section with any relevant details, for example customer
contat details, project scope, etc."></textarea>
            <h1 class="text-cortex">
                Contact Details
            </h1>
            <p>
                <b>Corporate Headquarters</b><br>
                Palo Alto Networks<br>
                3000 Tannery Way<br>
                Santa Clara, CA 95054<br>
            </p>
        </div>
    </div>
    <p style="page-break-after: always;"></p>

    <h1 class="text-cortex text-center">Project Statistics Summary</h1>
    <div class="row mb-2">
        <div class="col text-center p-2 border-bottom border-cortex">
            {{ open_incidents }}
        </div>
        <div class="col text-center p-2 border-bottom border-cortex">
            {{ closed_incidents }}
        </div>
    </div>

    {{ playbook_stats }}
    <p>
        The playbook statistics represent how many incidents have been ingested and associated with
        a given playbook.

        <br>This is a good indicator of how each use case is being consumed.
    </p>
    <p style="page-break-after: always;"></p>

    <h1 class="text-cortex text-center">All Installed Content</h1>

    {{ integrations_table }}
    <p>The system configuration above represents the server configuration of XSOAR, including advanced
        server config parameters such as HTTP proxy. This configuration is accessible via
        settings->about->troubleshooting.</p>
    <p style="page-break-after: always;"></p>

    {% if installed_packs_table %}
        {{ installed_packs_table }}
        <p>The installed packs are all the content packs currently installed on the server. Content packs
            include playbooks, automations, and in some cases, integrations.</p>
        <p style="page-break-after: always;"></p>
    {% endif %}

    {% if playbooks_table %}
        {{ playbooks_table }}
        <p>
            Custom playbooks are written specifically for this deployment, or adapted from existing OOTB playbooks.
            The tasks in each playbook represent the overall size and complexity of each developed playbook.
        </p>
        <p style="page-break-after: always;"></p>
    {% endif %}

    {% if automations_table %}
        {{ automations_table }}
        <p>
            Custom automations are used to add additional logic and support to playbooks and use cases.
        </p>
        <p style="page-break-after: always;"></p>
    {% endif %}

    {% if reports %}
        {{ reports }}
        <p>
            Custom reports can be scheduled or manually initiated reports that report any statistic available through
            XSOAR.
        </p>
        <p style="page-break-after: always;"></p>
    {% endif %}

    {% if dashboards %}
        {{ dashboards }}
        <p>
            Custom dashboards are a dynamic way to visualize statistics within XSOAR.<br><br>
            XSOAR ships with a number of Out Of the Box dashboards, the above respresent only
            those that have been created as part of this PS engagement.
        </p>
        <p style="page-break-after: always;"></p>
    {% endif %}

    {{ system_config }}
    <p>
        The system configuration changes the behavior of the XSOAR server/application itself, including
        keys and the published hostname.
    </p>
    <p style="page-break-after: always;"></p>
</div>
</body>
"""  # noqa: E501


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

    def search(self, search_key, search_value):
        for row in self.data:
            if search_key in row:
                value = row.get(search_key)
                if value == search_value:
                    return row


class SortedTableData(TableData):
    def __init__(self, data, name, sort_key):
        sorted_data = sorted(data, key=lambda i: i[sort_key].lower())
        super(SortedTableData, self).__init__(sorted_data, name)


class SingleFieldData:
    def __init__(self, name, data):
        self.data = data
        self.name = name

    def __bool__(self):
        return True

    def as_markdown(self):
        return f"### {self.name}\n{self.data}"

    def as_html(self):
        return f"""<h3>{self.name}</h3><span class="display-5">{self.data}</span>"""


class NoneTableData:
    """
    Empty data type, returns e
    """

    def __bool__(self):
        return False

    def as_markdown(self, *args, **kwargs):  # noqa: F841
        return ""

    def as_html(self, *args, **kwargs):  # noqa: F841
        return ""


class UseCaseDocument:
    """
    Generates a "use case" document, that is, a document that collates the dependencies and requiremnts of a
    given playbook ("use case") within a running XSOAR environment.
    """

    def __init__(
            self,
            playbook_name,
            dependencies
    ):
        self.playbook_name = playbook_name
        self.automations = dependencies.get("automation", NoneTableData())
        self.integrations = dependencies.get("integration", NoneTableData())
        self.playbooks = dependencies.get("playbook", NoneTableData())
        self.incidentfields = dependencies.get("incidentfield", NoneTableData())
        self.incidenttypes = dependencies.get("incidenttype", NoneTableData())
        self.author = demisto.args().get("author")
        self.date = datetime.now().strftime("%m/%d/%Y")
        self.customer = demisto.args().get("customer")

    def markdown(self):
        template = jinja2.Template(USECASE_MD_DOCUMENT_TEMPLATE)
        return template.render(
            playbook_name=self.playbook_name,
            data=self
        )

    def html(self):
        template = jinja2.Template(USECASE_HTML_DOCUMENT_TEMPLATE)
        return template.render(
            playbook_name=self.playbook_name,
            data=self
        )


class Document:
    """
    General Platform as-built document - designed to collate all of the configuration and settings of a running XSOAR
    instance and is not Specific t any given use case.
    """

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
            playbook_stats,
            reports,
            dashboards
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
        self.reports = reports
        self.dashboards = dashboards

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
            playbook_stats=self.playbook_stats.as_html(headers=["playbook", "incidents"]),
            reports=self.reports.as_html(headers=["name", "type"]),
            dashboards=self.dashboards.as_html(headers=["name", "shared"])
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
            playbook_stats=self.playbook_stats.as_markdown(headers=["playbook", "incidents"]),
            reports=self.reports.as_markdown(headers=["name", "type"]),
            dashboards=self.dashboards.as_markdown(headers=["name", "shared"]),
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
        # If it's a string and not an object response, means this command has failed.
        if type(res) is str:
            return None
        return res
    except KeyError:
        return_error(f'API Request failed, no response from API call to {url}')


def get_all_incidents(days=7, size=1000):
    body = {
        "userFilter": False,
        "filter": {
            "page": 0,
            "size": int(size),
            "query": "-category:job",
            "sort": [
                {
                    "field": "id",
                    "asc": False
                }
            ],
            "period": {
                "by": "day",
                "fromValue": int(days)
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
            "size": int(size),
            "query": "-status:closed -category:job",
            "sort": [
                {
                    "field": "id",
                    "asc": False
                }
            ],
            "period": {
                "by": "day",
                "fromValue": int(days)
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
            "size": int(size),
            "query": "status:closed -category:job",
            "sort": [
                {
                    "field": "id",
                    "asc": False
                }
            ],
            "period": {
                "by": "day",
                "fromValue": int(days)
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

    rd = SortedTableData(enabled_instances, "Enabled Instances", "name")

    return rd


def get_installed_packs():
    """
    Get all the installed Content Packs
    :return: TableData
    """
    # if tis doesn't work, return nothing.
    r = get_api_request(DEMISTO_INSTALLED_PATH)
    if not r:
        return NoneTableData()
    else:
        return SortedTableData(r, "Installed Content Packs", "name")


def get_custom_playbooks():
    """
    Return all the custom playbooks installed in XSOAR>
    :return: TableData
    """
    r = post_api_request(DEMISTO_PLAYBOOKS_PATH, {"query": "system:F AND hidden:F"}).get("playbooks")
    for pb in r:
        pb["TotalTasks"] = len(pb.get("tasks", []))
    rd = SortedTableData(r, "Custom Playbooks", "name")
    return rd


def get_custom_reports():
    """
    Return all the custom reports installed in XSOAR.
    :return: TableData
    """
    r = get_api_request(DEMISTO_REPORTS_PATH)
    reports = []
    for report in r:
        # Check it's not an inbuilt (system) report
        if not report.get("system"):
            reports.append(report)
    rd = TableData(reports, "Custom Reports")
    return rd


def get_custom_dashboards():
    """
    Return all the custom dashboards configured in XSOAR
    :return: TableData
    """
    r = get_api_request(DEMISTO_DASHBOARDS_PATH)
    dashboards = []
    for dashboard in r.values():
        # Check it's not an inbuilt (system) dashboard
        if not dashboard.get("system"):
            dashboards.append(dashboard)
    rd = TableData(dashboards, "Custom dashboards")
    return rd


def get_all_playbooks():
    """
    Return all the custom playbooks installed in XSOAR>
    :return: TableData
    """
    r = post_api_request(DEMISTO_PLAYBOOKS_PATH, {"query": "hidden:F"}).get("playbooks")
    for pb in r:
        pb["TotalTasks"] = len(pb.get("tasks", []))
    rd = TableData(r, "All Playbooks")
    return rd


def get_playbook_stats(playbooks, days=7, size=1000):
    """
    Pull all the incident types and assoociated playbooks,
    then join this with the incident stats to determine how often each playbook has been used.

    :param playbooks (TableData): Table Data of Playbooks
    """
    # incident_types = get_api_request(DEMISTO_INCIDENT_TYPE_PATH)
    incidents = get_all_incidents(days, size)
    playbook_stats = {}
    for incident in incidents:
        playbook = incident.get("playbookId")
        if playbook not in playbook_stats:
            playbook_stats[playbook] = 0

        playbook_stats[playbook] = playbook_stats[playbook] + 1

    table = []
    for playbook, count in playbook_stats.items():
        # Try to join this with the playbooks we previously retrieved to populate
        # more info.
        playbook_data = playbooks.search("id", playbook)
        if playbook_data:
            table.append({
                "playbook": playbook_data.get("name"),
                "incidents": count
            })
        else:
            table.append({
                "playbook": playbook,
                "incidents": count
            })
    td = TableData(table, "Playbook Stats")
    return td


def get_playbook_dependencies(playbook_name):
    """
    Given a playbook name, searches for all dependencies.
    """
    playbooks = get_all_playbooks()
    playbook = playbooks.search("name", playbook_name)
    if not playbook:
        return_error(f"Playbook {playbook_name} not found.")
        sys.exit()
    playbook_id = playbook.get("id")
    body = {
        "items": [
            {
                "id": f"{playbook_id}",
                "type": "playbook"
            }
        ],
        "dependencyLevel": "optional"
    }
    dependencies = post_api_request(DEMISTO_DEPENDENCIES_PATH, body).get("existing").get("playbook").get(playbook_id)
    if not dependencies:
        return_error(f"Failed to retrieve dependencies for {playbook_id}")

    types: dict = {}
    for dependency in dependencies:
        d_type = dependency.get("type")
        if d_type not in types:
            types[d_type] = []

        pack = dependency.get("packID", "Custom")
        if not pack:
            pack = "Custom"

        types[d_type].append({
            "type": d_type,
            "name": dependency.get("name"),
            "pack": pack
        })

    result_table_datas = {}
    for k, v in types.items():
        if v:
            td = SortedTableData(v, f"{k}s", sort_key="name")
            result_table_datas[k] = td

    return result_table_datas


def get_custom_automations():
    r = post_api_request(DEMISTO_AUTOMATIONS_PATH, {"query": "system:F AND hidden:F"}).get("scripts")
    rd = SortedTableData(r, "Custom Automations", "name")
    return rd


def get_system_config():
    r = get_api_request(DEMISTO_CONFIG_PATH).get("defaultMap")
    rd = TableData(r, "System Configuration")
    return rd


def main():
    if demisto.args().get("playbook"):
        # If we get a playbook, we generate a use case document, instead of teh platform as build
        r = get_playbook_dependencies(demisto.args().get("playbook"))
        doc = UseCaseDocument(
            playbook_name=demisto.args().get("playbook"),
            dependencies=r
        )
        fr = fileResult("usecase.html", doc.html(), file_type=EntryType.ENTRY_INFO_FILE)
        return_results(fr)
        return_results(CommandResults(
            readable_output=doc.markdown(),
        ))
        return

    # If no playbook is passed, we generate a platform as built.
    open_incidents = get_open_incidents(MAX_DAYS, MAX_REQUEST_SIZE)
    closed_incidents = get_closed_incidents(MAX_DAYS, MAX_REQUEST_SIZE)

    system_config = get_system_config()
    integrations = get_enabled_integrations()
    installed_packs = get_installed_packs()
    playbooks = get_custom_playbooks()
    automations = get_custom_automations()
    playbook_stats = get_playbook_stats(playbooks, MAX_DAYS, MAX_REQUEST_SIZE)

    reports = get_custom_reports()
    dashboards = get_custom_dashboards()

    d = Document(
        MD_DOCUMENT_TEMPLATE,
        system_config=system_config,
        integrations_table=integrations,
        installed_packs_table=installed_packs,
        playbooks_table=playbooks,
        automations_table=automations,
        open_incidents=open_incidents,
        closed_incidents=closed_incidents,
        playbook_stats=playbook_stats,
        reports=reports,
        dashboards=dashboards
    )
    fr = fileResult("asbuilt.html", d.html(), file_type=EntryType.ENTRY_INFO_FILE)
    return_results(CommandResults(
        readable_output=d.markdown(),
    ))
    return_results(fr)


if __name__ in ('__builtin__', 'builtins'):
    main()
