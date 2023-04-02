from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from collections.abc import Callable

import urllib3
import traceback
from urllib.parse import urlparse

from gql import gql, Client
from gql.transport.requests import RequestsHTTPTransport
from requests.auth import HTTPBasicAuth

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

create_incident_mutation = gql("""
mutation CreateIncident(
  $severity: String!,
  $name: String!,
  $type: String!,
  $description: String
) {
  createIncident(
    type: $type,
    severity: $severity,
    name: $name,
    description: $description
  ) {
    id
    name
    severity {
      name
    }
    types {
      type {
        name
      }
    }
    description
    identifier
  }
}""")

get_incident_severities = gql("""{
  incidentSeverities {
    name
    ordering
  }
}""")

get_incident_types = gql("""{
  types {
    name
  }
}""")

get_actions_for_incident = gql("""
query GetActionsForIncident($incidentId: Int!) {
  actions(where: {
    incidentId: {
      equals: $incidentId
    }
  }) {
    id
    name
    description
    phase {
      name
      id
    }
    user {
      fullName
      email
    }
  }
}""")

get_incident_by_name = gql("""
query GetIncidentByName($name: String, $identifier: String) {
  incidents(first: 1, where: {
    name: {
      contains: $name,
      mode: insensitive
    }
    identifier: {
      contains: $identifier,
      mode: insensitive
    }
  }) {
    id
    name
    severity {
      name
    }
    types {
      type {
        name
      }
    }
    description
    identifier
  }
}""")


class BreachRxClient:
    def __init__(self, base_url: str, api_key: str, secret_key: str, org_name: str, verify: bool):
        self.api_key = api_key
        self.secret_key = secret_key
        self.org_name = org_name

        auth = HTTPBasicAuth(api_key, secret_key)

        transport = RequestsHTTPTransport(
            url=base_url,
            auth=auth,
            headers={"orgname": org_name},
            timeout=60,
            verify=verify
        )

        self.client = Client(
            transport=transport, fetch_schema_from_transport=False
        )

    def get_incident_severities(self):
        return self.client.execute(get_incident_severities)["incidentSeverities"]

    def get_incident_types(self):
        return self.client.execute(get_incident_types)["types"]

    def create_incident(self, name: Optional[str], description: Optional[str]):
        severities = self.get_incident_severities()
        types = self.get_incident_types()

        params = {
            "severity": severities[0]["name"],
            "name": name,
            "type": types[0]["name"],
            "description": description
        }
        return self.client.execute(create_incident_mutation, params)["createIncident"]

    def get_incident(self, name: Optional[str], identifier: Optional[str]):
        params = {
            "name": name,
            "identifier": identifier
        }
        results = self.client.execute(get_incident_by_name, params)['incidents']

        if results:
            return results.pop()
        else:
            return None

    def get_actions_for_incident(self, incident_id):
        params = {
            "incidentId": incident_id
        }

        return self.client.execute(get_actions_for_incident, params)["actions"]


def test_module(client: BreachRxClient):
    try:
        client.get_incident_severities()
        return "ok"
    except Exception:
        raise Exception("Authorization Error: make sure your API Key and Secret Key are correctly set")


def create_incident_command(
    client: BreachRxClient,
    incident_name: str = None,
    description: str = None
) -> CommandResults:
    if not incident_name:
        incident_name = demisto.incident().get("name")
    if not description:
        description = (
            f"""An Incident copied from the Palo Alto Networks XSOAR platform.
            <br>
            <br>
            XSOAR Incident Name: {demisto.incident().get('name')}"""
        )

    response = client.create_incident(incident_name, description)

    incident_name = response["name"]

    return CommandResults(
        outputs_prefix="BreachRx.Incident",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
        readable_output=f"Incident created with name={incident_name}."
    )


def get_incident_actions_command(
    client: BreachRxClient,
    incident_name: str = None,
    incident_identifier: str = None
) -> Union[CommandResults, str]:
    incidents = demisto.dt(demisto.context(), 'BreachRx.Incident')

    if not incidents:
        if not incident_name and not incident_identifier:
            raise Exception(
                "Error: No BreachRx privacy Incident associated with this Incident,"
                " and no Incident search terms provided."
            )

        incidents = [client.get_incident(incident_name, incident_identifier)]

        if not incidents:
            raise Exception("Error: No BreachRx privacy Incident found using the search terms provided.")

    if type(incidents) is not list:
        incidents = [incidents]

    for incident in incidents:
        incident["actions"] = client.get_actions_for_incident(incident['id'])

        for action in incident["actions"]:
            action["phase_name"] = action["phase"]["name"]

    readable_output = ""

    for incident in incidents:
        actions_markdown_table = tableToMarkdown("Actions", incident["actions"], headers=["name", "phase_name"])
        readable_output += f"# {incident['name']} ({incident['id']})\n" + actions_markdown_table + "\n"

    return CommandResults(
        outputs_prefix="BreachRx.Incident",
        outputs_key_field="id",
        outputs=incidents,
        raw_response=incidents,
        readable_output=readable_output
    )


def import_incident_command(
    client: BreachRxClient,
    incident_name: str = None,
    incident_identifier: str = None
) -> Union[CommandResults, str]:
    incident = client.get_incident(incident_name, incident_identifier)

    if not incident:
        raise Exception("Error: No BreachRx privacy Incident found using the search terms provided.")

    return CommandResults(
        outputs_prefix="BreachRx.Incident",
        outputs_key_field="id",
        outputs=incident,
        raw_response=incident,
        readable_output=f"Incident imported with name={incident.get('name')}."
    )


def get_incident_command(
    client: BreachRxClient,
    incident_name: str = None,
    incident_identifier: str = None
) -> Union[CommandResults, str]:
    incident = client.get_incident(incident_name, incident_identifier)

    if incident:
        return CommandResults(
            raw_response=incident,
            readable_output=f'Incident found with name="{incident.get("name")}" and identifier="{incident.get("identifier")}".'
        )
    else:
        return "No Incident found with those search terms."


COMMANDS = {
    "test-module": test_module,
    "breachrx-incident-create": create_incident_command,
    "breachrx-incident-actions-get": get_incident_actions_command,
    "breachrx-incident-import": import_incident_command,
    "breachrx-incident-get": get_incident_command,
}


def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


def main() -> None:  # pragma: no cover
    try:
        base_url = demisto.params()["api_url"]
        org_name = demisto.params()["url"].split(".")[0].replace("https://", "")
        api_key = demisto.params().get("credentials", {}).get("identifier")
        secret_key = demisto.params().get("credentials", {}).get("password")
        verify = demisto.params().get("insecure", False)

        if not is_valid_url(base_url):
            raise Exception("The GraphQL API URL is not a valid URL.")

        if not is_valid_url(demisto.params()["url"]):
            raise Exception("The BreachRx instance URL is not a valid URL.")

        client = BreachRxClient(base_url, api_key, secret_key, org_name, verify)

        command_func: Any[Callable, None] = COMMANDS.get(demisto.command())

        if command_func:
            return_results(command_func(client, **demisto.args()))
        else:
            raise NotImplementedError(f'{demisto.command()} command is not implemented.')
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
