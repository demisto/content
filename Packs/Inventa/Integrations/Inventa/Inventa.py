import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


"""IMPORTS"""


import traceback
from typing import Any, Dict
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
empty_file = {
    "id": "",
    "timestamp": "",
    "name": "",
    "size": "",
    "path": "",
    "url": "",
    "entityTypes": ""
}
empty_transaction: Dict = {
}
empty_dataasset: Dict = {
    "id": "",
    "name": "",
    "piis": "",
    "reasonsOfProcessing": ""
}
empty_database: Dict = {
    "id": "",
    "name": "",
    "database": "",
    "entityTypes": ""
}
empty_pii: Dict = {
    "entities": []
}


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def get_entities(self):
        pii_entities = self._http_request(
            method="GET",
            url_suffix="/pii/api/configuration/categories",
            return_empty_response=True
        )
        return pii_entities

    def get_datasubject(self, **kwargs):
        pii_entities = format_pii_entities(self.get_entities())["entities"]

        payload = generate_datasubject_payload(pii_entities, **kwargs)

        found_piis = self._http_request(
            method="POST",
            url_suffix="/dsr/api/pii/find",
            return_empty_response=True,
            json_data=payload,
            retries=5)
        return found_piis

    def prepare_ticket(self, datasubject_id: Any, reason: str) -> Any:
        payload = {
            "askToErasure": None,
            "changeConsent": None,
            "dataPortability": None,
            "disputeRequest": None,
            "dataSubjectId": datasubject_id,
            "id": None,
            "reason": reason,
            "updateDataSubjectDetails": None
        }
        demisto.debug(f"{payload}")
        if datasubject_id:
            # create ticket id
            ticket_id = self._http_request(
                method="POST",
                json_data={"dataSubjectId": datasubject_id},
                url_suffix="/dsr/api/dsar-management/tickets",
                return_empty_response=True,
                retries=5
            )
            return ticket_id
        else:
            return None

    def create_ticket(self, datasubject_id: Any, reason: str) -> Dict[str, Any]:
        # new payload for ticket creation
        payload = {
            "askToErasure": None,
            "changeConsent": None,
            "dataPortability": None,
            "disputeRequest": None,
            "dataSubjectId": datasubject_id,
            "id": None,
            "reason": reason,
            "updateDataSubjectDetails": None
        }
        ticket_id = self.prepare_ticket(datasubject_id, reason)
        if ticket_id:
            demisto.debug(f"{ticket_id}")
            payload["id"] = str(ticket_id)
            demisto.debug(f"{payload}")
            # create actual ticket
            ticket_id = self._http_request(
                method="POST",
                json_data=payload,
                url_suffix="/dsr/api/dsar-management/tickets",
                return_empty_response=True,
                retries=5
            )
        return ticket_id

    def get_ticket(self, ticket_id: Any) -> Dict:
        result = self._http_request(
            method="GET",
            url_suffix=f"/dsr/api/dsar-management/tickets/{ticket_id}",
            return_empty_response=True,
            retries=5
        )
        return result

    def get_dsar(self, ticket_id: Any) -> Dict:
        ticket_details = self.get_ticket(ticket_id)
        demisto.debug(f"{ticket_details}")
        datasubject_id = ticket_details.get("piiId", "")
        demisto.debug(f"{datasubject_id}")

        return self._http_request(
            method="GET",
            url_suffix=f"/dsr/api/dsar-management/personal-data-usage/ticket/{ticket_id}",
            # url_suffix=f"/pii/api/piis/{datasubject_id}/sources",
            return_empty_response=True,
            retries=5
        )


''' HELPER FUNCTIONS '''


def format_pii_entities(pii_entities):
    entities_listed = [[subitem for subitem in pii_entities[item]] for item in pii_entities]
    # return entities_listed
    result = list()
    for item in entities_listed:
        result.extend(item)
    result = {"entities": [item["entityName"] for item in result]}
    return result


def generate_datasubject_payload(pii_entities, **kwargs):
    payload = []
    # fill initial payload
    for item in kwargs:
        if item.upper() in pii_entities:
            subpayload = {}
            subpayload["piiEntityType"] = item.upper()
            subpayload["piiEntityValue"] = kwargs[item]
            payload.append(subpayload)
    return payload


''' COMMAND FUNCTIONS '''


def get_entities_command(client: Client) -> CommandResults:

    pii_entities = client.get_entities()

    result = format_pii_entities(pii_entities)
    return CommandResults(
        outputs_prefix="Inventa.Entities",
        outputs_key_field="entity",
        outputs=result
    )


def get_datasubjects_command(client: Client, **kwargs) -> CommandResults:
    return CommandResults(outputs=client.get_datasubject(**kwargs),
                          outputs_prefix="Inventa.DataSubjects",
                          outputs_key_field="id")


def get_datasubject_id_command(client: Client, **kwargs) -> CommandResults:
    found_piis = client.get_datasubject(**kwargs)
    datasubs = found_piis.get("dataSubjects", [])
    if datasubs:
        datasubject_id = datasubs[0].get("id", "")
        return CommandResults(outputs={"datasubject_id": datasubject_id},
                              outputs_prefix="Inventa.DataSubjects",
                              outputs_key_field="datasubject_id")
    else:
        return CommandResults(outputs={"datasubject_id": 0},
                              outputs_prefix="Inventa.DataSubjects",
                              outputs_key_field="datasubject_id")


def create_ticket_command(client: Client, reason: str, datasubject_id: int) -> CommandResults:
    ticket_id = client.create_ticket(datasubject_id, reason)
    return CommandResults(outputs={"ticket_id": f"{ticket_id}"},
                          outputs_prefix="Inventa.DataSubjects.Ticket",
                          outputs_key_field="ticket_id")


def get_datasubjectid_from_ticket_command(client: Client, ticket_id: int) -> CommandResults:
    ticket_details = client.get_ticket(ticket_id)
    datasubject_id = ticket_details.get("piiId", "")
    return CommandResults(outputs={"datasubject_id": datasubject_id},
                          outputs_prefix="Inventa.DataSubjects",
                          outputs_key_field="datasubject_id")


def get_datasubject_details_command(client: Client, ticket_id: int) -> CommandResults:
    ticket_details = client.get_ticket(ticket_id)
    datasubject_name = ticket_details.get("name", "")
    datasubject_email = ticket_details.get("email", "")
    return CommandResults(outputs={"name": datasubject_name, "email": datasubject_email},
                          outputs_prefix="Inventa.DataSubject",
                          outputs_key_field="name")


def get_dsar_piis_command(client: Client, ticket_id: int) -> CommandResults:
    dsar = client.get_dsar(ticket_id)
    piis = dsar.get("piis", [])
    pii_list = list()
    for pii in piis:
        pii_list.append(pii.get("piiEntityType", ""))

    demisto.debug(f"{piis}")
    demisto.debug(f"{pii_list}")

    return CommandResults(outputs={"piis": list(set(pii_list))},
                          outputs_prefix="Inventa.Dsar.Piis")


def get_dsar_transactions_command(client: Client, ticket_id: int) -> CommandResults:
    dsar = client.get_dsar(ticket_id)
    transactions = dsar.get("copiesUsageData", {}).get("transactions", [])
    if "entityTypes" in transactions:
        transactions["entityTypes"] = [transactions["entityTypes"]["type"]
                                       for item in transactions["entityTypes"] if item == "type"]

    for transaction in transactions:
        demisto.debug(f"file: {transaction}")
        if "entityTypes" in transaction:
            entityTypes = transaction["entityTypes"]
            demisto.debug(f"types: {entityTypes}")
            stripped = [item["type"] for item in entityTypes]
            demisto.debug(f"stripped: {stripped}")
            transaction["entityTypes"] = stripped
    if transactions:
        return CommandResults(outputs={"transactions": transactions},
                              outputs_prefix="Inventa.Dsar.Transactions",
                              outputs_key_field="id")
    else:
        return CommandResults(outputs={"transactions": [empty_transaction]},
                              outputs_prefix="Inventa.Dsar.Transactions",
                              outputs_key_field="id")


def get_dsar_files_command(client: Client, ticket_id: int) -> CommandResults:
    dsar = client.get_dsar(ticket_id)
    demisto.debug(f"{dsar}")
    files = dsar.get("copiesUsageData", {}).get("files", [])
    demisto.debug(f"{files}")
    for file in files:
        # file.pop("path")
        # file.pop("url")
        demisto.debug(f"file: {file}")
        if "entityTypes" in file:
            entityTypes = file["entityTypes"]
            demisto.debug(f"types: {entityTypes}")
            stripped = [item["type"] for item in entityTypes]
            stripped = list(set(stripped))
            demisto.debug(f"types: {stripped}")
            file["entityTypes"] = ", ".join(stripped)
        if "timestamp" in file:
            ts = file.get("timestamp", 0)
            if type(ts) is int:
                file["timestamp"] = datetime.utcfromtimestamp(
                    float(f"{str(ts)[:10]}.{str(ts)[10:]}")).strftime("%d %b %Y %H:%M:%S")
            # file["entityTypes"] = stripped
    if files:
        return CommandResults(outputs={"files": files},
                              outputs_prefix="Inventa.Dsar.Files",
                              outputs_key_field="id")

    else:
        return CommandResults(outputs={"files": [empty_file]},
                              outputs_prefix="Inventa.Dsar.Files",
                              outputs_key_field="id")


def get_dsar_databases_command(client: Client, ticket_id: int) -> CommandResults:
    dsar = client.get_dsar(ticket_id)
    databases = dsar.get("copiesUsageData", {}).get("databases", [])
    tables = []
    for db in databases:
        demisto.debug(f"db: {db}")
        database_name = db.get("name", "")
        if "tables" in db:
            for table in db["tables"]:
                table["database"] = database_name

                if "entityTypes" in table:
                    entityTypes = table["entityTypes"]
                    stripped = [item["type"] for item in entityTypes]
                    stripped = list(set(stripped))
                    demisto.debug(f"types: {stripped}")
                    table["entityTypes"] = ", ".join(stripped)
                    # table["entityTypes"] = stripped

                tables.append(table)

    if databases:
        return CommandResults(outputs={"databases": tables},
                              outputs_prefix="Inventa.Dsar.Databases",
                              outputs_key_field="id")
    else:
        return CommandResults(outputs={"databases": [empty_database]},
                              outputs_prefix="Inventa.Dsar.Databases",
                              outputs_key_field="id")


def get_dsar_dataassets_command(client: Client, ticket_id: int) -> CommandResults:
    dsar = client.get_dsar(ticket_id)
    dataAssets = dsar.get("copiesUsageData", {}).get("dataAssets", [])
    for da in dataAssets:
        demisto.debug(f"file: {da}")
        if "piis" in da:
            entityTypes = da["piis"]
            if entityTypes:
                demisto.debug(f"types: {entityTypes}")
                stripped = [item["type"] for item in entityTypes]
                stripped = list(set(stripped))
                demisto.debug(f"types: {stripped}")
                da["piis"] = ", ".join(stripped)
            else:
                da["piis"] = "None"

        if "reasonsOfProcessing" in da:
            reasons = da["reasonsOfProcessing"]
            if reasons:
                da["reasonsOfProcessing"] = ', '.join(reasons)
            else:
                da["reasonsOfProcessing"] = "None"

    if dataAssets:
        demisto.debug(f"{dataAssets}")
        return CommandResults(outputs={"dataAssets": dataAssets},
                              outputs_prefix="Inventa.Dsar.DataAssets",
                              outputs_key_field="id")
    else:
        return CommandResults(outputs={"dataAssets": [empty_dataasset]},
                              outputs_prefix="Inventa.Dsar.DataAssets",
                              outputs_key_field="id")


def validate_incident_inputs_command(**kwargs):
    ticket_id = kwargs.get("ticket_id", "")
    datasubject_id = kwargs.get("datasubject_id", "")
    national_id = kwargs.get("national_id", "")
    passport_number = kwargs.get("passport_number", "")
    driver_license = kwargs.get("driver_license", "")
    tax_id = kwargs.get("tax_id", "")
    cc_number = kwargs.get("cc_number", "")
    given_name = kwargs.get("given_name", "")
    surname = kwargs.get("surname", "")
    full_name = kwargs.get("full_name", "")
    vehicle_number = kwargs.get("vehicle_number", "")
    phone_number = kwargs.get("phone_number", "")
    birthday = kwargs.get("birthday", "")
    city = kwargs.get("city", "")
    street_address = kwargs.get("street_address", "")
    reason = kwargs.get("reason", "")

    demisto.debug(f"{ticket_id}")
    demisto.debug(f"{datasubject_id}")

    constraints = [
        national_id,
        passport_number,
        driver_license,
        tax_id,
        cc_number,
        (given_name and vehicle_number),
        (given_name and phone_number),
        (given_name and surname and birthday),
        (given_name and surname and city and street_address),
        (full_name and birthday),
        (full_name and city and street_address)
    ]

    constraints_validated = False
    for constraint in constraints:
        if constraint:
            demisto.debug(f"{constraint}")
            constraints_validated = True
            break

    ticket_validated = False
    if ticket_id:
        ticket_validated = True
    datasubject_id_validated = False
    if datasubject_id:
        datasubject_id_validated = True

    demisto.debug("CONSTRAINTS")
    if constraints_validated and reason:
        return CommandResults(outputs={"validated": True},
                              outputs_prefix="Inventa.Incident",
                              outputs_key_field="validated")
    elif datasubject_id_validated and reason:
        return CommandResults(outputs={"validated": True},
                              outputs_prefix="Inventa.Incident",
                              outputs_key_field="validated")
    elif ticket_validated:
        return CommandResults(outputs={"validated": True},
                              outputs_prefix="Inventa.Incident",
                              outputs_key_field="validated")
    else:
        raise Exception("Validation failed: constraints missing. Check incident's inputs.")


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        client.get_entities()
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


'''FETCH INCIDENTS'''


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    try:
        # authentication
        api_key = demisto.params().get('apikey', "")

        # get the service API url
        base_url = demisto.params().get("url", '')

        # if your Client class inherits from BaseClient, SSL verification is
        # handled out of the box by it, just pass ``verify_certificate`` to
        # the Client constructor
        verify_certificate = not demisto.params().get('insecure', False)

        # if your Client class inherits from BaseClient, system proxy is handled
        # out of the box by it, just pass ``proxy`` to the Client constructor
        proxy = demisto.params().get('proxy', False)

        demisto.debug(f'Command being called is {demisto.command()}')

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers: Dict = {
            'Authorization': f"Bearer {api_key}"
        }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'inventa-get-datasubjects':
            return_results(get_datasubjects_command(client, **demisto.args()))

        elif demisto.command() == 'inventa-get-datasubject-id':
            return_results(get_datasubject_id_command(client, **demisto.args()))

        elif demisto.command() == 'inventa-create-ticket':
            return_results(create_ticket_command(client, **demisto.args()))

        elif demisto.command() == 'inventa-get-datasubject-details':
            return_results(get_datasubject_details_command(client, demisto.args().get("ticket_id", "")))

        elif demisto.command() == 'inventa-get-dsar-piis':
            return_results(get_dsar_piis_command(client, demisto.args().get("ticket_id", "")))

        elif demisto.command() == 'inventa-get-dsar-transactions':
            return_results(get_dsar_transactions_command(client, demisto.args().get("ticket_id", "")))

        elif demisto.command() == 'inventa-get-dsar-files':
            return_results(get_dsar_files_command(client, demisto.args().get("ticket_id", "")))

        elif demisto.command() == 'inventa-get-dsar-databases':
            return_results(get_dsar_databases_command(client, demisto.args().get("ticket_id", "")))

        elif demisto.command() == 'inventa-get-dsar-dataassets':
            return_results(get_dsar_dataassets_command(client, demisto.args().get("ticket_id", "")))

        elif demisto.command() == 'inventa-get-datasubject-id-from-ticket':
            return_results(get_datasubjectid_from_ticket_command(client, demisto.args().get("ticket_id", 0)))

        elif demisto.command() == 'inventa-get-entities':
            return_results(get_entities_command(client))

        elif demisto.command() == 'inventa-validate-incident-inputs':
            return_results(validate_incident_inputs_command(**demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
