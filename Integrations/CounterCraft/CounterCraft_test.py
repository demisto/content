import pytest
import demistomock as demisto
from CommonServerPython import formatEpochDate

SERVER_URL = "https://1.2.3.4"


@pytest.fixture(autouse=True)
def get_params(requests_mock, mocker):
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "server": SERVER_URL,
            "api_key": "1234567890",
            "secret_key": "s3cr3t",
            "insecure": False,
        },
    )


def test_list_dsns_command(requests_mock, mocker):

    from CounterCraft import list_dsns_command
    from test_data.api_response import response_dsns as json_response

    requests_mock.get(
        f"{SERVER_URL}/api/deception_support_nodes", json=json_response, status_code=200
    )

    mocker.patch.object(demisto, "results")
    list_dsns_command()
    results = demisto.results.call_args[0][0]
    assert (
        results["HumanReadable"]
        == "### Deception Support Node\n|Id|Name|Description|Hostname|Port|\n|---|---|---|---|---|\n| 2 | \
Remote DSN | Remote DSN | 1.2.3.3 | 7080 |\n| 1 | Local network | Local network | thedsn | 7080 |\n"
    )
    assert results["Contents"] == json_response["data"]
    assert results["EntryContext"] == {
        "CounterCraft.DSN(val.ID && val.ID === obj.ID)": [
            {
                "ID": 2,
                "Name": "Remote DSN",
                "Description": "Remote DSN",
                "Hostname": "1.2.3.3",
                "Port": 7080,
            },
            {
                "ID": 1,
                "Name": "Local network",
                "Description": "Local network",
                "Hostname": "thedsn",
                "Port": 7080,
            },
        ]
    }


def test_list_providers_command(requests_mock, mocker):

    from CounterCraft import list_providers_command

    from test_data.api_response import response_providers as json_response

    requests_mock.get(
        f"{SERVER_URL}/api/providers", json=json_response, status_code=200
    )

    mocker.patch.object(demisto, "results")
    list_providers_command()
    results = demisto.results.call_args[0][0]
    assert (
        results["HumanReadable"]
        == "### Providers\n|Id|Name|Description|Typecode|Statuscode|\n|---|---|---|---|---|\n| 1 | \
ManualMachine | Hosts that are manually created | MANUAL_MACHINE | ACTIVE |\n| 2 | CompanyProvider | \
Hosts that are automatically created when activating breadcrumbs | COMPANY_PROVIDER | ACTIVE |\n| 3 | \
ManualIdentity | Identities that are manually created | MANUAL_IDENTITY | ACTIVE |\n| 4 | ManualRouter | \
Routers that are manually created | MANUAL_ROUTER | ACTIVE |\n| 5 | MISP Provider |  | MISP_PROVIDER | ACTIVE |\n"
    )
    assert results["Contents"] == json_response["data"]
    assert results["EntryContext"] == {
        "CounterCraft.Provider(val.ID && val.ID === obj.ID)": [
            {
                "ID": 1,
                "Name": "ManualMachine",
                "Description": "Hosts that are manually created",
                "TypeCode": "MANUAL_MACHINE",
                "StatusCode": "ACTIVE",
            },
            {
                "ID": 2,
                "Name": "CompanyProvider",
                "Description": "Hosts that are automatically created when activating breadcrumbs",
                "TypeCode": "COMPANY_PROVIDER",
                "StatusCode": "ACTIVE",
            },
            {
                "ID": 3,
                "Name": "ManualIdentity",
                "Description": "Identities that are manually created",
                "TypeCode": "MANUAL_IDENTITY",
                "StatusCode": "ACTIVE",
            },
            {
                "ID": 4,
                "Name": "ManualRouter",
                "Description": "Routers that are manually created",
                "TypeCode": "MANUAL_ROUTER",
                "StatusCode": "ACTIVE",
            },
            {
                "ID": 5,
                "Name": "MISP Provider",
                "TypeCode": "MISP_PROVIDER",
                "StatusCode": "ACTIVE",
            },
        ]
    }


def test_list_campaigns_command(requests_mock, mocker):

    from CounterCraft import list_campaigns_command
    from test_data.api_response import response_campaigns as json_response

    requests_mock.get(
        f"{SERVER_URL}/api/campaigns", json=json_response, status_code=200
    )

    mocker.patch.object(demisto, "results")
    list_campaigns_command()
    results = demisto.results.call_args[0][0]

    assert (
        results["HumanReadable"]
        == "### Campaigns\n|Id|Name|Description|Statuscode|\n|---|---|---|---|\n| 1 | \
Devel Campaign | Campaign just to be used in devel | DESIGN |\n| 2 | 2nd Campaign | \
Campaign just to be used in devel 2 | DESIGN |\n"
    )
    assert results["Contents"] == json_response["data"]
    assert results["EntryContext"] == {
        "CounterCraft.Campaign(val.ID && val.ID === obj.ID)": [
            {
                "ID": 1,
                "Name": "Devel Campaign",
                "Description": "Campaign just to be used in devel",
                "StatusCode": "DESIGN",
            },
            {
                "ID": 2,
                "Name": "2nd Campaign",
                "Description": "Campaign just to be used in devel 2",
                "StatusCode": "DESIGN",
            },
        ]
    }


def test_list_hosts_command(requests_mock, mocker):

    from CounterCraft import list_hosts_command
    from test_data.api_response import response_hosts as json_response

    requests_mock.get(f"{SERVER_URL}/api/hosts", json=json_response, status_code=200)

    mocker.patch.object(demisto, "results")
    list_hosts_command()
    results = demisto.results.call_args[0][0]

    assert (
        results["HumanReadable"]
        == "### Hosts\n|Id|Name|Description|Statuscode|Typecode|\n|---|---|---|---|---|\n| 1 | \
Linux in AWS | Linux machine in AWS | DESIGN | MACHINE |\n"
    )
    assert results["Contents"] == json_response["data"]
    assert results["EntryContext"] == {
        "CounterCraft.Host(val.ID && val.ID === obj.ID)": [
            {
                "ID": 1,
                "Name": "Linux in AWS",
                "Description": "Linux machine in AWS",
                "TypeCode": "MACHINE",
                "StatusCode": "DESIGN",
            }
        ],
        'Host(val.IP && val.IP === obj.IP)': [
            {
                'ID': '61daa693-11cf-49a6-8fae-5111f630ee39',
                'IP': '1.4.5.6'
            }
        ]
    }


def test_list_services_command(requests_mock, mocker):

    from CounterCraft import list_services_command
    from test_data.api_response import response_services as json_response

    requests_mock.get(f"{SERVER_URL}/api/services", json=json_response, status_code=200)

    mocker.patch.object(demisto, "results")
    list_services_command()
    results = demisto.results.call_args[0][0]

    assert (
        results["HumanReadable"]
        == "### Services\n|Id|Name|Description|Statuscode|Typecode|\n|---|---|---|---|---|\n| 1 | \
Employee web portal | <p>-</p> | ACTIVE | WEB_SERVER |\n| 2 | Test | <p>-</p> | DESIGN | WEB_SERVER |\n"
    )
    assert results["Contents"] == json_response["data"]
    assert results["EntryContext"] == {
        "CounterCraft.Service(val.ID && val.ID === obj.ID)": [
            {
                "ID": 1,
                "Name": "Employee web portal",
                "Description": "<p>-</p>",
                "TypeCode": "WEB_SERVER",
                "StatusCode": "ACTIVE",
            },
            {
                "ID": 2,
                "Name": "Test",
                "Description": "<p>-</p>",
                "TypeCode": "WEB_SERVER",
                "StatusCode": "DESIGN",
            },
        ]
    }


def test_list_breadcrumbs_command(requests_mock, mocker):

    from CounterCraft import list_breadcrumbs_command
    from test_data.api_response import response_breadcrumbs as json_response

    requests_mock.get(
        f"{SERVER_URL}/api/breadcrumbs", json=json_response, status_code=200
    )

    mocker.patch.object(demisto, "results")
    list_breadcrumbs_command()
    results = demisto.results.call_args[0][0]

    assert (
        results["HumanReadable"]
        == "### Breadcrumbs\n|Id|Name|Description|Statuscode|Typecode|\n|---|---|---|---|---|\n| 1 | \
Fake Document | <p>-</p> | DESIGN | DOCUMENT |\n| 2 | Fake Mobile App | <p>-</p> | ACTIVE | MOBILE_APP |\n"
    )
    assert results["Contents"] == json_response["data"]
    assert results["EntryContext"] == {
        "CounterCraft.Breadcrumb(val.ID && val.ID === obj.ID)": [
            {
                "ID": 1,
                "Name": "Fake Document",
                "Description": "<p>-</p>",
                "TypeCode": "DOCUMENT",
                "StatusCode": "DESIGN",
            },
            {
                "ID": 2,
                "Name": "Fake Mobile App",
                "Description": "<p>-</p>",
                "TypeCode": "MOBILE_APP",
                "StatusCode": "ACTIVE",
            },
        ]
    }


def test_list_incidents_command(requests_mock, mocker):

    from CounterCraft import list_incidents_command
    from test_data.api_response import response_incidents as json_response

    requests_mock.get(
        f"{SERVER_URL}/api/incidents", json=json_response, status_code=200
    )

    mocker.patch.object(demisto, "results")
    list_incidents_command()
    results = demisto.results.call_args[0][0]

    assert (
        results["HumanReadable"]
        == "### Incidents\n|Id|Name|Description|Statuscode|Tlpcode|Tags|\n|---|---|---|---|---|---|\n| 1 | \
Invalid auth | Invalid auth incident. | OPEN | GREEN |  |\n"
    )
    assert results["Contents"] == json_response["data"]
    assert results["EntryContext"] == {
        "CounterCraft.Incident(val.ID && val.ID === obj.ID)": [
            {
                "ID": 1,
                "Name": "Invalid auth",
                "Description": "Invalid auth incident.",
                "StatusCode": "OPEN",
                "TLPCode": "GREEN",
            }
        ]
    }


def test_get_object_command(requests_mock, mocker):

    from CounterCraft import get_object_command
    from test_data.api_response import response_objects as json_response

    mocker.patch.object(demisto, "args", return_value={"value": "1.2.3.3"})

    requests_mock.get(f"{SERVER_URL}/api/objects", json=json_response, status_code=200)

    mocker.patch.object(demisto, "results")
    get_object_command()
    results = demisto.results.call_args[0][0]

    assert (
        results["HumanReadable"]
        == f"### Objects\n|Id|Value|Hits|Eventscount|Typecode|Score|Firstseen|Lastseen|Tags|\n|\
---|---|---|---|---|---|---|---|---|\n| 1411 | 1.2.3.3 | 370 | 168 | CC_IP | 0 | \
{formatEpochDate(json_response['data'][0]['first_seen'])} | {formatEpochDate(json_response['data'][0]['last_seen'])} |  |\n"
    )

    # Only dates have been changed
    results["Contents"][0]["first_seen"] = 1507030039.331
    results["Contents"][0]["last_seen"] = 1507313997.703
    assert results["Contents"] == json_response["data"]
    assert results["EntryContext"] == {
        "CounterCraft.Object(val.ID && val.ID === obj.ID)": [
            {
                "ID": 1411,
                "Value": "1.2.3.3",
                "Hits": 370,
                "Score": 0,
                "TypeCode": "CC_IP",
                "FirstSeen": f"{formatEpochDate(json_response['data'][0]['first_seen'])}",
                "LastSeen": f"{formatEpochDate(json_response['data'][0]['last_seen'])}",
                "EventsCount": 168,
            }
        ]
    }


def test_get_events_command(requests_mock, mocker):

    from CounterCraft import get_events_command
    from test_data.api_response import response_events as json_response

    mocker.patch.object(
        demisto,
        "args",
        return_value={"criteria": "type_code:ValidAuth", "max_results": 1},
    )

    requests_mock.get(f"{SERVER_URL}/api/events", json=json_response, status_code=200)

    mocker.patch.object(demisto, "results")
    get_events_command()
    results = demisto.results.call_args[0][0]

    assert (
        results["HumanReadable"]
        == f"### Events\n|Id|Campaignname|Categorycode|Hostname|Servicename|Eventdate|Score|\
Typecode|Data|Tags|\n|---|---|---|---|---|---|---|---|---|---|\n| 7882 | Linux Campaign |  | \
Ubuntu18.04 | SYSTEM (Ubuntu18.04) | {formatEpochDate(json_response['data'][0]['event_date'])} | 100 | ValidAuth | \
event: ValidAuth<br>subject: Login successful<br>username: ubuntu<br>logon_type: -1<br>process_basename: su | \
attack.T1078 |\n"
    )

    # Only dates have been changed
    results["Contents"][0]["event_date"] = 1570049630.0
    assert results["Contents"] == json_response["data"]
    assert results["EntryContext"] == {
        "CounterCraft.Event(val.ID && val.ID === obj.ID)": [
            {
                "ID": 7882,
                "CampaignName": "Linux Campaign",
                "HostName": "Ubuntu18.04",
                "ServiceName": "SYSTEM (Ubuntu18.04)",
                "EventDate": f"{formatEpochDate(json_response['data'][0]['event_date'])}",
                "Score": 100,
                "TypeCode": "ValidAuth",
                "Data": {
                    "event": "ValidAuth",
                    "subject": "Login successful",
                    "username": "ubuntu",
                    "logon_type": -1,
                    "process_basename": "su",
                },
                "Tags": ["attack.T1078"],
            }
        ]
    }


def test_create_campaign_command(requests_mock, mocker):

    from CounterCraft import create_campaign_command
    from test_data.api_response import response_campaigns as json_response

    mocker.patch.object(
        demisto,
        "args",
        return_value={"name": "TestCampaign", "description": "Test Description"},
    )

    requests_mock.post(
        f"{SERVER_URL}/api/campaigns", json=json_response["data"][0], status_code=201
    )

    mocker.patch.object(demisto, "results")
    create_campaign_command()
    results = demisto.results.call_args[0][0]

    assert (
        results["HumanReadable"]
        == "### Campaign\n|Id|Name|Description|Statuscode|\n|---|---|---|---|\n| 1 | Devel Campaign | \
Campaign just to be used in devel | DESIGN |\n"
    )

    assert results["Contents"] == json_response["data"][0]
    assert results["EntryContext"] == {
        "CounterCraft.Campaign(val.ID && val.ID === obj.ID)": {
            "ID": 1,
            "Name": "Devel Campaign",
            "Description": "Campaign just to be used in devel",
            "StatusCode": "DESIGN",
        }
    }


def test_manage_campaign_command(requests_mock, mocker):

    from CounterCraft import manage_campaign_command

    mocker.patch.object(
        demisto, "args", return_value={"campaign_id": "1", "operation": "activate"},
    )

    requests_mock.patch(
        f"{SERVER_URL}/api/campaigns/1",
        json={"message": "Action successful"},
        status_code=200,
    )

    mocker.patch.object(demisto, "results")
    manage_campaign_command()
    results = demisto.results.call_args[0][0]

    assert (
        results["HumanReadable"]
        == "### Campaign Management\n|Id|Message|\n|---|---|\n| 1 | Action successful |\n"
    )

    assert results["Contents"] == {"message": "Action successful"}
    assert results["EntryContext"] == {
        "CounterCraft.Campaign(val.ID && val.ID === obj.ID)": [
            {"ID": "1", "Message": "Action successful"}
        ]
    }


def test_create_host_command(requests_mock, mocker):

    from CounterCraft import create_host_machine_command
    from test_data.api_response import response_hosts as json_response

    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "name": "TestCampaign",
            "description": "Test Description",
            "provider_id": 1,
            "deception_support_node_id": 1,
            "campaign_id": 1,
            "ip_address": "1.1.1.1",
            "port": 22,
            "username": "ubuntu",
            "password": "password",
        },
    )

    requests_mock.post(
        f"{SERVER_URL}/api/hosts", json=json_response["data"][0], status_code=201
    )

    mocker.patch.object(demisto, "results")
    create_host_machine_command()
    results = demisto.results.call_args[0][0]

    assert (
        results["HumanReadable"]
        == "### Hosts\n|Id|Name|Description|Statuscode|Typecode|\n|---|---|---|---|---|\n| 1 | \
Linux in AWS | Linux machine in AWS | DESIGN | MACHINE |\n"
    )

    assert results["Contents"] == json_response["data"][0]
    assert results["EntryContext"] == {
        "CounterCraft.Host(val.ID && val.ID === obj.ID)": {
            "ID": 1,
            "Name": "Linux in AWS",
            "Description": "Linux machine in AWS",
            "TypeCode": "MACHINE",
            "StatusCode": "DESIGN",
        }
    }


def test_manage_host_command(requests_mock, mocker):

    from CounterCraft import manage_host_command

    mocker.patch.object(
        demisto, "args", return_value={"host_id": "1", "operation": "activate"},
    )

    requests_mock.patch(
        f"{SERVER_URL}/api/hosts/1",
        json={"message": "Action successful"},
        status_code=200,
    )

    mocker.patch.object(demisto, "results")
    manage_host_command()
    results = demisto.results.call_args[0][0]

    assert (
        results["HumanReadable"]
        == "### Host Management\n|Id|Message|\n|---|---|\n| 1 | Action successful |\n"
    )

    assert results["Contents"] == {"message": "Action successful"}
    assert results["EntryContext"] == {
        "CounterCraft.Host(val.ID && val.ID === obj.ID)": {
            "ID": "1",
            "Message": "Action successful",
        }
    }


def test_manage_service_command(requests_mock, mocker):

    from CounterCraft import manage_service_command

    mocker.patch.object(
        demisto, "args", return_value={"service_id": "1", "operation": "activate"},
    )

    requests_mock.patch(
        f"{SERVER_URL}/api/services/1",
        json={"message": "Action successful"},
        status_code=200,
    )

    mocker.patch.object(demisto, "results")
    manage_service_command()
    results = demisto.results.call_args[0][0]

    assert (
        results["HumanReadable"]
        == "### Service Management\n|Id|Message|\n|---|---|\n| 1 | Action successful |\n"
    )

    assert results["Contents"] == {"message": "Action successful"}
    assert results["EntryContext"] == {
        "CounterCraft.Service(val.ID && val.ID === obj.ID)": {
            "ID": "1",
            "Message": "Action successful",
        }
    }


def test_manage_breadcrumb_command(requests_mock, mocker):

    from CounterCraft import manage_breadcrumb_command

    mocker.patch.object(
        demisto, "args", return_value={"breadcrumb_id": "1", "operation": "activate"},
    )

    requests_mock.patch(
        f"{SERVER_URL}/api/breadcrumbs/1",
        json={"message": "Action successful"},
        status_code=200,
    )

    mocker.patch.object(demisto, "results")
    manage_breadcrumb_command()
    results = demisto.results.call_args[0][0]

    assert (
        results["HumanReadable"]
        == "### Breadcrumb Management\n|Id|Message|\n|---|---|\n| 1 | Action successful |\n"
    )

    assert results["Contents"] == {"message": "Action successful"}
    assert results["EntryContext"] == {
        "CounterCraft.Breadcrumb(val.ID && val.ID === obj.ID)": {
            "ID": "1",
            "Message": "Action successful",
        }
    }


def test_fetch_incidents_command(requests_mock, mocker):

    from CounterCraft import fetch_incidents_command
    from test_data.api_response import response_alerts as json_response

    requests_mock.get(
        f"{SERVER_URL}/api/notifications", json=json_response, status_code=200,
    )

    mocker.patch.object(demisto, "incidents")
    fetch_incidents_command()
    incidents = demisto.incidents.call_args[0][0]
    assert demisto.incidents.call_count == 1
    assert len(incidents) == 1
    assert incidents[0]["name"] == "Possible mimikatz"
