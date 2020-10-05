"""HelloWorld Integration for Cortex XSOAR - Unit Tests file

This file contains the Unit Tests for the HelloWorld Integration based
on pytest. Cortex XSOAR contribution requirements mandate that every
integration should have a proper set of unit tests to automatically
verify that the integration is behaving as expected during CI/CD pipeline.

Test Execution
--------------

Unit tests can be checked in 3 ways:
- Using the command `lint` of demisto-sdk. The command will build a dedicated
  docker instance for your integration locally and use the docker instance to
  execute your tests in a dedicated docker instance.
- From the command line using `pytest -v` or `pytest -vv`
- From PyCharm

Example with demisto-sdk (from the content root directory):
demisto-sdk lint -i Packs/HelloWorld/Integrations/HelloWorld

Coverage
--------

There should be at least one unit test per command function. In each unit
test, the target command function is executed with specific parameters and the
output of the command function is checked against an expected output.

Unit tests should be self contained and should not interact with external
resources like (API, devices, ...). To isolate the code from external resources
you need to mock the API of the external resource using pytest-mock:
https://github.com/pytest-dev/pytest-mock/

In the following code we configure requests-mock (a mock of Python requests)
before each test to simulate the API calls to the HelloWorld API. This way we
can have full control of the API behavior and focus only on testing the logic
inside the integration code.

We recommend to use outputs from the API calls and use them to compare the
results when possible. See the ``test_data`` directory that contains the data
we use for comparison, in order to reduce the complexity of the unit tests and
avoding to manually mock all the fields.

NOTE: we do not have to import or build a requests-mock instance explicitly.
requests-mock library uses a pytest specific mechanism to provide a
requests_mock instance to any function with an argument named requests_mock.

More Details
------------

More information about Unit Tests in Cortex XSOAR:
https://xsoar.pan.dev/docs/integrations/unit-testing

"""

import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_entity_get(requests_mock):
    """Tests entity_get_command command function.

    Configures requests_mock instance to generate the appropriate search
    API response. Checks the output of the command function with the expected output.
    """
    from XMCyberIntegration import Client, entity_get_command

    mock_response = {"paging":{"page":1,"pageSize":100,"total":1,"totalPages":1},"data":[{"_id":"5f476813262923a05fc1c969","isAlwaysStartingPoint":False,"attackedByTechniques":[{"technique":"Exploit::DnsHeapOverflow","displayName":"DNS Heap Overflow (CVE-2018-8626)","count":46},{"technique":"SIGRed","displayName":"SIGRed (CVE-2020-1350)","count":34}],"totalVectors":80,"agentId":"3110337924893579985","name":"CorporateDC","productType":"DomainController","os":{"type":"Windows","version":{"major":6,"minor":3,"patch":9600,"build":0},"servicePack":{"major":0,"minor":0,"patch":0,"build":0},"distributionName":"","distributionVersion":"","name":"Windows Server 2012 R2 (DC)"},"arch":"amd64","ipv4":["rABkAQ=="],"ipv6":["/oAAAAAAAAACAF7+rABkAQ=="],"agentVersion":{"major":1,"minor":5,"patch":798,"build":0},"latestPossibleAgentVersion":{"major":1,"minor":5,"patch":798,"build":0},"hasUpdateAvailable":False,"lastConnectionTime":"2020-09-26T00:44:43.231Z","status":"active","lastStatusChange":"2020-09-26T00:44:43.231Z","lastDisconnectionReason":"DisconnectionReason_Fuse_TooMuchCPU","remoteAddress":"172.0.100.1","notReportedBySouthAt":None,"firstSeen":"2020-04-28T06:37:24.726Z","disabled":False,"disabledChangedAt":None,"disabledReason":None,"timeToReviveAt":None,"nameUppercase":"CORPORATEDC","cmId":"0000","customProperties":{"snifferStatus":"Active","snifferStatusChangeable":True,"domainWorkgroup":{"type":"domain","data":"Corporate.xm"},"ouComputer":"Corporate.xm/Domain Controllers/","ouUser":"Corporate.xm/","subnetInfo":"172.0.100.0/24","labels":[{"label":"dns_server"},{"label":"spooler"},{"label":"dc"}],"mdatpMachineId":"19511d11002347bafa68650f283d034f2e30aebf"},"agentVersionStr":"1.5.798","latestPossibleAgentVersionStr":"1.5.798","ipv4Str":["172.0.100.1"],"ipv6Str":["fe80::200:5efe:ac00:6401"],"securityFlags":{},"inActiveWorkingSet":True,"activeWorkingSetLastPick":"2020-09-30T06:42:59.229Z","markedForUpdate":False,"lastUpdateAttempt":"2020-08-26T12:29:49.622Z","autoUpdate":True,"lastUpdateResult":"Updated Successfully","vulnerabilities":728,"patches":32,"maxCvssV3":10,"availabilityChanges":[{"timestamp":"2020-09-30T06:48:31.301Z","available":True}],"color":"red","joinedCampaignAt":"2020-09-30T06:48:31.989Z","entityId":"3110337924893579985","entityType":"node","entityTypeDisplayName":"Sensor","entitySubType":{"name":"osType","displayName":"OS Type","value":"windows","displayValue":"Windows"},"entityBasicData":{"entityFlavorProperties":[{"name":"osName","displayName":"OS","value":"Windows Server 2012 R2 (DC)","displayValue":"Windows Server 2012 R2 (DC)"}],"entityNetworkIdentifierProperties":[{"name":"ipv4","displayName":"Private IP Address","value":[172,0,100,1],"displayValue":"172.0.100.1"}]},"entityExtraData":[{"name":"publicIp","displayName":"Public IP Address","value":[172,0,100,1],"displayValue":"172.0.100.1"}],"displayName":"CorporateDC","title":"CorporateDC","compromised":True,"compromisedRate":{"compromised":58,"total":115,"score":0.5043478260869565,"level":"high"},"tags":["dns_server","spooler","dc"],"discovered":True,"discoveredAt":"2020-09-30T06:49:12.023Z","lastBecameRedAt":"2020-09-30T07:19:31.283Z","asset":True,"assetAt":"2020-09-30T06:48:36.292Z","becameRedAt":"2020-09-30T07:19:31.051Z","startingPoint":True,"startingPointAt":"2020-09-30T06:45:27.324Z","timeId":"timeAgo_days_7","scenarioId":None,"snapshotMetadata":{"snapshotFromDate":"2020-09-23T08:00:00.000Z","snapshotToDate":"2020-09-30T08:00:00.000Z","jobId":"110","snapshotCreatedAt":"2020-09-30T08:00:55.253Z"},"affectedUniqueAssets":{"count":{"value":14,"score":0.18666666666666668,"level":"medium"}},"affectedUniqueEntities":{"count":{"value":29,"score":0.05697445972495088,"level":"medium"}},"affectedEntities":{"max":{"value":96},"min":{"value":1},"avg":{"value":11.25,"score":0.05,"level":"low"},"count":{"value":124}},"affectedAssets":{"max":{"value":11},"min":{"value":0},"avg":{"value":0.32,"score":0.05,"level":"low"},"count":{"value":124}},"attackComplexity":{"max":{"value":2},"min":{"value":2,"score":2,"level":"low"},"avg":{"value":2,"score":2,"level":"low"},"count":{"value":58,"score":0.11,"level":"high"}}}]}

    requests_mock.get('https://test.com/systemReport/entities?search=%2FCorporateDC%2Fi&page=1&pageSize=200', json=mock_response)

    client = Client(
        base_url='https://test.com',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'name': 'CorporateDC'
    }

    response = entity_get_command(client, args)
    assert response.outputs_prefix == 'XMCyber'
    assert response.outputs_key_field == 'entity_id'
    assert response.outputs == [{
        'entity_id': '3110337924893579985',
        'name': 'CorporateDC',
        'is_asset': True,
        'is_choke_point': True,
        'affected_assets': {
            'value': 14,
            'level': "medium"
        }
    }]