import demistomock as demisto

"""GLOBAL VARS"""

CUSTOMER_ID = "08c9f30e-5233-49d7-93ab-5b7c04ff97e9"
KEY = "OE5JFSEORJGXZPXANA4QHRMDMGVCC5CQ"
SECRET = "Y4SrBv/J/hqQQ8Rzxs2HErfm88WuEhR2XGsrphuPu5pQZNLHhGXmscnQfChOHzyE"
DOMAIN = "teststack.uptycs.io"


def test_uptycs_get_carves(mocker, requests_mock):
    """
    Tests uptycs-get-carves command function.

        Given:
            - requests_mock instance to generate the appropriate carves API
              response when the correct uptycs-get-carves API request is performed.

        When:
            - Running the 'uptycs-get-carves'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_carves_source_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        'items': [
            {
                "id": "e037cb0b-e9b0-4061-8966-5d3404cef9f6",
                "assetId": "2fb29ec9-5c16-4021-af7c-65528fead280",
                "path": "/etc/hosts",
                "createdAt": "2023-05-19T06:58:12.304Z",
                "updatedAt": "2023-05-19T06:58:13.576Z",
                "status": "FINISHED",
                "assetHostName": "uptycs-testhost",
                "offset": 0,
                "length": 197,
                "deletedUserName": "",
                "deletedAt": ""
            }
        ]
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/carves'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_carves_source_command()

    assert response['Contents'] == mock_response


def test_uptycs_get_carves_link(mocker, requests_mock):
    """
    Tests uptycs_get_carves_link_command command function.

        Given:
            - requests_mock instance to generate the appropriate carves link API
              response when the correct uptycs-get-carves-link API request is performed.

        When:
            - Running the 'uptycs-get-carves-link'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_carves_link_command, uptycs_get_carves_file_command

    carve_id = "e037cb0b-e9b0-4061-8966-5d3404cef9f6"

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mocker.patch.object(demisto, 'args', return_value={
        "carve_id": carve_id
    })

    mock_response = {
        "url": "https://uptycs-carves-testing.s3.us-west-2.amazonaws.com/%s/testurl?" % CUSTOMER_ID
    }
    access_control_headers = ['x-amz-server-side-encryption-customer-algorithm',
                              'x-amz-server-side-encryption-customer-key',
                              'x-amz-server-side-encryption-customer-key-md5',
                              'x-requested-with']
    for header in access_control_headers:
        mock_response['url'] += header + '=' + 'testvalue&'
    mock_response['url'] = mock_response['url'][:-1]

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/carves/{carve_id}/link'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_carves_link_command()
    assert response['Contents'] == mock_response

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/carves/{carve_id}/link'
    requests_mock.get(test_url, json=mock_response)

    with open('test_data/blob.tar', 'rb') as file_mock:
        requests_mock.get(mock_response['url'], content=file_mock.read())

    result = uptycs_get_carves_file_command()
    assert result is None


def test_uptycs_get_assets(mocker, requests_mock):
    """
    Tests uptycs-get-assets command function.

        Given:
            - requests_mock instance to generate the appropriate assets API
              response when the correct uptycs-get-assets API request is performed.

        When:
            - Running the 'uptycs-get-assets'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_assets_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    mocker.patch.object(demisto, 'args', return_value={
        "os": "mac",
        "host_name_like": "work",
        "object_group_id": "test"
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        'items': [
            {
                "status": "active",
                "last_enrolled_at": "2019-07-19 14:47:27.485",
                "os_version": "10.14.5",
                "osquery_version": "3.2.6.51-Uptycs",
                "created_at": "2018-09-25 16:38:16.440",
                "longitude": -97.822,
                "os_flavor": "darwin",
                "host_name": "kyle-mbp-work",
                "latitude": 37.751,
                "last_activity_at": "2019-07-19 17:02:41.704",
                "os": "Mac OS X",
                "id": "984d4a7a-9f3a-580a-a3ef-2841a561669b",
                "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b",
                "location": "United States"
            }
        ]
    }
    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/query'
    requests_mock.post(test_url, json=mock_response)

    response = uptycs_get_assets_command()

    assert response['Contents'] == mock_response['items']


def test_uptycs_get_asset_with_id(mocker, requests_mock):
    """
    Tests uptycs-get-asset-with-id command function.

        Given:
            - requests_mock instance to generate the appropriate assets API
              response when the correct uptycs-get-asset-with-id API request is performed.

        When:
            - Running the 'uptycs-get-asset-with-id'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_asset_id_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    asset_id = "984d4a7a-9f3a-580a-a3ef-2841a561669b"
    mocker.patch.object(demisto, 'args', return_value={
        "asset_id": asset_id
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        "status": "active",
        "live": True,
        "disabled": False,
        "quarantinedStatus": False,
        "lastEnrolledAt": "2019-07-19 14:47:27.485",
        "osVersion": "10.14.5",
        "osqueryVersion": "3.x.x.x-Uptycs",
        "agentVersion": "5.x.x.x-Uptycs",
        "osFlavor": "darwin",
        "hostName": "kyle-mbp-work",
        "gateway": "x.y.z.a",
        "os": "Mac OS X",
        "osKey": "darwin_10.14.5",
        "objectGroupId": "984d4a7a-9f3a-580a-a3ef-2841a561669b",
        "cpuBrand": "Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz",
        "hardwareModel": "HVM domU",
        "hardwareVendor": "Xen",
        "cores": 2,
        "logicalCores": 2,
        "memoryMb": 8192,
        "arch": "x86_64",
        "osDisplay": "macOS 10.14.5",
        "location": "United States"
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/assets/{asset_id}'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_asset_id_command()
    mock_response['tags'] = ''
    assert response['Contents'] == mock_response


def test_uptycs_get_tag(mocker, requests_mock):
    """
    Tests uptycs-get-tag command function.

        Given:
            - requests_mock instance to generate the appropriate tags API
              response when the correct uptycs-get-tag API request is performed.

        When:
            - Running the 'uptycs-get-tag'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_tag_with_id_source_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    tag_id = "984d4a7a-9f3a-580a-a3ef-2841a561669b"
    mocker.patch.object(demisto, 'args', return_value={
        "tag_id": tag_id
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        "tag": "asset-group=Asset test 1",
        "resourceType": "asset",
        "seedId": "14e579e4-3661-4bd6-ace3-082cf6fc4ec5",
        "key": "asset-group",
        "value": "Asset test 1",
        "flagProfileId": "5d894e7c-5606-4380-8711-123ee2a7d96c",
        "customProfileId": "",
        "complianceProfileId": "",
        "processBlockRuleId": "ec272101-e5c1-58b2-f847-c439abdadcf4",
        "dnsBlockRuleId": "984d4a7a-9f3a-580a-a3ef-2841a561669b",
        "windowsDefenderPreferenceId": "",
        "createdBy": "testuser",
        "updatedBy": "testuser",
        "createdAt": "2019-07-19 14:47:27.485",
        "updatedAt": "2019-07-19 14:47:27.485",
        "status": "active",
        "source": "direct",
        "system": False,
        "custom": False,
        "tagRuleId": ""
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/tags/{tag_id}'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_tag_with_id_source_command()

    assert response['Contents'] == mock_response


def test_uptycs_get_tags(mocker, requests_mock):
    """
    Tests uptycs-get-tags command function.

        Given:
            - requests_mock instance to generate the appropriate tags API
              response when the correct uptycs-get-tags API request is performed.

        When:
            - Running the 'uptycs-get-tags'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_tags_source_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        'items': [
            {
                "tag": "asset-group=Asset test 1",
                "resourceType": "asset",
                "seedId": "14e579e4-3661-4bd6-ace3-082cf6fc4ec5",
                "key": "asset-group",
                "value": "Asset test 1",
                "flagProfileId": "5d894e7c-5606-4380-8711-123ee2a7d96c",
                "customProfileId": "",
                "complianceProfileId": "",
                "processBlockRuleId": "ec272101-e5c1-58b2-f847-c439abdadcf4",
                "dnsBlockRuleId": "984d4a7a-9f3a-580a-a3ef-2841a561669b",
                "windowsDefenderPreferenceId": "",
                "createdBy": "testuser",
                "updatedBy": "testuser",
                "createdAt": "2019-07-19 14:47:27.485",
                "updatedAt": "2019-07-19 14:47:27.485",
                "status": "active",
                "source": "direct",
                "system": False,
                "custom": False,
                "tagRuleId": ""
            }
        ]
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/tags'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_tags_source_command()

    assert response['Contents'] == mock_response


def test_uptycs_get_lookuptable(mocker, requests_mock):
    """
    Tests uptycs-get-lookuptable command function.

        Given:
            - requests_mock instance to generate the appropriate lookuptble API
              response when the correct uptycs-get-lookuptable API request is performed.

        When:
            - Running the 'uptycs-get-lookuptable'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_lookuptable_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    table_id = "984d4a7a-9f3a-580a-a3ef-2841a561669b"
    mocker.patch.object(demisto, 'args', return_value={
        "table_id": table_id
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        "active": True,
        "createdAt": "2023-04-21T08:27:20.888Z",
        "createdBy": "f976bda8-d5dc-468f-8283-20d5368352e2",
        "dataLookupTable": "",
        "description": "look up table with remote address",
        "fetchRowsquery": "SELECT id_field_value,data FROM upt_lookup_rows",
        "forRuleEngine": "",
        "idField": "remote_address",
        "name": "test_table_new",
        "rowCount": 24,
        "seedId": "",
        "updatedAt": "2023-04-25T04:11:04.664Z",
        "updatedBy": "f976bda8-d5dc-468f-8283-20d5368352e2"
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/lookupTables/{table_id}'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_lookuptable_command()

    assert response['Contents'] == mock_response


def test_uptycs_get_lookuptables(mocker, requests_mock):
    """
    Tests uptycs-get-lookuptables command function.

        Given:
            - requests_mock instance to generate the appropriate lookuptble API
              response when the correct uptycs-get-lookuptables API request is performed.

        When:
            - Running the 'uptycs-get-lookuptables'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_lookuptables_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        'items': [
            {
                "active": True,
                "createdAt": "2023-04-21T08:27:20.888Z",
                "createdBy": "f976bda8-d5dc-468f-8283-20d5368352e2",
                "dataLookupTable": "",
                "description": "look up table with remote address",
                "fetchRowsquery": "SELECT id_field_value,data FROM upt_lookup_rows",
                "forRuleEngine": "",
                "id": "984d4a7a-9f3a-580a-a3ef-2841a561669b",
                "idField": "remote_address",
                "name": "test_table_new",
                "rowCount": 24,
                "seedId": "",
                "updatedAt": "2023-04-25T04:11:04.664Z",
                "updatedBy": "f976bda8-d5dc-468f-8283-20d5368352e2"
            }
        ]
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/lookupTables'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_lookuptables_command()

    assert response['Contents'] == mock_response


def test_uptycs_edit_lookuptable(mocker, requests_mock):
    """
    Tests uptycs-edit-lookuptable command function.

        Given:
            - requests_mock instance to generate the appropriate lookuptble API
              response when the correct uptycs-edit-lookuptable API request is performed.

        When:
            - Running the 'uptycs-edit-lookuptable'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_edit_lookuptable_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    table_id = "984d4a7a-9f3a-580a-a3ef-2841a561669b"
    mocker.patch.object(demisto, 'args', return_value={
        "table_id": table_id,
        "name": "test_table_new_1",
        "description": "look up table with new address",
        "active": True
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        "active": True,
        "createdAt": "2023-04-21T08:27:20.888Z",
        "createdBy": "f976bda8-d5dc-468f-8283-20d5368352e2",
        "customerId": "b1c3b08c-eedd-4b94-8ba0-9ca322401016",
        "dataLookupTable": "",
        "description": "look up table with new address",
        "fetchRowsquery": "SELECT id_field_value,data FROM upt_lookup_rows",
        "forRuleEngine": "",
        "id": table_id,
        "idField": "remote_address",
        "name": "test_table_new_1",
        "rowCount": 24,
        "seedId": "",
        "updatedAt": "2023-04-25T04:11:04.664Z",
        "updatedBy": "f976bda8-d5dc-468f-8283-20d5368352e2"
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/lookupTables/{table_id}'
    requests_mock.put(test_url, json=mock_response)

    response = uptycs_edit_lookuptable_command()

    assert response['Contents'] == mock_response
    assert response['HumanReadable'] == 'Uptycs Edited lookuptable'


def test_uptycs_delete_lookuptable(mocker, requests_mock):
    """
    Tests uptycs-delete-lookuptable command function.

        Given:
            - requests_mock instance to generate the appropriate lookuptble API
              response when the correct uptycs-delete-lookuptable API request is performed.

        When:
            - Running the 'uptycs-delete-lookuptable'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_delete_lookuptable_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    table_id = "984d4a7a-9f3a-580a-a3ef-2841a561669b"
    mocker.patch.object(demisto, 'args', return_value={
        "table_id": table_id
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/lookupTables/{table_id}'
    requests_mock.delete(test_url, json={})

    response = uptycs_delete_lookuptable_command()

    assert response['HumanReadable'] == 'Uptycs Deleted lookuptable'


def test_uptycs_delete_assets_tag(mocker, requests_mock):
    """
    Tests uptycs-delete-assets-tag command function.

        Given:
            - requests_mock instance to generate the appropriate assets tag API
              response when the correct uptycs-delete-assets-tag API request is performed.

        When:
            - Running the 'uptycs-delete-assets-tag'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_delete_assets_tag_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    asset_id = "984d4a7a-9f3a-580a-a3ef-2841a561669b"
    tag_id = "984d4a7a-9f3a-580a-a3ef-2841a561669b"
    mocker.patch.object(demisto, 'args', return_value={
        "asset_id": asset_id,
        "tagId": tag_id
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/assets/tags'
    requests_mock.delete(test_url, json={})

    response = uptycs_delete_assets_tag_command()

    assert response['HumanReadable'] == 'Uptycs disassociated assets tags'


def test_uptycs_delete_tag(mocker, requests_mock):
    """
    Tests uptycs-delete-tag command function.

        Given:
            - requests_mock instance to generate the appropriate tag API
              response when the correct uptycs-delete-tag API request is performed.

        When:
            - Running the 'uptycs-delete-tag'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_delete_tag_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    tag_id = "984d4a7a-9f3a-580a-a3ef-2841a561669b"
    mocker.patch.object(demisto, 'args', return_value={
        "tag_id": tag_id
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/tags/{tag_id}'
    requests_mock.delete(test_url, json={})

    response = uptycs_delete_tag_command()

    assert response['HumanReadable'] == 'Uptycs Deleted tag'


def test_uptycs_get_threat_indicators(mocker, requests_mock):
    """
    Tests uptycs-get-threat-indicators command function.

        Given:
            - requests_mock instance to generate the appropriate threat indicators API
              response when the correct uptycs-get-threat-indicators API request is performed.

        When:
            - Running the 'uptycs-get-threat-indicators'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_threat_indicators_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    mocker.patch.object(demisto, 'args', return_value={
        "limit": '1'
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        'items': [
            {
                "indicator": "54.165.17.209",
                "description": "malware.com",
                "threatId": "b3f44b34-f6a1-46bc-88f1-9755e3ac1a65",
                "indicatorType": "IPv4",
                "createdAt": "2019-07-19T16:44:17.511Z",
                "id": "8e54f94c-469a-4737-9eef-4e650a93ab58",
                "isActive": True
            }
        ]
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/threatIndicators?limit=1'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_threat_indicators_command()

    assert response['Contents'] == mock_response


def test_uptycs_get_threat_indicator(mocker, requests_mock):
    """
    Tests uptycs-get-threat-indicator command function.

        Given:
            - requests_mock instance to generate the appropriate threat indicators API
              response when the correct uptycs-get-threat-indicator API request is performed.

        When:
            - Running the 'uptycs-get-threat-indicator'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_threat_indicator_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    indicator_id = "0ab619bb-cfe0-4db0-8a31-0a71fcc2a362"
    mocker.patch.object(demisto, 'args', return_value={
        "indicator_id": indicator_id
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        "indicator": "92.242.140.21",
        "description": "nishant.uptycs.io",
        "threatId": "60e2e9eb-f756-4a4d-a85d-55aa8167d59d",
        "indicatorType": "IPv4",
        "createdAt": "2019-01-10T21:25:49.280Z",
        "updatedAt": "2019-01-10T21:25:49.280Z",
        "id": indicator_id,
        "isActive": True,
        "threat": {
            "threatSourceId": "testsourceid",
            "threatSource": {
                "threatVendorId": "testvendor",
                "name": "testsource"
            }
        }
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/threatIndicators/{indicator_id}'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_threat_indicator_command()
    mock_response['threat_source_id'] = 'testsourceid'
    mock_response['threat_vendor_id'] = 'testvendor'
    mock_response['threat_source_name'] = 'testsource'
    del mock_response['threat']
    assert response['Contents'] == mock_response


def test_uptycs_get_threat_source(mocker, requests_mock):
    """
    Tests uptycs-get-threat-source command function.

        Given:
            - requests_mock instance to generate the appropriate threat source API
              response when the correct uptycs-get-threat-source API request is performed.

        When:
            - Running the 'uptycs-get-threat-source'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_threat_source_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    threat_source_id = "0ab619bb-cfe0-4db0-8a31-0a71fcc2a362"
    mocker.patch.object(demisto, 'args', return_value={
        "threat_source_id": threat_source_id
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        "name": "AlienVault Open Threat Exchange Malicious Domains and IPs",
        "url": "4533da856e43f06ee00bb5f1adf170a0ce5cacaca5992ab1279733c2bdd0a88c",
        "enabled": True,
        "custom": False,
        "lastDownload": "2019-05-13T01:00:05.934Z",
        "createdAt": "2019-05-12T01:01:04.154Z",
        "description": "A feed of malicious domains and IP addresses"
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/threatSources/{threat_source_id}'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_threat_source_command()

    assert response['Contents'] == mock_response


def test_uptycs_get_threat_sources(mocker, requests_mock):
    """
    Tests uptycs-get-threat-sources command function.

        Given:
            - requests_mock instance to generate the appropriate threat source API
              response when the correct uptycs-get-threat-sources API request is performed.

        When:
            - Running the 'uptycs-get-threat-sources'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_threat_sources_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    mocker.patch.object(demisto, 'args', return_value={
        "limit": '1'
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        "items": [
            {
                "name": "AlienVault Open Threat Exchange Malicious Domains and IPs",
                "url": "4533da856e43f06ee00bb5f1adf170a0ce5cacaca5992ab1279733c2bdd0a88c",
                "enabled": True,
                "custom": False,
                "lastDownload": "2019-05-13T01:00:05.934Z",
                "createdAt": "2019-05-12T01:01:04.154Z",
                "description": "A feed of malicious domains and IP addresses"
            }
        ]
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/threatSources?limit=1'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_threat_sources_command()

    assert response['Contents'] == mock_response


def test_uptycs_get_threat_vendors(mocker, requests_mock):
    """
    Tests uptycs-get-threat-vendors command function.

        Given:
            - requests_mock instance to generate the appropriate threat vendors API
              response when the correct uptycs-get-threat-vendors API request is performed.

        When:
            - Running the 'uptycs-get-threat-vendors'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_threat_vendors_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    mocker.patch.object(demisto, 'args', return_value={
        "limit": '1'
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        "items": [
            {
                "name": "Bschmoll Inc.-Threats",
                "url": "testurl",
                "updatedAt": "2018-11-20T19:15:05.611Z",
                "customerId": "e8213ef3-ef92-460e-a542-46dccd700c16",
                "numThreats": 1,
                "numIocs": 0,
                "lastDownload": "2018-11-20T19:15:05.611Z",
                "id": "42b9220c-7e29-4fd8-9cf7-9f811e851f8e",
                "createdAt": "2018-11-20T19:15:05.611Z",
                "description": "Uptycs threat vendor"
            }
        ]
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/threatVendors?limit=1'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_threat_vendors_command()

    assert response['Contents'] == mock_response['items']


def test_uptycs_get_alerts(mocker, requests_mock):
    """
    Tests uptycs-get-alerts command function.

        Given:
            - requests_mock instance to generate the appropriate alerts API
              response when the correct uptycs-get-alerts API request is performed.

        When:
            - Running the 'uptycs-get-alerts'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_alerts_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    mocker.patch.object(demisto, 'args', return_value={
        "limit": '1',
        "host_name": 'testhost',
        "time_ago": "1 day",
        "host_name_like": 'test'
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        "items": [
            {
                "status": "open",
                "code": "OSX_CRASHES",
                "description": "Crash",
                "severity": "medium",
                "created_at": "2019-07-02 11:41:25.915",
                "updated_at": "2019-07-02 11:41:25.915",
                "value": "Amazon Music Helper",
                "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b",
                "alert_time": "2019-07-02 11:41:22.000",
                "host_name": "kyle-mbp-work",
                "key": "identifier",
                "assigned_to": "testuser",
                "metadata": "{\"type\":\"application\",\"pid\":\"437\"}",
                "id": "0049641c-1645-4b98-830f-7f1ce783bfcc",
                "grouping": "OS X Crashes"
            }
        ]
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/query'
    requests_mock.post(test_url, json=mock_response)

    response = uptycs_get_alerts_command()

    mock_response['items'][0]["threat_source_name"] = 'No threat source for this alert'
    mock_response['items'][0]["pid"] = '437'
    mock_response['items'][0]["threat_indicator_id"] = 'No threat indicator for this alert'

    assert response['Contents'] == mock_response


def test_uptycs_get_events(mocker, requests_mock):
    """
    Tests uptycs-get-events command function.

        Given:
            - requests_mock instance to generate the appropriate events API
              response when the correct uptycs-get-events API request is performed.

        When:
            - Running the 'uptycs-get-events'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_events_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    mocker.patch.object(demisto, 'args', return_value={
        "limit": '1',
        "host_name": 'testhost',
        "time_ago": "1 day",
        "host_name_like": 'test'
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        "items": [
            {
                "status": "open",
                "code": "OSX_CRASHES",
                "description": "Crash",
                "severity": "medium",
                "created_at": "2019-07-02 11:41:25.915",
                "value": "Amazon Music Helper",
                "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b",
                "event_time": "2019-07-02 11:41:22.000",
                "host_name": "kyle-mbp-work",
                "key": "identifier",
                "assigned_to": "testuser",
                "id": "0049641c-1645-4b98-830f-7f1ce783bfcc",
                "grouping": "OS X Crashes"
            }
        ]
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/query'
    requests_mock.post(test_url, json=mock_response)

    response = uptycs_get_events_command()

    assert response['Contents'] == mock_response


def test_uptycs_get_alert_rules(mocker, requests_mock):
    """
    Tests uptycs-get-alert-rules command function.

        Given:
            - requests_mock instance to generate the appropriate alert rules API
              response when the correct uptycs-get-alert-rules API request is performed.

        When:
            - Running the 'uptycs-get-alert-rules'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_alert_rules_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    mocker.patch.object(demisto, 'args', return_value={
        "limit": '1'
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        "items": [
            {
                "name": "Bschmoll Inc.-Threats",
                "code": "test",
                "grouping": "test",
                "enabled": True,
                "updatedAt": "2018-11-20T19:15:05.611Z",
                "description": "Uptycs threat vendor"
            }
        ]
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/alertRules?limit=1'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_alert_rules_command()

    assert response['Contents'] == mock_response['items']


def test_uptycs_get_event_rules(mocker, requests_mock):
    """
    Tests uptycs-get-event-rules command function.

        Given:
            - requests_mock instance to generate the appropriate event rules API
              response when the correct uptycs-get-event-rules API request is performed.

        When:
            - Running the 'uptycs-get-event-rules'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_event_rules_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    mocker.patch.object(demisto, 'args', return_value={
        "limit": '1'
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        "items": [
            {
                "name": "Bschmoll Inc.-Threats",
                "code": "test",
                "grouping": "test",
                "enabled": True,
                "updatedAt": "2018-11-20T19:15:05.611Z",
                "description": "Uptycs threat vendor"
            }
        ]
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/eventRules?limit=1'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_event_rules_command()

    assert response['Contents'] == mock_response['items']


def test_uptycs_get_users(mocker, requests_mock):
    """
    Tests uptycs-get-users and uptycs-get-user-asset-groups command function.

        Given:
            - requests_mock instance to generate the appropriate users API
              response when the correct uptycs-get-users or
              uptycs-get-user-asset-groups API request is performed.

        When:
            - Running the 'uptycs-get-users'.
            - Running the 'uptycs-get-user-asset-groups'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_users_command, uptycs_get_user_asset_groups_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    user_id = "33436e24-f30f-42d0-8438-d948be12b5af"
    object_group_id = "8963abf8-9c8d-4ef5-8a80-af836fe69be4"
    mocker.patch.object(demisto, 'args', return_value={
        "limit": '1',
        "asset_group_id": object_group_id
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_user = {
        "name": "Bschmoll",
        "id": user_id,
        "email": "goo@test.com",
        "admin": True,
        "active": True,
        "createdAt": "2018-11-20T19:15:05.611Z",
        "updatedAt": "2018-11-20T19:15:05.611Z",
        "userObjectGroups": [
            {
                "objectGroupId": object_group_id
            }
        ]
    }

    mock_response = {}
    mock_response['items'] = [mock_user]

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/users?limit=1'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_users_command()

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/users'
    requests_mock.get(test_url, json=mock_response)

    test_url_extra = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/users/{user_id}'
    requests_mock.get(test_url_extra, json=mock_user)

    asset_groups = uptycs_get_user_asset_groups_command()

    del mock_user['userObjectGroups']
    assert response['Contents'] == mock_response

    users_in_group = {
        mock_user['name']: {
            'email': mock_user['email'],
            'id': mock_user['id']
        }
    }

    assert asset_groups['Contents'] == users_in_group


def test_uptycs_get_user_information(mocker, requests_mock):
    """
    Tests uptycs-get-user-information command function.

        Given:
            - requests_mock instance to generate the appropriate users API
              response when the correct uptycs-get-user-information API request is performed.

        When:
            - Running the 'uptycs-get-user-information'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_user_information_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    user_id = "33436e24-f30f-42d0-8438-d948be12b5af"
    mocker.patch.object(demisto, 'args', return_value={
        "user_id": user_id
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        "name": "Bschmoll",
        "id": user_id,
        "email": "goo@test.com",
        "userRoles": [
            {
                'role': {
                    'name': 'admin'
                }
            }
        ],
        "userObjectGroups": "testuser"
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/users/{user_id}'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_user_information_command()

    for key in ['name', 'id', 'email', 'userObjectGroups']:
        assert response['Contents'][key] == mock_response[key]


def test_uptycs_get_asset_groups(mocker, requests_mock):
    """
    Tests uptycs-get-asset-groups command function.

        Given:
            - requests_mock instance to generate the appropriate asset groups API
              response when the correct uptycs-get-asset-groups API request is performed.

        When:
            - Running the 'uptycs-get-asset-groups'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_asset_groups_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    mocker.patch.object(demisto, 'args', return_value={
        "limit": '1'
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        "items": [
            {
                "name": "assets",
                "description": "Default asset group",
                "custom": False,
                "updatedAt": "2018-09-24T17:24:45.604Z",
                "id": "106eef5e-c3a6-44eb-bb3d-1a2087cded3d",
                "createdAt": "2018-09-24T17:24:45.604Z",
                "objectType": "ASSET"
            }
        ]
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/objectGroups?limit=1'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_asset_groups_command()

    assert response['Contents'] == mock_response


def test_uptycs_get_saved_queries(mocker, requests_mock):
    """
    Tests uptycs-get-saved-queries command function.

        Given:
            - requests_mock instance to generate the appropriate queries API
              response when the correct uptycs-get-saved-queries API request is performed.

        When:
            - Running the 'uptycs-get-saved-queries'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_saved_queries_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    query_id = "16de057d-6f69-46b0-80d0-46cb9348c8fe"
    query_name = "test_saved_query"
    mocker.patch.object(demisto, 'args', return_value={
        "query_id": query_id,
        "name": query_name
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        "items": [
            {
                "query": "select * from upt_assets limit 1",
                "id": query_id,
                "grouping": "default",
                "description": "this is a test query",
                "name": query_name,
                "executionType": "realtime"
            }
        ]
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/queries/{query_id}?name={query_name}'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_saved_queries_command()

    assert response['Contents'] == mock_response['items']


def test_uptycs_run_saved_query(mocker, requests_mock):
    """
    Tests uptycs-run-saved-query command function.

        Given:
            - requests_mock instance to generate the appropriate queries API
              response when the correct uptycs-run-saved-query API request is performed.

        When:
            - Running the 'uptycs-run-saved-query'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_run_saved_query_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })
    query_id = "16de057d-6f69-46b0-80d0-46cb9348c8fe"
    query_name = "test_saved_query"
    mocker.patch.object(demisto, 'args', return_value={
        "query_id": query_id,
        "name": query_name,
        "host_name_like": "test"
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = {
        "items": [
            {
                "query": "select * from upt_assets limit 1",
                "id": query_id,
                "grouping": "default",
                "description": "this is a test query",
                "name": query_name,
                "executionType": "realtime"
            }
        ]
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/queries/{query_id}?name={query_name}'
    requests_mock.get(test_url, json=mock_response)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/assets/query'
    requests_mock.post(test_url, json=mock_response)

    response = uptycs_run_saved_query_command()
    assert response['Contents'] == mock_response['items']


def test_uptycs_run_query(mocker, requests_mock):
    """
    Tests uptycs-run-query command function.

        Given:
            - requests_mock instance to generate the appropriate queries API
              response when the correct uptycs-run-query API request is performed.

        When:
            - Running the 'uptycs-run-query'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_run_query_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    mock_response = {
        "query": "select * from upt_assets limit 1",
        "asset_id": "testassetid",
        "description": "this is a test query",
        "name": "test_saved_query",
        "executionType": "realtime",
        "type": "default",
        "custom": True
    }

    mocker.patch.object(demisto, 'args', return_value={
        "name": mock_response['name'],
        "type": mock_response['type'],
        "description": mock_response['description'],
        "execution_type": mock_response['executionType'],
        "query": mock_response['query'],
        "asset_id": mock_response['asset_id']
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/assets/query'
    requests_mock.post(test_url, json=mock_response)

    response = uptycs_run_query_command()
    assert response['Contents'] == mock_response


def test_uptycs_get_process_open_sockets(mocker, requests_mock):
    """
    Tests uptycs-get-process-open-sockets command function.

        Given:
            - requests_mock instance to generate the appropriate queries API
              response when the correct uptycs-get-process-open-sockets API request is performed.

        When:
            - Running the 'uptycs-get-process-open-sockets'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_process_open_sockets_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    mock_response = {
        "items": [
            {
                "protocol": 6,
                "socket": 0,
                "family": 2,
                "local_port": 54755,
                "remote_port": 443,
                "pid": 704,
                "remote_address": "69.147.92.12",
                "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b",
                "upt_time": "2019-07-19 17:03:31.000",
                "state": "ESTABLISHED",
                "upt_hostname": "kyle-mbp-work",
                "path": "",
                "local_address": "192.168.86.61"
            }
        ]
    }

    mocker.patch.object(demisto, 'args', return_value={
        "limit": '1',
        "host_name_is": "testhost",
        "host_name_like": "test",
        "time_ago": "1 day"
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/query'
    requests_mock.post(test_url, json=mock_response)

    response = uptycs_get_process_open_sockets_command()
    assert response['Contents'] == mock_response


def test_uptycs_get_process_information(mocker, requests_mock):
    """
    Tests uptycs-get-process-open-information command function.

        Given:
            - requests_mock instance to generate the appropriate queries API
              response when the correct uptycs-get-process-information API request is performed.

        When:
            - Running the 'uptycs-get-process-information'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_process_information_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    mock_response = {
        "items": [
            {
                "pid": 5119,
                "parent": 484,
                "upt_hostname": "kyle-mbp-work",
                "path": "/Applications/VirtualBox.app/Contents/MacOS/VBoxHeadless",
                "cmdline": "/Applications/VirtualBox.app/Contents/MacOS/VBoxHeadless",
                "name": "VBoxHeadless"
            }
        ]
    }

    mocker.patch.object(demisto, 'args', return_value={
        "pid": '5119',
        "host_name_is": "testhost",
        "host_name_like": "test",
        "time_ago": "1 day"
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/query'
    requests_mock.post(test_url, json=mock_response)

    response = uptycs_get_process_information_command()
    assert response['Contents'] == mock_response


def test_uptycs_get_process_child_processes(mocker, requests_mock):
    """
    Tests uptycs-get-process-child-processes command function.

        Given:
            - requests_mock instance to generate the appropriate queries API
              response when the correct uptycs-get-process-child-processes API request is performed.

        When:
            - Running the 'uptycs-get-process-child-processes'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_process_child_processes_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    mock_response = {
        "items": [
            {
                "upt_time": "2019-01-29 16:14:27.000",
                "upt_add_time": "2019-01-29 16:14:27.000",
                "pid": 5119,
                "upt_hostname": "kyle-mbp-work",
                "path": "/Applications/VirtualBox.app/Contents/MacOS/VBoxHeadless",
                "cmdline": "/Applications/VirtualBox.app/Contents/MacOS/VBoxHeadless",
                "name": "VBoxHeadless"
            }
        ]
    }

    mocker.patch.object(demisto, 'args', return_value={
        "parent": '5119',
        "limit": '1',
        "asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b",
        "parent_start_time": "2023-01-28 14:16:58.000",
        "parent_end_time": "2019-01-29 14:16:58.000",
        "time_ago": "1 day"
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/query'
    requests_mock.post(test_url, json=mock_response)

    response = uptycs_get_process_child_processes_command()
    assert response['Contents'] == mock_response


def test_uptycs_processes(mocker, requests_mock):
    """
    Tests uptycs-get-processes command function.

        Given:
            - requests_mock instance to generate the appropriate queries API
              response when the correct uptycs-get-processes API request is performed.

        When:
            - Running the 'uptycs-get-processes'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_processes_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    mock_response = {
        "items": [
            {
                "name": "SCHelper",
                "parent": 1,
                "upt_time": "2019-07-19 07:29:32.000",
                "pid": 60051,
                "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b",
                "cmdline": "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/Helpers/SCHelper",
                "upt_hostname": "kyle-mbp-work",
                "pgroup": 60051,
                "path": "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/Helpers/SCHelper",
                "cwd": "/"
            }
        ]
    }

    mocker.patch.object(demisto, 'args', return_value={
        "limit": '1',
        "time_ago": "1 day",
        "host_name_is": "test",
        "host_name_like": "test"
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/query'
    requests_mock.post(test_url, json=mock_response)

    response = uptycs_get_processes_command()
    assert response['Contents'] == mock_response


def test_uptycs_process_open_files(mocker, requests_mock):
    """
    Tests uptycs-get-process-open-files command function.

        Given:
            - requests_mock instance to generate the appropriate queries API
              response when the correct uptycs-get-process-open-files API request is performed.

        When:
            - Running the 'uptycs-get-process-open-files'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_process_open_files_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    mock_response = {
        "items": [
            {
                "upt_time": "2019-07-19 07:29:32.000",
                "pid": 60051,
                "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b",
                "upt_hostname": "kyle-mbp-work",
                "path": "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/Helpers/SCHelper",
                "fd": 35
            }
        ]
    }

    mocker.patch.object(demisto, 'args', return_value={
        "limit": '1',
        "time_ago": "1 day",
        "host_name_is": "test",
        "host_name_like": "test"
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/query'
    requests_mock.post(test_url, json=mock_response)

    response = uptycs_get_process_open_files_command()
    assert response['Contents'] == mock_response


def test_uptycs_process_event_information(mocker, requests_mock):
    """
    Tests uptycs-get-process-event-information command function.

        Given:
            - requests_mock instance to generate the appropriate queries API
              response when the correct uptycs-get-process-event-information API request is performed.

        When:
            - Running the 'uptycs-get-process-event-information'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_process_event_information_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    mock_response = {
        "items": [
            {
                "upt_time": "2019-07-19 07:29:32.000",
                "parent": 5001,
                "pid": 60051,
                "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b",
                "upt_hostname": "kyle-mbp-work",
                "path": "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/Helpers/SCHelper",
                "cmdline": "xpcproxy com.apple.WebKit.WebContent.024FB342-0ECE-4E09-82E1-B9C9CF5F9CDF 3266",
                "cwd": "/"
            }
        ]
    }

    mocker.patch.object(demisto, 'args', return_value={
        "limit": '1',
        "time_ago": "1 day",
        "host_name_is": "test",
        "host_name_like": "test"
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/query'
    requests_mock.post(test_url, json=mock_response)

    response = uptycs_get_process_event_information_command()
    assert response['Contents'] == mock_response


def test_uptycs_process_events(mocker, requests_mock):
    """
    Tests uptycs-get-process-events command function.

        Given:
            - requests_mock instance to generate the appropriate queries API
              response when the correct uptycs-get-process-events API request is performed.

        When:
            - Running the 'uptycs-get-process-events'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_process_events_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    mock_response = {
        "items": [
            {
                "upt_time": "2019-07-19 07:29:32.000",
                "parent": 5001,
                "pid": 60051,
                "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b",
                "upt_hostname": "kyle-mbp-work",
                "path": "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/Helpers/SCHelper",
                "cmdline": "xpcproxy com.apple.WebKit.WebContent.024FB342-0ECE-4E09-82E1-B9C9CF5F9CDF 3266",
                "cwd": "/"
            }
        ]
    }

    mocker.patch.object(demisto, 'args', return_value={
        "limit": '1',
        "time_ago": "1 day",
        "host_name_is": "test",
        "host_name_like": "test"
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/query'
    requests_mock.post(test_url, json=mock_response)

    response = uptycs_get_process_events_command()
    assert response['Contents'] == mock_response


def test_uptycs_socket_events(mocker, requests_mock):
    """
    Tests uptycs-get-socker-events command function.

        Given:
            - requests_mock instance to generate the appropriate queries API
              response when the correct uptycs-get-socker-events API request is performed.

        When:
            - Running the 'uptycs-get-socket-events'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_socket_events_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    mock_response = {
        "items": [
            {
                "upt_time": "2019-07-19 07:29:32.000",
                "family": 2,
                "pid": 60051,
                "local_port": 47873,
                "remote_port": "",
                "protocol": "",
                "socket": "",
                "remote_address": "17.142.171.8",
                "local_address": "0.0.0.0",
                "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b",
                "upt_hostname": "kyle-mbp-work",
                "path": "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/Helpers/SCHelper",
                "action": "connect"
            }
        ]
    }

    mocker.patch.object(demisto, 'args', return_value={
        "limit": '1',
        "time_ago": "1 day",
        "host_name_is": "test",
        "host_name_like": "test"
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/query'
    requests_mock.post(test_url, json=mock_response)

    response = uptycs_get_socket_events_command()
    assert response['Contents'] == mock_response


def test_uptycs_parent_event_information(mocker, requests_mock):
    """
    Tests uptycs-get-parent-event-information command function.

        Given:
            - requests_mock instance to generate the appropriate queries API
              response when the correct uptycs-get-parent-event-information API request is performed.

        When:
            - Running the 'uptycs-get-parent-event-information'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_parent_event_information_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    mock_response = {
        "items": [
            {
                "upt_time": "2019-07-19 07:29:32.000",
                "parent": 5005,
                "pid": 60051,
                "upt_hostname": "kyle-mbp-work",
                "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b",
                "path": "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/Helpers/SCHelper",
                "cmdline": "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/Helpers/SCHelper",
                "cwd": ""
            }
        ]
    }

    mocker.patch.object(demisto, 'args', return_value={
        "limit": '1',
        "time_ago": "1 day",
        "host_name_is": "test",
        "host_name_like": "test"
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/query'
    requests_mock.post(test_url, json=mock_response)

    response = uptycs_get_parent_event_information_command()
    assert response['Contents'] == mock_response


def test_uptycs_socket_event_information(mocker, requests_mock):
    """
    Tests uptycs-get-socket-event-information command function.

        Given:
            - requests_mock instance to generate the appropriate queries API
              response when the correct uptycs-get-socket-event-information API request is performed.

        When:
            - Running the 'uptycs-get-socket-event-information'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_socket_event_information_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    mock_response = {
        "items": [
            {
                "upt_time": "2019-07-19 07:29:32.000",
                "family": 2,
                "pid": 60051,
                "local_port": 47873,
                "remote_port": "",
                "protocol": "",
                "socket": "",
                "remote_address": "17.142.171.8",
                "local_address": "0.0.0.0",
                "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b",
                "upt_hostname": "kyle-mbp-work",
                "path": "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/Helpers/SCHelper",
                "action": "connect"
            }
        ]
    }

    mocker.patch.object(demisto, 'args', return_value={
        "limit": '1',
        "time_ago": "1 day",
        "host_name_is": "test",
        "host_name_like": "test"
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/query'
    requests_mock.post(test_url, json=mock_response)

    response = uptycs_get_socket_event_information_command()
    assert response['Contents'] == mock_response


def test_uptycs_get_asset_tags(mocker, requests_mock):
    """
    Tests uptycs-get-asset-tags command function.

        Given:
            - requests_mock instance to generate the appropriate queries API
              response when the correct uptycs-get-asset-tags API request is performed.

        When:
            - Running the 'uptycs-get-asset-tags'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_get_asset_tags_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    mock_response = {
        "tags": [
            "Uptycs=work laptop",
            "owner=Uptycs office",
            "network=low",
            "cpu=unknown",
            "memory=unknown",
            "disk=high"
        ]
    }

    asset_id = "984d4a7a-9f3a-580a-a3ef-2841a561669b"
    mocker.patch.object(demisto, 'args', return_value={
        "asset_id": asset_id
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/assets/{asset_id}'
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_asset_tags_command()
    assert response['Contents'] == mock_response['tags']


def test_uptycs_set_alert_status(mocker, requests_mock):
    """
    Tests uptycs-set-alert-status command function.

        Given:
            - requests_mock instance to generate the appropriate queries API
              response when the correct uptycs-set-alert-status API request is performed.

        When:
            - Running the 'uptycs-set-alert-status'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_set_alert_status_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    mock_response = {
        "status": "assigned",
        "code": "OUTBOUND_CONNECTION_TO_THREAT_IOC",
        "updatedAt": "2019-07-19T17:07:27.447Z",
        "id": "9cb18abd-2c9a-43a8-988a-0601e9140f6c",
        "createdAt": "2019-02-22T21:13:21.238Z",
        "updatedByUser": {
            "name": "B schmoll",
            "admin": "True",
            "email": "goo@test.com"
        }
    }

    mocker.patch.object(demisto, 'args', return_value={
        "alert_id": "testalert",
        "status": "open"
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/alerts/testalert'
    requests_mock.put(test_url, json=mock_response)

    response = uptycs_set_alert_status_command()

    del mock_response["updatedByUser"]
    mock_response["updatedByEmail"] = "goo@test.com"
    mock_response["updatedByAdmin"] = "True"
    mock_response["updatedBy"] = "B schmoll"

    assert response['Contents'] == mock_response


def test_uptycs_create_lookuptable(mocker, requests_mock):
    """
    Tests uptycs-create-lookuptable command function.

        Given:
            - requests_mock instance to generate the appropriate lookuptble API
              response when the correct uptycs-create-lookuptable API request is performed.

        When:
            - Running the 'uptycs-create-lookuptable'.
            - Running the 'uptycs_post_lookuptable_data_source_command'.

        Then:
            -  Checks the output of the command function with the expected output.

    """
    from Uptycs import uptycs_post_new_lookuptable_command, uptycs_post_lookuptable_data_source_command

    mocker.patch.object(demisto, 'params', return_value={
        "key": KEY,
        "secret": SECRET,
        "domain": DOMAIN,
        "customer_id": CUSTOMER_ID,
        "proxy": "false",
        "fetch_time": "7 days"
    })

    table_id = "984d4a7a-9f3a-580a-a3ef-2841a561669b"
    id_field = "remote_address"
    description = "look up table with remote address"
    mocker.patch.object(demisto, 'args', return_value={
        "name": "test_table_new",
        "id_field": id_field,
        "description": description,
        "table_id": table_id,
        "filename": "test_data/look_up_table_test.csv"
    })

    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)
    # Mocking demisto.getFilePath
    mocker.patch.object(demisto, "getFilePath", return_value={
        'path': './test_data/look_up_table_test.csv'
    })

    mock_response = {
        "active": True,
        "createdAt": "2023-04-21T08:27:20.888Z",
        "createdBy": "f976bda8-d5dc-468f-8283-20d5368352e2",
        "dataLookupTable": "",
        "description": description,
        "fetchRowsquery": "SELECT id_field_value,data FROM upt_lookup_rows",
        "forRuleEngine": "",
        "idField": id_field,
        "name": "test_table_new",
        "rowCount": 24,
        "seedId": "",
        "updatedAt": "2023-04-25T04:11:04.664Z",
        "updatedBy": "f976bda8-d5dc-468f-8283-20d5368352e2",
        "id": table_id
    }

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/lookupTables'
    requests_mock.post(test_url, json=mock_response)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/lookupTables/{table_id}/csvdata'
    requests_mock.post(test_url, json=mock_response)

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/lookupTables/{table_id}'
    requests_mock.put(test_url, json=mock_response)

    response = uptycs_post_new_lookuptable_command()

    assert response['Contents'] == mock_response

    test_url = f'https://{DOMAIN}/public/api/customers/{CUSTOMER_ID}/lookupTables/{table_id}/csvdata'
    requests_mock.post(test_url, json=mock_response)

    response = uptycs_post_lookuptable_data_source_command()

    assert response['Contents'] == mock_response
