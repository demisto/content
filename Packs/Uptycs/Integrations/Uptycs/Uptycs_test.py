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

    mock_response = [
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
    test_url = 'https://%s/public/api/customers/%s/carves' % (DOMAIN, CUSTOMER_ID)
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_carves_source_command()

    assert response.Contents == mock_response


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
    from Uptycs import uptycs_get_carves_link_command

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
        "url": "https://uptycs-carves-testing.s3.us-west-2.amazonaws.com/%s/testurl" % CUSTOMER_ID
    }
    test_url = 'https://%s/public/api/customers/%s/carves/%s/link' % (DOMAIN, CUSTOMER_ID, carve_id)
    requests_mock.get(test_url, json=mock_response)

    response = uptycs_get_carves_link_command()

    assert response.Contents == mock_response


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
        "host_name_like" : "work",
        "object_group_id": "test"
    })
    mocker.patch("Uptycs.KEY", new=KEY)
    mocker.patch("Uptycs.SECRET", new=SECRET)
    mocker.patch("Uptycs.CUSTOMER_ID", new=CUSTOMER_ID)
    mocker.patch("Uptycs.DOMAIN", new=DOMAIN)

    mock_response = [
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
            "location": "United States"
        }
    ]
    test_url = 'https://%s/public/api/customers/%s/query' % (DOMAIN, CUSTOMER_ID)
    requests_mock.post(test_url, json=mock_response)

    response = uptycs_get_assets_command()

    assert response.Contents == mock_response
