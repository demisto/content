import demistomock as demisto

"""GLOBAL VARS"""

CUSTOMER_ID = "08c9f30e-5233-49d7-93ab-5b7c04ff97e9"
KEY = "OE5JFSEORJGXZPXANA4QHRMDMGVCC5CQ"
SECRET = "Y4SrBv/J/hqQQ8Rzxs2HErfm88WuEhR2XGsrphuPu5pQZNLHhGXmscnQfChOHzyE"
DOMAIN = "testdomain.com"


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
    test_url = 'https://testdomain.com/public/api/customers/%s/carves' % CUSTOMER_ID
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
