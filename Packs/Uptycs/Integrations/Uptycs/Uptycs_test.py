import demistomock as demisto

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
        'key': 'testkey',
        'secret': 'testsecret',
        'domain': 'testdomain.com',
        'customer_id': 'testcustomer',
        'fetch_time': '7 days'
    })

    mock_response = [{
            "id": "e037cb0b-e9b0-4061-8966-5d3404cef9f6",
            "assetId": "2fb29ec9-5c16-4021-af7c-65528fead280",
            "path": "/etc/hosts",
            "createdAt": "2023-05-19T06:58:12.304Z",
            "updatedAt": "2023-05-19T06:58:13.576Z",
            "status": "FINISHED",
            "assetHostName": "uptycs-testhost",
            "offset": 0,
            "length": 197,
            "deletedUserName": '',
            "deletedAt": ''
    }]
    requests_mock.get('https://testdomain.com/public/api/customers/testcustomer/carves', json=mock_response)

    response = uptycs_get_carves_source_command()

    assert response.Contents == mock_response
