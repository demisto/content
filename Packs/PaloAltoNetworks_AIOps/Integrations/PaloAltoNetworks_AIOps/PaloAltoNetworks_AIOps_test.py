from PaloAltoNetworks_AIOps import Client

AIOps_client = Client(base_url='some_mock_url',
                      api_key='api_key',
                      tsg_id='tsg_id',
                      client_id='client_id',
                      client_secret='client_secret',)


def generate_access_token_request(mocker):
    """

        Given:
            - args: Dict(str, Any)

        When:
            - Calling aiops-bpa-report-generate

        Then:
            - returns the report

    """
    from PaloAltoNetworks_AIOps import generate_report_command
    http_request = mocker.patch.object(AIOps_client, '_http_request')
    generate_report_command(AIOps_client, {})
    http_request.assert_called_with('PUT', 'api/users/2',
                                    json_data={'email': 'e@mail', 'login': 'login', 'name': 'Name', 'theme': 'dark'},
                                    headers=None)
