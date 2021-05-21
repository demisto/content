def test_queryai_run_query(requests_mock):
    """Tests queryai-run-quer command function.
    """
    from QueryAI import Client, queryai_run_query_command

    mock_response = {
        "data": [
            {"agegroupdesc": "18-19", "agegroupbin": 2},
            {"agegroupdesc": "20-21", "agegroupbin": 3},
            {"agegroupdesc": "22-24", "agegroupbin": 4},
            {"agegroupdesc": "25-29", "agegroupbin": 5},
            {"agegroupdesc": "30-34", "agegroupbin": 6},
            {"agegroupdesc": "35-39", "agegroupbin": 7},
            {"agegroupdesc": "40-49", "agegroupbin": 8},
            {"agegroupdesc": "50-64", "agegroupbin": 9},
            {"agegroupdesc": "65 AND OVER", "agegroupbin": 10},
            {"agegroupdesc": "UNDER 18", "agegroupbin": 1},
            {"agegroupdesc": "UNKNOWN", "agegroupbin": 0}
        ],
        "reply": "hello world"
    }
    requests_mock.post('https://proxy.query.ai/api/v1/query', json=mock_response)

    client = Client(
        base_url='https://proxy.query.ai/api/v1',
        verify=False,
        headers={},
        proxy=False,
        api_token='ABCD12345',
        alias='my_default_alias',
        connection_params={}
    )

    args = {
        'query': 'run workflow all data'
    }

    response = queryai_run_query_command(client, args)

    assert response.outputs_prefix == 'QueryAI.query'
    assert response.outputs_key_field == ''
    assert response.outputs['result'] == [
        {"agegroupdesc": "18-19", "agegroupbin": 2},
        {"agegroupdesc": "20-21", "agegroupbin": 3},
        {"agegroupdesc": "22-24", "agegroupbin": 4},
        {"agegroupdesc": "25-29", "agegroupbin": 5},
        {"agegroupdesc": "30-34", "agegroupbin": 6},
        {"agegroupdesc": "35-39", "agegroupbin": 7},
        {"agegroupdesc": "40-49", "agegroupbin": 8},
        {"agegroupdesc": "50-64", "agegroupbin": 9},
        {"agegroupdesc": "65 AND OVER", "agegroupbin": 10},
        {"agegroupdesc": "UNDER 18", "agegroupbin": 1},
        {"agegroupdesc": "UNKNOWN", "agegroupbin": 0}
    ]
