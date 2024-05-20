import GLIMPSDetect

DUMMY_TOKEN = "11111111-11111111-11111111-11111111-11111111"


def mocked_gdetect_get():
    return {
        "uuid": "23465d22-3464-39ce-b8b3-bc2ee7d6eecf",
        "sha256": "005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31",
        "sha1": "2159b8d8b985f32641314220bb24126747b71d13",
        "md5": "c24d410c7e7d4b6066e09ceee057fbf9",
        "ssdeep": "6153:KyJE1yd7WHJmcyfjtPWna8DQFu/U3buRKlemZ9DnGAevIhdi++:KU/d7WsvBPWa9DQFu/U3buRKlemZ9DnG",
        "is_malware": True,
        "score": 4000,
        "done": True,
        "timestamp": 1651157541588,
        "filetype": "exe",
        "size": 219648,
        "filenames": [
                "sha256"
        ],
        "malwares": [
            "Win.Ransomware.Buhtrap-9865977-0",
            "TR/Redcap.ltkcp",
            "Mal/Behav-010"
        ],
        "files": [
            {
                "sha256": "005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31",
                "sha1": "2159b8d8b985f32641314220bb24126747b71d13",
                "md5": "c24d410c7e7d4b6066e09ceee057fbf9",
                "ssdeep": "6153:KyJE1yd7WHJmcyfjtPWna8DQFu/U3buRKlemZ9DnGAevIhdi++:KU/d7WsvBPWa9DQFu/U3buRKlemZ9DnG",
                "magic": "PE32 executable (GUI) Intel 80386, for MS Windows",
                "av_results": [
                    {
                        "av": "SignatureOyster",
                        "result": "Win.Ransomware.Buhtrap-9865977-0",
                        "score": 1000
                    },
                    {
                        "av": "SignatureUmbrella",
                        "result": "TR/Redcap.ltkcp",
                        "score": 1000
                    },
                    {
                        "av": "SignatureSophos",
                        "result": "Mal/Behav-010",
                        "score": 1000
                    }
                ],
                "size": 219648,
                "is_malware": True
            },
            {
                "sha256": "bd52eb164e64e6316791a8c260689b8ca0bf54440fa629edc05f6d4c301faec",
                "sha1": "d0333bf36f7bd1bdc1b2110e0a55e608ec378577",
                "md5": "5edb7d7e63f80d657e975628add89cd3",
                "ssdeep": "99:JKXtFmZan3KNhTP+5oXlNbAuC5mDDtUEDPUmgXSM:JMFkNhy1qlNkPDDzPcF",
                "magic": "data",
                "size": 6144,
                "is_malware": False
            },
            {
                "sha256": "f9c00d396b73fc4b4d05c518a7c9eddbed35462270d2ae5e31380fe5ca0f0c67",
                "sha1": "d5cfd73469f053c4ec8cd34d7a81baaf4e6d5068",
                "md5": "5a58f4825aa4cc6ce9098c20dcc99448",
                "ssdeep": "98:WuuR8iHj18usiDdeKvg3nbNqCH7FazFT3jCDomhCuorfhHSEdP2pVUVi7P1uH:Q6ijDUsEg0nf5CCo0Cu054VUViCu",
                "magic": "data",
                "size": 6144,
                "is_malware": False
            }
        ],
        "sid": "9gzYCsX4R9jzlyZC3ierKY",
        "file_count": 3,
        "duration": 8268,
        "token": ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ6.eyJ1c2VybmFtZSI6ImFwaS10YW8ndWl0ZXN0IiwiZ7JvdXBzIjpbInRhbmd1aXRlc3QiXSwi"
                  "c2lkIjoiN2d6WUNzWDRSNmp6bHlaQzNpZXJLWSIsImV4cCI4MTY1MzgwNzgwOSwiaWF3IjoxNjUxMjE3ODA2fQ.EGk75tKwAq70TPCjClnOp_"
                  "2_339XqMXk0TbPJhSN2uE"),
        "threats": {
            "005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31": {
                "filenames": [
                    "23465d22-3464-39ce-b8b3-bc2ee7d6eecf"
                ],
                "tags": [
                    {
                        "name": "av.virus_name",
                        "value": "Mal/Behav-010"
                    },
                    {
                        "name": "attribution.family",
                        "value": "win_vegalocker_auto"
                    },
                    {
                        "name": "av.virus_name",
                        "value": "win_vegalocker_auto"
                    },
                    {
                        "name": "av.virus_name",
                        "value": "Win.Ransomware.Buhtrap-9865977-0"
                    },
                    {
                        "name": "av.virus_name",
                        "value": "TR/Redcap.ltkcp"
                    }
                ],
                "score": 4000,
                "magic": "PE32 executable (GUI) Intel 80386, for MS Windows",
                "sha256": "005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31",
                "sha1": "2159b8d8b985f32641314220bb24126747b71d13",
                "md5": "c24d410c7e7d4b6066e09ceee057fbf9",
                "ssdeep": "6153:KyJE1yd7WHJmcyfjtPWna8DQFu/U3buRKlemZ9DnGAevIhdi++:KU/d7WsvBPWa9DQFu/U3buRKlemZ9DnG",
                "file_size": 219648,
                "mime": "application/x-dosexec"
            }
        },
        "status": True
    }


def mocked_gdetect_get_base():
    return {
        "sha256": "005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31",
        "sha1": "2159b8d8b985f32641314220bb24126747b71d13",
        "md5": "c24d410c7e7d4b6066e09ceee057fbf9",
        "size": 219648,
        "ssdeep": "6153:KyJE1yd7WHJmcyfjtPWna8DQFu/U3buRKlemZ9DnGAevIhdi++:KU/d7WsvBPWa9DQFu/U3buRKlemZ9DnG",
        "status": True,
        "timestamp": 1651157541588,
        "uuid": "23465d22-3464-39ce-b8b3-bc2ee7d6eecf",
        "malwares": [
            "Win.Ransomware.Buhtrap-9865977-0",
            "TR/Redcap.ltkcp",
            "Mal/Behav-010"
        ],
        "is_malware": True,
        "filetype": "exe",
        "filenames": [
            "23465d22-3464-39ce-b8b3-bc2ee7d6eecf"
        ],
        "file_count": 3,
        "duration": 8268,
        "done": True,
    }


def mocker_gdetect_get_error():
    return {
        'status': False,
        'error': 'bad request'
    }


def mock_add_sid(mock):
    mock["sid"] = "9gzYCsX4R9jzlyZC3ierKY"
    return mock


def mocked_gdetect_get_sid():
    base = mocked_gdetect_get_base()
    mock = mock_add_sid(base)
    return mock


def mock_add_token(mock):
    mock = mock_add_sid(mock)
    mock["token"] = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ6.eyJ1c2VybmFtZSI6ImFwaS10YW8ndWl0ZXN0IiwiZ7JvdXBzIjpbInRhbmd1aXRlc3QiX"
                     "Swic2lkIjoiN2d6WUNzWDRSNmp6bHlaQzNpZXJLWSIsImV4cCI4MTY1MzgwNzgwOSwiaWF3IjoxNjUxMjE3ODA2fQ.EGk75tKwAq70T"
                     "PCjClnOp_2_339XqMXk0TbPJhSN2uE")
    return mock


def mocked_gdetect_get_token():
    base = mocked_gdetect_get_base()
    tokenized = mock_add_token(base)
    return tokenized


def mocked_gdetect_get_errors():
    base = mocked_gdetect_get_base()
    base["errors"] = {
        "Extract": "The number of retries has passed the limit."
    }
    base["error"] = "an error occurred with 1 services",
    return base


def mocked_gdetect_get_files():
    base = mocked_gdetect_get_base()
    base["files"] = [
        {
            "sha256": "c7c4547d5a8313a7edca3fbbc4a45e4a647c93b0c89234eb1bc09ab2893cc688",
            "sha1": "f28a2f914c7a6e6206456bed19d545af260cf6fd",
            "md5": "34c9516df650349f236908ca163a2553",
            "ssdeep": "49158:KW2x/eYZrm7c5CSV6fan+2pXVmWtagzBMFpvuyUkZ5HwdW:6",
            "magic": "Zip archive data, at least v1.0 to extract",
            "size": 1816832,
            "is_malware": False
        }
    ]
    return base


def mocked_gdetect_get_files_av_results():
    base = mocked_gdetect_get_base()
    base["files"] = [
        {
            "sha256": "005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31",
            "sha1": "2159b8d8b985f32641314220bb24126747b71d13",
            "md5": "c24d410c7e7d4b6066e09ceee057fbf9",
            "ssdeep": "6153:KyJE1yd7WHJmcyfjtPWna8DQFu/U3buRKlemZ9DnGAevIhdi++:KU/d7WsvBPWa9DQFu/U3buRKlemZ9DnG",
            "magic": "PE32 executable (GUI) Intel 80386, for MS Windows",
            "av_results": [
                {
                    "av": "SignatureOyster",
                    "result": "Win.Ransomware.Buhtrap-9865977-0",
                    "score": 1000
                },
                {
                    "av": "SignatureUmbrella",
                    "result": "TR/Redcap.ltkcp",
                    "score": 1000
                },
                {
                    "av": "SignatureSophos",
                    "result": "Mal/Behav-010",
                    "score": 1000
                }
            ],
            "size": 219648,
            "is_malware": True
        },
        {
            "sha256": "bd52eb164e64e6316791a8c260689b8ca0bf54440fa629edc05f6d4c301faec",
            "sha1": "d0333bf36f7bd1bdc1b2110e0a55e608ec378577",
            "md5": "5edb7d7e63f80d657e975628add89cd3",
            "ssdeep": "99:JKXtFmZan3KNhTP+5oXlNbAuC5mDDtUEDPUmgXSM:JMFkNhy1qlNkPDDzPcF",
            "magic": "data",
            "size": 6144,
            "is_malware": False
        },
        {
            "sha256": "f9c00d396b73fc4b4d05c518a7c9eddbed35462270d2ae5e31380fe5ca0f0c67",
            "sha1": "d5cfd73469f053c4ec8cd34d7a81baaf4e6d5068",
            "md5": "5a58f4825aa4cc6ce9098c20dcc99448",
            "ssdeep": "98:WuuR8iHj18usiDdeKvg3nbNqCH7FazFT3jCDomhCuorfhHSEdP2pVUVi7P1uH:Q6ijDUsEg0nf5CCo0Cu054VUViCu",
            "magic": "data",
            "size": 6144,
            "is_malware": False
        }
    ]
    return base


def mocked_gdetect_get_threats():
    base = mocked_gdetect_get_base()
    base['threats'] = {
        "005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31": {
            "filenames": [
                "23465d22-3464-39ce-b8b3-bc2ee7d6eecf"
            ],
            "tags": [
                {
                    "name": "av.virus_name",
                    "value": "Mal/Behav-010"
                },
                {
                    "name": "attribution.family",
                    "value": "win_vegalocker_auto"
                },
                {
                    "name": "av.virus_name",
                    "value": "win_vegalocker_auto"
                },
                {
                    "name": "av.virus_name",
                    "value": "Win.Ransomware.Buhtrap-9865977-0"
                },
                {
                    "name": "av.virus_name",
                    "value": "TR/Redcap.ltkcp"
                }
            ],
            "score": 4000,
            "magic": "PE32 executable (GUI) Intel 80386, for MS Windows",
            "sha256": "005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31",
            "sha1": "2159b8d8b985f32641314220bb24126747b71d13",
            "md5": "c24d410c7e7d4b6066e09ceee057fbf9",
            "ssdeep": "6153:KyJE1yd7WHJmcyfjtPWna8DQFu/U3buRKlemZ9DnGAevIhdi++:KU/d7WsvBPWa9DQFu/U3buRKlemZ9DnG",
            "file_size": 219648,
            "mime": "application/x-dosexec"
        }
    }
    return base


def mocked_gdetect_get_threats_with_token():
    base = mocked_gdetect_get_threats()
    mock = mock_add_token(base)
    return mock


def mocked_gdetect_get_threats_with_sid():
    base = mocked_gdetect_get_threats()
    mock = mock_add_sid(base)
    return mock


def test_gdetect_send(mocker):
    mocker.patch('GLIMPSDetect.gClient.push', return_value='23465d22-3464-39ce-b8b3-bc2ee7d6eecf')
    client = GLIMPSDetect.Client('url', DUMMY_TOKEN, False, False)
    resp = client.gdetect_send('test_purpose')
    assert resp == '23465d22-3464-39ce-b8b3-bc2ee7d6eecf'


def test_gdetect_get(mocker):
    mocker.patch('GLIMPSDetect.gClient.get_by_uuid', return_value=mocked_gdetect_get())
    client = GLIMPSDetect.Client('url', DUMMY_TOKEN, False, False)
    resp = client.gdetect_get('23465d22-3464-39ce-b8b3-bc2ee7d6eecf')
    assert 'status' in resp
    assert resp.get('uuid') == '23465d22-3464-39ce-b8b3-bc2ee7d6eecf'


def test_gdetect_send_command_ok(mocker):
    mocker.patch('GLIMPSDetect.gClient.push', return_value='23465d22-3464-39ce-b8b3-bc2ee7d6eecf')
    client = GLIMPSDetect.Client('url', DUMMY_TOKEN, False, False)
    args = {'entryID': '1@042262f2-6a12-44da-8e11-74cf4bc67063'}
    results = GLIMPSDetect.gdetect_send_command(client, args)
    assert results.outputs.get('entryID') == '1@042262f2-6a12-44da-8e11-74cf4bc67063'
    assert results.outputs.get('uuid') == '23465d22-3464-39ce-b8b3-bc2ee7d6eecf'
    assert 'threats' not in results.outputs


def test_gdetect_send_command_wrong_entry(mocker):
    mocker.patch('demistomock.getFilePath', return_value={})
    client = GLIMPSDetect.Client('url', DUMMY_TOKEN, False, False)
    args = {'entryID': '1@042262f2-6a12-44da-8e11-74cf4bc67063'}
    results = GLIMPSDetect.gdetect_send_command(client, args)
    assert 'not found' in results


def test_gdetect_get_all_command_error(mocker):
    mocker.patch('GLIMPSDetect.gClient.get_by_uuid', return_value=mocker_gdetect_get_error())
    client = GLIMPSDetect.Client('url', DUMMY_TOKEN, False, False)
    args = {'entryID': '1@042262f2-6a12-44da-8e11-74cf4bc67063'}
    try:
        results = GLIMPSDetect.gdetect_get_all_command(client, args)
    except Exception as e:
        assert e is not None
    assert 'status' in results.outputs
    assert 'error' in results.outputs
    assert 'Error' in results.readable_output
    assert 'uuid' not in results.outputs


def test_gdetect_get_all_command_token(mocker):
    mocker.patch('GLIMPSDetect.gClient.get_by_uuid', return_value=mocked_gdetect_get_token())
    client = GLIMPSDetect.Client('url', DUMMY_TOKEN, False, False)
    args = {'entryID': '1@042262f2-6a12-44da-8e11-74cf4bc67063'}
    results = GLIMPSDetect.gdetect_get_all_command(client, args)
    assert 'token' in results.outputs
    assert 'link' in results.outputs
    assert 'analysis-redirect' in results.outputs.get('link')
    assert 'sid' not in results.outputs


def test_gdetect_get_all_command_link_sid(mocker):
    mocker.patch('GLIMPSDetect.gClient.get_by_uuid', return_value=mocked_gdetect_get_sid())
    client = GLIMPSDetect.Client('url', DUMMY_TOKEN, False, False)
    args = {'entryID': '1@042262f2-6a12-44da-8e11-74cf4bc67063'}
    results = GLIMPSDetect.gdetect_get_all_command(client, args)
    assert 'token' not in results.outputs
    assert 'link' in results.outputs
    assert 'analysis/advanced' in results.outputs.get('link')
    assert 'sid' not in results.outputs


def test_gdetect_get_all_command_link_uuid(mocker):
    mocker.patch('GLIMPSDetect.gClient.get_by_uuid', return_value=mocked_gdetect_get_base())
    client = GLIMPSDetect.Client('url', DUMMY_TOKEN, False, False)
    args = {'entryID': '1@042262f2-6a12-44da-8e11-74cf4bc67063'}
    results = GLIMPSDetect.gdetect_get_all_command(client, args)
    assert 'token' not in results.outputs
    assert 'sid' not in results.outputs
    assert 'uuid' in results.outputs
    assert 'link' in results.outputs
    assert 'analysis/response' in results.outputs.get('link')


def test_gdetect_get_all_command_errors(mocker):
    mocker.patch('GLIMPSDetect.gClient.get_by_uuid', return_value=mocked_gdetect_get_errors())
    client = GLIMPSDetect.Client('url', DUMMY_TOKEN, False, False)
    args = {'entryID': '1@042262f2-6a12-44da-8e11-74cf4bc67063'}
    results = GLIMPSDetect.gdetect_get_all_command(client, args)
    assert 'Error' in results.readable_output
    assert 'error' in results.outputs
    assert 'Errors' in results.readable_output
    assert 'errors' in results.outputs


def test_gdetect_get_all_command_files(mocker):
    mocker.patch('GLIMPSDetect.gClient.get_by_uuid', return_value=mocked_gdetect_get_files())
    client = GLIMPSDetect.Client('url', DUMMY_TOKEN, False, False)
    args = {'entryID': '1@042262f2-6a12-44da-8e11-74cf4bc67063'}
    results = GLIMPSDetect.gdetect_get_all_command(client, args)
    assert 'File' in results.readable_output
    assert 'files' in results.outputs


def test_gdetect_get_all_command_files_av_results(mocker):
    mocker.patch('GLIMPSDetect.gClient.get_by_uuid', return_value=mocked_gdetect_get_files_av_results())
    client = GLIMPSDetect.Client('url', DUMMY_TOKEN, False, False)
    args = {'entryID': '1@042262f2-6a12-44da-8e11-74cf4bc67063'}
    results = GLIMPSDetect.gdetect_get_all_command(client, args)
    assert 'File' in results.readable_output
    assert 'AV Result for' in results.readable_output
    assert 'files' in results.outputs


def test_gdetect_get_all_command_threats(mocker):
    mocker.patch('GLIMPSDetect.gClient.get_by_uuid', return_value=mocked_gdetect_get_threats())
    client = GLIMPSDetect.Client('url', DUMMY_TOKEN, False, False)
    args = {'entryID': '1@042262f2-6a12-44da-8e11-74cf4bc67063'}
    results = GLIMPSDetect.gdetect_get_all_command(client, args)
    assert 'threats' in results.outputs
    assert 'Threat' in results.readable_output
    assert 'Tags of threat' in results.readable_output


def test_gdetect_get_threats_command_token(mocker):
    mocker.patch('GLIMPSDetect.gClient.get_by_uuid', return_value=mocked_gdetect_get_threats_with_token())
    client = GLIMPSDetect.Client('url', DUMMY_TOKEN, False, False)
    args = {'entryID': '1@042262f2-6a12-44da-8e11-74cf4bc67063'}
    results = GLIMPSDetect.gdetect_get_threats_command(client, args)
    assert 'link' in results.outputs
    assert 'Link' in results.readable_output
    assert 'analysis-redirect' in results.outputs.get('link')
    assert 'sid' not in results.outputs


def test_gdetect_get_threats_command_sid(mocker):
    mocker.patch('GLIMPSDetect.gClient.get_by_uuid', return_value=mocked_gdetect_get_threats_with_sid())
    client = GLIMPSDetect.Client('url', DUMMY_TOKEN, False, False)
    args = {'entryID': '1@042262f2-6a12-44da-8e11-74cf4bc67063'}
    results = GLIMPSDetect.gdetect_get_threats_command(client, args)
    assert 'link' in results.outputs
    assert 'Link' in results.readable_output
    assert 'analysis/advanced' in results.outputs.get('link')
    assert 'sid' not in results.outputs


def test_gdetect_get_threats_command_uuid(mocker):
    mocker.patch('GLIMPSDetect.gClient.get_by_uuid', return_value=mocked_gdetect_get_threats())
    client = GLIMPSDetect.Client('url', DUMMY_TOKEN, False, False)
    args = {'entryID': '1@042262f2-6a12-44da-8e11-74cf4bc67063'}
    results = GLIMPSDetect.gdetect_get_threats_command(client, args)
    assert 'link' in results.outputs
    assert 'Link' in results.readable_output
    assert 'analysis/response' in results.outputs.get('link')
    assert 'sid' not in results.outputs


def test_gdetect_get_threats_command_no_threats(mocker):
    mocker.patch('GLIMPSDetect.gClient.get_by_uuid', return_value=mocked_gdetect_get_base())
    client = GLIMPSDetect.Client('url', DUMMY_TOKEN, False, False)
    args = {'entryID': '1@042262f2-6a12-44da-8e11-74cf4bc67063'}
    results = GLIMPSDetect.gdetect_get_threats_command(client, args)
    assert 'link' in results.outputs
    assert 'uuid' in results.outputs
    assert 'No threats' in results.readable_output
