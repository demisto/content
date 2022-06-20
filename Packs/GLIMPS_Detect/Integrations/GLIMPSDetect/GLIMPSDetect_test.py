import GLIMPSDetect


mocked_gdetect_get = {
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

mocked_gdetect_get_errors_files_no_av_results_no_threats = {
    "uuid": "fa78fb4e-a501-4964-a068-33f73a1167f5",
    "sha256": "c7c4547d5a8313a7edca3fbbc4a45e4a647c93b0c89234eb1bc09ab2893cc688",
    "sha1": "f28a2f914c7a6e6206456bed19d545af260cf6fd",
    "md5": "34c9516df650349f236908ca163a2553",
    "ssdeep": "49158:KW2x/eYZrm7c5CSV6fan+2pXVmWtagzBMFpvuyUkZ5HwdW:6",
    "is_malware": False,
    "score": 0,
    "done": True,
    "timestamp": 1651155344483,
    "errors": {
            "Extract": "The number of retries has passed the limit."
    },
    "error": "an error occurred with 1 services",
    "filetype": "zip",
    "size": 1816832,
    "filenames": [
        "sha256"
    ],
    "files": [
        {
            "sha256": "c7c4547d5a8313a7edca3fbbc4a45e4a647c93b0c89234eb1bc09ab2893cc688",
            "sha1": "f28a2f914c7a6e6206456bed19d545af260cf6fd",
            "md5": "34c9516df650349f236908ca163a2553",
            "ssdeep": "49158:KW2x/eYZrm7c5CSV6fan+2pXVmWtagzBMFpvuyUkZ5HwdW:6",
            "magic": "Zip archive data, at least v1.0 to extract",
            "size": 1816832,
            "is_malware": False
        }
    ],
    "sid": "fH4gcZBR45OEP1wOO9R2t",
    "file_count": 1,
    "duration": 297949,
    "token": ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ6.eyJ1c2VybmFtZSI6ImFwaS14YW5ndWl0ZXN0IiwiZ1JvdXBzIjpbInRhbmd1aXRlc6QiXSwi"
              "c5lkIjoiZkgwZ2NaQlI0OU9FUDF3T081UjJ0IiwiZXhwIjoxNjUzODA4NDg3LCJpYXQiOjE2NTEyMTY0ODd7.MyVtdTb7P0R448kraTN2SWrf"
              "raFlbe-CU4CoTTKCZlQ"),
    "status": True
}


def test_gdetect_send(mocker):
    mocker.patch('GLIMPSDetect.gClient.push', return_value='23465d22-3464-39ce-b8b3-bc2ee7d6eecf')
    client = GLIMPSDetect.Client('url', 'token', False, False)
    resp = client.gdetect_send('test_purpose')
    assert resp == '23465d22-3464-39ce-b8b3-bc2ee7d6eecf'


def test_gdetect_get(mocker):
    mocker.patch('GLIMPSDetect.gClient.get', return_value=mocked_gdetect_get)
    client = GLIMPSDetect.Client('url', 'token', False, False)
    resp = client.gdetect_get('23465d22-3464-39ce-b8b3-bc2ee7d6eecf')
    assert 'status' in resp
    assert resp.get('uuid') == '23465d22-3464-39ce-b8b3-bc2ee7d6eecf'


def test_gdetect_send_command(mocker):
    mocker.patch('GLIMPSDetect.gClient.push', return_value='23465d22-3464-39ce-b8b3-bc2ee7d6eecf')
    client = GLIMPSDetect.Client('url', 'token', False, False)
    args = {'entryID': '1@042262f2-6a12-44da-8e11-74cf4bc67063'}
    results = GLIMPSDetect.gdetect_send_command(client, args)
    assert results.outputs.get('entryID') == '1@042262f2-6a12-44da-8e11-74cf4bc67063'
    assert results.outputs.get('uuid') == '23465d22-3464-39ce-b8b3-bc2ee7d6eecf'
    assert 'threats' not in results.outputs


def test_gdetect_get_all_command_no_errors(mocker):
    mocker.patch('GLIMPSDetect.gClient.get', return_value=mocked_gdetect_get)
    client = GLIMPSDetect.Client('url', 'token', False, False)
    args = {'uuid': '23465d22-3464-39ce-b8b3-bc2ee7d6eecf'}
    results = GLIMPSDetect.gdetect_get_all_command(client, args)
    assert results.outputs.get('uuid') == '23465d22-3464-39ce-b8b3-bc2ee7d6eecf'
    assert 'errors' not in results.outputs
    assert 'files' in results.outputs
    assert 'threats' in results.outputs
    assert 'token' in results.outputs
    assert 'entryID' not in results.outputs


def test_gdetect_get_all_command_errors(mocker):
    mocker.patch('GLIMPSDetect.gClient.get', return_value=mocked_gdetect_get_errors_files_no_av_results_no_threats)
    client = GLIMPSDetect.Client('url', 'token', False, False)
    args = {'uuid': 'fa78fb4e-a501-4964-a068-33f73a1167f5'}
    results = GLIMPSDetect.gdetect_get_all_command(client, args)
    assert results.outputs.get('uuid') == 'fa78fb4e-a501-4964-a068-33f73a1167f5'
    assert 'errors' in results.outputs
    assert 'entryID' not in results.outputs


def test_gdetect_get_threats_command_no_errors(mocker):
    mocker.patch('GLIMPSDetect.gClient.get', return_value=mocked_gdetect_get)
    client = GLIMPSDetect.Client('url', 'token', False, False)
    args = {'uuid': '23465d22-3464-39ce-b8b3-bc2ee7d6eecf'}
    results = GLIMPSDetect.gdetect_get_threats_command(client, args)
    assert results.outputs.get('uuid') == '23465d22-3464-39ce-b8b3-bc2ee7d6eecf'
    assert 'result' not in results.outputs
    assert 'entryID' not in results.outputs
    assert 'files' not in results.outputs


def test_gdetect_get_threats_command_errors(mocker):
    mocker.patch('GLIMPSDetect.gClient.get', return_value=mocked_gdetect_get_errors_files_no_av_results_no_threats)
    client = GLIMPSDetect.Client('url', 'token', False, False)
    args = {'uuid': 'fa78fb4e-a501-4964-a068-33f73a1167f5'}
    results = GLIMPSDetect.gdetect_get_threats_command(client, args)
    assert results.outputs.get('uuid') == 'fa78fb4e-a501-4964-a068-33f73a1167f5'
    assert 'result' in results.outputs
    assert 'entryID' not in results.outputs
