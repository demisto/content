import pytest
from json import load
from GroupIBTIA import fetch_incidents_command, Client


with open('test_data/example.json') as example:
    RAW_JSON = load(example)
with open('test_data/results.json') as results:
    RESULTS = load(results)

# Because of errors with markdown tables
RESULTS.update({
    'osi/git_leak': (
        {'last_fetch': {'osi/git_leak': 1611219371626093}},
        [
            {
                'name': 'Git Leak: conf/nginx/sites-available/whatsinmyyogurt',
                'occurred': '2021-01-21T08:56:11Z',
                'rawJSON': '{"dateDetected": "2021-01-21T08:56:11+00:00", "dateUpdated": "1561036415", '
                           '"evaluation": {"admiraltyCode": "A6", "credibility": 100, "reliability": 100, '
                           '"severity": "green", "tlp": "amber", "ttl": 30}, '
                           '"file": "https://bt.group-ib.com/api/v2/osi/git_leak'
                           '/f201c253ac71f7d78db39fa111a2af9d7ee7a3f7/bWFpbi01NDA4'
                           'YWY0MDE2ZTVmZDFjYTZlYWQzNThjYzNiMmI0YjYwNWY1NGY2ODU4Yzc'
                           '4YmVmMGNlYmUyZGVlMDZmMDhm", "id": "f201c253ac71f7d78db39fa111a2af9d7ee7a3f7", '
                           '"matchesType": ["keyword"], "matchesTypeCount": {"card": 0, '
                           '"cisco": 0, "commonKeywords": 0, "domain": 0, "dsn": 0, "email": 0, '
                           '"google": 0, "ip": 0, "keyword": 1, "login": 0, "metasploit": 0, "nmap": 0, '
                           '"pgp": 0, "sha": 0, "slackAPI": 0, "ssh": 0}, '
                           '"name": "Git Leak: conf/nginx/sites-available/whatsinmyyogurt", '
                           '"repository": "openfoodfacts/openfoodfacts-server", '
                           '"revisions": "| File | File Difference | Author Email | Author Name | Date Created |\\n'
                           '| ---- | --------------- | ------------ | ----------- | ------------ |\\n'
                           '| [https://bt.group-ib.com/api/v2/osi/git_leak]'
                           '(https://bt.group-ib.com/api/v2/osi/git_leak'
                           '/f201c253ac71f7d78db39fa111a2af9d7ee7a3f7/cmV2aXNpb24tZmlsZS01NDA4YWY0MDE2ZTVmZDF'
                           'jYTZlYWQzNThjYzNiMmI0YjYwNWY1NGY2ODU4Yzc4YmVmMGNlYmUyZGVlMDZmMDhm) | '
                           '[https://bt.group-ib.com/api/v2/osi/git_leak]'
                           '(https://bt.group-ib.com'
                           '/api/v2/osi/git_leak/f201c253ac71f7d78db39fa111a2af9d7ee7a3f7/cmV2aXNpb24tZml'
                           'sZURpZmYtNTQwOGFmNDAxNmU1ZmQxY2E2ZWFkMzU4Y2MzYjJiNGI2MDVmNTRmNjg1OGM3OGJlZjB'
                           'jZWJlMmRlZTA2ZjA4Zg==) | some@gmail.ru | sadsdsa | 2019-06-20T13:13:35+00:00 |\\n", '
                           '"seqUpdate": 1611219371626093, "source": "github", '
                           '"gibType": "osi/git_leak", "relatedIndicatorsData": [], "systemSeverity": 1}'}]),
    'osi/public_leak': (
        {'last_fetch': {'osi/public_leak': 1601909532153438}},
        [
            {
                'name': 'Public Leak: a9a5b5cb9b971a2a037e3a0a30654185ea148095',
                'occurred': '2020-10-05T17:51:31Z',
                'rawJSON': '{"bind": [], "created": "2020-10-05T17:51:31+03:00", "data": '
                           '"Pasted at: 05/10/2020 15:45", "displayOptions": null, '
                           '"evaluation": {"admiraltyCode": "C3", "credibility": 50, '
                           '"reliability": 50, "severity": "orange", "tlp": "amber", "ttl": '
                           '30}, "hash": "a9a5b5cb9b971a2a037e3a0a30654185ea148095", "id": '
                           '"a9a5b5cb9b971a2a037e3a0a30654185ea148095", "language": "c", '
                           '"linkList": "| Author | Date Detected | Date Published | Hash | Link | Source |\\n'
                           '| ------ | ------------- | -------------- | ---- |----- | ------ |\\n| whaaaaaat | '
                           '2020-10-05T17:51:31+03:00 | 2020-10-05T17:45:46+03:00 | '
                           '3066db9f57b7997607208fedc45d7203029d9cb3 | '
                           '[https://some.ru](https://some.ru) | some.ru '
                           '|\\n", "matches": "| Type | Sub Type | Value |\\n| ---- | -------- | ----- |\\n| email '
                           '| email | some@gmail.ru |\\n", '
                           '"oldId": null, '
                           '"portalLink": "https://bt.group-ib.com/osi/public_leak?'
                           'searchValue=id:a9a5b5cb9b971a2a037e3a0a30654186ea248094", '
                           '"seqUpdate": 1601909532153438, "size": "345 B", "updated": '
                           '"2020-10-05T17:51:31+03:00", "useful": 1, "name": '
                           '"Public Leak: a9a5b5cb9b971a2a037e3a0a30654185ea148095", "gibType": '
                           '"osi/public_leak", "relatedIndicatorsData": [], "systemSeverity": 2}'
            }
        ]
    ),
    'bp/phishing_kit': (
        {'last_fetch': {'bp/phishing_kit': 1614921031175}},
        [
            {'name': 'Phishing Kit: 8d7ea805fe20d6d77f57e2f0cadd17b1',
             'occurred': '2021-01-14T12:10:41Z',
             'rawJSON': '{"dateDetected": "2021-01-14T12:10:41+00:00", "dateFirstSeen": "2021-01-14T13:10:41+00:00", '
                        '"dateLastSeen": "2021-01-14T14:12:17+00:00", "downloadedFrom": "| URL | File Name '
                        '| Domain | Date |\\n| --- | --------- | ------ | ---- |\\n'
                        '| https://some.ru | show.zip | some.ru | 2021-01-21 10:10:41 |\\n'
                        '| https://some.ru | show.zip | ''some.ru '
                        '| 2021-01-21 10:10:41 |\\n| https://some.ru | show.zip '
                        '| some.ru | 2021-01-21 10:10:41 |\\n", '
                        '"emails": [], "evaluation": {"admiraltyCode": "B2", "credibility": 70, '
                        '"reliability": 80, "severity": "orange", "tlp": "amber", "ttl": '
                        '30}, "hash": "8d7ea805fe20d6d77f57e2f0cadd17b1", "id": '
                        '"044f3f2cb599228c1882884eb77eb073f68a25f2", "isFavourite": '
                        'false, "isHidden": false, "oldId": "396793696", "path": '
                        '"https://tap.group-ib.com/api/api/v2/web/attacks/phishing_kit'
                        '/044f3f2cb599228c1882884eb77eb073f68a25f2/file'
                        '/95b61a1df152012abb79c3951ed98680e0bd917bbcf1d440e76b66a120292c76", '
                        '"portalLink": "https://bt.group-ib.com/attacks/phishing_kit?searchValue='
                        'id:044f3f2cb599228c1882884eb77eb073f68a25f2", '
                        '"seqUpdate": 1614921031175, "targetBrand": [], "tsFirstSeen": '
                        'null, "tsLastSeen": null, "variables": null, "name": '
                        '"Phishing Kit: 8d7ea805fe20d6d77f57e2f0cadd17b1", "gibType": '
                        '"bp/phishing_kit", "relatedIndicatorsData": [[]], '
                        '"systemSeverity": 2}'}]),
})
COLLECTION_NAMES = ['compromised/account', 'compromised/card', 'osi/git_leak', 'osi/public_leak',
                    'bp/phishing', 'bp/phishing_kit', 'malware/targeted_malware', "compromised/breached",
                    'bp/domain']


@pytest.fixture(scope='function', params=COLLECTION_NAMES, ids=COLLECTION_NAMES)
def session_fixture(request):
    return request.param, Client(base_url='https://some.ru')


def test_fetch_incidents_command(mocker, session_fixture):
    collection_name, client = session_fixture
    mocker.patch.object(client, 'create_poll_generator', return_value=[RAW_JSON[collection_name]])
    result = fetch_incidents_command(client=client, last_run={}, first_fetch_time='3 days',
                                     incident_collections=[collection_name], requests_count=1)
    assert result == tuple(RESULTS[collection_name])
