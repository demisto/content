import pytest
from json import load
from GroupIBTIA import fetch_incidents_command, Client


with open('test_data/example.json') as example:
    RAW_JSON = load(example)
with open('test_data/results.json') as results:
    RESULTS = load(results)

# Because of errors with markdown tables
RESULTS.update({
    'osi/git_repository': (
        ({'last_fetch': {'osi/git_repository': 1611862631144674}},
         [{'name': 'Git Leak: https://github.com/somegit',
           'occurred': '2021-01-28T22:32:54Z',
           'rawJSON': '{"company": [], "companyId": [3150], "contributors": '
                      '[{"authorEmail": "some@email.com", "authorName": "somename"}, '
                      '{"authorEmail": "some@email.com", "authorName": "somename"}, '
                      '{"authorEmail": "some@email.com", "authorName": "somename"}], '
                      '"dataFound": {"password": 8, "apikey": 2, "secret": 1}, '
                      '"dateCreated": "2021-01-23T22:12:58+03:00", "dateDetected": '
                      '"2021-01-28T22:32:54+03:00", "evaluation": {"admiraltyCode": '
                      '"A1", "credibility": 50, "reliability": 50, "severity": '
                      '"orange", "tlp": "amber", "ttl": 30}, "favouriteForCompanies": '
                      '[], "files": "| URL  |   Author Email  | Author Name  | Date '
                      'Created| TimeStamp    |\\n| ---- | --------------- | '
                      '------------ | ----------- | ------------ |\\n| '
                      'https://github.com/somegit | some@email.com | TEST | '
                      '1970-01-01T03:00:00+03:00 | [1611429178] |\\n", '
                      '"hideForCompanies": [], "id": '
                      '"21aed9b86d2e6cbb15180d803a84f6d27f673db4", '
                      '"ignoreForCompanies": [], "isFavourite": false, "isHidden": '
                      'false, "isIgnore": false, "matchesTypes": [], "name": "Git '
                      'Leak: https://github.com/somegit", "numberOf": {"contributors": '
                      '3, "files": 10}, "relations": {"infobip.com": "some.com", '
                      '"Infobip": "some"}, "seqUpdate": 1611862631144674, "source": '
                      '"github", "gibType": "osi/git_repository", '
                      '"relatedIndicatorsData": [], "systemSeverity": 2}'}])),
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
                        '| https://some.ru | show.zip | "some.ru" '
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
COLLECTION_NAMES = ['compromised/account', 'compromised/card', 'osi/git_repository', 'osi/public_leak',
                    'bp/phishing', 'bp/phishing_kit', 'malware/targeted_malware', "compromised/breached"]


@pytest.fixture(scope='function', params=COLLECTION_NAMES, ids=COLLECTION_NAMES)
def session_fixture(request):
    return request.param, Client(base_url='https://some.ru')


def test_fetch_incidents_command(mocker, session_fixture):
    collection_name, client = session_fixture
    mocker.patch.object(client, 'create_poll_generator', return_value=[RAW_JSON[collection_name]])
    result = fetch_incidents_command(client=client, last_run={}, first_fetch_time='3 days',
                                     incident_collections=[collection_name], requests_count=1)
    assert result == tuple(RESULTS[collection_name])
