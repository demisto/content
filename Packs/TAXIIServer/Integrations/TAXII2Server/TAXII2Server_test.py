import io
import json

import pytest
from requests.auth import _basic_auth_str
from TAXII2Server import TAXII2Server, APP
import demistomock as demisto

HEADERS = {
    'Authorization': _basic_auth_str("username", "password"),
    'Accept': '*/*',
}
SERVER20 = TAXII2Server(url_scheme='http',
                        host='demisto',
                        port=7000,
                        collections={'Collection1': 'type:IP', 'Collection2': 'sourceBrands:"Some Feed"'},
                        certificate='',
                        private_key='',
                        http_server=True,
                        credentials={'identifier': 'username',
                                     'password': 'password'},
                        version='2.0',
                        service_address=None)

SERVER21 = TAXII2Server(url_scheme='http',
                        host='demisto',
                        port=7000,
                        collections={'Collection1': 'type:IP', 'Collection2': 'sourceBrands:"Some Feed"'},
                        certificate='',
                        private_key='',
                        http_server=True,
                        credentials={'identifier': 'username',
                                     'password': 'password'},
                        version='2.1',
                        service_address=None)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('headers', [{'Authorization': _basic_auth_str("user", "pwd")}, {}])
def test_taxii_wrong_auth(mocker, headers):
    """
        Given
            Taxii server v2.0
        When
            Getting server discovery, with wrong auth
        Then
            Validate that the error and status code right
    """
    mocker.patch('TAXII2Server.SERVER', SERVER20)
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(demisto, 'updateModuleHealth')
    with APP.test_client() as test_client:
        response = test_client.get('/taxii/', headers=headers)
        assert response.status_code == 401
        assert response.json == {'title': 'Authorization failed'}


@pytest.mark.parametrize('headers', [{'Authorization': _basic_auth_str("username", "password")},
                                     {'Authorization': _basic_auth_str("username", "password"),
                                      'Accept': 'wrong_type'}])
def test_taxii_wrong_accept(mocker, headers):
    """
        Given
            Taxii server v2.0
        When
            Getting server discovery, with wrong accept header
        Then
            Validate that the error and status code right
    """
    mocker.patch('TAXII2Server.SERVER', SERVER20)
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(demisto, 'updateModuleHealth')
    with APP.test_client() as test_client:
        response = test_client.get('/taxii/', headers=headers)
        assert response.status_code == 406


def test_taxii20_server_discovery(mocker):
    """
        Given
            Taxii server v2.0
        When
            Getting server discovery
        Then
            Validate that the discovery output as expected
    """
    mocker.patch('TAXII2Server.SERVER', SERVER20)
    with APP.test_client() as test_client:
        response = test_client.get('/taxii/', headers=HEADERS)
        assert response.status_code == 200
        assert response.content_type == 'application/vnd.oasis.taxii+json; version=2.0'
        assert response.json.get('default') == 'http://demisto:7000/threatintel/'


def test_taxii21_server_discovery(mocker):
    """
        Given
            Taxii server v2.1
        When
            Call server discovery api request
        Then
            Validate that the discovery output as expected
    """
    mocker.patch('TAXII2Server.SERVER', SERVER21)
    with APP.test_client() as test_client:
        response = test_client.get('/taxii/', headers=HEADERS)
        assert response.status_code == 200
        assert response.content_type == 'application/taxii+json;version=2.1'
        assert response.json.get('default') == 'http://demisto:7000/threatintel/'


def test_taxii20_api_root(mocker):
    """
        Given
            TAXII v2.0 server, api_root
        When
            Call api_root api request
        Then
            Validate that the api_root information returned as expected
    """
    mocker.patch('TAXII2Server.SERVER', SERVER20)
    with APP.test_client() as test_client:
        response = test_client.get('/threatintel/', headers=HEADERS)
        assert response.status_code == 200
        assert response.content_type == 'application/vnd.oasis.taxii+json; version=2.0'
        assert response.json.get('title') == 'XSOAR TAXII2 Server ThreatIntel'


def test_taxii_wrong_api_root(mocker):
    """
        Given
            Taxii server v2.0, Not exiting api_root
        When
            Getting api root information, for wrong api_root
        Then
            Validate that the error and status code right
    """
    mocker.patch('TAXII2Server.SERVER', SERVER20)
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(demisto, 'updateModuleHealth')
    with APP.test_client() as test_client:
        response = test_client.get('/not_exsisting_api_root/', headers=HEADERS)
        assert response.status_code == 404
        assert response.json.get('title') == 'Unknown API Root'


def test_taxii20_status(mocker):
    """
        Given
            Status api call
        When
            Calling a status request
        Then
            Validate the error returned.
    """
    mocker.patch('TAXII2Server.SERVER', SERVER20)
    with APP.test_client() as test_client:
        response = test_client.get('/threatintel/status/1223456/', headers=HEADERS)
        assert response.status_code == 400


def test_taxii20_collections(mocker):
    """
        Given
            TAXII Server v2.0
        When
            Calling collections api request
        Then
            Validate that collections returned as expected
    """
    collections = util_load_json('test_files/collections20.json')
    mocker.patch('TAXII2Server.SERVER', SERVER20)
    with APP.test_client() as test_client:
        response = test_client.get('/threatintel/collections/', headers=HEADERS)
        assert response.status_code == 200
        assert response.content_type == 'application/vnd.oasis.taxii+json; version=2.0'
        assert response.json == collections


def test_taxii21_collections(mocker):
    """
        Given
            TAXII Server v2.1
        When
            Calling collections api request
        Then
            Validate that collections returned as expected
    """
    collections = util_load_json('test_files/collections21.json')
    mocker.patch('TAXII2Server.SERVER', SERVER21)
    with APP.test_client() as test_client:
        response = test_client.get('/threatintel/collections/', headers=HEADERS)
        assert response.status_code == 200
        assert response.content_type == 'application/taxii+json;version=2.1'
        assert response.json == collections


def test_taxii20_collection(mocker):
    """
        Given
            TAXII Server v2.0, collection_id
        When
            Calling collection by id api request
        Then
            Validate that right collection returned
    """
    collections = util_load_json('test_files/collections20.json')
    mocker.patch('TAXII2Server.SERVER', SERVER20)
    with APP.test_client() as test_client:
        response = test_client.get('/threatintel/collections/583487c2-8cea-5acd-9a44-093d15241ece/', headers=HEADERS)
        assert response.status_code == 200
        assert response.content_type == 'application/vnd.oasis.taxii+json; version=2.0'
        assert response.json == collections[0]


def test_taxii21_collection(mocker):
    """
        Given
            TAXII Server v2.1, collection_id
        When
            Calling collection by id api request
        Then
            Validate that right collection returned
    """
    collections = util_load_json('test_files/collections21.json')
    mocker.patch('TAXII2Server.SERVER', SERVER21)
    with APP.test_client() as test_client:
        response = test_client.get('/threatintel/collections/583487c2-8cea-5acd-9a44-093d15241ece/', headers=HEADERS)
        assert response.status_code == 200
        assert response.content_type == 'application/taxii+json;version=2.1'
        assert response.json == collections[0]


def test_taxii_wrong_collection_id(mocker):
    """
        Given
            Taxii server v2.1, Not exiting collection_id
        When
            Getting collection information, for wrong collection_id
        Then
            Validate that the error and status code right
    """
    mocker.patch('TAXII2Server.SERVER', SERVER21)
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(demisto, 'updateModuleHealth')
    with APP.test_client() as test_client:
        response = test_client.get('/threatintel/collections/not_exsisting_collection_id/', headers=HEADERS)
        assert response.status_code == 404
        assert response.json.get('title') == 'Unknown Collection'


def test_taxii20_manifest(mocker):
    """
        Given
            TAXII Server v2.0, collection_id
        When
            Calling manifest api request for given collection
        Then
            Validate that right manifest returned.
    """
    iocs = util_load_json('test_files/iocs.json')
    manifest = util_load_json('test_files/manifest20.json')
    mocker.patch('TAXII2Server.SERVER', SERVER20)
    mocker.patch.object(demisto, 'searchIndicators', return_value=iocs)
    with APP.test_client() as test_client:
        response = test_client.get('/threatintel/collections/583487c2-8cea-5acd-9a44-093d15241ece/manifest/',
                                   headers=HEADERS)
        assert response.status_code == 200
        assert response.content_type == 'application/vnd.oasis.taxii+json; version=2.0'
        assert response.json == manifest


def test_taxii21_manifest(mocker):
    """
        Given
            TAXII Server v2.1, collection_id
        When
            Calling manifest api request for given collection
        Then
            Validate that right manifest returned.
    """
    iocs = util_load_json('test_files/iocs.json')
    manifest = util_load_json('test_files/manifest21.json')
    mocker.patch('TAXII2Server.SERVER', SERVER21)
    mocker.patch.object(demisto, 'searchIndicators', return_value=iocs)
    with APP.test_client() as test_client:
        response = test_client.get('/threatintel/collections/583487c2-8cea-5acd-9a44-093d15241ece/manifest/',
                                   headers=HEADERS)
        assert response.status_code == 200
        assert response.content_type == 'application/taxii+json;version=2.1'
        assert response.json == manifest


# todo: test llimit, test query params, test objects
def create_json_output_file(result, file_name):
    json_object = json.dumps(result, indent=4)
    # Writing to sample.json
    with open(f"test_files/{file_name}.json", "w") as outfile:
        outfile.write(json_object)
