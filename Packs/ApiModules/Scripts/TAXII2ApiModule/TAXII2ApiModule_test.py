from CommonServerPython import *
from TAXII2ApiModule import Taxii2FeedClient, TAXII_VER_2_1, HEADER_USERNAME
from taxii2client import v20, v21
import json

with open('test_data/stix_envelope_no_indicators.json', 'r') as f:
    STIX_ENVELOP_NO_IOCS = json.load(f)

with open('test_data/stix_envelope_17|19.json', 'r') as f:
    STIX_ENVLOPE_17_IOCS_19_OBJS = json.load(f)

with open('test_data/cortex_parsed_indicators_17|19.json', 'r') as f:
    CORTEX_17_IOCS_19_OBJS = json.load(f)


class MockCollection:
    def __init__(self, id_, title):
        self.id = id_
        self.title = title


class TestInitCollectionsToFetch:
    """
    Scenario: Initialize collections to fetch
    """
    mock_client = Taxii2FeedClient(url='', collection_to_fetch='default', proxies=[], verify=False)
    default_id = 1
    nondefault_id = 2
    mock_client.collections = [MockCollection(nondefault_id, 'not_default'),
                               MockCollection(default_id, 'default')]

    def test_default_collection(self):
        """
        Scenario: Initialize with collection name provided in class __init__

        Given
        - collection name is provided via __init__ (title: default)
        - collection is available

        When
        - Initializing collection to fetch

        Then
        - Ensure initialized collection to fetch with collection provided in __init__
        """
        self.mock_client.init_collection_to_fetch()
        assert self.mock_client.collection_to_fetch.id == self.default_id

    def test_non_default_collection(self):
        """
        Scenario: Initialize with collection name provided via argument

        Given:
        - collection name is provided via argument (title: non_default)
        - collection is available

        When
        - Initializing collection to fetch

        Then
        - Ensure initialized collection to fetch with collection provided in argument
        """
        self.mock_client.init_collection_to_fetch('not_default')
        assert self.mock_client.collection_to_fetch.id == self.nondefault_id

    def test_collection_not_found(self):
        """
        Scenario: Fail to initialize with a collection that is not available

        Given:
        - collection name is provided via argument (title: not_found)
        - collection is NOT available

        When
        - Initializing collection to fetch

        Then:
        - Ensure exception is raised with proper error message
        """
        try:
            exception_raised = False
            self.mock_client.init_collection_to_fetch('not_found')
        except DemistoException as e:
            exception_raised = True
            assert "Could not find the provided Collection name" in str(e)
        assert exception_raised

    def test_no_collections_available(self):
        """
        Scenario: Fail to initialize when there is no collection available

        Given:
        - collection name is provided via __init__ (title: default)
        - NO collection is available

        When
        - Initializing collection to fetch

        Then:
        - Ensure exception is raised with proper error message
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='default', proxies=[], verify=False)
        try:
            exception_raised = False
            mock_client.init_collection_to_fetch('not_found')
        except DemistoException as e:
            exception_raised = True
            assert "No collection is available for this user" in str(e)
        assert exception_raised


class TestBuildIterator:
    """
    Scenario: Get indicators via build_iterator method
    """
    def test_no_collection_to_fetch(self):
        """
        Scenario: Fail to build iterator when there is no collection to fetch from

        Given:
        - Collection to fetch is empty

        When:
        - Calling build_iterators

        Then:
        - Ensure exception is raised with proper error message
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False)
        try:
            exception_raised = False
            mock_client.build_iterator()
        except DemistoException as e:
            exception_raised = True
            assert "Could not find a collection to fetch from." in str(e)
        assert exception_raised

    def test_limit_0_v20(self, mocker):
        """
        Scenario: Call build iterator when limit is 0 and the collection is v20.Collection

        Given:
        - Limit is 0
        - Collection to fetch is of type v20.Collection

        When
        - Initializing collection to fetch

        Then:
        - Ensure 0 iocs are returned
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False)
        mocker.patch.object(mock_client, "collection_to_fetch", spec=v20.Collection)
        iocs = mock_client.build_iterator(limit=0)
        assert iocs == []

    def test_limit_0_v21(self, mocker):
        """
        Scenario: Call build iterator when limit is 0 and the collection is v21.Collection

        Given:
        - Limit is 0
        - Collection to fetch is of type v21.Collection

        When
        - Initializing collection to fetch

        Then:
        - Ensure 0 iocs are returned
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False)
        mocker.patch.object(mock_client, "collection_to_fetch", spec=v21.Collection)
        iocs = mock_client.build_iterator(limit=0)
        assert iocs == []


class TestInitServer:
    """
    Scenario: Initialize server
    """
    def test_default_v20(self):
        """
        Scenario: Intialize server with the default option

        Given:
        - no version is provided to init_server

        Then:
        - initalize with v20.Server
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False)
        mock_client.init_server()
        assert isinstance(mock_client.server, v20.Server)

    def test_v21(self):
        """
        Scenario: Intialize server with v21

        Given:
        - v21 version is provided to init_server

        Then:
        - initalize with v21.Server
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False)
        mock_client.init_server(TAXII_VER_2_1)
        assert isinstance(mock_client.server, v21.Server)

    def test_auth_key(self):
        """
        Scenario: Intialize server with the default option with an auth key

        Given:
        - no version is provided to init_server
        - client is set with `auth_key` and `auth_header`

        Then:
        - initialize with v20.Server with _conn.headers set with the auth_header
        """
        mock_auth_header_key = 'mock_auth'
        mock_username = f'{HEADER_USERNAME}{mock_auth_header_key}'
        mock_password = 'mock_pass'
        mock_client = Taxii2FeedClient(
            url='',
            username=mock_username,
            password=mock_password,
            collection_to_fetch='',
            proxies=[],
            verify=False
        )
        mock_client.init_server()
        assert isinstance(mock_client.server, v20.Server)
        assert mock_auth_header_key in mock_client.server._conn.session.headers[0]
        assert mock_client.server._conn.session.headers[0].get(mock_auth_header_key) == mock_password


class TestExtractIndicatorsAndParse:
    """
    Scenario: Test extract_indicators_from_envelope_and_parse
    """
    def test_21_empty(self):
        """
        Scenario: Test 21 envelope extract

        Given:
        - Envelope with 0 STIX2 objects

        When:
        - extract_indicators_from_envelope_and_parse is called

        Then:
        - Extract and parse the indicators from the envelope

        """
        expected = []
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False)
        actual = mock_client.extract_indicators_from_envelope_and_parse(STIX_ENVELOP_NO_IOCS)

        assert len(actual) == 0
        assert expected == actual

    def test_21(self):
        """
        Scenario: Test 21 envelope extract

        Given:
        - Envelope with 19 STIX2 objects - out of them 17 are iocs

        When:
        - extract_indicators_from_envelope_and_parse is called

        Then:
        - Extract and parse the indicators from the envelope

        """
        expected = CORTEX_17_IOCS_19_OBJS
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False)
        actual = mock_client.extract_indicators_from_envelope_and_parse(STIX_ENVLOPE_17_IOCS_19_OBJS)

        assert len(actual) == 17
        assert expected == actual
