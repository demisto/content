from CommonServerPython import *
from TAXII2ApiModule import Taxii2FeedClient, TAXII_VER_2_1, HEADER_USERNAME
from taxii2client import v20, v21
import pytest
import json

with open('test_data/stix_envelope_no_indicators.json', 'r') as f:
    STIX_ENVELOPE_NO_IOCS = json.load(f)

with open('test_data/stix_envelope_17-19.json', 'r') as f:
    STIX_ENVELOPE_17_IOCS_19_OBJS = json.load(f)

with open('test_data/stix_envelope_complex_20-19.json', 'r') as f:
    STIX_ENVELOPE_20_IOCS_19_OBJS = json.load(f)

with open('test_data/cortex_parsed_indicators_17-19.json', 'r') as f:
    CORTEX_17_IOCS_19_OBJS = json.load(f)

with open('test_data/cortex_parsed_indicators_complex_20-19.json', 'r') as f:
    CORTEX_COMPLEX_20_IOCS_19_OBJS = json.load(f)

with open('test_data/cortex_parsed_indicators_complex_skipped_14-19.json', 'r') as f:
    CORTEX_COMPLEX_14_IOCS_19_OBJS = json.load(f)
with open('test_data/id_to_object_test.json', 'r') as f:
    id_to_object = json.load(f)
with open('test_data/parsed_stix_objects.json', 'r') as f:
    parsed_objects = json.load(f)
with open('test_data/objects_envelopes_v21.json', 'r') as f:
    envelopes_v21 = json.load(f)
with open('test_data/objects_envelopes_v20.json', 'r') as f:
    envelopes_v20 = json.load(f)


class MockCollection:
    def __init__(self, id_, title):
        self.id = id_
        self.title = title


class TestInitCollectionsToFetch:
    """
    Scenario: Initialize collections to fetch
    """
    mock_client = Taxii2FeedClient(url='', collection_to_fetch='default', proxies=[], verify=False, objects_to_fetch=[])
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
        with pytest.raises(DemistoException, match="Could not find the provided Collection name"):
            self.mock_client.init_collection_to_fetch('not_found')

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
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='default', proxies=[], verify=False, objects_to_fetch=[])
        with pytest.raises(DemistoException, match="No collection is available for this user"):
            mock_client.init_collection_to_fetch('not_found')


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
        mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False, objects_to_fetch=[])
        with pytest.raises(DemistoException, match='Could not find a collection to fetch from.'):
            mock_client.build_iterator()

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
        mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False, objects_to_fetch=[])
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
        mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False, objects_to_fetch=[])
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
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, objects_to_fetch=[])
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
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, objects_to_fetch=[])
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
            verify=False,
            objects_to_fetch=[]
        )
        mock_client.init_server()
        assert isinstance(mock_client.server, v20.Server)
        assert mock_auth_header_key in mock_client.server._conn.session.headers[0]
        assert mock_client.server._conn.session.headers[0].get(mock_auth_header_key) == mock_password


class TestFetchingStixObjects:
    """
    Scenario: Test load_stix_objects_from_envelope and parse_stix_objects
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
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, objects_to_fetch=[])

        actual = mock_client.load_stix_objects_from_envelope({"indicator": STIX_ENVELOPE_NO_IOCS}, -1)

        assert len(actual) == 0
        assert expected == actual

    def test_21_simple(self):
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
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, tlp_color='GREEN',
                                       objects_to_fetch=[])

        actual = mock_client.load_stix_objects_from_envelope({"indicator": STIX_ENVELOPE_17_IOCS_19_OBJS}, -1)

        assert len(actual) == 17
        assert expected == actual

    def test_21_complex_not_skipped(self):
        """
        Scenario: Test 21 envelope complex extract without skip

        Given:
        - Envelope with 19 STIX2 objects - 14 normal iocs, 3 are complex indicators (x2 iocs), and 2 aren't indicators
        - skip is False

        When:
        - extract_indicators_from_envelope_and_parse is called

        Then:
        - Extract and parse the indicators from the envelope with the complex iocs

        """
        expected = CORTEX_COMPLEX_20_IOCS_19_OBJS
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, tlp_color='GREEN',
                                       objects_to_fetch=[])

        actual = mock_client.load_stix_objects_from_envelope({"indicator": STIX_ENVELOPE_20_IOCS_19_OBJS}, -1)

        assert len(actual) == 20
        assert actual == expected

    def test_21_complex_skipped(self):
        """
        Scenario: Test 21 envelope complex extract with skip

        Given:
        - Envelope with 19 STIX2 objects - 14 normal iocs, 3 are complex indicators (x2 iocs), and 2 aren't indicators
        - skip is True

        When:
        - extract_indicators_from_envelope_and_parse is called

        Then:
        - Extract and parse the indicators from the envelope with the complex iocs

        """
        expected = CORTEX_COMPLEX_14_IOCS_19_OBJS
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, skip_complex_mode=True,
                                       objects_to_fetch=[])

        actual = mock_client.load_stix_objects_from_envelope({"indicator": STIX_ENVELOPE_20_IOCS_19_OBJS}, -1)

        assert len(actual) == 14
        assert actual == expected

    def test_load_stix_objects_from_envelope_v21(self):
        """
        Scenario: Test loading of STIX objects from envelope for v2.1

        Given:
        - Envelope with indicators, arranged by object type.

        When:
        - load_stix_objects_from_envelope is called

        Then: - Load and parse objects from the envelope according to their object type and ignore
        extension-definition objects.

        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, objects_to_fetch=[])
        objects_envelopes = envelopes_v21
        mock_client.id_to_object = id_to_object

        result = mock_client.load_stix_objects_from_envelope(objects_envelopes, -1)
        assert mock_client.id_to_object == id_to_object
        assert result == parsed_objects

    def test_load_stix_objects_from_envelope_v20(self):
        """
        Scenario: Test loading of STIX objects from envelope for v2.0

        Given:
        - Envelope with indicators, arranged by object type.

        When:
        - parse_generator_type_envelope is called (skipping condition from load_stix_objects_from_envelope).

        Then: - Load and parse objects from the envelope according to their object type and ignore
        extension-definition objects.

        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, objects_to_fetch=[])
        objects_envelopes = envelopes_v20
        mock_client.id_to_object = id_to_object

        parse_stix_2_objects = {
            "indicator": mock_client.parse_indicator,
            "attack-pattern": mock_client.parse_attack_pattern,
            "malware": mock_client.parse_malware,
            "report": mock_client.parse_report,
            "course-of-action": mock_client.parse_course_of_action,
            "campaign": mock_client.parse_campaign,
            "intrusion-set": mock_client.parse_intrusion_set,
            "tool": mock_client.parse_tool,
            "threat-actor": mock_client.parse_threat_actor,
            "infrastructure": mock_client.parse_infrastructure
        }
        result = mock_client.parse_generator_type_envelope(objects_envelopes, parse_stix_2_objects)
        assert mock_client.id_to_object == id_to_object
        assert result == parsed_objects
