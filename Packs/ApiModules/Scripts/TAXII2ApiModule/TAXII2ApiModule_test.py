from taxii2client.exceptions import TAXIIServiceException, InvalidJSONError

from CommonServerPython import *
from TAXII2ApiModule import Taxii2FeedClient, TAXII_VER_2_1, HEADER_USERNAME
from taxii2client import v20, v21
import pytest
import json

with open('test_data/stix_envelope_no_indicators.json') as f:
    STIX_ENVELOPE_NO_IOCS = json.load(f)

with open('test_data/stix_envelope_17-19.json') as f:
    STIX_ENVELOPE_17_IOCS_19_OBJS = json.load(f)

with open('test_data/stix_envelope_complex_20-19.json') as f:
    STIX_ENVELOPE_20_IOCS_19_OBJS = json.load(f)

with open('test_data/cortex_parsed_indicators_17-19.json') as f:
    CORTEX_17_IOCS_19_OBJS = json.load(f)

with open('test_data/cortex_parsed_indicators_complex_20-19.json') as f:
    CORTEX_COMPLEX_20_IOCS_19_OBJS = json.load(f)

with open('test_data/cortex_parsed_indicators_complex_skipped_14-19.json') as f:
    CORTEX_COMPLEX_14_IOCS_19_OBJS = json.load(f)
with open('test_data/id_to_object_test.json') as f:
    id_to_object = json.load(f)
with open('test_data/parsed_stix_objects.json') as f:
    parsed_objects = json.load(f)
with open('test_data/objects_envelopes_v21.json') as f:
    envelopes_v21 = json.load(f)
with open('test_data/objects_envelopes_v20.json') as f:
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
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='default', proxies=[], verify=False,
                                       objects_to_fetch=[])
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

    def test_handle_json_error(self, mocker):
        """
        Scenario: Call build iterator when the collection raises an InvalidJSONError because the response is "筽"

        Given:
        - Collection to fetch is of type v21.Collection

        When
        - Initializing collection to fetch

        Then:
        - Ensure 0 iocs are returned
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False, objects_to_fetch=[])
        mocker.patch.object(mock_client, 'collection_to_fetch', spec=v21.Collection)
        mocker.patch.object(mock_client, 'load_stix_objects_from_envelope',
                            side_effect=InvalidJSONError('Invalid JSON'))

        iocs = mock_client.build_iterator()
        assert iocs == []


class TestInitServer:
    """
    Scenario: Initialize server
    """

    def test_default_v20(self):
        """
        Scenario: Initialize server with the default option

        Given:
        - no version is provided to init_server

        Then:
        - initialize with v20.Server
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, objects_to_fetch=[])
        mock_client.init_server()
        assert isinstance(mock_client.server, v20.Server)

    def test_v21(self):
        """
        Scenario: Initialize server with v21

        Given:
        - v21 version is provided to init_server

        Then:
        - initialize with v21.Server
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, objects_to_fetch=[])
        mock_client.init_server(TAXII_VER_2_1)
        assert isinstance(mock_client.server, v21.Server)

    def test_auth_key(self):
        """
        Scenario: Initialize server with the default option with an auth key

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
        assert mock_auth_header_key in mock_client.server._conn.session.headers
        assert mock_client.server._conn.session.headers.get(mock_auth_header_key) == mock_password


class TestInitRoots:
    """
    Scenario: Initialize roots
    """

    api_root_urls = ["https://ais2.cisa.dhs.gov/public/",
                     "https://ais2.cisa.dhs.gov/default/",
                     "https://ais2.cisa.dhs.gov/ingest/",
                     "https://ais2.cisa.dhs.gov/ciscp/",
                     "https://ais2.cisa.dhs.gov/federal/"]
    v20_api_roots = [v20.ApiRoot(url) for url in api_root_urls]
    v21_api_roots = [v21.ApiRoot(url) for url in api_root_urls]

    default_api_root_url = "https://ais2.cisa.dhs.gov/default/"
    v20_default_api_root = v20.ApiRoot(default_api_root_url)
    v21_default_api_root = v21.ApiRoot(default_api_root_url)

    def test_given_default_api_root_v20(self):
        """
        Given:
        - default_api_root is given

        When:
        - Initializing roots in v20

        Then:
        - api_root is initialized with the given default_api_root
        """
        mock_client = Taxii2FeedClient(url='https://ais2.cisa.dhs.gov/taxii2/', collection_to_fetch='default',
                                       proxies=[],
                                       verify=False, objects_to_fetch=[], default_api_root='federal')
        mock_client.init_server()
        self._title = ""
        mock_client.server._api_roots = self.v20_api_roots
        mock_client.server._default = self.v20_default_api_root
        mock_client.server._loaded = True

        mock_client.init_roots()
        assert mock_client.api_root.url == "https://ais2.cisa.dhs.gov/federal/"

    def test_no_default_api_root_v20(self):
        """
        Given:
        - default_api_root is not given, and there is no defined default api_root for the server

        When:
        - Initializing roots in v20

        Then:
        - api_root is initialized with the first api_root
        """
        mock_client = Taxii2FeedClient(url='https://ais2.cisa.dhs.gov/taxii2/', collection_to_fetch='default',
                                       proxies=[],
                                       verify=False, objects_to_fetch=[], default_api_root=None)
        mock_client.init_server()
        self._title = ""
        mock_client.server._api_roots = self.v20_api_roots
        mock_client.server._default = False
        mock_client.server._loaded = True

        mock_client.init_roots()
        assert mock_client.api_root.url == "https://ais2.cisa.dhs.gov/public/"

    def test_no_given_default_api_root_v20(self):
        """
        Given:
        - default_api_root is not given

        When:
        - Initializing roots in v20

        Then:
        - api_root is initialized with the server defined default api_root
        """
        mock_client = Taxii2FeedClient(url='https://ais2.cisa.dhs.gov/taxii2/', collection_to_fetch='default',
                                       proxies=[],
                                       verify=False, objects_to_fetch=[], default_api_root=None)
        mock_client.init_server()
        self._title = ""
        mock_client.server._api_roots = self.v20_api_roots
        mock_client.server._default = self.v20_default_api_root
        mock_client.server._loaded = True

        mock_client.init_roots()
        assert mock_client.api_root.url == self.default_api_root_url

    def test_given_default_api_root_v21(self):
        """
        Given:
        - default_api_root is given

        When:
        - Initializing roots in v21

        Then:
        - api_root is initialized with the given default_api_root
        """
        mock_client = Taxii2FeedClient(url='https://ais2.cisa.dhs.gov/taxii2/', collection_to_fetch='default',
                                       proxies=[],
                                       verify=False, objects_to_fetch=[], default_api_root='federal')
        mock_client.init_server(TAXII_VER_2_1)
        self._title = ""
        mock_client.server._api_roots = self.v21_api_roots
        mock_client.server._default = self.v21_default_api_root
        mock_client.server._loaded = True

        mock_client.init_roots()
        assert mock_client.api_root.url == "https://ais2.cisa.dhs.gov/federal/"

    def test_no_default_api_root_v21(self):
        """
        Given:
        - default_api_root is not given, and there is no defined default api_root for the server

        When:
        - Initializing roots in v21

        Then:
        - api_root is initialized with the first api_root
        """
        mock_client = Taxii2FeedClient(url='https://ais2.cisa.dhs.gov/taxii2/', collection_to_fetch='default',
                                       proxies=[],
                                       verify=False, objects_to_fetch=[], default_api_root=None)
        mock_client.init_server(TAXII_VER_2_1)
        self._title = ""
        mock_client.server._api_roots = self.v21_api_roots
        mock_client.server._default = False
        mock_client.server._loaded = True

        mock_client.init_roots()
        assert mock_client.api_root.url == "https://ais2.cisa.dhs.gov/public/"

    def test_no_given_default_api_root_v21(self):
        """
        Given:
        - default_api_root is not given

        When:
        - Initializing roots in v21

        Then:
        - api_root is initialized with the server defined default api_root
        """
        mock_client = Taxii2FeedClient(url='https://ais2.cisa.dhs.gov/taxii2/', collection_to_fetch='default',
                                       proxies=[],
                                       verify=False, objects_to_fetch=[], default_api_root=None)
        mock_client.init_server(TAXII_VER_2_1)
        self._title = ""
        mock_client.server._api_roots = self.v21_api_roots
        mock_client.server._default = self.v21_default_api_root
        mock_client.server._loaded = True

        mock_client.init_roots()
        assert mock_client.api_root.url == self.default_api_root_url

    has_none = "Unexpected Response."
    has_version_error = "Unexpected Response. Got Content-Type: 'application/taxii+json; charset=utf-8; version=2.1' " \
                        "for Accept: 'application/vnd.oasis.taxii+json; version=2.0' If you are trying to contact a " \
                        "TAXII 2.0 Server use 'from taxii2client.v20 import X' If you are trying to contact a TAXII 2.1 " \
                        "Server use 'from taxii2client.v21 import X'"
    has_client_error = "Unexpected Response. 406 Client Error."
    has_both_errors = "Unexpected Response. 406 Client Error. Got Content-Type: 'application/taxii+json; charset=utf-8; " \
                      "version=2.1' for Accept: 'application/vnd.oasis.taxii+json; version=2.0' If you are trying to contact a " \
                      "TAXII 2.0 Server use 'from taxii2client.v20 import X' If you are trying to contact a TAXII 2.1 " \
                      "Server use 'from taxii2client.v21 import X'"

    @pytest.mark.parametrize('error_msg, should_raise_error',
                             [(has_none, True),
                              (has_version_error, False),
                              (has_client_error, False),
                              (has_both_errors, False),
                              ])
    def test_error_code(self, mocker, error_msg, should_raise_error):
        """
        Given:
            - Setting up a client with TAXII 2.0 server raised an error

        When:
            - Initializing roots for TAXII 2 client

        Then:
            - If the server is TAXII 2.1, error is handled and server is initialized with right version
            - If it is a different error, it is raised
        """
        mock_client = Taxii2FeedClient(url='https://ais2.cisa.dhs.gov/taxii2/', collection_to_fetch='default',
                                       proxies=[],
                                       verify=False, objects_to_fetch=[], default_api_root='federal')
        set_api_root_mocker = mocker.patch.object(mock_client, 'set_api_root',
                                                  side_effect=[TAXIIServiceException(error_msg), ''])

        if should_raise_error:
            with pytest.raises(Exception) as e:
                mock_client.init_roots()
            assert str(e.value) == error_msg
            assert set_api_root_mocker.call_count == 1

        else:
            mock_client.init_roots()
            assert set_api_root_mocker.call_count == 2


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

        actual = mock_client.load_stix_objects_from_envelope(STIX_ENVELOPE_NO_IOCS, -1)

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

        actual = mock_client.load_stix_objects_from_envelope(STIX_ENVELOPE_17_IOCS_19_OBJS, -1)

        assert len(actual) == 17
        assert expected == actual

    def test_21_complex_not_skipped(self):
        """
        Scenario: Test 21 envelope complex extract without skip

        Given:
        - Envelope with 19 STIX2 objects - 14 normal iocs, 3 are complex indicators (x2 iocs), and 2 aren't indicators
        - skip is False

        When:
        - load_stix_objects_from_envelope is called

        Then:
        - Extract and parse the indicators from the envelope with the complex iocs

        """
        expected = CORTEX_COMPLEX_20_IOCS_19_OBJS
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, tlp_color='GREEN',
                                       objects_to_fetch=[])

        actual = mock_client.load_stix_objects_from_envelope(STIX_ENVELOPE_20_IOCS_19_OBJS, -1)

        assert len(actual) == 20
        assert actual == expected

    def test_21_complex_skipped(self):
        """
        Scenario: Test 21 envelope complex extract with skip

        Given:
        - Envelope with 19 STIX2 objects - 14 normal iocs, 3 are complex indicators (x2 iocs), and 2 aren't indicators
        - skip is True

        When:
        - load_stix_objects_from_envelope is called

        Then:
        - Extract and parse the indicators from the envelope with the complex iocs

        """
        expected = CORTEX_COMPLEX_14_IOCS_19_OBJS
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, skip_complex_mode=True,
                                       objects_to_fetch=[])

        actual = mock_client.load_stix_objects_from_envelope(STIX_ENVELOPE_20_IOCS_19_OBJS, -1)

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

        result = mock_client.load_stix_objects_from_envelope(objects_envelopes, -1)
        assert mock_client.id_to_object == id_to_object
        assert result == parsed_objects

    def test_load_stix_objects_from_envelope_v20(self):
        """
        Scenario: Test loading of STIX objects from envelope for v2.0

        Given:
        - Envelope with indicators, arranged by object type.

        When:
        - load_stix_objects_from_envelope is called.

        Then: - Load and parse objects from the envelope according to their object type and ignore
        extension-definition objects.

        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, objects_to_fetch=[])

        result = mock_client.load_stix_objects_from_envelope(envelopes_v20)
        assert mock_client.id_to_object == id_to_object
        assert result == parsed_objects

    @pytest.mark.parametrize('last_modifies_client, last_modifies_param, expected_modified_result', [
        (None, None, None), (None, '2021-09-29T15:55:04.815Z', '2021-09-29T15:55:04.815Z'),
        ('2021-09-29T15:55:04.815Z', '2022-09-29T15:55:04.815Z', '2022-09-29T15:55:04.815Z')
    ])
    def test_update_last_modified_indicator_date(self, last_modifies_client, last_modifies_param,
                                                 expected_modified_result):
        """
               Scenario: Test updating the last_fetched_indicator__modified field of the client.

               Given:
                - A : An empty indicator_modified_str parameter.
                - B : A client with empty last_fetched_indicator__modified field.
                - C : A client with a value in last_fetched_indicator__modified
                 and a valid indicator_modified_str parameter.

               When:
               - Calling the last_modified_indicator_date function with given parameter.

               Then: Make sure the right value is updated in the client's last_fetched_indicator__modified field.
               - A : last_fetched_indicator__modified field remains empty
               - B : last_fetched_indicator__modified field remains empty
               - C : last_fetched_indicator__modified receives new value
        """

        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, objects_to_fetch=[], )
        mock_client.last_fetched_indicator__modified = last_modifies_client
        mock_client.update_last_modified_indicator_date(last_modifies_param)

        assert mock_client.last_fetched_indicator__modified == expected_modified_result

    @pytest.mark.parametrize(
        'objects_to_fetch_param', ([], ['example_type'], ['example_type1', 'example_type2'])
    )
    def test_objects_to_fetch_parameter(self, mocker, objects_to_fetch_param):
        """
               Scenario: Test handling for objects_to_fetch parameter.

               Given:
                - A : objects_to_fetch parameter is not set and therefor default to an empty list.
                - B : objects_to_fetch parameter is set to a list of one object type.
                - C : objects_to_fetch parameter is set to a list of two object type.


               When:
               - Fetching stix objects from a collection.

               Then:
               - A : the poll_collection method sends the HTTP request without the match[type] parameter,
                     therefor fetching all available object types in the collection.
               - B : the poll_collection method sends the HTTP request with the match[type] parameter,
                     therefor fetching only the requested object type in the collection.
               - C : the poll_collection method sends the HTTP request with the match[type] parameter,
                     therefor fetching only the requested object types in the collection.
        """

        class mock_collection_to_fetch:
            get_objects = []

        mock_client = Taxii2FeedClient(url='', collection_to_fetch=mock_collection_to_fetch,
                                       proxies=[], verify=False, objects_to_fetch=objects_to_fetch_param)
        mock_as_pages = mocker.patch.object(v21, 'as_pages', return_value=[])
        mock_client.poll_collection(page_size=1)

        if objects_to_fetch_param:
            mock_as_pages.assert_called_with([], per_request=1, type=objects_to_fetch_param)
        else:
            mock_as_pages.assert_called_with([], per_request=1)


class TestParsingIndicators:

    # test examples taken from here - https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_64yvzeku5a5c

    @staticmethod
    @pytest.fixture()
    def taxii_2_client():
        return Taxii2FeedClient(
            url='', collection_to_fetch='', proxies=[], verify=False, tlp_color='GREEN', objects_to_fetch=[]
        )

    # Parsing SCO Indicators

    def test_parse_autonomous_system_indicator(self, taxii_2_client):
        """
        Given:
         - autonomous-system object

        When:
         - parsing the autonomous-system into a format XSOAR knows to read.

        Then:
         - make sure all the fields are being parsed correctly.
           1. update_custom_fields = False
              assert custom fields are not parsed
           2. update_custom_fields = True
              assert custom fields are parsed
        """
        autonomous_system_obj = {
            "type": "autonomous-system",
            "spec_version": "2.1",
            "id": "autonomous-system--f720c34b-98ae-597f-ade5-27dc241e8c74",
            "number": 15139,
            "name": "Slime Industries",
            "rir": "ARIN",
            "extensions": {"extension-definition--1234": {"CustomFields": {"tags": ["test"], "description": "test"}}}
        }

        xsoar_expected_response_with_update_custom_fields = [
            {
                'value': 15139,
                'score': Common.DBotScore.NONE,
                'rawJSON': autonomous_system_obj,
                'type': 'ASN',
                'fields': {
                    'description': 'test',
                    'firstseenbysource': '',
                    'modified': '',
                    'name': 'Slime Industries',
                    'stixid': 'autonomous-system--f720c34b-98ae-597f-ade5-27dc241e8c74',
                    'tags': ["test"],
                    'trafficlightprotocol': 'GREEN'
                }
            }
        ]
        xsoar_expected_response = [
            {
                'value': 15139,
                'score': Common.DBotScore.NONE,
                'rawJSON': autonomous_system_obj,
                'type': 'ASN',
                'fields': {
                    'description': '',
                    'firstseenbysource': '',
                    'modified': '',
                    'name': 'Slime Industries',
                    'stixid': 'autonomous-system--f720c34b-98ae-597f-ade5-27dc241e8c74',
                    'tags': [],
                    'trafficlightprotocol': 'GREEN'
                }
            }
        ]
        assert taxii_2_client.parse_sco_autonomous_system_indicator(autonomous_system_obj) == xsoar_expected_response
        taxii_2_client.update_custom_fields = True
        assert taxii_2_client.parse_sco_autonomous_system_indicator(
            autonomous_system_obj) == xsoar_expected_response_with_update_custom_fields

    @pytest.mark.parametrize(
        '_object, xsoar_expected_response, xsoar_expected_response_with_update_custom_fields', [
            (
                {
                    "id": "ipv4-addr--e0caaaf7-6207-5d8e-8f2c-7ecf936b3c4e",  # ipv4-addr object.
                    "spec_version": "2.0",
                    "type": "ipv4-addr",
                    "value": "1.1.1.1",
                    "extensions": {
                        "extension-definition--1234": {"tags": ["test"],
                                                       "description": "test"}}
                },
                [
                    {
                        'value': '1.1.1.1',
                        'score': Common.DBotScore.NONE,
                        'type': 'IP',
                        'fields': {
                            'description': '',
                            'firstseenbysource': '',
                            'modified': '',
                            'stixid': 'ipv4-addr--e0caaaf7-6207-5d8e-8f2c-7ecf936b3c4e',
                            'tags': [],
                            'trafficlightprotocol': 'GREEN'
                        }
                    }
                ],
                [
                    {
                        'value': '1.1.1.1',
                        'score': Common.DBotScore.NONE,
                        'type': 'IP',
                        'fields': {
                            'description': 'test',
                            'firstseenbysource': '',
                            'modified': '',
                            'stixid': 'ipv4-addr--e0caaaf7-6207-5d8e-8f2c-7ecf936b3c4e',
                            'tags': ['test'],
                            'trafficlightprotocol': 'GREEN'
                        }
                    }
                ]
            ),
            (
                {
                    "type": "domain-name",  # domain object.
                    "spec_version": "2.1",
                    "id": "domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5",
                    "value": "example.com",
                    "extensions": {
                        "extension-definition--1234": {"CustomFields": {"tags": ["test"], "description": "test"}}}
                },
                [
                    {
                        'fields': {
                            'description': '',
                            'firstseenbysource': '',
                            'modified': '',
                            'stixid': 'domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5',
                            'tags': [],
                            'trafficlightprotocol': 'GREEN'
                        },
                        'rawJSON': {
                            'id': 'domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5',
                            'spec_version': '2.1',
                            'type': 'domain-name',
                            'value': 'example.com'
                        },
                        'score': Common.DBotScore.NONE,
                        'type': 'Domain',
                        'value': 'example.com'
                    }
                ],
                [
                    {
                        'fields': {
                            'description': 'test',
                            'firstseenbysource': '',
                            'modified': '',
                            'stixid': 'domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5',
                            'tags': ['test'],
                            'trafficlightprotocol': 'GREEN'
                        },
                        'rawJSON': {
                            'id': 'domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5',
                            'spec_version': '2.1',
                            'type': 'domain-name',
                            'value': 'example.com'
                        },
                        'score': Common.DBotScore.NONE,
                        'type': 'Domain',
                        'value': 'example.com'
                    }
                ]
            ),

        ]
    )
    def test_parse_general_sco_indicator(self, taxii_2_client, _object: dict, xsoar_expected_response: List[dict],
                                         xsoar_expected_response_with_update_custom_fields: List[dict]):
        """
        Given:
         - general SCO object.

        When:
         - parsing the SCO indicator into a format XSOAR knows to read.

        Then:
         - make sure all the fields are being parsed correctly.
           1. update_custom_fields = False
              assert custom fields are not parsed
           2. update_custom_fields = True
              assert custom fields are parsed
        """
        xsoar_expected_response[0]['rawJSON'] = _object
        assert taxii_2_client.parse_general_sco_indicator(_object) == xsoar_expected_response
        taxii_2_client.update_custom_fields = True
        xsoar_expected_response_with_update_custom_fields[0]['rawJSON'] = _object
        assert taxii_2_client.parse_general_sco_indicator(_object) == xsoar_expected_response_with_update_custom_fields

    def test_parse_file_sco_indicator(self, taxii_2_client):
        """
        Given:
         - file object

        When:
         - parsing the file into a format XSOAR knows to read.

        Then:
         - make sure all the fields are being parsed correctly.
           1. update_custom_fields = False
              assert custom fields are not parsed
           2. update_custom_fields = True
              assert custom fields are parsed
        """
        file_obj = {
            "type": "file",
            "spec_version": "2.1",
            "id": "file--90bd400b-89a5-51a5-b17d-55bc7719723b",
            "hashes": {
                "SHA-256": "841a8921140aba50671ebb0770fecc4ee308c4952cfeff8de154ab14eeef4649"
            },
            "name": "quêry.dll",
            "name_enc": "windows-1252",
            "extensions": {
                "extension-definition--1234": {"CustomFields": {"tags": ["test"], "description": "test"}}}
        }

        xsoar_expected_response = [
            {
                'fields': {
                    'associatedfilenames': 'quêry.dll',
                    'description': '',
                    'firstseenbysource': '',
                    'md5': None,
                    'modified': '',
                    'path': None,
                    'sha1': None,
                    'sha256': '841a8921140aba50671ebb0770fecc4ee308c4952cfeff8de154ab14eeef4649',
                    'size': None,
                    'stixid': 'file--90bd400b-89a5-51a5-b17d-55bc7719723b',
                    'tags': [],
                    'trafficlightprotocol': 'GREEN'
                },
                'rawJSON': file_obj,
                'score': Common.DBotScore.NONE,
                'type': 'File',
                'value': '841a8921140aba50671ebb0770fecc4ee308c4952cfeff8de154ab14eeef4649'
            }
        ]
        xsoar_expected_response_with_update_custom_fields = [
            {
                'fields': {
                    'associatedfilenames': 'quêry.dll',
                    'description': 'test',
                    'firstseenbysource': '',
                    'md5': None,
                    'modified': '',
                    'path': None,
                    'sha1': None,
                    'sha256': '841a8921140aba50671ebb0770fecc4ee308c4952cfeff8de154ab14eeef4649',
                    'size': None,
                    'stixid': 'file--90bd400b-89a5-51a5-b17d-55bc7719723b',
                    'tags': ["test"],
                    'trafficlightprotocol': 'GREEN'
                },
                'rawJSON': file_obj,
                'score': Common.DBotScore.NONE,
                'type': 'File',
                'value': '841a8921140aba50671ebb0770fecc4ee308c4952cfeff8de154ab14eeef4649'
            }
        ]

        assert taxii_2_client.parse_sco_file_indicator(file_obj) == xsoar_expected_response
        taxii_2_client.update_custom_fields = True
        assert taxii_2_client.parse_sco_file_indicator(file_obj) == xsoar_expected_response_with_update_custom_fields

    def test_parse_mutex_sco_indicator(self, taxii_2_client):
        """
        Given:
         - mutex object

        When:
         - parsing the mutex into a format XSOAR knows to read.

        Then:
         - make sure all the fields are being parsed correctly.
           1. update_custom_fields = False
              assert custom fields are not parsed
           2. update_custom_fields = True
              assert custom fields are parsed
        """
        mutex_obj = {
            "type": "mutex",
            "spec_version": "2.1",
            "id": "mutex--eba44954-d4e4-5d3b-814c-2b17dd8de300",
            "name": "__CLEANSWEEP__",
            "extensions": {"extension-definition--1234": {"CustomFields": {"tags": ["test"], "description": "test"}}}

        }

        xsoar_expected_response = [
            {
                'fields': {
                    'description': '',
                    'firstseenbysource': '',
                    'modified': '',
                    'stixid': 'mutex--eba44954-d4e4-5d3b-814c-2b17dd8de300',
                    'tags': [],
                    'trafficlightprotocol': 'GREEN'
                },
                'rawJSON': mutex_obj,
                'score': Common.DBotScore.NONE,
                'type': 'Mutex',
                'value': '__CLEANSWEEP__'
            }
        ]
        xsoar_expected_response_with_update_custom_fields = [
            {
                'fields': {
                    'description': 'test',
                    'firstseenbysource': '',
                    'modified': '',
                    'stixid': 'mutex--eba44954-d4e4-5d3b-814c-2b17dd8de300',
                    'tags': ['test'],
                    'trafficlightprotocol': 'GREEN'
                },
                'rawJSON': mutex_obj,
                'score': Common.DBotScore.NONE,
                'type': 'Mutex',
                'value': '__CLEANSWEEP__'
            }
        ]

        assert taxii_2_client.parse_sco_mutex_indicator(mutex_obj) == xsoar_expected_response
        taxii_2_client.update_custom_fields = True
        assert taxii_2_client.parse_sco_mutex_indicator(mutex_obj) == xsoar_expected_response_with_update_custom_fields

    def test_parse_sco_windows_registry_key_indicator(self, taxii_2_client):
        """
        Given:
         - windows registry object

        When:
         - parsing the windows registry into a format XSOAR knows to read.

        Then:
         - make sure all the fields are being parsed correctly.
           1. update_custom_fields = False
              assert custom fields are not parsed
           2. update_custom_fields = True
              assert custom fields are parsed
        """
        registry_object = {
            "type": "windows-registry-key",
            "spec_version": "2.1",
            "id": "windows-registry-key--2ba37ae7-2745-5082-9dfd-9486dad41016",
            "key": "hkey_local_machine\\system\\bar\\foo",
            "extensions": {"extension-definition--1234": {"CustomFields": {"tags": ["test"], "description": "test"}}},
            "values": [
                {
                    "name": "Foo",
                    "data": "qwerty",
                    "data_type": "REG_SZ"
                },
                {
                    "name": "Bar",
                    "data": "42",
                    "data_type": "REG_DWORD"
                }
            ]
        }

        xsoar_expected_response = [
            {
                'fields': {
                    'description': '',
                    'firstseenbysource': '',
                    'modified': '',
                    'modified_time': None,
                    'number_of_subkeys': None,
                    'registryvalue': [
                        {
                            'data': 'qwerty',
                            'data_type': 'REG_SZ',
                            'name': 'Foo'
                        },
                        {
                            'data': '42',
                            'data_type': 'REG_DWORD',
                            'name': 'Bar'
                        }
                    ],
                    'stixid': 'windows-registry-key--2ba37ae7-2745-5082-9dfd-9486dad41016',
                    'tags': [],
                    'trafficlightprotocol': 'GREEN'
                },
                'rawJSON': registry_object,
                'score': Common.DBotScore.NONE,
                'type': 'Registry Key',
                'value': "hkey_local_machine\\system\\bar\\foo"
            }
        ]
        xsoar_expected_response_with_update_custom_fields = [
            {
                'fields': {
                    'description': 'test',
                    'firstseenbysource': '',
                    'modified': '',
                    'modified_time': None,
                    'number_of_subkeys': None,
                    'registryvalue': [
                        {
                            'data': 'qwerty',
                            'data_type': 'REG_SZ',
                            'name': 'Foo'
                        },
                        {
                            'data': '42',
                            'data_type': 'REG_DWORD',
                            'name': 'Bar'
                        }
                    ],
                    'stixid': 'windows-registry-key--2ba37ae7-2745-5082-9dfd-9486dad41016',
                    'tags': ['test'],
                    'trafficlightprotocol': 'GREEN'
                },
                'rawJSON': registry_object,
                'score': Common.DBotScore.NONE,
                'type': 'Registry Key',
                'value': "hkey_local_machine\\system\\bar\\foo"
            }
        ]

        assert taxii_2_client.parse_sco_windows_registry_key_indicator(registry_object) == xsoar_expected_response
        taxii_2_client.update_custom_fields = True
        assert taxii_2_client.parse_sco_windows_registry_key_indicator(
            registry_object) == xsoar_expected_response_with_update_custom_fields

    def test_parse_vulnerability(self, taxii_2_client):
        """
        Given:
         - Vulnerability object.

        When:
         - Parsing the vulnerability into a format XSOAR knows to read.

        Then:
         - Make sure all the fields are being parsed correctly.
        """
        vulnerability_object = {'created': '2021-06-01T00:00:00.000Z',
                                "extensions": {"extension-definition--1234": {
                                    "CustomFields": {"tags": ["test", "elevated"], "description": "test"}}},
                                'created_by_ref': 'identity--ce222222-2a22-222b-2222-222222222222',
                                'external_references': [{'external_id': 'CVE-1234-5', 'source_name': 'cve'},
                                                        {'external_id': '1', 'source_name': 'other'}],
                                'id': 'vulnerability--25222222-2a22-222b-2222-222222222222',
                                'modified': '2021-06-01T00:00:00.000Z',
                                'object_marking_refs': ['marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
                                                        'marking-definition--085ea65f-15af-48d8-86f0-adc7075b9457'],
                                'spec_version': '2.1',
                                'type': 'vulnerability',
                                'labels': ['elevated']}

        xsoar_expected_response = [
            {
                'fields': {
                    'description': '',
                    'firstseenbysource': '2021-06-01T00:00:00.000Z',
                    'modified': '2021-06-01T00:00:00.000Z',
                    'stixid': 'vulnerability--25222222-2a22-222b-2222-222222222222',
                    'trafficlightprotocol': 'WHITE'},
                'rawJSON': vulnerability_object,
                'score': Common.DBotScore.NONE,
                'type': 'CVE',
                'value': 'CVE-1234-5'
            }
        ]

        xsoar_expected_response_with_update_custom_fields = [
            {
                'fields': {
                    'description': 'test',
                    'firstseenbysource': '2021-06-01T00:00:00.000Z',
                    'modified': '2021-06-01T00:00:00.000Z',
                    'stixid': 'vulnerability--25222222-2a22-222b-2222-222222222222',
                    'trafficlightprotocol': 'WHITE'},
                'rawJSON': vulnerability_object,
                'score': Common.DBotScore.NONE,
                'type': 'CVE',
                'value': 'CVE-1234-5'
            }
        ]
        parsed_response = taxii_2_client.parse_vulnerability(vulnerability_object)
        response_tags = parsed_response[0]['fields'].pop('tags')
        xsoar_expected_tags = {'CVE-1234-5', 'elevated'}
        assert parsed_response == xsoar_expected_response
        assert set(response_tags) == xsoar_expected_tags

        taxii_2_client.update_custom_fields = True

        parsed_response = taxii_2_client.parse_vulnerability(vulnerability_object)
        response_tags = parsed_response[0]['fields'].pop('tags')
        xsoar_expected_tags = {'CVE-1234-5', 'elevated', 'test'}
        assert parsed_response == xsoar_expected_response_with_update_custom_fields
        assert set(response_tags) == xsoar_expected_tags

    def test_parse_indicator(self, taxii_2_client):
        """
        Given:
         - Indicator object.

        When:
         - Parsing the indicator into a format XSOAR knows to read.

        Then:
         - Make sure all the fields are being parsed correctly.
        """
        indicator_obj = {
            "id": "indicator--1234", "pattern": "[domain-name:value = 'test.org']", "confidence": 85, "lang": "en",
            "type": "indicator", "created": "2020-05-14T00:14:05.401Z", "modified": "2020-05-14T00:14:05.401Z",
            "name": "suspicious_domain: test.org", "description": "TS ID: 55475482483; iType: suspicious_domain; ",
            "valid_from": "2020-05-07T14:33:02.714602Z", "pattern_type": "stix",
            "object_marking_refs": ["marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"],
            "labels": ["medium"],
            "indicator_types": ["anomalous-activity"],
            "extensions":
            {"extension-definition--1234": {"CustomFields": {"tags": ["medium"],
                                                             "description": "test"}}},
            "pattern_version": "2.1", "spec_version": "2.1"}

        indicator_obj['value'] = 'test.org'
        indicator_obj['type'] = 'Domain'
        xsoar_expected_response = [
            {
                'fields': {
                    'description': 'TS ID: 55475482483; iType: suspicious_domain; ',
                    'tags': ['medium'],
                    'trafficlightprotocol': 'GREEN'
                },
                'rawJSON': indicator_obj,
                'type': 'Domain',
                'value': 'test.org'
            }
        ]

        xsoar_expected_response_with_update_custom_fields = [
            {
                'fields': {
                    'description': 'test',
                    'tags': ['medium'],
                    'trafficlightprotocol': 'GREEN'
                },
                'rawJSON': indicator_obj,
                'type': 'Domain',
                'value': 'test.org'
            }
        ]
        taxii_2_client.tlp_color = None
        assert taxii_2_client.parse_indicator(indicator_obj) == xsoar_expected_response
        taxii_2_client.update_custom_fields = True
        assert taxii_2_client.parse_indicator(indicator_obj) == xsoar_expected_response_with_update_custom_fields

    # Parsing SDO Indicators

    def test_parse_identity(self, taxii_2_client):
        """
        Given:
         - Identity object.

        When:
         - Parsing the identity into a format XSOAR knows to read.

        Then:
         - Make sure all the fields are being parsed correctly.
        """
        identity_object = {'contact_information': 'test@org.com',
                           'created': '2021-06-01T00:00:00.000Z',
                           'created_by_ref': 'identity--b3222222-2a22-222b-2222-222222222222',
                           'description': 'Identity to represent the government entities.',
                           'id': 'identity--f8222222-2a22-222b-2222-222222222222',
                           'identity_class': 'organization',
                           'labels': ['consent-everyone'],
                           'modified': '2021-06-01T00:00:00.000Z',
                           'name': 'Government',
                           'sectors': ['government-national'],
                           'spec_version': '2.1',
                           "extensions": {"extension-definition--1234": {
                               "CustomFields": {"tags": ["consent-everyone"], "description": "test"}}},
                           'type': 'identity'}

        xsoar_expected_response = [
            {
                'fields': {
                    'description': 'Identity to represent the government entities.',
                    'firstseenbysource': '2021-06-01T00:00:00.000Z',
                    'identityclass': 'organization',
                    'industrysectors': ['government-national'],
                    'modified': '2021-06-01T00:00:00.000Z',
                    'stixid': 'identity--f8222222-2a22-222b-2222-222222222222',
                    'tags': ['consent-everyone'],
                    'trafficlightprotocol': 'GREEN'
                },
                'rawJSON': identity_object,
                'score': Common.DBotScore.NONE,
                'type': 'Identity',
                'value': 'Government'
            }
        ]

        xsoar_expected_response_with_update_custom_fields = [
            {
                'fields': {
                    'description': 'test',
                    'firstseenbysource': '2021-06-01T00:00:00.000Z',
                    'identityclass': 'organization',
                    'industrysectors': ['government-national'],
                    'modified': '2021-06-01T00:00:00.000Z',
                    'stixid': 'identity--f8222222-2a22-222b-2222-222222222222',
                    'tags': ['consent-everyone'],
                    'trafficlightprotocol': 'GREEN'
                },
                'rawJSON': identity_object,
                'score': Common.DBotScore.NONE,
                'type': 'Identity',
                'value': 'Government'
            }
        ]

        assert taxii_2_client.parse_identity(identity_object) == xsoar_expected_response
        taxii_2_client.update_custom_fields = True
        assert taxii_2_client.parse_identity(identity_object) == xsoar_expected_response_with_update_custom_fields

    upper_case_country_object = {'administrative_area': 'US-MI',
                                 'country': 'US',
                                 'created': '2022-11-19T23:27:34.000Z',
                                 'created_by_ref': 'identity--27222222-2a22-222b-2222-222222222222',
                                 'id': 'location--28222222-2a22-222b-2222-222222222222',
                                 'modified': '2022-11-19T23:27:34.000Z',
                                 'object_marking_refs': ['marking-definition--f88d31f6-486f-44da-b317-01333bde0b82'],
                                 'spec_version': '2.1',
                                 'type': 'location',
                                 'labels': ['elevated']}
    upper_case_country_response = [
        {
            'fields': {
                'description': '',
                'countrycode': 'US',
                'firstseenbysource': '2022-11-19T23:27:34.000Z',
                'modified': '2022-11-19T23:27:34.000Z',
                'stixid': 'location--28222222-2a22-222b-2222-222222222222',
                'tags': ['elevated'],
                'trafficlightprotocol': 'AMBER'
            },
            'rawJSON': upper_case_country_object,
            'score': Common.DBotScore.NONE,
            'type': 'Location',
            'value': 'United States'
        }
    ]
    lower_case_country_object = {'type': 'location',
                                 'spec_version': '2.1',
                                 'id': 'location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64',
                                 'created_by_ref': 'identity--f431f809-377b-45e0-aa1c-6a4751cae5ff',
                                 'created': '2016-04-06T20:03:00.000Z',
                                 'modified': '2016-04-06T20:03:00.000Z',
                                 'region': 'south-eastern-asia',
                                 'country': 'th',
                                 'administrative_area': 'Tak',
                                 'postal_code': '63170'}
    lower_case_country_response = [
        {
            'fields': {
                'countrycode': 'th',
                'description': '',
                'firstseenbysource': '2016-04-06T20:03:00.000Z',
                'modified': '2016-04-06T20:03:00.000Z',
                'stixid': 'location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64',
                'tags': [],
                'trafficlightprotocol': 'GREEN'
            },
            'rawJSON': lower_case_country_object,
            'score': Common.DBotScore.NONE,
            'type': 'Location',
            'value': 'Thailand'
        }
    ]
    location_with_name_object = {'administrative_area': 'US-MI',
                                 'country': 'US',
                                 'name': 'United States of America',
                                 'created': '2022-11-19T23:27:34.000Z',
                                 'created_by_ref': 'identity--27222222-2a22-222b-2222-222222222222',
                                 'id': 'location--28222222-2a22-222b-2222-222222222222',
                                 'modified': '2022-11-19T23:27:34.000Z',
                                 'object_marking_refs': ['marking-definition--f88d31f6-486f-44da-b317-01333bde0b82'],
                                 'spec_version': '2.1',
                                 'type': 'location',
                                 'labels': ['elevated']}
    location_with_name_response = [
        {
            'fields': {
                'description': '',
                'countrycode': 'US',
                'firstseenbysource': '2022-11-19T23:27:34.000Z',
                'modified': '2022-11-19T23:27:34.000Z',
                'stixid': 'location--28222222-2a22-222b-2222-222222222222',
                'tags': ['elevated'],
                'trafficlightprotocol': 'AMBER'
            },
            'rawJSON': location_with_name_object,
            'score': Common.DBotScore.NONE,
            'type': 'Location',
            'value': 'United States of America'
        }
    ]

    @pytest.mark.parametrize('location_object, xsoar_expected_response',
                             [(upper_case_country_object, upper_case_country_response),
                              (lower_case_country_object, lower_case_country_response),
                              (location_with_name_object, location_with_name_response),
                              ])
    def test_parse_location(self, taxii_2_client, location_object, xsoar_expected_response):
        """
        Given:
         - Location object.

        When:
         - Parsing the location into a format XSOAR knows to read.

        Then:
         - Make sure all the fields are being parsed correctly.
        """
        assert taxii_2_client.parse_location(location_object) == xsoar_expected_response


class TestParsingObjects:

    def test_parsing_report_with_relationships(self):
        """
        Scenario: Test parsing report envelope for v2.0

        Given:
        - Envelope with reports.

        When:
        - load_stix_objects_from_envelope is called.

        Then: - validate the result contained the report with relationships as expected.

        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, objects_to_fetch=[])

        result = mock_client.load_stix_objects_from_envelope(envelopes_v20)
        reports = [obj for obj in result if obj.get('type') == 'Report']
        report_with_relationship = [report for report in reports if report.get('relationships')]

        assert len(report_with_relationship) == 1
        assert len(report_with_relationship[0].get('relationships')) == 2


@pytest.mark.parametrize('limit, element_count, return_value',
                         [(8, 8, True),
                          (8, 9, True),
                          (8, 0, False),
                          (-1, 10, False)])
def test_reached_limit(limit, element_count, return_value):
    """
    Given:
        - A limit and element count.
    When:
        - Enforcing limit on the elements count.
    Then:
        - Assert that the element count is not exceeded.
    """
    from TAXII2ApiModule import reached_limit
    assert reached_limit(limit, element_count) == return_value
