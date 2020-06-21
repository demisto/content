from CommonServerPython import *
# from Packs.ApiModules.Scripts.TAXII2ApiModule.TAXII2ApiModule import Taxii2FeedClient
from TAXII2ApiModule import Taxii2FeedClient
from taxii2client import v20, v21
# import types


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


# class TestExtractIndicatorsAndParse:
#     def test_20_empty(self, mocker):
#         def envelope_generator():
#             yield {}
#             raise StopIteration
#         mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False)
#         res = mock_client.extract_indicators_from_envelope_and_parse(envelope_generator())
