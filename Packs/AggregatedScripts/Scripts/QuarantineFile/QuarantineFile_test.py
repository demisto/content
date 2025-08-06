import pytest
import demistomock as demisto  # noqa: F401

# Import the script we are testing
from QuarantineFile import QuarantineException, QuarantineOrchestrator, Brands, EndpointBrandMapper, QuarantineResult


# Pytest fixture to patch demisto functions
@pytest.fixture(autouse=True)
def mock_demisto(mocker):
    """
    This fixture automatically mocks all required demisto functions for each test.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error")
    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "get", return_value={})  # Mocks context
    mocker.patch.object(demisto, "setContext")
    mocker.patch.object(demisto, "executeCommand")
    # Mock getModules to return active integrations by default
    mocker.patch.object(
        demisto,
        "getModules",
        return_value={
            "Cortex XDR - IR": {"state": "disabled", "brand": Brands.CORTEX_XDR_IR},
            "Cortex Core - IR": {"state": "active", "brand": Brands.CORTEX_CORE_IR},
        },
    )


def _get_orchestrator(args: dict) -> QuarantineOrchestrator:
    """Helper function to create a QuarantineOrchestrator instance for testing."""
    return QuarantineOrchestrator(args)


class TestArgumentValidationSanitization:
    """
    Unit tests for the _sanitize_and_validate_args method of the QuarantineOrchestrator.
    This approach directly tests the validation logic in isolation.
    """

    # --- Endpoint ID Tests ---
    class TestEndpointId:
        """Tests specifically for the 'endpoint_id' script argument."""

        def test_missing_endpoint_id_raises_exception(self):
            """
            Given: Args without 'endpoint_id'.
            When:  _sanitize_and_validate_args is called.
            Then:  Ensure QuarantineException is raised.
            """
            args = {"file_hash": "sha256_hash", "file_path": "/path"}
            orchestrator = QuarantineOrchestrator(args)

            with pytest.raises(QuarantineException) as e:
                orchestrator._sanitize_and_validate_args()
            assert "Missing required argument" in str(e.value)
            assert QuarantineOrchestrator.ENDPOINT_IDS_ARG in str(e.value)

        def test_duplicate_endpoint_ids_are_deduplicated(self):
            """
            Given: Args with duplicate endpoint IDs.
            When:  _sanitize_and_validate_args is called.
            Then:  Ensure the 'endpoint_id' list in orchestrator.args is deduplicated.
            """
            args = {
                "endpoint_id": "id1,id2,id1,id3,id2",
                "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "file_path": "/path",
            }
            orchestrator = _get_orchestrator(args)
            orchestrator._sanitize_and_validate_args()

            actual_ids_list = orchestrator.args[QuarantineOrchestrator.ENDPOINT_IDS_ARG]
            actual_ids_list.sort()  # sort to have same order for comparison
            expected_sorted_list = ["id1", "id2", "id3"]

            assert actual_ids_list == expected_sorted_list

        # --- Brands Tests ---

    class TestBrands:
        """Tests specifically for the 'brands' script argument."""

        def test_no_brands_provided_defaults_to_all_active_brands(self):
            """
            Given: No 'brands' argument is provided.
            When:  _sanitize_and_validate_args is called.
            Then:  Ensure orchestrator.args['brands'] contains all active brands.
            """
            args = {
                "endpoint_id": "id1",
                "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "file_path": "/path",
            }
            orchestrator = QuarantineOrchestrator(args)
            orchestrator._sanitize_and_validate_args()

            expected_brands = [Brands.CORTEX_CORE_IR]
            actual_brands = orchestrator.args[QuarantineOrchestrator.BRANDS_ARG]
            assert actual_brands == expected_brands

        def test_invalid_brand_name_raises_exception(self):
            """
            Given: An invalid brand name is provided in 'brands'.
            When:  _sanitize_and_validate_args is called.
            Then:  Ensure QuarantineException is raised.
            """
            args = {
                "endpoint_id": "id1",
                "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "file_path": "/path",
                "brands": "Invalid Brand Name",
            }
            orchestrator = QuarantineOrchestrator(args)
            with pytest.raises(QuarantineException) as e:
                orchestrator._sanitize_and_validate_args()
            assert "Invalid brand" in str(e.value)

        def test_disabled_brand_is_filtered_out(self, mocker):
            """
            Given: A mix of active and disabled brands are provided.
            When:  _sanitize_and_validate_args is called.
            Then:  Ensure only the active brand remains in the arguments.
            """
            # Arrange: Mock getModules to have one disabled brand
            mocker.patch.object(
                demisto,
                "getModules",
                return_value={
                    "Cortex XDR - IR": {"state": "active", "brand": Brands.CORTEX_XDR_IR},
                    "Cortex Core - IR": {"state": "disabled", "brand": Brands.CORTEX_CORE_IR},  # This one is disabled
                },
            )
            args = {
                "endpoint_id": "id1",
                "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "file_path": "/path",
                "brands": f"{Brands.CORTEX_CORE_IR},{Brands.CORTEX_XDR_IR}",
            }
            orchestrator = QuarantineOrchestrator(args)
            orchestrator._sanitize_and_validate_args()

            # Assert that only the active brand is left
            assert orchestrator.args[QuarantineOrchestrator.BRANDS_ARG] == [Brands.CORTEX_XDR_IR]

        def test_no_active_brands_raises_exception(self, mocker):
            """
            Given: All integrations for the target brands are disabled.
            When:  _sanitize_and_validate_args is called.
            Then:  Ensure DemistoException is raised.
            """
            # Arrange: Mock getModules to have all relevant brands disabled
            mocker.patch.object(
                demisto,
                "getModules",
                return_value={
                    "Cortex XDR - IR": {"state": "disabled", "brand": Brands.CORTEX_XDR_IR},
                    "Cortex Core - IR": {"state": "disabled", "brand": Brands.CORTEX_CORE_IR},
                },
            )
            args = {
                "endpoint_id": "id1",
                "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "file_path": "/path",
            }
            orchestrator = QuarantineOrchestrator(args)
            with pytest.raises(QuarantineException) as e:
                orchestrator._sanitize_and_validate_args()
            assert (
                "have an enabled "
                "integration instance. Ensure valid integration IDs are specified, and that "
                "the integrations are enabled."
            ) in str(e.value)

    # --- File Hash Tests ---
    class TestFileHash:
        """Tests specifically for the 'file_hash' script argument."""

        def test_missing_file_hash_raises_exception(self):
            """
            Given: Args without 'file_hash'.
            When:  _sanitize_and_validate_args is called.
            Then:  Ensure DemistoException is raised.
            """
            args = {"endpoint_id": "id1", "file_path": "/path"}
            orchestrator = QuarantineOrchestrator(args)
            with pytest.raises(QuarantineException) as e:
                orchestrator._sanitize_and_validate_args()
            assert "Missing required argument" in str(e.value)
            assert QuarantineOrchestrator.FILE_HASH_ARG in str(e.value)

        @pytest.mark.parametrize(
            "unsupported_hash",
            [
                "md5md5md5md5md5md5md5md5md5md5md",  # md5
                "sha1sha1sha1sha1sha1sha1sha1sha1sha1sha1",  # sha1
            ],
        )
        def test_unsupported_hash_type_raises_exception(self, unsupported_hash):
            """
            Given: An unsupported hash type (MD5, SHA1).
            When:  _sanitize_and_validate_args is called.
            Then:  Ensure DemistoException is raised with 'Unsupported hash type'.
            """
            args = {"endpoint_id": "id1", "file_hash": unsupported_hash, "file_path": "/path"}
            orchestrator = QuarantineOrchestrator(args)
            with pytest.raises(QuarantineException) as e:
                orchestrator._sanitize_and_validate_args()
            assert "Unsupported hash type" in str(e.value)

        def test_hash_type_not_matching_active_brands_raises_exception(self, mocker):
            """
            Given: A hash type that is not supported by the active brands.
            When:  _sanitize_and_validate_args is called.
            Then:  Ensure DemistoException is raised with 'Unsupported hash type'.
            """
            # TODO, to be implemented with MDE
            assert True


class TestEndpointBrandMapper:
    """
    Unit tests for the EndpointBrandMapper class, which handles endpoint discovery and grouping.
    """

    def _get_mapper(self, args: dict, orchestrator=None) -> EndpointBrandMapper:
        """Helper to create an EndpointBrandMapper instance for testing."""
        if orchestrator is None:
            orchestrator = _get_orchestrator(args)
        return EndpointBrandMapper(args, orchestrator)

    def test_group_by_brand_end_to_end(self, mocker):
        """
        Given:
            - A list of endpoint IDs containing online, offline, and not-found endpoints.
        When:
            - The group_by_brand method is called.
        Then:
            - Ensure online endpoints are grouped correctly by brand.
            - Ensure failure results are created for offline and not-found endpoints.
        """
        # Arrange
        args = {
            "endpoint_id": "xdr-online-1,core-online-1,offline-1,not-found-1,xdr-online-2,ep-without-brand",
            "file_hash": "some_hash",
            "file_path": "/path",
        }
        mock_response = [
            {
                "Type": 1,
                "Contents": {},
                "EntryContext": {
                    "EndpointData(val.ID && val.ID == obj.ID)": [
                        {
                            "ID": "xdr-online-1",
                            "Brand": Brands.CORTEX_XDR_IR,
                            "Status": "Online",
                            "Message": "Command successful",
                        },
                        {
                            "ID": "core-online-1",
                            "Brand": Brands.CORTEX_CORE_IR,
                            "Status": "Online",
                            "Message": "Command successful",
                        },
                        {"ID": "offline-1", "Brand": Brands.CORTEX_XDR_IR, "Status": "Offline", "Message": "Command successful"},
                        {
                            "ID": "not-found-1",
                            "Brand": Brands.CORTEX_XDR_IR,
                            "Status": "Unknown",
                            "Message": "Command failed - no endpoint found",
                        },
                        {
                            "ID": "xdr-online-2",
                            "Brand": Brands.CORTEX_XDR_IR,
                            "Status": "Online",
                            "Message": "Command successful",
                        },
                    ]
                },
            }
        ]
        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mapper = self._get_mapper(args)

        # Act
        grouped_endpoints = mapper.group_by_brand()

        # Assert Grouping
        expected_groups = {Brands.CORTEX_XDR_IR: ["xdr-online-1", "xdr-online-2"], Brands.CORTEX_CORE_IR: ["core-online-1"]}
        assert grouped_endpoints == expected_groups

        # Assert Initial Failure Results
        assert len(mapper.initial_results) == 3

        offline_result = next((r for r in mapper.initial_results if r.endpoint_id == "offline-1"), None)
        assert offline_result is not None
        assert offline_result.status == QuarantineResult.Statuses.FAILED
        assert "Endpoint status is 'Offline'" in offline_result.message

        not_found_result = next((r for r in mapper.initial_results if r.endpoint_id == "not-found-1"), None)
        assert not_found_result is not None
        assert not_found_result.status == QuarantineResult.Statuses.FAILED
        assert not_found_result.message == QuarantineResult.Messages.FAILED_WITH_REASON.format(
            reason="Command failed - no endpoint found"
        )

        ep_without_brand_result = next((r for r in mapper.initial_results if r.endpoint_id == "ep-without-brand"), None)
        assert ep_without_brand_result is not None
        assert ep_without_brand_result.status == QuarantineResult.Statuses.FAILED
        assert ep_without_brand_result.message == QuarantineResult.Messages.ENDPOINT_NOT_FOUND

    def test_all_endpoints_offline_or_not_found_dont_raise_exception(self, mocker):
        """
        Given:
            - A get-endpoint-data response where no endpoints are 'Online'.
        When:
            - The group_by_brand method is called.
        Then:
            - Ensure the grouped_endpoints result is empty.
            - Ensure failure results are created for all endpoints.
        """
        # Arrange
        args = {"endpoint_id": "offline-1,not-found-1"}
        mock_response = [
            {
                "Type": 1,  # Type 1 means its not an error
                "EntryContext": {
                    "EndpointData(val.ID && val.ID == obj.ID)": [
                        {"ID": "offline-1", "Brand": Brands.CORTEX_XDR_IR, "Status": "Offline", "Message": "Command successful"},
                        {
                            "ID": "not-found-1",
                            "Brand": Brands.CORTEX_XDR_IR,
                            "Status": "Unknown",
                            "Message": "Command failed - no endpoint found",
                        },
                    ]
                },
            }
        ]
        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mapper = self._get_mapper(args)

        # Act
        grouped_endpoints = mapper.group_by_brand()

        # Assert
        assert not grouped_endpoints  # Should be an empty dict
        assert len(mapper.initial_results) == 2

    def test_get_endpoint_data_command_fails(self, mocker):
        """
        Given:
            - The underlying 'get-endpoint-data' command will raise an exception.
        When:
            - The group_by_brand method is called.
        Then:
            - Ensure the exception is propagated upwards.
        """
        # Arrange
        args = {"endpoint_id": "any-id"}
        mocker.patch.object(demisto, "executeCommand", side_effect=QuarantineException("API limit reached"))
        mapper = self._get_mapper(args)

        # Act & Assert
        with pytest.raises(QuarantineException) as e:
            mapper.group_by_brand()
        assert "API limit reached" in str(e.value)

    def test_handles_duplicate_api_entries_for_same_endpoint(self, mocker):
        """
        Given:
            - The get-endpoint-data response contains two entries for the same endpoint ID,
              one 'Online' and one 'Offline'.
        When:
            - The group_by_brand method is called.
        Then:
            - Ensure the endpoint is correctly identified as 'Online'.
            - Ensure no failure result is created for the 'Offline' duplicate.
        """
        # Arrange
        args = {"endpoint_id": "duplicate-id"}
        mock_response = [
            {
                "Type": 1,
                "EntryContext": {
                    "EndpointData(val.ID && val.ID == obj.ID)": [
                        # The script should prioritize the 'Online' entry
                        {
                            "ID": "duplicate-id",
                            "Brand": Brands.CORTEX_XDR_IR,
                            "Status": "Online",
                            "Message": "Command successful",
                        },
                        {
                            "ID": "duplicate-id",
                            "Brand": Brands.CORTEX_XDR_IR,
                            "Status": "Offline",
                            "Message": "Command successful",
                        },
                    ]
                },
            }
        ]
        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mapper = self._get_mapper(args)

        # Act
        grouped_endpoints = mapper.group_by_brand()

        # Assert
        assert grouped_endpoints == {Brands.CORTEX_XDR_IR: ["duplicate-id"]}
        assert not mapper.initial_results  # No failure results should be created

    def test_empty_api_response_raises_exception(self, mocker):
        """
        Given:
            - The 'get-endpoint-data' command returns a response with an empty data list.
        When:
            - The group_by_brand method is called.
        Then:
            - Ensure a QuarantineException is raised.
        """
        # Arrange
        args = {"endpoint_id": "any-id"}
        mock_response = [{"Type": 1, "Contents": {}, "EntryContext": {"EndpointData(val.ID && val.ID == obj.ID)": []}}]
        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)
        mapper = self._get_mapper(args)

        # Act & Assert
        with pytest.raises(QuarantineException) as e:
            mapper.group_by_brand()
        assert "Could not retrieve endpoint data" in str(e.value)

    def test_verbose_mode_populates_verbose_results(self, mocker):
        """
        Given:
            - The 'verbose' argument is set to True.
        When:
            - The group_by_brand method is called, which executes a command.
        Then:
            - Ensure the orchestrator's verbose_results list is populated.
        """
        # Arrange
        args = {
            "endpoint_id": "any-id",
            "verbose": True,  # Enable verbose mode
        }
        mock_response = [
            {
                "Type": 1,
                "HumanReadable": "This is a verbose message.",
                "EntryContext": {"EndpointData(val.ID && val.ID == obj.ID)": [{"ID": "any-id", "Status": "Online"}]},
            }
        ]
        mocker.patch.object(demisto, "executeCommand", return_value=mock_response)

        orchestrator = _get_orchestrator(args)
        mapper = self._get_mapper(args, orchestrator)

        # Act
        mapper.group_by_brand()

        # Assert
        assert len(orchestrator.verbose_results) == 1
        assert orchestrator.verbose_results[0].readable_output == "This is a verbose message."


if __name__ == "__main__":
    pytest.main()
