import pytest
import demistomock as demisto  # noqa: F401

from QuarantineFile import (
    QuarantineException,
    QuarantineOrchestrator,
    Brands,
    EndpointBrandMapper,
    QuarantineResult,
    handler_factory,
    XDRHandler,
    Command,
    main,
)

SHA_256_HASH = "sha256sha256sha256sha256sha256sha256sha256sha256sha256sha256sha2"


# Pytest fixture to patch demisto functions
@pytest.fixture(autouse=True)
def mock_demisto(mocker):
    """
    This fixture automatically mocks all required demisto functions for each test.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error")

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


class TestCommand:
    def test_get_entry_context_only_returns_populated_entries(self):
        # Arrange
        raw_response = [
            {
                "Type": 1,
                "EntryContext": {},
            },
            {
                "Type": 1,
                "EntryContext": {
                    "EndpointData(val.Brand && val.Brand == obj.Brand && val.ID && val.ID == obj.ID && val.Hostname && val.Hostname == obj.Hostname)": [
                        {
                            "Brand": "Cortex Core - IR",
                            "Hostname": "FT",
                            "ID": "EP1_ID",
                            "IPAddress": ["172.16.8.116"],
                            "IsIsolated": "No",
                            "Message": "Command successful",
                            "Status": "Online",
                        },
                        {
                            "Brand": "Cortex Core - IR",
                            "Hostname": "FT",
                            "ID": "EP2_ID",
                            "IPAddress": ["172.16.8.47"],
                            "IsIsolated": "No",
                            "Message": "Command successful",
                            "Status": "Online",
                        },
                    ]
                },
            },
            {
                "Type": 16,
                "EntryContext": None,
            },
        ]

        # Act
        entry_contexts = Command.get_entry_contexts(raw_response)

        # Assert
        assert len(entry_contexts) == 1
        assert entry_contexts[0] == raw_response[1]["EntryContext"]

    def test_get_entry_context_doesnt_return_error_entry_context(self):
        # Arrange
        raw_response = [
            {
                "Type": 1,
                "EntryContext": {
                    "EndpointData(val.Brand && val.Brand == obj.Brand && val.ID && val.ID == obj.ID && val.Hostname && val.Hostname == obj.Hostname)": [
                        {
                            "Brand": "Cortex Core - IR",
                            "Hostname": "FT",
                            "ID": "EP1_ID",
                            "IPAddress": ["172.16.8.116"],
                            "IsIsolated": "No",
                            "Message": "Command successful",
                            "Status": "Online",
                        },
                    ]
                },
            },
            {
                "Type": 4,  # Type 4 means it's an error
                "EntryContext": {"Error": []},
            },
        ]

        # Act
        entry_contexts = Command.get_entry_contexts(raw_response)

        # Assert
        assert len(entry_contexts) == 1
        assert entry_contexts[0] == raw_response[0]["EntryContext"]

    def test_get_entry_context_object_containing_key_returns_first_entry_with_key(self):
        # Arrange
        raw_response = [
            {
                "Type": 1,
                "EntryContext": {
                    "EndpointData(val.ID && val.ID == obj.ID)": [
                        {"ID": "EP1_ID", "Status": "Online"},
                        {"ID": "EP2_ID", "Status": "Online"},
                    ]
                },
            },
            {
                "Type": 1,
                "EntryContext": {
                    "AnotherKey(val.ID && val.ID == obj.ID)": [
                        {"ID": "blabla", "Status": "Online"},
                        {"ID": "anotherblabla", "Status": "Online"},
                    ]
                },
            },
        ]

        # Act
        entry_context = Command.get_entry_context_object_containing_key(raw_response, "ID")

        # Assert
        assert entry_context == raw_response[0]["EntryContext"]["EndpointData(val.ID && val.ID == obj.ID)"]

    def test_get_entry_context_object_containing_key_returns_none_if_no_entry_with_key(self):
        # Arrange
        raw_response = [
            {
                "Type": 1,
                "EntryContext": {
                    "EndpointData(val.ID && val.ID == obj.ID)": [
                        {"ID": "EP1_ID", "Status": "Online"},
                        {"ID": "EP2_ID", "Status": "Online"},
                    ]
                },
            }
        ]

        # Act
        entry_context = Command.get_entry_context_object_containing_key(raw_response, "blabla")

        # Assert
        assert entry_context is None


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
                "Type": 1,
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


class TestBrandFactory:
    def test_handler_factory_returns_correct_handler(self):
        orchestrator = _get_orchestrator({"endpoint_id": "any-id"})

        brand = Brands.CORTEX_XDR_IR
        handler = handler_factory(brand, orchestrator)
        assert isinstance(handler, XDRHandler)

        brand = Brands.CORTEX_CORE_IR
        handler = handler_factory(brand, orchestrator)
        assert isinstance(handler, XDRHandler)

    def test_handler_factory_raises_exception_for_invalid_brand(self):
        orchestrator = _get_orchestrator({"endpoint_id": "any-id"})
        with pytest.raises(ValueError) as e:
            handler_factory("invalid-brand", orchestrator)
        assert "No handler available for brand: invalid-brand" in str(e.value)


class TestXDRHandler:
    def test_constructor_sets_correct_properties(self):
        args = {"endpoint_id": "id1", "file_hash": SHA_256_HASH, "file_path": "/path"}
        orchestrator = _get_orchestrator(args)

        handler = XDRHandler(Brands.CORTEX_XDR_IR, orchestrator)
        assert handler.command_prefix == "xdr"
        assert handler.quarantine_command == "xdr-file-quarantine"

        handler = XDRHandler(Brands.CORTEX_CORE_IR, orchestrator)
        assert handler.command_prefix == "core"
        assert handler.quarantine_command == "core-quarantine-files"

    class TestPreProcessing:
        def test_validate_args_raises_exception_for_missing_file_path(self):
            args = {"endpoint_id": "id1", "file_hash": SHA_256_HASH}
            orchestrator = _get_orchestrator(args)
            handler = XDRHandler(Brands.CORTEX_XDR_IR, orchestrator)

            with pytest.raises(QuarantineException) as e:
                handler.validate_args(args)
            assert "The 'file_path' argument is required for brand Cortex XDR - IR." in str(e.value)

        def test_run_pre_checks_and_get_initial_results_returns_empty_list_when_no_endpoint_ids_given(self):
            args = {"file_hash": SHA_256_HASH, "file_path": "/path"}
            orchestrator = _get_orchestrator(args)
            handler = XDRHandler(Brands.CORTEX_XDR_IR, orchestrator)

            endpoints_to_quarantine, completed_results = handler.run_pre_checks_and_get_initial_results(args)
            assert endpoints_to_quarantine == []
            assert completed_results == []

        def test_run_pre_checks_and_get_initial_results_returns_no_eps_to_quarantine_when_all_already_quarantined(self, mocker):
            args = {"endpoint_id": "id1", "file_hash": SHA_256_HASH, "file_path": "/path"}
            orchestrator = _get_orchestrator(args)
            handler = XDRHandler(Brands.CORTEX_XDR_IR, orchestrator)

            mocker.patch.object(handler, "_execute_quarantine_status_command", return_value={"status": True})

            endpoints_to_quarantine, completed_results = handler.run_pre_checks_and_get_initial_results(args)
            assert endpoints_to_quarantine == []
            assert completed_results == [
                QuarantineResult.create(
                    endpoint_id="id1",
                    status=QuarantineResult.Statuses.SUCCESS,
                    message=QuarantineResult.Messages.ALREADY_QUARANTINED,
                    brand=Brands.CORTEX_XDR_IR,
                    script_args={"endpoint_id": "id1", "file_hash": SHA_256_HASH, "file_path": "/path"},
                )
            ]

        def test_run_pre_checks_and_get_initial_results_returns_eps_to_quarantine(self, mocker):
            args = {"endpoint_id": "id1,id2", "file_hash": "sha256", "file_path": "/path"}
            orchestrator = _get_orchestrator(args)
            handler = XDRHandler(Brands.CORTEX_XDR_IR, orchestrator)

            # mock to return true for first endpoint, false for second
            mocker.patch.object(handler, "_execute_quarantine_status_command", side_effect=[{"status": False}, {"status": False}])

            endpoints_to_quarantine, completed_results = handler.run_pre_checks_and_get_initial_results(args)
            assert endpoints_to_quarantine == ["id1", "id2"]
            assert completed_results == []

        def test_run_pre_checks_and_get_initial_results_fails_ep_when_check_status_raises_unexpected_exception(self, mocker):
            args = {"endpoint_id": "id1,id2,id3,id4", "file_hash": "sha256", "file_path": "/path"}
            orchestrator = _get_orchestrator(args)
            handler = XDRHandler(Brands.CORTEX_XDR_IR, orchestrator)

            # mock to return true for first endpoint, raises exception for second, false for third, none for fourth
            def side_effect(endpoint_id, file_hash, file_path):
                if endpoint_id == "id1":
                    return {"status": True}
                elif endpoint_id == "id2":
                    raise Exception("Unexpected error")
                elif endpoint_id == "id3":
                    return {"status": False}
                else:
                    return None

            mocker.patch.object(handler, "_execute_quarantine_status_command", side_effect=side_effect)

            endpoints_to_quarantine, completed_results = handler.run_pre_checks_and_get_initial_results(args)
            assert endpoints_to_quarantine == ["id3"]
            assert completed_results == [
                QuarantineResult.create(
                    endpoint_id="id1",
                    status=QuarantineResult.Statuses.SUCCESS,
                    message=QuarantineResult.Messages.ALREADY_QUARANTINED,
                    brand=Brands.CORTEX_XDR_IR,
                    script_args={"endpoint_id": "id1", "file_hash": "sha256", "file_path": "/path"},
                ),
                QuarantineResult.create(
                    endpoint_id="id2",
                    status=QuarantineResult.Statuses.FAILED,
                    message=QuarantineResult.Messages.ENDPOINT_OFFLINE,
                    brand=Brands.CORTEX_XDR_IR,
                    script_args={"endpoint_id": "id2", "file_hash": "sha256", "file_path": "/path"},
                ),
                QuarantineResult.create(
                    endpoint_id="id4",
                    status=QuarantineResult.Statuses.FAILED,
                    message=QuarantineResult.Messages.ENDPOINT_OFFLINE,
                    brand=Brands.CORTEX_XDR_IR,
                    script_args={"endpoint_id": "id3", "file_hash": "sha256", "file_path": "/path"},
                ),
            ]

    class TestInitialQuarantine:
        """Tests the quarantine kickoff flow of the XDRHandler."""

        def test_initiate_quarantine_calls_expected_xdr_command(self, mocker):
            args = {"endpoint_id": ["id1", "id2"], "file_hash": "sha256", "file_path": "/path"}
            orchestrator = _get_orchestrator(args)
            handler = XDRHandler(Brands.CORTEX_XDR_IR, orchestrator)

            # mock the Command class execute() method, and check that it was called with the expected arguments
            mock_command_instance = mocker.Mock()
            mock_command_instance.execute.return_value = (
                [{"Metadata": {"pollingCommand": "xdr-get-quarantine-status", "pollingArgs": {"action_id": "123"}}}],
                [],
            )
            mock_command_class = mocker.patch("QuarantineFile.Command", return_value=mock_command_instance)

            job = handler.initiate_quarantine(args)

            # Assert that the Command class was instantiated correctly
            expected_command_args = {
                "endpoint_id_list": ["id1", "id2"],
                "file_hash": "sha256",
                "file_path": "/path",
                "timeout_in_seconds": 300,  # the default timeout
            }
            mock_command_class.assert_called_once_with(
                name="xdr-file-quarantine", args=expected_command_args, brand=Brands.CORTEX_XDR_IR
            )

            # Assert that the returned job object is correct
            expected_job = {
                "brand": Brands.CORTEX_XDR_IR,
                "poll_command": "xdr-get-quarantine-status",
                "poll_args": {"action_id": "123"},
                "finalize_args": {"file_hash": "sha256", "file_path": "/path"},
            }
            assert job == expected_job

        def test_initiate_quarantine_calls_expected_xdr_command_with_timeout(self, mocker):
            args = {"endpoint_id": ["id1", "id2"], "file_hash": SHA_256_HASH, "file_path": "/path", "timeout": 123}
            orchestrator = _get_orchestrator(args)
            handler = XDRHandler(Brands.CORTEX_XDR_IR, orchestrator)

            # mock the Command class execute() method, and check that it was called with the expected arguments
            mock_command_instance = mocker.Mock()
            mock_command_instance.execute.return_value = (
                [{"Metadata": {"pollingCommand": "xdr-get-quarantine-status", "pollingArgs": {"action_id": "123"}}}],
                [],
            )
            mock_command_class = mocker.patch("QuarantineFile.Command", return_value=mock_command_instance)

            job = handler.initiate_quarantine(args)

            # Assert that the Command class was instantiated correctly
            expected_command_args = {
                "endpoint_id_list": ["id1", "id2"],
                "file_hash": SHA_256_HASH,
                "file_path": "/path",
                "timeout_in_seconds": 123,
            }
            mock_command_class.assert_called_once_with(
                name="xdr-file-quarantine", args=expected_command_args, brand=Brands.CORTEX_XDR_IR
            )

            # Assert that the returned job object is correct
            expected_job = {
                "brand": Brands.CORTEX_XDR_IR,
                "poll_command": "xdr-get-quarantine-status",
                "poll_args": {"action_id": "123"},
                "finalize_args": {"file_hash": SHA_256_HASH, "file_path": "/path"},
            }
            assert job == expected_job

        def test_initiate_quarantine_adds_verbose_results_when_requested(self, mocker):
            args = {"endpoint_id": ["id1", "id2"], "file_hash": SHA_256_HASH, "file_path": "/path", "verbose": True}
            orchestrator = _get_orchestrator(args)
            handler = XDRHandler(Brands.CORTEX_XDR_IR, orchestrator)

            mock_command_instance = mocker.Mock()
            mock_command_instance.execute.return_value = (
                [{"Metadata": {"pollingCommand": "xdr-get-quarantine-status", "pollingArgs": {"action_id": "123"}}}],
                [
                    {
                        "Type": 1,
                        "HumanReadable": "This is a verbose message.",
                        "EntryContext": {"EndpointData(val.ID && val.ID == obj.ID)": [{"ID": "any-id", "Status": "Online"}]},
                    }
                ],
            )
            mocker.patch("QuarantineFile.Command", return_value=mock_command_instance)

            assert orchestrator.verbose_results == []
            assert orchestrator.verbose == True

            handler.initiate_quarantine(args)

            assert orchestrator.verbose_results == [
                {
                    "Type": 1,
                    "HumanReadable": "This is a verbose message.",
                    "EntryContext": {"EndpointData(val.ID && val.ID == obj.ID)": [{"ID": "any-id", "Status": "Online"}]},
                }
            ]

    class TestFinalizeQuarantine:
        """Tests the finalization flow of the XDRHandler."""

        @pytest.fixture
        def setup_finalize(self, mocker):
            """A fixture to set up a handler and job object for finalize tests."""
            args = {"file_hash": "hash123", "file_path": "/path/test.txt"}
            orchestrator = _get_orchestrator(args)
            handler = XDRHandler(Brands.CORTEX_CORE_IR, orchestrator)
            job = {
                "brand": "Cortex Core - IR",
                "poll_command": "core-quarantine-files",
                "poll_args": {
                    "action_id": [6],
                    "endpoint_id": "ep1",
                    "endpoint_id_list": ["ep1"],
                    "file_hash": "hash123",
                    "file_path": "/path/test.txt",
                    "integration_context_brand": "Core",
                    "integration_name": "Cortex Core - IR",
                    "interval_in_seconds": 60,
                    "timeout_in_seconds": "300",
                },
                "finalize_args": {"file_hash": "hash123", "file_path": "/path/test.txt"},
            }
            mocker.patch.object(handler, "_execute_quarantine_status_command")
            return handler, job

        def test_process_final_endpoint_status_receives_successfully_quarantined(self, setup_finalize, mocker):
            """
            Given:
                - The polling action completes successfully.
                - The final status check confirms the file is quarantined.
            When:
                - _process_final_endpoint_status is called.
            Then:
                - Ensure a 'Success' result is returned.
            """
            # Arrange
            handler, job_data = setup_finalize

            handler._execute_quarantine_status_command.return_value = {"status": True}

            # Act
            final_result = handler._process_final_endpoint_status(
                {"action_id": 123, "endpoint_id": "ep1", "status": "COMPLETED_SUCCESSFULLY"}, job_data
            )

            # Assert
            assert handler._execute_quarantine_status_command.call_args[0][0] == "ep1"
            assert handler._execute_quarantine_status_command.call_args[0][1] == "hash123"
            assert handler._execute_quarantine_status_command.call_args[0][2] == "/path/test.txt"

            assert final_result.status == QuarantineResult.Statuses.SUCCESS
            assert final_result.message == QuarantineResult.Messages.SUCCESS
            assert final_result.endpoint_id == "ep1"
            assert final_result.file_hash == "hash123"
            assert final_result.file_path == "/path/test.txt"
            assert final_result.brand == Brands.CORTEX_CORE_IR

        def test_process_final_endpoint_status_receives_unsuccessfully_quarantined(self, setup_finalize, mocker):
            """
            Given:
                - The polling action completes successfully.
                - The final status check returns that the file is not quarantined.
            When:
                - _process_final_endpoint_status is called.
            Then:
                - Ensure a 'Failed' result is returned.
            """
            # Arrange
            handler, job_data = setup_finalize

            handler._execute_quarantine_status_command.return_value = {"status": True}

            # Act
            final_result = handler._process_final_endpoint_status(
                {"action_id": 123, "endpoint_id": "ep1", "status": "FAILED", "error_description": "Error from xdr agent"},
                job_data,
            )

            # Assert that _execute_quarantine_status_command was not called
            handler._execute_quarantine_status_command.assert_not_called()

            assert final_result.status == QuarantineResult.Statuses.FAILED
            assert final_result.message == QuarantineResult.Messages.FAILED_WITH_REASON.format(reason="Error from xdr agent")
            assert final_result.endpoint_id == "ep1"
            assert final_result.file_hash == "hash123"
            assert final_result.file_path == "/path/test.txt"
            assert final_result.brand == Brands.CORTEX_CORE_IR

        def test_finalize_all_eps_success(self, setup_finalize, mocker):
            """
            Given:
                - The polling action completes successfully.
                - The final status check confirms the file is quarantined.
            When:
                - finalize is called.
            Then:
                - Ensure a 'Success' result is returned.
            """
            # Arrange
            handler, job = setup_finalize
            mocker.patch(
                "QuarantineFile.Command.get_entry_context_object_containing_key",
                return_value=[
                    {"action_id": 123, "endpoint_id": "ep1", "status": "COMPLETED_SUCCESSFULLY"},
                    {"action_id": 123, "endpoint_id": "ep2", "status": "COMPLETED_SUCCESSFULLY"},
                ],
            )
            handler._execute_quarantine_status_command.return_value = {"status": True}

            # Act
            final_results = handler.finalize(job, [])

            # Assert
            assert len(final_results) == 2
            result = final_results[0]
            assert result.status == QuarantineResult.Statuses.SUCCESS
            assert result.message == QuarantineResult.Messages.SUCCESS
            assert result.endpoint_id == "ep1"

            result = final_results[1]
            assert result.status == QuarantineResult.Statuses.SUCCESS
            assert result.message == QuarantineResult.Messages.SUCCESS
            assert result.endpoint_id == "ep2"

        def test_finalize_all_some_eps_failed(self, setup_finalize, mocker):
            """
            Given:
                - The polling action completes successfully.
                - The final status check returns some eps are not quarantined.
            When:
                - finalize is called.
            Then:
                - Ensure a the failed results are returned.
            """
            # Arrange
            handler, job = setup_finalize
            mocker.patch(
                "QuarantineFile.Command.get_entry_context_object_containing_key",
                return_value=[
                    {"action_id": 123, "endpoint_id": "ep1", "status": "COMPLETED_SUCCESSFULLY"},
                    {"action_id": 123, "endpoint_id": "ep2", "status": "Failed", "error_description": "Error from xdr agent"},
                ],
            )
            handler._execute_quarantine_status_command.return_value = {"status": True}

            # Act
            final_results = handler.finalize(job, [])

            # Assert
            assert len(final_results) == 2
            result = final_results[0]
            assert result.status == QuarantineResult.Statuses.SUCCESS
            assert result.message == QuarantineResult.Messages.SUCCESS
            assert result.endpoint_id == "ep1"

            result = final_results[1]
            assert result.status == QuarantineResult.Statuses.FAILED
            assert result.message == QuarantineResult.Messages.FAILED_WITH_REASON.format(reason="Error from xdr agent")
            assert result.endpoint_id == "ep2"

        def test_finalize_returns_failed_when_unexpected_exception(self, setup_finalize, mocker):
            """
            Given:
                - The polling action completes successfully.
            When:
                - finalize is called.
                - During the final status check, an unexpected exception is raised.
            Then:
                - Ensure a 'Success' result is returned.
            """
            # Arrange
            handler, job = setup_finalize
            mocker.patch(
                "QuarantineFile.Command.get_entry_context_object_containing_key",
                return_value=[{"action_id": 123, "endpoint_id": "ep1", "status": "COMPLETED_SUCCESSFULLY"}],
            )

            mocker.patch.object(handler, "_process_final_endpoint_status", side_effect=Exception("some error"))

            # Act
            result = handler.finalize(job, [])

            # Assert
            assert len(result) == 1
            result = result[0]
            assert result.status == QuarantineResult.Statuses.FAILED
            assert result.message == QuarantineResult.Messages.GENERAL_FAILURE
            assert result.endpoint_id == "ep1"
            assert result.file_hash == "hash123"
            assert result.file_path == "/path/test.txt"
            assert result.brand == Brands.CORTEX_CORE_IR


class TestQuarantineOrchestrator:
    class TestArgumentValidationSanitization:
        """
        Unit tests for the _sanitize_and_validate_args method of the QuarantineOrchestrator.
        This approach directly tests the validation logic in isolation.
        """

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

            def test_duplicate_endpoint_ids_are_deduplicated(self, mocker):
                """
                Given: Args with duplicate endpoint IDs.
                When:  _sanitize_and_validate_args is called.
                Then:  Ensure the 'endpoint_id' list in orchestrator.args is deduplicated.
                """
                args = {
                    "endpoint_id": "id1,id2,id1,id3,id2",
                    "file_hash": SHA_256_HASH,
                    "file_path": "/path",
                }
                mocker.patch.object(
                    demisto,
                    "getModules",
                    return_value={
                        "Cortex XDR - IR": {"state": "disabled", "brand": Brands.CORTEX_XDR_IR},
                        "Cortex Core - IR": {"state": "active", "brand": Brands.CORTEX_CORE_IR},
                    },
                )
                orchestrator = _get_orchestrator(args)
                orchestrator._sanitize_and_validate_args()

                actual_ids_list = orchestrator.args[QuarantineOrchestrator.ENDPOINT_IDS_ARG]
                actual_ids_list.sort()  # sort to have same order for comparison
                expected_sorted_list = ["id1", "id2", "id3"]

                assert actual_ids_list == expected_sorted_list

            # --- Brands Tests ---

        class TestBrands:
            """Tests specifically for the 'brands' script argument."""

            def test_no_brands_provided_defaults_to_all_active_brands(self, mocker):
                """
                Given: No 'brands' argument is provided.
                When:  _sanitize_and_validate_args is called.
                Then:  Ensure orchestrator.args['brands'] contains all active brands.
                """
                args = {
                    "endpoint_id": "id1",
                    "file_hash": SHA_256_HASH,
                    "file_path": "/path",
                }
                mocker.patch.object(
                    demisto,
                    "getModules",
                    return_value={
                        "Cortex XDR - IR": {"state": "disabled", "brand": Brands.CORTEX_XDR_IR},
                        "Cortex Core - IR": {"state": "active", "brand": Brands.CORTEX_CORE_IR},
                    },
                )
                orchestrator = QuarantineOrchestrator(args)
                orchestrator._sanitize_and_validate_args()

                expected_brands = [Brands.CORTEX_CORE_IR]
                actual_brands = orchestrator.args[QuarantineOrchestrator.BRANDS_ARG]
                assert actual_brands == expected_brands

            def test_invalid_brand_name_raises_exception(self, mocker):
                """
                Given: An invalid brand name is provided in 'brands'.
                When:  _sanitize_and_validate_args is called.
                Then:  Ensure QuarantineException is raised.
                """
                args = {
                    "endpoint_id": "id1",
                    "file_hash": SHA_256_HASH,
                    "file_path": "/path",
                    "brands": "Invalid Brand Name",
                }
                mocker.patch.object(
                    demisto,
                    "getModules",
                    return_value={
                        "Cortex XDR - IR": {"state": "disabled", "brand": Brands.CORTEX_XDR_IR},
                        "Cortex Core - IR": {"state": "active", "brand": Brands.CORTEX_CORE_IR},
                    },
                )
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
                    "file_hash": SHA_256_HASH,
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
                    "file_hash": SHA_256_HASH,
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

    class TestConstructor:
        def test_constructor_sets_args(self, mocker):
            args = {
                "endpoint_id": "id1",
                "file_hash": "sha256",
                "file_path": "/path",
                "brands": f"{Brands.CORTEX_CORE_IR},{Brands.CORTEX_XDR_IR}",
            }

            orchestrator = QuarantineOrchestrator(args)
            assert orchestrator.args == args
            assert orchestrator.verbose == False

        def test_constructor_sets_from_context(self, mocker):
            args = {
                "endpoint_id": "id1",
                "file_hash": "sha256",
                "file_path": "/path",
                "brands": f"{Brands.CORTEX_CORE_IR},{Brands.CORTEX_XDR_IR}",
                "verbose": True,
            }

            completed_result = QuarantineResult.create(
                endpoint_id="id4",
                status=QuarantineResult.Statuses.FAILED,
                message=QuarantineResult.Messages.ENDPOINT_OFFLINE,
                brand=Brands.CORTEX_XDR_IR,
                script_args={"endpoint_id": "id3", "file_hash": "sha256", "file_path": "/path"},
            )

            mocker.patch.object(
                demisto,
                "context",
                return_value={
                    "quarantine_pending_jobs": ["pending job"],
                    "quarantine_completed_results": QuarantineResult.to_context_entry([completed_result]),
                },
            )

            orchestrator = QuarantineOrchestrator(args)
            assert orchestrator.args == args
            assert orchestrator.verbose == True
            assert orchestrator.pending_jobs == ["pending job"]
            assert orchestrator.completed_results == [completed_result]

    class TestRun:
        def test_run_first_run_handles_mixed_results_and_schedules_poll(self, mocker):
            """
            Given:
                - A first run with a mix of endpoints (online, offline, already quarantined).
            When:
                - The orchestrator's run() method is called.
            Then:
                - Ensure a polling job is created only for endpoints needing action.
                - Ensure initial results from both the mapper and handler are collected.
                - Ensure both pending jobs and completed results are saved to context.
            """
            # Arrange
            args = {
                "endpoint_id": "ep1,ep2,ep3,offline-ep",
                "file_hash": "sha256sha256sha256sha256sha256sha256sha256sha256sha256sha256sha2",
                "file_path": "/path",
            }

            # Mock context to be empty for a first run
            mocker.patch.object(demisto, "context", return_value={})
            mock_set_context = mocker.patch.object(demisto, "setContext")

            # Mock EndpointBrandMapper to find some endpoints and fail others
            mock_mapper_instance = mocker.Mock()
            mock_mapper_instance.group_by_brand.return_value = {Brands.CORTEX_CORE_IR: ["ep1", "ep2", "ep3"]}
            offline_result = QuarantineResult.create("offline-ep", "Failed", "Offline", "Unknown", args)
            mock_mapper_instance.initial_results = [offline_result]
            mocker.patch("QuarantineFile.EndpointBrandMapper", return_value=mock_mapper_instance)

            # Mock XDRHandler to find some endpoints already quarantined
            mock_handler_instance = mocker.Mock()
            already_quarantined_result = QuarantineResult.create(
                "ep3", "Success", "Already quarantined", Brands.CORTEX_CORE_IR, args
            )
            mock_handler_instance.run_pre_checks_and_get_initial_results.return_value = (
                ["ep1", "ep2"],
                [already_quarantined_result],
            )
            mock_handler_instance.initiate_quarantine.return_value = {
                "brand": Brands.CORTEX_CORE_IR,
                "poll_command": "some-poll-cmd",
            }
            mocker.patch("QuarantineFile.handler_factory", return_value=mock_handler_instance)

            orchestrator = _get_orchestrator(args)

            # Act
            result = orchestrator.run()

            # Assert Polling is Scheduled
            assert result.continue_to_poll is True

            # Assert Context Saving
            assert mock_set_context.call_count == 2

            # 1. Check Pending Jobs was set Context
            pending_jobs_call = next(
                (c for c in mock_set_context.call_args_list if c[0][0] == QuarantineOrchestrator.CONTEXT_PENDING_JOBS), None
            )
            assert pending_jobs_call is not None
            saved_jobs = pending_jobs_call[0][1]
            assert len(saved_jobs) == 1
            assert saved_jobs[0]["brand"] == Brands.CORTEX_CORE_IR
            assert saved_jobs[0]["poll_command"] == "some-poll-cmd"

            # 2. Check Completed Results Context
            completed_results_call = next(
                (c for c in mock_set_context.call_args_list if c[0][0] == QuarantineOrchestrator.CONTEXT_COMPLETED_RESULTS), None
            )
            assert completed_results_call is not None
            saved_results = completed_results_call[0][1]
            assert len(saved_results) == 2

            # Check for the offline result from the mapper
            assert any(r["endpoint_id"] == "offline-ep" for r in saved_results)
            # Check for the already quarantined result from the handler
            assert any(r["endpoint_id"] == "ep3" for r in saved_results)

        def test_run_polling_run_job_still_polling(self, mocker):
            """
            Given:
                - A polling run with a pending job in the context.
                - The polling command indicates the action is still in progress.
            When:
                - The orchestrator's run() method is called.
            Then:
                - Ensure the pending job is updated with new polling args.
                - Ensure the method returns a PollResult to continue polling.
            """
            # Arrange
            args = {"file_hash": "hash123", "file_path": "/path"}
            pending_job = {"brand": Brands.CORTEX_CORE_IR, "poll_command": "some-poll-cmd", "poll_args": {"action_id": "123"}}

            # Mock context to contain the pending job
            mocker.patch.object(demisto, "context", return_value={QuarantineOrchestrator.CONTEXT_PENDING_JOBS: [pending_job]})
            mock_set_context = mocker.patch.object(demisto, "setContext")

            # Mock the polling command to return 'polling: True'
            polling_response = [{"Type": 1, "Contents": {}, "Metadata": {"polling": True, "pollingArgs": {"action_id": "456"}}}]
            mocker.patch.object(demisto, "executeCommand", return_value=polling_response)

            orchestrator = _get_orchestrator(args)

            # Act
            result = orchestrator.run()

            # Assert
            assert result.continue_to_poll is True

            # Check that the pending jobs context was updated
            pending_jobs_call = next(
                (c for c in mock_set_context.call_args_list if c[0][0] == QuarantineOrchestrator.CONTEXT_PENDING_JOBS), None
            )
            assert pending_jobs_call is not None
            updated_jobs = pending_jobs_call[0][1]
            assert len(updated_jobs) == 1
            assert updated_jobs[0]["poll_args"]["action_id"] == "456"  # Assert the args were updated

        def test_run_polling_run_job_finishes(self, mocker):
            """
            Given:
                - A polling run with a pending job in the context.
                - The polling command indicates the action is complete.
            When:
                - The orchestrator's run() method is called.
            Then:
                - Ensure the handler's finalize method is called.
                - Ensure the pending jobs list becomes empty.
                - Ensure the method returns a final result (continue_to_poll=False).
            """
            # Arrange
            args = {"file_hash": "hash123", "file_path": "/path"}
            pending_job = {"brand": Brands.CORTEX_CORE_IR, "poll_command": "some-poll-cmd", "poll_args": {"action_id": "123"}}

            # Mock context to contain the pending job
            mocker.patch.object(demisto, "context", return_value={QuarantineOrchestrator.CONTEXT_PENDING_JOBS: [pending_job]})
            mocker.patch.object(demisto, "setContext")  # We don't need to check its content here

            # Mock the polling command to return 'polling: False'
            polling_response = [{"Type": 1, "Contents": {}, "Metadata": {"polling": False}}]
            mocker.patch.object(demisto, "executeCommand", return_value=polling_response)

            # Mock the handler's finalize method
            mock_handler_instance = mocker.Mock()
            final_result = QuarantineResult.create("ep1", "Success", "File quarantined", Brands.CORTEX_CORE_IR, args)
            mock_handler_instance.finalize.return_value = [final_result]
            mocker.patch("QuarantineFile.handler_factory", return_value=mock_handler_instance)

            orchestrator = _get_orchestrator(args)

            # Act
            result = orchestrator.run()

            # Assert
            assert result.continue_to_poll is False
            mock_handler_instance.finalize.assert_called_once_with(pending_job, polling_response)
            assert len(orchestrator.completed_results) == 1
            assert orchestrator.completed_results[0].endpoint_id == "ep1"
            assert not orchestrator.pending_jobs  # The list should now be empty


class TestScriptEntrypoints:
    """
    Tests for the main script entry points, main() and quarantine_file_script().
    """

    def test_main_function_success_path(self, mocker):
        """
        Given:
            - Script arguments provided via demisto.args().
        When:
            - The main() function is called.
        Then:
            - Ensure the polling entry point is called with polling enabled.
            - Ensure return_results is called with the result.
        """
        # Arrange
        args = {"endpoint_id": "ep1", "file_hash": "hash123"}
        mocker.patch.object(demisto, "args", return_value=args)
        mock_return_results = mocker.patch("QuarantineFile.return_results")
        mock_script_func = mocker.patch("QuarantineFile.quarantine_file_script", return_value="SUCCESS")

        # Act
        main()

        # Assert
        expected_args = args.copy()
        expected_args["polling"] = True
        mock_script_func.assert_called_once_with(expected_args)
        mock_return_results.assert_called_once_with("SUCCESS")

    def test_main_function_exception_path_cleans_up_context(self, mocker):
        """
        Given:
            - The script execution raises an exception.
        When:
            - The main() function is called.
        Then:
            - Ensure return_error is called with the correct error message.
            - Ensure the context is cleaned up by calling DeleteContext.
        """
        # Arrange
        mocker.patch.object(demisto, "args", return_value={})
        mock_return_error = mocker.patch("QuarantineFile.return_error")
        mock_delete_context = mocker.patch.object(demisto, "executeCommand")
        mocker.patch("QuarantineFile.quarantine_file_script", side_effect=Exception("A critical error occurred"))

        # Act
        main()

        # Assert
        mock_return_error.assert_called_once()
        assert "A critical error occurred" in mock_return_error.call_args[0][0]

        # Assert that DeleteContext was called
        mock_delete_context.assert_called_with(
            "DeleteContext",
            {"key": f"{QuarantineOrchestrator.CONTEXT_PENDING_JOBS},{QuarantineOrchestrator.CONTEXT_COMPLETED_RESULTS}"},
        )


if __name__ == "__main__":
    pytest.main()
