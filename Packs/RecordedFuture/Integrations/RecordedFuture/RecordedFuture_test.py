def create_client():
    import os
    from RecordedFuture import Client

    base_url = "https://api.recordedfuture.com/gw/xsoar/"
    verify_ssl = True
    token = os.environ.get("RF_TOKEN")
    headers = {
        "X-RFToken": token,
        "X-RF-User-Agent": "RecordedFuture.py/2.4 (Linux-5.13.0-1031-aws-x86_64-with) "
        "XSOAR/2.4 RFClient/2.4 (Cortex_XSOAR_6.5.0)",
    }

    return Client(base_url=base_url, verify=verify_ssl, headers=headers, proxy=False)


class TestHelpers:
    def test_translate_score(self):
        from RecordedFuture import translate_score
        from CommonServerPython import Common

        assert translate_score(score=10, threshold=0) == Common.DBotScore.BAD
        assert translate_score(score=10, threshold=10) == Common.DBotScore.BAD
        assert translate_score(score=10, threshold=11) == Common.DBotScore.NONE
        assert translate_score(score=24, threshold=40) == Common.DBotScore.NONE
        assert translate_score(score=25, threshold=40) == Common.DBotScore.SUSPICIOUS
        assert translate_score(score=26, threshold=40) == Common.DBotScore.SUSPICIOUS
        assert translate_score(score=40, threshold=40) == Common.DBotScore.BAD
        assert translate_score(score=45, threshold=40) == Common.DBotScore.BAD
        assert translate_score(score=10, threshold=-1) == Common.DBotScore.BAD
        assert translate_score(score=10, threshold=0) == Common.DBotScore.BAD
        assert translate_score(score=25, threshold=-1) == Common.DBotScore.BAD
        assert translate_score(score=25, threshold=0) == Common.DBotScore.BAD
        assert translate_score(score=26, threshold=-1) == Common.DBotScore.BAD
        assert translate_score(score=26, threshold=0) == Common.DBotScore.BAD

    def test_determine_hash(self):
        from RecordedFuture import determine_hash

        assert determine_hash(hash_value="s" * 128) == "SHA512"
        assert determine_hash(hash_value="s" * 64) == "SHA256"
        assert determine_hash(hash_value="s" * 40) == "SHA1"
        assert determine_hash(hash_value="s" * 32) == "MD5"
        assert determine_hash(hash_value="s" * 8) == "CRC32"
        assert determine_hash(hash_value="s" * 50) == "CTPH"
        assert determine_hash(hash_value="s" * 10) == "CTPH"
        assert determine_hash(hash_value="s") == "CTPH"

    def test_create_indicator_ip(self, mocker):
        from RecordedFuture import create_indicator
        from CommonServerPython import Common, DBotScoreType

        mock_return_value = mocker.Mock()
        mocker.patch("CommonServerPython.Common.IP", return_value=mock_return_value)
        dbot_score_spy = mocker.spy(Common, "DBotScore")

        entity = "8.8.8.8"
        entity_type = "ip"
        score = 45
        description = "test_description"
        location = {"asn": "test_asn", "location": {"country": "test_country"}}

        result = create_indicator(
            entity=entity,
            entity_type=entity_type,
            score=score,
            description=description,
            location=location,
        )

        assert result == mock_return_value

        dbot_score_spy.assert_called_once_with(
            entity,
            DBotScoreType.IP,
            "Recorded Future v2",
            Common.DBotScore.SUSPICIOUS,
            "",
            # reliability=DBotScoreReliability.B
            reliability=None,
        )

        mock_call = Common.IP.mock_calls[0]
        assert mock_call.args[0] == entity
        assert mock_call.args[1].indicator == entity

        # mock_call.args[1] - is Common.IP, and we verify it by dbot_score_spy.
        # We can't assert it with `==` as the Common.IP does not implement `__eq__` method.

        assert mock_call.kwargs == {
            "asn": "test_asn",
            "geo_country": "test_country",
        }

    def test_create_indicator_domain(self, mocker):
        from RecordedFuture import create_indicator
        from CommonServerPython import Common, DBotScoreType

        mock_return_value = mocker.Mock()
        mocker.patch("CommonServerPython.Common.Domain", return_value=mock_return_value)
        dbot_score_spy = mocker.spy(Common, "DBotScore")

        entity = "google.com"
        entity_type = "domain"
        score = 45
        description = "test_description"

        result = create_indicator(
            entity=entity,
            entity_type=entity_type,
            score=score,
            description=description,
        )

        assert result == mock_return_value

        dbot_score_spy.assert_called_once_with(
            entity,
            DBotScoreType.DOMAIN,
            "Recorded Future v2",
            Common.DBotScore.SUSPICIOUS,
            "",
            # reliability=DBotScoreReliability.B
            reliability=None,
        )

        mock_call = Common.Domain.mock_calls[0]
        assert mock_call.args[0] == entity
        assert mock_call.args[1].indicator == entity

    def test_create_indicator_url(self, mocker):
        from RecordedFuture import create_indicator
        from CommonServerPython import Common, DBotScoreType

        mock_return_value = mocker.Mock()
        mocker.patch("CommonServerPython.Common.URL", return_value=mock_return_value)
        dbot_score_spy = mocker.spy(Common, "DBotScore")

        entity = "https://google.com"
        entity_type = "url"
        score = 45
        description = "test_description"

        result = create_indicator(
            entity=entity,
            entity_type=entity_type,
            score=score,
            description=description,
        )

        assert result == mock_return_value

        dbot_score_spy.assert_called_once_with(
            entity,
            DBotScoreType.URL,
            "Recorded Future v2",
            Common.DBotScore.SUSPICIOUS,
            "",
            # reliability=DBotScoreReliability.B
            reliability=None,
        )

        mock_call = Common.URL.mock_calls[0]
        assert mock_call.args[0] == entity
        assert mock_call.args[1].indicator == entity

    def test_create_indicator_cve(self, mocker):
        from RecordedFuture import create_indicator
        from CommonServerPython import Common

        mock_return_value = mocker.Mock()
        mocker.patch("CommonServerPython.Common.CVE", return_value=mock_return_value)

        entity = "CVE-123"
        entity_type = "cve"
        score = 45
        description = "test_description"

        result = create_indicator(
            entity=entity,
            entity_type=entity_type,
            score=score,
            description=description,
        )

        assert result == mock_return_value

        mock_call = Common.CVE.mock_calls[0]
        assert mock_call.args[0] == entity
        assert mock_call.args[1] == ""
        assert mock_call.args[2] == ""
        assert mock_call.args[3] == ""
        assert mock_call.args[4] == description

    def test_create_indicator_file(self, mocker):
        from RecordedFuture import create_indicator
        from CommonServerPython import Common, DBotScoreType

        mock_return_value = mocker.Mock()
        mocker.patch("CommonServerPython.Common.File", return_value=mock_return_value)
        dbot_score_spy = mocker.spy(Common, "DBotScore")

        entity_type = "file"
        score = 45
        description = "test_description"

        # MD5.
        entity = "s" * 32
        result = create_indicator(
            entity=entity,
            entity_type=entity_type,
            score=score,
            description=description,
        )

        assert result == mock_return_value

        dbot_score_spy.assert_called_once_with(
            entity,
            DBotScoreType.FILE,
            "Recorded Future v2",
            Common.DBotScore.SUSPICIOUS,
            "",
            # reliability=DBotScoreReliability.B
            reliability=None,
        )

        mock_call = Common.File.mock_calls[0]
        assert mock_call.args[0].indicator == entity
        assert mock_call.kwargs.get("md5") == entity

        # SHA1.
        entity = "s" * 40
        result = create_indicator(
            entity=entity,
            entity_type=entity_type,
            score=score,
            description=description,
        )

        assert result == mock_return_value

        dbot_score_spy.assert_called_with(
            entity,
            DBotScoreType.FILE,
            "Recorded Future v2",
            Common.DBotScore.SUSPICIOUS,
            "",
            # reliability=DBotScoreReliability.B
            reliability=None,
        )

        mock_call = Common.File.mock_calls[-1]
        assert mock_call.args[0].indicator == entity
        assert mock_call.kwargs.get("sha1") == entity

        # SHA256.
        entity = "s" * 64
        result = create_indicator(
            entity=entity,
            entity_type=entity_type,
            score=score,
            description=description,
        )

        assert result == mock_return_value

        dbot_score_spy.assert_called_with(
            entity,
            DBotScoreType.FILE,
            "Recorded Future v2",
            Common.DBotScore.SUSPICIOUS,
            "",
            # reliability=DBotScoreReliability.B
            reliability=None,
        )

        mock_call = Common.File.mock_calls[-1]
        assert mock_call.args[0].indicator == entity
        assert mock_call.kwargs.get("sha256") == entity

        # SHA512.
        entity = "s" * 128
        result = create_indicator(
            entity=entity,
            entity_type=entity_type,
            score=score,
            description=description,
        )

        assert result == mock_return_value

        dbot_score_spy.assert_called_with(
            entity,
            DBotScoreType.FILE,
            "Recorded Future v2",
            Common.DBotScore.SUSPICIOUS,
            "",
            # reliability=DBotScoreReliability.B
            reliability=None,
        )

        mock_call = Common.File.mock_calls[-1]
        assert mock_call.args[0].indicator == entity
        assert mock_call.kwargs.get("sha512") == entity

        # CRC32.
        entity = "s" * 20  # Length different from any previous hashes.
        result = create_indicator(
            entity=entity,
            entity_type=entity_type,
            score=score,
            description=description,
        )

        assert result == mock_return_value

        dbot_score_spy.assert_called_with(
            entity,
            DBotScoreType.FILE,
            "Recorded Future v2",
            Common.DBotScore.SUSPICIOUS,
            "",
            # reliability=DBotScoreReliability.B
            reliability=None,
        )

        mock_call = Common.File.mock_calls[-1]
        assert mock_call.args[0].indicator == entity
        assert mock_call.kwargs == {}


class TestRFClient:
    def test_whoami(self, mocker):
        client = create_client()

        mock_http_request = mocker.patch.object(client, "_http_request")

        client.whoami()

        mock_http_request.assert_called_once_with(
            method="get",
            url_suffix="info/whoami",
            timeout=60,
        )

    def test_get_writeback_data_writeback_off(self, mocker):
        """
        Test _get_writeback_data with writeback turned OFF.
        """

        import demistomock as demisto

        client = create_client()

        mocker.patch.object(demisto, "params", return_value={"writeback": False})
        assert client._get_writeback_data() is None

    def test_get_writeback_data_writeback_on(self, mocker):
        """
        Test _get_writeback_data with writeback turned ON.
        """
        import demistomock as demisto

        client = create_client()

        mocker.patch.object(
            demisto, "params", return_value={"collective_insights": "On"}
        )

        demisto.callingContext = {
            "context": {"ExecutionContext": "to be removed", "Incidents": []}
        }

        assert client._get_writeback_data() == {"context": {"Incidents": []}}

    #
    def test_call_writeback_on(self, mocker):
        """
        Test _call() with writeback turned ON.
        """

        import os
        import demistomock as demisto

        STATUS_TO_RETRY = [500, 501, 502, 503, 504]

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        # Mock data for writeback.
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "collective_insights": "On",
            },
        )

        mock_calling_context = {
            "context": {"ExecutionContext": "to be removed", "Incidents": []},
            "other": "data",
        }
        demisto.callingContext = mock_calling_context

        client = create_client()

        mock_http_request = mocker.patch.object(client, "_http_request")

        mock_url_suffix = "mock_url_suffix"

        client._call(url_suffix=mock_url_suffix)

        json_data = {
            "demisto_command": mock_command_name,
            "demisto_args": mock_command_args,
            "callingContext": {
                "context": {"Incidents": []},
            },
        }

        mock_http_request.assert_called_once_with(
            method="post",
            url_suffix=mock_url_suffix,
            json_data=json_data,
            timeout=90,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY,
        )

    def test_call_writeback_off(self, mocker):
        """
        Test _call() with writeback turned OFF.
        """

        import os
        import demistomock as demisto

        STATUS_TO_RETRY = [500, 501, 502, 503, 504]

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        # Mock data for writeback.
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "collective_insights": "Off",
            },
        )

        mock_calling_context = {
            "context": {"ExecutionContext": "to be removed", "other": "data"},
            "other": "data",
        }
        demisto.callingContext = mock_calling_context

        client = create_client()

        mock_http_request = mocker.patch.object(client, "_http_request")

        mock_url_suffix = "mock_url_suffix"

        client._call(url_suffix=mock_url_suffix)

        json_data = {
            "demisto_command": mock_command_name,
            "demisto_args": mock_command_args,
        }

        mock_http_request.assert_called_once_with(
            method="post",
            url_suffix=mock_url_suffix,
            json_data=json_data,
            timeout=90,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY,
        )

    def test_call_with_kwargs(self, mocker):
        """
        Test _call() with kwargs.
        """

        import os
        import demistomock as demisto

        STATUS_TO_RETRY = [500, 501, 502, 503, 504]

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_http_request = mocker.patch.object(client, "_http_request")

        mock_url_suffix = "mock_url_suffix"

        client._call(url_suffix=mock_url_suffix, timeout=120, any_other_kwarg=True)

        json_data = {
            "demisto_command": mock_command_name,
            "demisto_args": mock_command_args,
        }

        mock_http_request.assert_called_once_with(
            method="post",
            url_suffix=mock_url_suffix,
            json_data=json_data,
            timeout=120,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY,
            any_other_kwarg=True,
        )

    def test_call_returns_response(self, mocker):
        """
        Test _call() returns response.
        """

        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_response = {"response": {"data": "mock data"}}

        mocker.patch.object(client, "_http_request", return_value=mock_response)

        mock_url_suffix = "mock_url_suffix"

        response = client._call(url_suffix=mock_url_suffix)
        assert response == mock_response

    def test_call_response_processing_return_error(self, mocker):
        """
        Test _call() return_error response processing.
        """

        import os
        import demistomock as demisto

        STATUS_TO_RETRY = [500, 501, 502, 503, 504]

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        mock_return_error = mocker.patch("RecordedFuture.return_error")

        client = create_client()

        mock_http_request = mocker.patch.object(
            client,
            "_http_request",
            return_value={"return_error": {"message": "mock error"}},
        )

        mock_url_suffix = "mock_url_suffix"

        client._call(url_suffix=mock_url_suffix)

        json_data = {
            "demisto_command": mock_command_name,
            "demisto_args": mock_command_args,
        }

        mock_http_request.assert_called_once_with(
            method="post",
            url_suffix=mock_url_suffix,
            json_data=json_data,
            timeout=90,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY,
        )

        mock_return_error.assert_called_once_with(message="mock error")

    def test_call_response_processing_404(self, mocker):
        """
        Test _call() response processing.
        """

        import os
        import demistomock as demisto
        from CommonServerPython import DemistoException, CommandResults

        STATUS_TO_RETRY = [500, 501, 502, 503, 504]

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        mocker.patch("RecordedFuture.return_error")

        client = create_client()

        def mock_http_request_method(*args, **kwargs):
            # Imitate how CommonServerPython handles bad responses (when status code not in ok_codes,
            # or if ok_codes=None - it uses requests.Response.ok to check whether response is good).
            raise DemistoException("404")

        mocker.patch.object(client, "_http_request", mock_http_request_method)

        spy_http_request = mocker.spy(client, "_http_request")

        mock_url_suffix = "mock_url_suffix"

        result = client._call(url_suffix=mock_url_suffix)

        json_data = {
            "demisto_command": mock_command_name,
            "demisto_args": mock_command_args,
        }

        spy_http_request.assert_called_once_with(
            method="post",
            url_suffix=mock_url_suffix,
            json_data=json_data,
            timeout=90,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY,
        )

        assert isinstance(result, CommandResults)

        assert result.outputs_prefix == ""
        assert result.outputs_key_field == ""
        assert result.outputs == {}
        assert result.raw_response == {}
        assert result.readable_output == "No results found."

    def test_fetch_incidents(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}
        mock_params = {"param1": "param1 value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)
        mocker.patch.object(demisto, "params", return_value=mock_params)

        mock_last_run_dict = {"lastRun": "2022-08-31T12:12:20+00:00"}
        mocker.patch.object(demisto, "getLastRun", return_value=mock_last_run_dict)

        client = create_client()

        mock_call_response = {"response": {"data": "mock response"}}
        mock_call = mocker.patch.object(
            client, "_call", return_value=mock_call_response
        )

        response = client.fetch_incidents()

        mock_call.assert_called_once_with(
            json_data={
                "demisto_command": mock_command_name,
                "demisto_args": mock_command_args,
                "demisto_last_run": mock_last_run_dict,
                "demisto_params": mock_params,
            },
            timeout=120,
            url_suffix="/v2/alert/fetch_incidents",
        )

        assert response == mock_call_response

    def test_entity_search(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "mock response"}}
        mock_call = mocker.patch.object(
            client, "_call", return_value=mock_call_response
        )

        response = client.entity_search()

        mock_call.assert_called_once_with(url_suffix="/v2/search")

        assert response == mock_call_response

    def test_get_intelligence(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "mock response"}}
        mock_call = mocker.patch.object(
            client, "_call", return_value=mock_call_response
        )

        response = client.get_intelligence()

        mock_call.assert_called_once_with(url_suffix="/v2/lookup/intelligence")

        assert response == mock_call_response

    def test_get_links(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "mock response"}}
        mock_call = mocker.patch.object(
            client, "_call", return_value=mock_call_response
        )

        response = client.get_links()

        mock_call.assert_called_once_with(url_suffix="/v2/lookup/links")

        assert response == mock_call_response

    def test_get_single_alert(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "mock response"}}
        mock_call = mocker.patch.object(
            client, "_call", return_value=mock_call_response
        )

        response = client.get_single_alert()

        mock_call.assert_called_once_with(url_suffix="/v2/alert/lookup")

        assert response == mock_call_response

    def test_get_alerts(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "mock response"}}
        mock_call = mocker.patch.object(
            client, "_call", return_value=mock_call_response
        )

        response = client.get_alerts()

        mock_call.assert_called_once_with(url_suffix="/v2/alert/search")

        assert response == mock_call_response

    def test_get_alert_rules(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "mock response"}}
        mock_call = mocker.patch.object(
            client, "_call", return_value=mock_call_response
        )

        response = client.get_alert_rules()

        mock_call.assert_called_once_with(url_suffix="/v2/alert/rule")

        assert response == mock_call_response

    def test_alert_set_status(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "mock response"}}
        mock_call = mocker.patch.object(
            client, "_call", return_value=mock_call_response
        )

        alert_data = {"mock": "data"}
        response = client.alert_set_status(alert_data)

        mock_call.assert_called_once_with(
            url_suffix="/v2/alert/set_status",
            json_data={
                "demisto_command": mock_command_name,
                "demisto_args": mock_command_args,
                "alerts_update_data": alert_data,
            },
        )

        assert response == mock_call_response

        response = client.alert_set_status()

        mock_call.assert_called_with(
            url_suffix="/v2/alert/set_status",
            json_data={
                "demisto_command": mock_command_name,
                "demisto_args": mock_command_args,
                "alerts_update_data": None,
            },
        )

        assert response == mock_call_response

    def test_alert_set_note(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "mock response"}}
        mock_call = mocker.patch.object(
            client, "_call", return_value=mock_call_response
        )

        alert_data = {"mock": "data"}
        response = client.alert_set_note(alert_data)

        mock_call.assert_called_once_with(
            url_suffix="/v2/alert/set_note",
            json_data={
                "demisto_command": mock_command_name,
                "demisto_args": mock_command_args,
                "alerts_update_data": alert_data,
            },
        )

        assert response == mock_call_response

        response = client.alert_set_note()

        mock_call.assert_called_with(
            url_suffix="/v2/alert/set_note",
            json_data={
                "demisto_command": mock_command_name,
                "demisto_args": mock_command_args,
                "alerts_update_data": None,
            },
        )

        assert response == mock_call_response

    def test_get_triage(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "mock response"}}
        mock_call = mocker.patch.object(
            client, "_call", return_value=mock_call_response
        )

        response = client.get_triage()

        mock_call.assert_called_once_with(url_suffix="/v2/lookup/triage")

        assert response == mock_call_response

    def test_get_threat_map(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "threat_map"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "threat map response"}}
        mock_call = mocker.patch.object(
            client, "_call", return_value=mock_call_response
        )

        response = client.get_threat_map()

        mock_call.assert_called_once_with(url_suffix="/v2/threat/actors")

        assert response == mock_call_response

    def test_get_threat_links(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "threat_links"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "threat links response"}}
        mock_call = mocker.patch.object(
            client, "_call", return_value=mock_call_response
        )

        response = client.get_threat_links()

        mock_call.assert_called_once_with(url_suffix="/v2/links/search")

        assert response == mock_call_response

    def test_get_detection_rules(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "detection_rules"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "detection rules response"}}
        mock_call = mocker.patch.object(
            client, "_call", return_value=mock_call_response
        )

        response = client.get_detection_rules()

        mock_call.assert_called_once_with(url_suffix="/v2/detection_rules/search")

        assert response == mock_call_response

    def test_submit_collective_insight(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "collective_insight"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "collective insight response"}}
        mock_call = mocker.patch.object(
            client, "_call", return_value=mock_call_response
        )

        response = client.submit_detection_to_collective_insight()

        mock_call.assert_called_once_with(
            url_suffix="/v2/collective-insights/detections"
        )

        assert response == mock_call_response


class TestActions:
    def test_init(self, mocker):
        from RecordedFuture import Actions

        mock_client = mocker.Mock()
        actions = Actions(mock_client)
        assert actions.client == mock_client

    def test_process_result_actions_404(self, mocker):
        from RecordedFuture import Actions
        from CommonServerPython import CommandResults

        mock_client = mocker.Mock()
        actions = Actions(mock_client)

        # Test if response is CommandResults
        # (case when we got 404 on response, and it was processed in self.client._call() method).
        response = CommandResults(readable_output="Mock")
        result_actions = actions._process_result_actions(response=response)
        assert result_actions == [response]

    def test_process_result_actions_response_is_not_dict(self, mocker):
        from RecordedFuture import Actions

        mock_client = mocker.Mock()
        actions = Actions(mock_client)

        # Test if response is not CommandResults and not Dict.
        response = "Mock string - not CommandResults and not dict"
        result_actions = actions._process_result_actions(response=response)  # type: ignore
        assert result_actions is None

    def test_process_result_actions_no_or_empty_result_actions_in_response(
        self, mocker
    ):
        from RecordedFuture import Actions

        mock_client = mocker.Mock()
        actions = Actions(mock_client)

        # Test no results_actions in response.
        response = {"data": "mock"}
        result_actions = actions._process_result_actions(response=response)
        assert result_actions is None

        # Test case when bool(results_actions) in response is False.
        response = {"data": "mock", "result_actions": None}
        result_actions = actions._process_result_actions(response=response)
        assert result_actions is None

        response = {"data": "mock", "result_actions": []}
        result_actions = actions._process_result_actions(response=response)
        assert result_actions is None

        response = {"data": "mock", "result_actions": {}}
        result_actions = actions._process_result_actions(response=response)
        assert result_actions is None

    def test_process_result_actions_command_results_only(self, mocker):
        from RecordedFuture import Actions, CommandResults

        mock_client = mocker.Mock()
        actions = Actions(mock_client)

        response = {
            "data": "mock",
            "result_actions": [
                {
                    "CommandResults": {
                        "outputs_prefix": "mock_outputs_prefix",
                        "outputs": "mock_outputs",
                        "raw_response": "mock_raw_response",
                        "readable_output": "mock_readable_output",
                        "outputs_key_field": "mock_outputs_key_field",
                    },
                }
            ],
        }
        result_actions = actions._process_result_actions(response=response)

        assert len(result_actions) == 1

        r_a = result_actions[0]

        assert isinstance(r_a, CommandResults)

        assert r_a.outputs_prefix == "mock_outputs_prefix"
        assert r_a.outputs == "mock_outputs"
        assert r_a.raw_response == "mock_raw_response"
        assert r_a.readable_output == "mock_readable_output"
        assert r_a.outputs_key_field == "mock_outputs_key_field"

    def test_process_result_actions_create_indicator_and_default_command_results(
        self, mocker
    ):
        import RecordedFuture

        spy_create_indicator = mocker.spy(
            RecordedFuture,
            "create_indicator",
        )

        mock_client = mocker.Mock()
        actions = RecordedFuture.Actions(mock_client)

        response = {
            "data": "mock",
            "result_actions": [
                {
                    "create_indicator": {
                        "entity": "mock_entity",
                        "entity_type": "ip",
                        "score": 15,
                        "description": "mock_description",
                        "location": {"country": "mock_country", "ans": "mock_asn"},
                    },
                }
            ],
        }
        result_actions = actions._process_result_actions(response=response)

        spy_create_indicator.assert_called_once_with(
            entity="mock_entity",
            entity_type="ip",
            score=15,
            description="mock_description",
            location={"country": "mock_country", "ans": "mock_asn"},
        )

        assert len(result_actions) == 1

        r_a = result_actions[0]

        assert isinstance(r_a, RecordedFuture.CommandResults)

        assert r_a.readable_output == (
            "### New indicator was created.\n"
            "|DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == "
            "obj.Vendor && val.Type == obj.Type)|IP(val.Address && val.Address == "
            "obj.Address)|\n"
            "|---|---|\n"
            "| Indicator: mock_entity<br>Type: ip<br>Vendor: Recorded Future v2<br>Score: "
            "0 | Address: mock_entity |\n"
        )

    def test_process_result_actions_create_indicator_and_command_results(self, mocker):
        import RecordedFuture

        spy_create_indicator = mocker.spy(
            RecordedFuture,
            "create_indicator",
        )

        mock_client = mocker.Mock()
        actions = RecordedFuture.Actions(mock_client)

        response = {
            "data": "mock",
            "result_actions": [
                {
                    "create_indicator": {
                        "entity": "mock_entity",
                        "entity_type": "ip",
                        "score": 15,
                        "description": "mock_indicator_description",
                    },
                    "CommandResults": {
                        "outputs_prefix": "mock_outputs_prefix",
                        "outputs": "mock_outputs",
                        "raw_response": "mock_raw_response",
                        "readable_output": "mock_readable_output",
                        "outputs_key_field": "mock_outputs_key_field",
                        "indicator": "indicator",
                    },
                }
            ],
        }
        result_actions = actions._process_result_actions(response=response)

        spy_create_indicator.assert_called_once_with(
            entity="mock_entity",
            entity_type="ip",
            score=15,
            description="mock_indicator_description",
        )

        assert len(result_actions) == 1

        r_a = result_actions[0]

        assert isinstance(r_a, RecordedFuture.CommandResults)

        assert r_a.outputs_prefix == "mock_outputs_prefix"
        assert r_a.outputs == "mock_outputs"
        assert r_a.raw_response == "mock_raw_response"
        assert r_a.readable_output == "mock_readable_output"
        assert r_a.outputs_key_field == "mock_outputs_key_field"

        assert r_a.indicator.to_context() == {
            "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)": {
                "Indicator": "mock_entity",
                "Score": 0,
                "Type": "ip",
                "Vendor": "Recorded Future v2",
            },
            "IP(val.Address && val.Address == obj.Address)": {"Address": "mock_entity"},
        }

    def test_fetch_incidents_with_incidents_present(self, mocker):
        from RecordedFuture import Actions
        import demistomock as demisto

        client = create_client()

        mock_incidents_value = [
            {"mock_incident_key1": "mock_incident_value1"},
            {"mock_incident_key2": "mock_incident_value2"},
        ]

        mock_demisto_last_run_value = "mock_demisto_last_run"

        mock_alerts_update_data_value = "mock_alerts_update_data_value"

        mock_client_fetch_incidents_response = {
            "incidents": mock_incidents_value,
            "demisto_last_run": mock_demisto_last_run_value,
            "data": "mock",
            "alerts_update_data": mock_alerts_update_data_value,
        }
        mock_client_fetch_incidents = mocker.patch.object(
            client, "fetch_incidents", return_value=mock_client_fetch_incidents_response
        )

        mock_client_alert_set_status = mocker.patch.object(
            client,
            "alert_set_status",
        )

        mock_demisto_incidents = mocker.patch.object(demisto, "incidents")
        mock_demisto_set_last_run = mocker.patch.object(demisto, "setLastRun")

        actions = Actions(client)

        actions.fetch_incidents()

        mock_client_fetch_incidents.assert_called_once_with()

        mock_demisto_incidents.assert_called_once_with(mock_incidents_value)
        mock_demisto_set_last_run.assert_called_once_with(mock_demisto_last_run_value)

        # Verify that we update alert status.
        mock_client_alert_set_status.assert_called_once_with(
            mock_alerts_update_data_value
        )

    def test_malware_search_command(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = "mock_response"

        mock_client_entity_search = mocker.patch.object(
            client, "entity_search", return_value=mock_response
        )

        actions = Actions(client)

        mock_process_result_actions_return_value = (
            "mock_process_result_actions_return_value"
        )
        mock_process_result_actions = mocker.patch.object(
            actions,
            "_process_result_actions",
            return_value=mock_process_result_actions_return_value,
        )

        result = actions.malware_search_command()

        mock_client_entity_search.assert_called_once_with()

        mock_process_result_actions.assert_called_once_with(response=mock_response)

        assert result == mock_process_result_actions_return_value

    def test_lookup_command(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = "mock_response"

        mock_client_entity_lookup = mocker.patch.object(
            client, "entity_lookup", return_value=mock_response
        )

        actions = Actions(client)

        mock_process_result_actions_return_value = (
            "mock_process_result_actions_return_value"
        )
        mock_process_result_actions = mocker.patch.object(
            actions,
            "_process_result_actions",
            return_value=mock_process_result_actions_return_value,
        )

        result = actions.lookup_command()

        mock_client_entity_lookup.assert_called_once_with()

        mock_process_result_actions.assert_called_once_with(response=mock_response)

        assert result == mock_process_result_actions_return_value

    def test_intelligence_command(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = "mock_response"

        mock_client_get_intelligence = mocker.patch.object(
            client, "get_intelligence", return_value=mock_response
        )

        actions = Actions(client)

        mock_process_result_actions_return_value = (
            "mock_process_result_actions_return_value"
        )
        mock_process_result_actions = mocker.patch.object(
            actions,
            "_process_result_actions",
            return_value=mock_process_result_actions_return_value,
        )

        result = actions.intelligence_command()

        mock_client_get_intelligence.assert_called_once_with()

        mock_process_result_actions.assert_called_once_with(response=mock_response)

        assert result == mock_process_result_actions_return_value

    def test_get_links_command(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = "mock_response"

        mock_client_get_links = mocker.patch.object(
            client, "get_links", return_value=mock_response
        )

        actions = Actions(client)

        mock_process_result_actions_return_value = (
            "mock_process_result_actions_return_value"
        )
        mock_process_result_actions = mocker.patch.object(
            actions,
            "_process_result_actions",
            return_value=mock_process_result_actions_return_value,
        )

        result = actions.get_links_command()

        mock_client_get_links.assert_called_once_with()

        mock_process_result_actions.assert_called_once_with(response=mock_response)

        assert result == mock_process_result_actions_return_value

    def test_get_single_alert_command_with_result_actions(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = "mock_response"

        mock_client_get_single_alert = mocker.patch.object(
            client, "get_single_alert", return_value=mock_response
        )

        actions = Actions(client)

        mock_process_result_actions_return_value = (
            "mock_process_result_actions_return_value"
        )
        mock_process_result_actions = mocker.patch.object(
            actions,
            "_process_result_actions",
            return_value=mock_process_result_actions_return_value,
        )

        result = actions.get_single_alert_command()

        mock_client_get_single_alert.assert_called_once_with()

        mock_process_result_actions.assert_called_once_with(response=mock_response)

        # As there are some result actions - return those result actions.
        assert result == mock_process_result_actions_return_value

    def test_get_single_alert_command_without_result_actions(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = "mock_response"

        mock_client_get_single_alert = mocker.patch.object(
            client, "get_single_alert", return_value=mock_response
        )

        actions = Actions(client)

        mock_process_result_actions_return_value = None
        mock_process_result_actions = mocker.patch.object(
            actions,
            "_process_result_actions",
            return_value=mock_process_result_actions_return_value,
        )

        result = actions.get_single_alert_command()

        mock_client_get_single_alert.assert_called_once_with()

        mock_process_result_actions.assert_called_once_with(response=mock_response)

        # As there is no result actions - just return response.
        assert result == mock_response

    def test_get_alerts_command(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = "mock_response"

        mock_client_get_alerts = mocker.patch.object(
            client, "get_alerts", return_value=mock_response
        )

        actions = Actions(client)

        result = actions.get_alerts_command()

        mock_client_get_alerts.assert_called_once_with()

        assert result == mock_response

    def test_get_alert_rules_command(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = "mock_response"

        mock_client_get_alert_rules = mocker.patch.object(
            client, "get_alert_rules", return_value=mock_response
        )

        actions = Actions(client)

        result = actions.get_alert_rules_command()

        mock_client_get_alert_rules.assert_called_once_with()

        assert result == mock_response

    def test_alert_set_status_command(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = "mock_response"

        mock_client_alert_set_status = mocker.patch.object(
            client, "alert_set_status", return_value=mock_response
        )

        actions = Actions(client)

        mock_process_result_actions_return_value = (
            "mock_process_result_actions_return_value"
        )
        mock_process_result_actions = mocker.patch.object(
            actions,
            "_process_result_actions",
            return_value=mock_process_result_actions_return_value,
        )

        result = actions.alert_set_status_command()

        mock_client_alert_set_status.assert_called_once_with()

        mock_process_result_actions.assert_called_once_with(response=mock_response)

        assert result == mock_process_result_actions_return_value

    def test_alert_set_note_command(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = "mock_response"

        mock_client_alert_set_note = mocker.patch.object(
            client, "alert_set_note", return_value=mock_response
        )

        actions = Actions(client)

        mock_process_result_actions_return_value = (
            "mock_process_result_actions_return_value"
        )
        mock_process_result_actions = mocker.patch.object(
            actions,
            "_process_result_actions",
            return_value=mock_process_result_actions_return_value,
        )

        result = actions.alert_set_note_command()

        mock_client_alert_set_note.assert_called_once_with()

        mock_process_result_actions.assert_called_once_with(response=mock_response)

        assert result == mock_process_result_actions_return_value

    def test_triage_command(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = "mock_response"

        mock_client_get_triage = mocker.patch.object(
            client, "get_triage", return_value=mock_response
        )

        actions = Actions(client)

        mock_process_result_actions_return_value = (
            "mock_process_result_actions_return_value"
        )
        mock_process_result_actions = mocker.patch.object(
            actions,
            "_process_result_actions",
            return_value=mock_process_result_actions_return_value,
        )

        result = actions.triage_command()

        mock_client_get_triage.assert_called_once_with()

        mock_process_result_actions.assert_called_once_with(response=mock_response)

        assert result == mock_process_result_actions_return_value

    def test_threat_map_command(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = "mock_threat_map"

        mock_client_get_threat_map = mocker.patch.object(
            client, "get_threat_map", return_value=mock_response
        )

        actions = Actions(client)

        mock_process_result_actions_return_value = (
            "mock_process_result_actions_return_value"
        )
        mock_process_result_actions = mocker.patch.object(
            actions,
            "_process_result_actions",
            return_value=mock_process_result_actions_return_value,
        )

        result = actions.threat_actors_command()

        mock_client_get_threat_map.assert_called_once_with()

        mock_process_result_actions.assert_called_once_with(response=mock_response)

        assert result == mock_process_result_actions_return_value

    def test_threat_links_command(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = "mock_threat_links"

        mock_client_get_threat_links = mocker.patch.object(
            client, "get_threat_links", return_value=mock_response
        )

        actions = Actions(client)

        mock_process_result_actions_return_value = "return_value"
        mock_process_result_actions = mocker.patch.object(
            actions,
            "_process_result_actions",
            return_value=mock_process_result_actions_return_value,
        )

        result = actions.threat_links_command()
        mock_client_get_threat_links.assert_called_once_with()
        mock_process_result_actions.assert_called_once_with(response=mock_response)

        assert result == mock_process_result_actions_return_value

    def test_detection_rules_command(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = "mock_detection_rules"

        mock_get_detection_rules = mocker.patch.object(
            client, "get_detection_rules", return_value=mock_response
        )

        actions = Actions(client)

        mock_process_result_actions_return_value = "return_value"
        mock_process_result_actions = mocker.patch.object(
            actions,
            "_process_result_actions",
            return_value=mock_process_result_actions_return_value,
        )

        result = actions.detection_rules_command()
        mock_get_detection_rules.assert_called_once_with()
        mock_process_result_actions.assert_called_once_with(response=mock_response)

        assert result == mock_process_result_actions_return_value

    def test_collective_insight_command(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = "mock_collective_insight"

        mock_submit_detection_to_collective_insight = mocker.patch.object(
            client, "submit_detection_to_collective_insight", return_value=mock_response
        )

        actions = Actions(client)

        mock_process_result_actions_return_value = "return_value"
        mock_process_result_actions = mocker.patch.object(
            actions,
            "_process_result_actions",
            return_value=mock_process_result_actions_return_value,
        )

        result = actions.collective_insight_command()
        mock_submit_detection_to_collective_insight.assert_called_once_with()
        mock_process_result_actions.assert_called_once_with(response=mock_response)

        assert result == mock_process_result_actions_return_value

    def test_test_module(self, mocker):
        import RecordedFuture
        import demistomock as demisto
        import platform

        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(
            demisto, "demistoVersion", return_value={"version": "mock_version"}
        )
        mocker.patch.object(
            demisto, "params", return_value={"token": {"password": "mocktoken"}}
        )
        mocker.patch.object(platform, "platform", return_value="mock_platform")
        mocker.patch.object(RecordedFuture.Client, "whoami")
        mocked_return_res = mocker.patch.object(RecordedFuture, "return_results")
        RecordedFuture.main()
        mocked_return_res.assert_called_with("ok")

    def test_test_module_with_boom(self, mocker):
        import RecordedFuture
        import demistomock as demisto
        import platform

        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(
            demisto, "demistoVersion", return_value={"version": "mock_version"}
        )
        mocker.patch.object(
            demisto, "params", return_value={"token": {"password": "mocktoken"}}
        )
        mocker.patch.object(platform, "platform", return_value="mock_platform")
        mock_whoami = mocker.patch.object(RecordedFuture.Client, "whoami")
        mock_whoami.side_effect = Exception("Side effect triggered")
        mocked_return_err = mocker.patch.object(RecordedFuture, "return_error")
        RecordedFuture.main()
        mocked_return_err.assert_called_with(
            message=(
                f"Failed to execute {demisto.command()} command: "
                "Failed due to - Unknown error. Please verify that the API URL and Token are correctly configured. "
                "RAW Error: Side effect triggered"
            ),
            error=mocker.ANY,
        )
