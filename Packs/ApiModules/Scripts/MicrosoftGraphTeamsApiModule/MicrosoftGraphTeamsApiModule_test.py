"""Unit tests for MicrosoftGraphTeamsApiModule.

Coverage focuses on the new `msgraph-teams-message-update-policy-violation` code path
(the four helpers, the client method, and the command function). The community-pack
code that was extracted verbatim inherits the community pack's `tests: - No tests
(auto formatted)` posture and is intentionally not re-tested here.
"""

import demistomock as demisto
import pytest

from CommonServerPython import DemistoException

from MicrosoftGraphTeamsApiModule import (
    MsGraphClient,
    build_policy_violation_body,
    build_teams_message_url_suffix,
    update_teams_message_policy_violation_command,
    validate_teams_message_target_args,
)

# Aliased on import: pytest would otherwise collect the `test_`-prefixed production
# function as a test case and error on its unresolvable `client` / `_` parameters.
from MicrosoftGraphTeamsApiModule import test_function as run_test_function

# ---------------------------------------------------------------------------
# build_teams_message_url_suffix
# ---------------------------------------------------------------------------


class TestBuildTeamsMessageUrlSuffix:
    def test_chat_message(self):
        suffix = build_teams_message_url_suffix(
            chat_id="19:abc",
            team_id="",
            channel_id="",
            message_id="msg-1",
            parent_message_id="",
            payment_model="",
        )
        assert suffix == "chats/19:abc/messages/msg-1"

    def test_channel_top_level_message(self):
        suffix = build_teams_message_url_suffix(
            chat_id="",
            team_id="team-1",
            channel_id="chan-1",
            message_id="msg-1",
            parent_message_id="",
            payment_model="",
        )
        assert suffix == "teams/team-1/channels/chan-1/messages/msg-1"

    def test_channel_reply(self):
        suffix = build_teams_message_url_suffix(
            chat_id="",
            team_id="team-1",
            channel_id="chan-1",
            message_id="reply-1",
            parent_message_id="parent-1",
            payment_model="",
        )
        assert suffix == "teams/team-1/channels/chan-1/messages/parent-1/replies/reply-1"

    def test_payment_model_appended(self):
        suffix = build_teams_message_url_suffix(
            chat_id="19:abc",
            team_id="",
            channel_id="",
            message_id="msg-1",
            parent_message_id="",
            payment_model="B",
        )
        assert suffix == "chats/19:abc/messages/msg-1?model=B"

    def test_chat_wins_over_channel_when_both_provided(self):
        # Guarded by validate_teams_message_target_args; this pins the raw
        # branch behavior so a future refactor can't silently reorder it.
        suffix = build_teams_message_url_suffix(
            chat_id="19:abc",
            team_id="team-1",
            channel_id="chan-1",
            message_id="msg-1",
            parent_message_id="",
            payment_model="",
        )
        assert suffix == "chats/19:abc/messages/msg-1"


# ---------------------------------------------------------------------------
# build_policy_violation_body
# ---------------------------------------------------------------------------


class TestBuildPolicyViolationBody:
    def test_minimal_body_omits_verdict_details(self):
        body = build_policy_violation_body(
            dlp_action="BlockAccess",
            policy_tip_general_text="Blocked by DLP",
            verdict_details="",
        )
        assert body == {
            "policyViolation": {
                "dlpAction": "BlockAccess",
                "policyTip": {"generalText": "Blocked by DLP"},
            }
        }
        # explicit: falsy verdict_details must not add the key at all
        assert "verdictDetails" not in body["policyViolation"]

    def test_full_body_includes_verdict_details(self):
        body = build_policy_violation_body(
            dlp_action="BlockAccessExternal",
            policy_tip_general_text="Contains sensitive data",
            verdict_details="AllowOverrideWithoutJustification",
        )
        assert body == {
            "policyViolation": {
                "dlpAction": "BlockAccessExternal",
                "policyTip": {"generalText": "Contains sensitive data"},
                "verdictDetails": "AllowOverrideWithoutJustification",
            }
        }

    def test_no_action_preserved_verbatim(self):
        body = build_policy_violation_body(
            dlp_action="NoAction",
            policy_tip_general_text="",
            verdict_details="",
        )
        assert body["policyViolation"]["dlpAction"] == "NoAction"
        assert body["policyViolation"]["policyTip"] == {"generalText": ""}


# ---------------------------------------------------------------------------
# validate_teams_message_target_args
# ---------------------------------------------------------------------------


class TestValidateTeamsMessageTargetArgs:
    def test_chat_only_is_valid(self):
        # No exception → pass.
        validate_teams_message_target_args(chat_id="19:abc", team_id="", channel_id="", parent_message_id="")

    def test_channel_only_is_valid(self):
        validate_teams_message_target_args(chat_id="", team_id="team-1", channel_id="chan-1", parent_message_id="")

    def test_channel_reply_is_valid(self):
        validate_teams_message_target_args(chat_id="", team_id="team-1", channel_id="chan-1", parent_message_id="parent-1")

    def test_chat_and_parent_message_rejected(self):
        with pytest.raises(DemistoException, match="parent_message_id"):
            validate_teams_message_target_args(chat_id="19:abc", team_id="", channel_id="", parent_message_id="parent-1")

    def test_chat_and_channel_rejected(self):
        with pytest.raises(DemistoException, match="either 'chat_id' or 'team_id' and 'channel_id'"):
            validate_teams_message_target_args(chat_id="19:abc", team_id="team-1", channel_id="chan-1", parent_message_id="")

    def test_reply_without_channel_rejected(self):
        with pytest.raises(DemistoException, match="channel reply requires"):
            validate_teams_message_target_args(chat_id="", team_id="", channel_id="", parent_message_id="parent-1")

    def test_no_target_rejected(self):
        with pytest.raises(DemistoException, match="A message target is required"):
            validate_teams_message_target_args(chat_id="", team_id="", channel_id="", parent_message_id="")

    def test_partial_channel_rejected_team_only(self):
        with pytest.raises(DemistoException, match="channel message requires both"):
            validate_teams_message_target_args(chat_id="", team_id="team-1", channel_id="", parent_message_id="")

    def test_partial_channel_rejected_channel_only(self):
        with pytest.raises(DemistoException, match="channel message requires both"):
            validate_teams_message_target_args(chat_id="", team_id="", channel_id="chan-1", parent_message_id="")


# ---------------------------------------------------------------------------
# MsGraphClient.update_message_policy_violation
# ---------------------------------------------------------------------------


class _DummyMsClient:
    """Minimal stand-in for MicrosoftClient. Records the http_request call."""

    def __init__(self, response):
        self._response = response
        self.calls: list[dict] = []

    def http_request(self, **kwargs):
        self.calls.append(kwargs)
        return self._response


def _make_client_with_stubbed_ms_client(dummy):
    """Build an MsGraphClient without triggering MicrosoftClient.__init__ (which needs auth)."""
    client = MsGraphClient.__new__(MsGraphClient)
    client.ms_client = dummy
    return client


class TestUpdateMessagePolicyViolationClient:
    def test_issues_patch_with_expected_kwargs(self):
        dummy = _DummyMsClient(response="ok-response")
        client = _make_client_with_stubbed_ms_client(dummy)

        url_suffix = "chats/19:abc/messages/msg-1"
        body = {"policyViolation": {"dlpAction": "BlockAccess", "policyTip": {"generalText": "x"}}}

        result = client.update_message_policy_violation(url_suffix=url_suffix, body=body)

        assert result == "ok-response"
        assert len(dummy.calls) == 1
        call = dummy.calls[0]
        assert call["method"] == "PATCH"
        assert call["url_suffix"] == url_suffix
        assert call["json_data"] == body
        # resp_type="response" is required so callers can inspect status codes.
        assert call["resp_type"] == "response"


# ---------------------------------------------------------------------------
# test_function
# ---------------------------------------------------------------------------


class TestTestFunctionEndpointSelection:
    """`chats` is delegated-only: Microsoft Graph rejects it with 400 "Requested API is not
    supported in application-only context" when there is no signed-in user. `delegated_user`
    is the configured user to act as, so its presence decides whether a user-scoped probe can
    resolve; without one the probe must target the app-only addressable `teams`.
    """

    def _run(self, mocker, *, params=None, command="test-module"):
        mocker.patch.object(demisto, "params", return_value=params or {})
        mocker.patch.object(demisto, "command", return_value=command)
        results_mock = mocker.patch("MicrosoftGraphTeamsApiModule.return_results")
        dummy = _DummyMsClient(response="ok")
        client = _make_client_with_stubbed_ms_client(dummy)
        run_test_function(client, {})
        return dummy, results_mock

    def test_delegated_user_probes_user_scoped_endpoint(self, mocker):
        # The community pack requires `delegated_user`, so `chats` resolves against that user.
        dummy, _ = self._run(mocker, params={"delegated_user": "user@example.com"})

        assert len(dummy.calls) == 1
        assert dummy.calls[0]["url_suffix"] == "chats"
        assert dummy.calls[0]["method"] == "GET"

    def test_no_delegated_user_probes_app_only_endpoint(self, mocker):
        # The UCP satellite pack declares no `delegated_user` and is served an app-only token.
        dummy, _ = self._run(mocker)

        assert len(dummy.calls) == 1
        assert dummy.calls[0]["url_suffix"] == "teams"

    def test_blank_delegated_user_treated_as_absent(self, mocker):
        # An empty string is not a usable user, so it must not select the user-scoped probe.
        dummy, _ = self._run(mocker, params={"delegated_user": ""})

        assert dummy.calls[0]["url_suffix"] == "teams"

    def test_self_deployed_client_credentials_probes_app_only_endpoint(self, mocker):
        # Self-deployed without the auth-code flow yields an app-only token even outside UCP;
        # `!msgraph-teams-test` reaches the probe here because it does not raise like test-module.
        dummy, _ = self._run(
            mocker,
            params={"self_deployed": True},
            command="msgraph-teams-test",
        )

        assert dummy.calls[0]["url_suffix"] == "teams"


class TestTestFunctionResultContract:
    """`test-module` must emit exactly the string "ok"; any other payload is reported to the
    user as a failed connection test even when the underlying API call succeeded.
    """

    def _run(self, mocker, *, command, params=None):
        mocker.patch.object(demisto, "params", return_value=params or {})
        mocker.patch.object(demisto, "command", return_value=command)
        results_mock = mocker.patch("MicrosoftGraphTeamsApiModule.return_results")
        client = _make_client_with_stubbed_ms_client(_DummyMsClient(response="ok"))
        run_test_function(client, {})
        return results_mock

    def test_test_module_emits_bare_ok(self, mocker):
        results_mock = self._run(mocker, command="test-module")

        results_mock.assert_called_once_with("ok")

    def test_explicit_test_command_keeps_rich_output(self, mocker):
        # `msgraph-teams-test` is a regular command, so it is free to return a decorated result.
        results_mock = self._run(mocker, command="msgraph-teams-test")

        assert results_mock.call_count == 1
        assert results_mock.call_args[0][0].readable_output == "✅ Success!"

    def test_test_module_emits_bare_ok_for_delegated_config(self, mocker):
        # The result contract is independent of which endpoint the probe selected.
        results_mock = self._run(
            mocker,
            command="test-module",
            params={"delegated_user": "user@example.com"},
        )

        results_mock.assert_called_once_with("ok")


# ---------------------------------------------------------------------------
# update_teams_message_policy_violation_command
# ---------------------------------------------------------------------------


class TestUpdateTeamsMessagePolicyViolationCommand:
    def _run(self, mocker, args, response="ok"):
        dummy = _DummyMsClient(response=response)
        client = _make_client_with_stubbed_ms_client(dummy)
        results_mock = mocker.patch("MicrosoftGraphTeamsApiModule.return_results")
        update_teams_message_policy_violation_command(client, args)
        return dummy, results_mock

    def test_chat_message_full_flow(self, mocker):
        dummy, results_mock = self._run(
            mocker,
            args={
                "chat_id": "19:abc",
                "message_id": "msg-1",
                "dlp_action": "BlockAccess",
                "policy_tip_general_text": "Blocked by DLP",
                "verdict_details": "AllowOverrideWithoutJustification",
            },
        )

        # PATCH was issued with the composed suffix and body.
        assert len(dummy.calls) == 1
        call = dummy.calls[0]
        assert call["method"] == "PATCH"
        assert call["url_suffix"] == "chats/19:abc/messages/msg-1"
        assert call["json_data"] == {
            "policyViolation": {
                "dlpAction": "BlockAccess",
                "policyTip": {"generalText": "Blocked by DLP"},
                "verdictDetails": "AllowOverrideWithoutJustification",
            }
        }

        # Outputs were emitted via return_results with the standard-connector
        # prefix and message-id key.
        results_mock.assert_called_once()
        command_results = results_mock.call_args[0][0]
        assert command_results.outputs_prefix == "MSGraphTeams.TeamsMessagePolicyViolation"
        assert command_results.outputs_key_field == "messageId"
        assert command_results.outputs == {
            "messageId": "msg-1",
            "chatId": "19:abc",
            "dlpAction": "BlockAccess",
            "verdictDetails": "AllowOverrideWithoutJustification",
        }
        # empty fields (teamId/channelId/parentMessageId) are stripped.
        assert "teamId" not in command_results.outputs
        assert "channelId" not in command_results.outputs
        assert "parentMessageId" not in command_results.outputs

    def test_channel_reply_flow(self, mocker):
        dummy, results_mock = self._run(
            mocker,
            args={
                "team_id": "team-1",
                "channel_id": "chan-1",
                "parent_message_id": "parent-1",
                "message_id": "reply-1",
                "dlp_action": "BlockAccessExternal",
                "policy_tip_general_text": "External DLP",
                "payment_model": "B",
            },
        )
        assert dummy.calls[0]["url_suffix"] == "teams/team-1/channels/chan-1/messages/parent-1/replies/reply-1?model=B"
        # verdict_details omitted → not in body.
        assert "verdictDetails" not in dummy.calls[0]["json_data"]["policyViolation"]
        command_results = results_mock.call_args[0][0]
        # verdict_details empty → also stripped from outputs.
        assert "verdictDetails" not in command_results.outputs
        assert command_results.outputs["parentMessageId"] == "parent-1"

    def test_no_action_channel_message(self, mocker):
        dummy, _ = self._run(
            mocker,
            args={
                "team_id": "team-1",
                "channel_id": "chan-1",
                "message_id": "msg-9",
                "dlp_action": "NoAction",
                "policy_tip_general_text": "",
            },
        )
        body = dummy.calls[0]["json_data"]
        assert body["policyViolation"]["dlpAction"] == "NoAction"
        assert body["policyViolation"]["policyTip"] == {"generalText": ""}

    def test_validation_failure_short_circuits_http_call(self, mocker):
        dummy = _DummyMsClient(response="never")
        client = _make_client_with_stubbed_ms_client(dummy)
        mocker.patch("MicrosoftGraphTeamsApiModule.return_results")

        with pytest.raises(DemistoException):
            update_teams_message_policy_violation_command(
                client,
                {"chat_id": "19:abc", "team_id": "team-1", "channel_id": "chan-1"},
            )
        # Validation raised → no HTTP request should have been issued.
        assert dummy.calls == []


# ---------------------------------------------------------------------------
# demisto argument shape (guardrail for the YML→command binding)
# ---------------------------------------------------------------------------


class TestDemistoArgsShape:
    """demisto.args() returns str values; missing args are absent (not None).
    The command uses .get(name, "") throughout, so both shapes must work.
    """

    def test_missing_optional_args_default_to_empty(self, mocker):
        dummy = _DummyMsClient(response="ok")
        client = _make_client_with_stubbed_ms_client(dummy)
        mocker.patch("MicrosoftGraphTeamsApiModule.return_results")

        update_teams_message_policy_violation_command(
            client,
            {"chat_id": "19:abc", "message_id": "msg-1"},  # only the mandatory pair
        )

        assert dummy.calls[0]["url_suffix"] == "chats/19:abc/messages/msg-1"
        body = dummy.calls[0]["json_data"]
        # dlp_action absent → empty string, still passes verbatim.
        assert body["policyViolation"]["dlpAction"] == ""
