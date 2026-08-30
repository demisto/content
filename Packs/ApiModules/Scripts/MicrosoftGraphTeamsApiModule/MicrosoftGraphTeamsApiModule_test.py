"""Unit tests for MicrosoftGraphTeamsApiModule.

Coverage focuses on the new `msgraph-teams-message-update-policy-violation` code path
(the four helpers, the client method, and the command function). The community-pack
code that was extracted verbatim inherits the community pack's `tests: - No tests
(auto formatted)` posture and is intentionally not re-tested here.
"""

import pytest

from CommonServerPython import DemistoException

from MicrosoftGraphTeamsApiModule import (
    MsGraphClient,
    build_policy_violation_body,
    build_teams_message_url_suffix,
    update_teams_message_policy_violation_command,
    validate_teams_message_target_args,
)


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
