"""Unit tests for the IvantiHeat integration."""

import pytest

from IvantiHeat import Client, upload_attachment_command


def _client() -> Client:
    return Client(base_url="https://example.com/api", verify=False, headers={"Authorization": "rest_api_key=x"}, proxy=False)


class TestUploadAttachmentCommand:
    """Validates argument checks for ``ivanti-heat-object-attachment-upload``.

    The command must raise a clear, actionable error before issuing any HTTP
    request when a calling automation passes ``None``/empty/whitespace values
    for any required argument.
    """

    REQUIRED_ARGS = ("object-type", "entry-id", "rec-id")
    VALID_ARGS = {
        "object-type": "incidents",
        "entry-id": "123@456",
        "rec-id": "REC-1",
    }

    @pytest.mark.parametrize("missing_arg", REQUIRED_ARGS)
    @pytest.mark.parametrize("empty_value", [None, "", "   "])
    def test_raises_when_required_arg_is_missing_or_empty(self, mocker, missing_arg, empty_value):
        """Empty/whitespace/None values for any required arg must raise a clear error."""
        args = {**self.VALID_ARGS, missing_arg: empty_value}
        http_spy = mocker.patch.object(Client, "do_request")

        with pytest.raises(ValueError) as exc:
            upload_attachment_command(_client(), args)

        # Error must name the offending argument so users can act on it
        assert missing_arg in str(exc.value)
        # And the HTTP call must NOT have been made
        http_spy.assert_not_called()

    def test_uploads_when_all_required_args_are_present(self, mocker):
        """Happy path: when all args are present the upload is performed and
        a CommandResults-style tuple is returned."""
        mocker.patch(
            "IvantiHeat.get_file",
            return_value=("report.tsv", b"col1\tcol2\n1\t2\n"),
        )
        mocker.patch.object(
            Client,
            "do_request",
            return_value=[{"Message": "attach-id-1", "FileName": "report.tsv"}],
        )

        hr, ctx, raw = upload_attachment_command(_client(), dict(self.VALID_ARGS))

        assert "report.tsv" in hr
        assert ctx["IvantiHeat.Attachment"]["AttachmentId"] == "attach-id-1"
        assert ctx["IvantiHeat.Attachment"]["RecId"] == "REC-1"
        assert raw == [{"Message": "attach-id-1", "FileName": "report.tsv"}]
