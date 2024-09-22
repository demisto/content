import demistomock as demisto
from SekoiaXDRChangeStatus import main  # type: ignore


def test_main(mocker):
    mocker.patch.object(
        demisto,
        "args",
        return_value={"short_id": "1", "status": "Ongoing"},
    )
    mocker.patch.object(demisto, "results")
    main()
    assert (
        demisto.results.call_args[0][0]["Contents"]
        == "### Status of the alert changed to:\n Ongoing"
    )
