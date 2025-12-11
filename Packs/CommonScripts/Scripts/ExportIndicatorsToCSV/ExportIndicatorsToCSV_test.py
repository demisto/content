import demistomock as demisto
from ExportIndicatorsToCSV import main


def test_main(mocker):
    mocker.patch.object(demisto, "args", return_value={"query": "html", "seenDays": "6", "columns": "id,name"})
    mocker.patch.object(demisto, "results", return_value={})

    # Mock the first internalHttpRequest call (POST to create CSV)
    post_response = {"statusCode": 200, "body": '"test-file-id"'}

    # Mock the second internalHttpRequest call (GET to download CSV)
    get_response = {"statusCode": 200, "body": "id,name\n1,test"}

    # Create a side effect that returns different values for each call
    internal_http_mock = mocker.patch.object(demisto, "internalHttpRequest", side_effect=[post_response, get_response])

    main()

    # Verify the POST request was made with correct columns
    assert internal_http_mock.call_count == 2
    first_call_kwargs = internal_http_mock.call_args_list[0][1]
    assert first_call_kwargs["method"] == "POST"
    assert first_call_kwargs["uri"] == "/indicators/batch/exportToCsv"
    assert first_call_kwargs["body"]["columns"] == ["id", "name"]
