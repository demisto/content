import json

import demistomock as demisto
from WidgetNoOp import main


def test_main(mocker):
    """Test that the no-op script runs without error and returns a single space string."""
    # Given
    mocker.patch.object(demisto, "results")

    # When
    main()

    # Then
    expected_groups = [{"name": "", "data": [], "color": "", "groups": []}]
    demisto.results.assert_called_once_with({
        "Type": 1,
        "ContentsFormat": "json",
        "Contents": json.dumps(expected_groups)
    })
