import json

import demistomock as demisto
from WidgetNoOp import main


def test_main(mocker):
    """
    Given:
        - No input arguments (no-op script).
    When:
        - Running the main function.
    Then:
        - Ensure demisto.results is called once with the expected no-op payload.
    """
    # Given
    mocker.patch.object(demisto, "results")

    # When
    main()

    # Then
    expected_groups = [{"name": "", "data": [], "color": "", "groups": []}]
    demisto.results.assert_called_once_with({"Type": 1, "ContentsFormat": "json", "Contents": json.dumps(expected_groups)})
