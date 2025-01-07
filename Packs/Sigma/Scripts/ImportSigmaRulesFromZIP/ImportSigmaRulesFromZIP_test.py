from unittest.mock import patch, MagicMock
import tempfile
import os
import zipfile

from ImportSigmaRulesFromZIP import main
import ImportSigmaRulesFromZIP

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


@patch.object(ImportSigmaRulesFromZIP, "return_results")
@patch('ImportSigmaRulesFromZIP.demisto')
def test_main(mock_demisto, mock_return_results):
    # Create a temporary directory to hold the test files
    temp_dir = tempfile.mkdtemp()

    # Create a temporary zip file
    zip_file_path = os.path.join(temp_dir, "test.zip")
    with zipfile.ZipFile(zip_file_path, "w") as zipf:
        # Add test YAML file
        test_yml_path = os.path.join(temp_dir, "test.yml")
        with open(test_yml_path, "w") as f:
            f.write("dummy sigma rule content")
        zipf.write(test_yml_path, os.path.basename(test_yml_path))

    # Mock the demisto args and file path retrieval
    mock_demisto.args.return_value = {"entry_id": "123"}
    mock_demisto.getFilePath.return_value = {"path": zip_file_path}

    # Mock demisto.debug(), demisto.error(), demisto.results(), and demisto.executeCommand() methods
    mock_demisto.debug = MagicMock()
    mock_demisto.error = MagicMock()
    mock_demisto.executeCommand = MagicMock()

    # Call the main function
    main()

    # Assert that a Sigma rule was created
    mock_demisto.executeCommand.assert_called_with("CreateSigmaRuleIndicator", {"sigma_rule_str": "dummy sigma rule content"})

    # Assert that results were returned
    mock_return_results.call_args.assert_called_with("Done, Created 1 Rules")
