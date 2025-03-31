import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import os
import zipfile
import tempfile


def main() -> None:
    """
    Main function that extracts a zip file, processes each .yml file except those starting with '__' or '.',
    and creates XSOAR Sigma rule indicators using the content of these files.
    """

    num_of_rules = 0

    try:
        # Retrieve the entry ID from the arguments
        entry_id = demisto.args().get('entry_id')

        if not entry_id:
            return_error("Missing 'entry_id' argument.")

        # Get the file path from the entry ID
        file_info = demisto.getFilePath(entry_id)

        if not file_info:
            return_error(f"File with entry ID {entry_id} not found.")

        file_path = file_info['path']

        # Create a temporary directory
        temp_dir = tempfile.mkdtemp()

        # Extract zip file to the temp directory
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            demisto.debug(f'SGM: Attempting to unzip {file_path} and extract files')
            zip_ref.extractall(temp_dir)
            total_files = len(zip_ref.namelist())

        # Iterate over the files in the temp directory
        for root, _, files in os.walk(temp_dir):
            for file_name in files:
                # Skip files that are not .yml or start with '__' or '.'
                if not file_name.endswith('.yml') or file_name.startswith(('__', '.')):
                    demisto.debug(f'SGM: Skipping file "{file_name}" as it is not a Sigma file')
                    continue

                num_of_rules += 1
                file_path = os.path.join(root, file_name)

                demisto.debug(f'SGM: Opening file "{file_name} ({num_of_rules}/{len(files)})"')

                # Read file contents
                with open(file_path) as file:
                    file_contents = file.read()

                try:
                    # Execute command to create Sigma rule indicator
                    demisto.debug(f'SGM: creating sigma rule for {file_name}')
                    demisto.executeCommand('CreateSigmaRuleIndicator', {"sigma_rule_str": file_contents})

                except Exception as e:
                    demisto.error(f'Error creating Sigma: {e}')

                # Log progress every 10 files
                if num_of_rules % 100 == 0:
                    demisto.debug(f'{num_of_rules}/{total_files}')

    except Exception as e:
        demisto.error(str(e))
        return_error(f"Failed to process zip file. Error: {str(e)}")

    return_results(f"Done, Created {num_of_rules} Rules")


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
