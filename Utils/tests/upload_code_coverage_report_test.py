from ruamel import yaml
import os
from Utils.upload_code_coverage_report import create_minimal_report


def test_create_minimal_report(tmpdir):
    source_file = "./TestData/coverage.json"
    destination_file = tmpdir.join("coverage_generated.json")

    try:
        success, last_updated = create_minimal_report(source_file=source_file, destination_file=destination_file)
        assert success
        assert '2021-08-10T11:37:35Z' == last_updated

        destination_file_contents = yaml.safe_load(open(destination_file))

        files = destination_file_contents.get('files')
        assert 2 == len(files)
        assert 75.33 == files.get('Packs/MyPack1/Integrations/MyIntegration/integration.py')
        assert 73.4 == files.get('Packs/MyPack2/Integrations/MyIntegration/integration.py')
        assert 59.310801855 == destination_file_contents.get('total_coverage')
        assert '2021-08-10T11:37:35Z' == destination_file_contents.get('last_updated')

    finally:
        if os.path.isfile(destination_file):
            os.remove(destination_file)
