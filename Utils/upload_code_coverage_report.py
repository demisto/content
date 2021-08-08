
from datetime import datetime
import json
import os

from typing import Dict


def create_minimal_report(source_file: str, destination_file: str):
    with open(source_file, 'r') as cov_util_output:
        data = json.load(cov_util_output)

    # TODO Check that we were able to read the json report corretly

    minimal_coverage_contents_files: Dict[str, float] = {}
    for current_file_name in data.get('files').keys():
        minimal_coverage_contents_files[current_file_name] = data['files'][current_file_name]['summary']['percent_covered']
    minimal_coverage_contents: Dict[str, any] = {}
    minimal_coverage_contents['files'] = minimal_coverage_contents_files
    minimal_coverage_contents['last_updated'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')
    with open(destination_file, 'w') as minimal_output:
        minimal_output.write(json.dumps(minimal_coverage_contents))


def upload_code_cov_report():
    # TODO Implement
    pass
