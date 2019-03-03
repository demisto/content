#!/usr/bin/env python

import yaml
import argparse
from io import open

INTEGRATION = 'integration'
SCRIPT = 'script'


def extract_code(yml_path, output_path, demisto_mock, commonserver=None, yml_type=None):
    if not yml_type:
        if SCRIPT in yml_path.lower():
            yml_type = SCRIPT
        elif INTEGRATION in yml_path.lower():
            yml_type = INTEGRATION
        else:
            raise ValueError(
                'Could not auto determine yml type ({}/{}) based on path: {}'.format(SCRIPT, INTEGRATION, yml_path))
    if commonserver is None:
        commonserver = "CommonServerPython" not in yml_path
    with open(yml_path, 'rb') as yml_file:
        yml_data = yaml.safe_load(yml_file)
        script = yml_data['script']
        if yml_type == INTEGRATION:  # in integration the script is stored at a second level
            script = script['script']
        if type(script) == str:  # pyyaml may return either a unicode or str depending upon the content of script
            script = unicode(script)
    with open(output_path, 'w', encoding='utf-8') as code_file:
        if demisto_mock:
            code_file.write(u"import demistomock as demisto\n")
        if commonserver:
            code_file.write(u"from CommonServerPython import *\n")
        code_file.write(script)
        if script[-1] != u'\n':  # make sure files end with a new line (pyml seems to strip the last newline)
            code_file.write(u"\n")


def str2bool(val):
    return val.lower() in {'yes', 'true', 't', '1', 'y'}


def main():
    parser = argparse.ArgumentParser(description='Extract code file from a demmisto integration or script yaml file',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-i", "--infile", help="The yml file to extract from", required=True)
    parser.add_argument("-o", "--outfile", help="The output file to write the code to", required=True)
    parser.add_argument("-t", "--type", help="Yaml type. If not specified will try to determine type based upon path.",
                        choices=[SCRIPT, INTEGRATION], default=None)
    parser.add_argument("-d", "--demistomock", help="Add an import for demisto mock",
                        choices=[True, False], type=str2bool, default=True)
    parser.add_argument("-c", "--commonserver",
                        help=("Add an import for CommonServerPython."
                              + " If not specified will import unless this is CommonServerPython"),
                        choices=[True, False], type=str2bool, default=None)
    args = parser.parse_args()
    extract_code(args.infile, args.outfile, args.demistomock, args.commonserver, args.type)


if __name__ == "__main__":
    main()
