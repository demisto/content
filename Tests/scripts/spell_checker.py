#!/usr/bin/env python3
import re
import sys
import yaml
import enchant
import argparse

from Tests.test_utils import print_error

ENGLISH = enchant.Dict("en_US")
DISPLAYABLE_LINES = [
    "description",
    "name",
    "display",
    "comment"
]


def is_displayable_line(line):
    for line_type in DISPLAYABLE_LINES:
        if re.match("(.*)?{}: .*".format(line_type), line):
            return True

    return False


def check_yaml(yml_info, unknown_words):
    for key, value in yml_info.items():
        if key in DISPLAYABLE_LINES:
            for word in value.split():
                if ENGLISH.check(word) is False and re.match('^[a-zA-Z ]*$', word):
                    unknown_words.add(word)

        else:
            if isinstance(value, dict):
                check_yaml(value, unknown_words)
            elif isinstance(value, list):
                for sub_list in value:
                    if isinstance(sub_list, dict):
                        check_yaml(sub_list, unknown_words)


def spell_checker():
    description = """Run spell check on a given yml file. """
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-p", "--path", help="Specify path of yml", required=True)

    args = parser.parse_args()
    with open(args.path, 'r') as yaml_file:
        yml_info = yaml.safe_load(yaml_file)

    unknown_words = set([])
    check_yaml(yml_info, unknown_words)

    if unknown_words:
        print_error(u"Found the problematic words:\n{}".format('\n'.join(unknown_words)))
        return 1

    print("No problematic words found")
    return 0


if __name__ == "__main__":
    sys.exit(spell_checker())
