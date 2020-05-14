#!/usr/bin/env python3
import sys
import yaml
import argparse

from spellchecker import SpellChecker

from demisto_sdk.commands.common.tools import print_error

DISPLAYABLE_LINES = [
    "description",
    "name",
    "display",
    "comment"
]

SCRIPT_ARGS = 'scriptarguments'


def check_yaml(spellchecker, yml_info, unknown_words):
    for key, value in yml_info.items():
        if key in DISPLAYABLE_LINES and isinstance(value, str):
            for word in value.split():
                if word.isalpha() and spellchecker.unknown([word]):
                    unknown_words.add(word)

        else:
            if isinstance(value, dict):
                if key != SCRIPT_ARGS:
                    check_yaml(spellchecker, value, unknown_words)
            elif isinstance(value, list):
                for sub_list in value:
                    if isinstance(sub_list, dict):
                        check_yaml(spellchecker, sub_list, unknown_words)


def check_md_file(spellchecker, md_data, unknown_words):
    for line in md_data:
        for word in line.split():
            if word.isalpha() and spellchecker.unknown([word]):
                unknown_words.add(word)


def spell_checker(path, is_md=False):
    unknown_words = set([])
    spellchecker = SpellChecker()
    spellchecker.word_frequency.load_text_file('Tests/known_words.txt')

    if is_md:
        with open(path, 'r') as md_file:
            md_data = md_file.readlines()

        check_md_file(spellchecker, md_data, unknown_words)
    else:
        with open(path, 'r') as yaml_file:
            yml_info = yaml.safe_load(yaml_file)

        check_yaml(spellchecker, yml_info, unknown_words)

    if unknown_words:
        print_error(u"Found the problematic words:\n{}".format('\n'.join(unknown_words)))
        return 1

    print("No problematic words found")
    return 0


if __name__ == "__main__":
    description = """Run spell check on a given yml/md file. """
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-p", "--path", help="Specify path of yml/md file", required=True)
    parser.add_argument("-i", "--isMD", help="Whether the path is to a yml file or an md.", action='store_true')

    args = parser.parse_args()
    sys.exit(spell_checker(args.path, args.isMD))
