import os

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import subprocess
from subprocess import Popen, PIPE
from typing import Dict, Any
import re
import tempfile
from pathlib import Path

WORDS_TEMP_DIR = 'words_temp_file.txt'
def create_rank_strings_args(args: dict) -> list:
    """
    Args:
        args (dict): Args given by Demisto
    Returns
        (list): A list of args for the rand_string commamd
    """
    limit = args.get('limit', '')
    args_rank_strings = list()
    args_rank_strings.append('rank_strings')
    args_rank_strings.append('--scores')
    if limit:
        args_rank_strings.append('--limit')
        args_rank_strings.append(limit)

    return args_rank_strings


def handle_words_as_string(string_input):
    seperated_words = re.split('\n| ', string_input)
    words_set = set()
    for word in seperated_words:
        if word and len(word) > 2:
            words_set.add(word)
    f = open(WORDS_TEMP_DIR, 'w')
    f.write('\n'.join(words_set))
    f.close()
    p = Path(os.getcwd(), WORDS_TEMP_DIR)
    return str(p)


def main():
    try:
        args = demisto.args()
        entry_id = args.get('entryID')
        string_text = args.get('string_text', '')

        if entry_id and string_text:
            raise ValueError('Use only one of the parameters entryID or string_text')
        if not entry_id and not string_text:
            raise ValueError('One of entryID of string_text must be specified')

        path = ''
        if entry_id:
            file_info = demisto.getFilePath(entry_id)
            path = file_info['path']
        else:
            path = handle_words_as_string(string_text)

        args_rank_strings = create_rank_strings_args(args)
        p1 = Popen(["flarestrings", path], stdout=PIPE)
        p2 = Popen(args_rank_strings, stdin=p1.stdout, stdout=PIPE)
        p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
        output = p2.communicate()[0]    # gets the stdout from the pipe.

        output_data = output.decode("utf-8")
        regex = r"(?P<rating>.*),(?P<word>.*)"
        min_score = args.get('min_score')
        words_rating_list = []
        for line in output_data.splitlines():
            matches = re.search(regex, line)
            # --min-score flag and --limit can't be used together added this implementation in the code
            if min_score and min_score > matches.group('rating'):
                break
            words_rating_list.append(
                {'rating': matches.group('rating'),
                 'word': matches.group('word')})

        readable = tableToMarkdown('Stringsifter word ranking based on their relevance for malware analysis.',
                                   words_rating_list)
        return CommandResults(readable_output=readable, outputs=words_rating_list, outputs_prefix='Stringsifter')
    except Exception as e:
        return_error(f'The script failed with the following error:\n {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
