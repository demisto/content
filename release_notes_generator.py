from __future__ import print_function
import os
import re
import sys
import abc
import json
import datetime
import argparse
import requests
import yaml

from demisto_sdk.commands.common.constants import INTEGRATIONS_DIR, SCRIPTS_DIR, PLAYBOOKS_DIR, REPORTS_DIR, \
    DASHBOARDS_DIR, WIDGETS_DIR, INCIDENT_FIELDS_DIR, LAYOUTS_DIR, CLASSIFIERS_DIR, INDICATOR_TYPES_DIR
from demisto_sdk.commands.common.tools import print_error, print_warning, get_last_release_version, \
    filter_packagify_changes, is_file_path_in_pack, \
    run_command, server_version_compare, old_get_release_notes_file_path, old_get_latest_release_notes_text, get_remote_file
from demisto_sdk.commands.validate.file_validator import FilesValidator


def get_all_modified_release_note_files():
    try:
        change_log = run_command('git diff --name-only {} \'*/ReleaseNotes/*.md\''.format(args.git_sha1), exit_on_error=False)
    except RuntimeError:
        print_error('Unable to get the SHA1 of the commit in which the version was released. This can happen if your '
                    'branch is not updated with origin master. Merge from origin master and, try again.\n'
                    'If you\'re not on a fork, run "git merge origin/master".\n'
                    'If you are on a fork, first set https://github.com/demisto/content to be '
                    'your upstream by running "git remote add upstream https://github.com/demisto/content". After '
                    'setting the upstream, run "git fetch upstream", and then run "git merge upstream/master". Doing '
                    'these steps will merge your branch with content master as a base.')
        sys.exit(1)


def generate_release_notes_summary():
    pass

