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
    pass


def generate_release_notes_summary():
    pass

