"""Structure Validator for Demisto files

Module contains validation of schemas, ids and paths.
"""
import json
import os
import re
import sys
from typing import Optional

import yaml

from Tests.scripts.constants import YML_INTEGRATION_REGEXES, YML_SCRIPT_REGEXES, JSON_ALL_WIDGETS_REGEXES, \
    JSON_ALL_DASHBOARDS_REGEXES, JSON_ALL_CONNECTIONS_REGEXES, JSON_ALL_CLASSIFIER_REGEXES, \
    JSON_ALL_LAYOUT_REGEXES, JSON_ALL_INCIDENT_FIELD_REGEXES, YML_ALL_PLAYBOOKS_REGEX, JSON_ALL_REPORTS_REGEXES, \
    MISC_REGEX, MISC_REPUTATIONS_REGEX, Errors
from Tests.test_utils import print_error, get_matching_regex, get_remote_file

try:
    from pykwalify.core import Core
    from pykwalify.errors import SchemaError
except ImportError:
    print('Please install pykwalify, you can do it by running: `pip install -I pykwalify`')
    sys.exit(1)


class StructureValidator(object):
    """Structure validator is designed to validate the correctness of the file structure we enter to content repo.

        Attributes:
            file_path (str): the path to the file we are examining at the moment.
            is_valid (bool): the attribute which saves the valid/in-valid status of the current file. will be bool only
                             after running is_file_valid.
            scheme_name (str): Name of the yaml scheme need to validate.
            file_type (str): equal to scheme_name if there's a scheme.
            current_file (dict): loaded json.
            old_file: (dict) loaded file from git.
        """
    SCHEMAS_PATH = "Tests/schemas/"

    FILE_SUFFIX_TO_LOAD_FUNCTION = {
        '.yml': yaml.safe_load,
        '.json': json.load,
    }
    SCHEMA_TO_REGEX = {
        'integration': YML_INTEGRATION_REGEXES,
        'playbook': YML_ALL_PLAYBOOKS_REGEX,
        'script': YML_SCRIPT_REGEXES,
        'widget': JSON_ALL_WIDGETS_REGEXES,
        'dashboard': JSON_ALL_DASHBOARDS_REGEXES,
        'canvas-context-connections': JSON_ALL_CONNECTIONS_REGEXES,
        'classifier': JSON_ALL_CLASSIFIER_REGEXES,
        'layout': JSON_ALL_LAYOUT_REGEXES,
        'incidentfield': JSON_ALL_INCIDENT_FIELD_REGEXES,
    }

    PATHS_TO_VALIDATE = {
        'reports': JSON_ALL_REPORTS_REGEXES,
        'reputation': [MISC_REPUTATIONS_REGEX],
        'reputations': [MISC_REGEX]
    }

    def __init__(self, file_path, old_file_path=None):
        # type: (str, Optional[str]) -> None
        self.is_valid = None  # type: Optional[bool]
        self.file_path = file_path
        self.scheme_name = self.scheme_of_file_by_path()
        self.file_type = self.get_file_type()
        self.current_file = self.load_data_from_file()
        self.old_file = get_remote_file(old_file_path) if old_file_path else None

    def is_valid_file(self):
        # type: () -> bool
        """Checks if given file is valid

        Returns:
            (bool): Is file is valid
        """
        answers = [
            self.is_valid_file_path(),
            self.is_valid_scheme(),
            self.is_file_id_without_slashes(),
        ]

        if not self.old_file:  # In case the file is modified
            answers.append(not self.is_id_modified())
            answers.append(self.is_valid_fromversion_on_modified())
        return all(answers)

    def scheme_of_file_by_path(self):
        # type:  () -> Optional[str]
        """Running on given regexes from `constants` to find out what type of file it is

        Returns:
            (str): Type of file by scheme name
        """
        for scheme_name, regex_list in self.SCHEMA_TO_REGEX.items():
            if get_matching_regex(self.file_path, regex_list):
                return scheme_name
        return None

    def is_valid_scheme(self):
        # type: () -> bool
        """Validate the file scheme according to the scheme we have saved in SCHEMAS_PATH.

        Returns:
            bool. Whether the scheme is valid on self.file_path.
        """
        if self.scheme_name is None:
            return True
        core = Core(source_file=self.file_path,
                    schema_files=[os.path.join(self.SCHEMAS_PATH, '{}.yml'.format(self.scheme_name))])
        try:
            core.validate(raise_exception=True)
        except SchemaError as err:
            print_error('Failed: {} failed.\n{}'.format(self.file_path, str(err)))
            self.is_valid = False
            return False
        return True

    @staticmethod
    def get_file_id_from_loaded_file_data(loaded_file_data):
        # type: (dict) -> Optional[str]
        """Gets a dict and extracting its `id` field

        Args:
            loaded_file_data: Data to find dict

        Returns:
            (str or None): file ID if exists.
        """
        try:
            file_id = loaded_file_data.get('id')
            if not file_id:
                # In integrations/scripts, the id is under 'commonfields'.
                file_id = loaded_file_data.get('commonfields', {}).get('id')
            if not file_id:
                # In layout, the id is under 'layout'.
                file_id = loaded_file_data.get('layout', {}).get('id')
            return file_id
        except AttributeError:
            return None

    def is_file_id_without_slashes(self):
        # type: () -> bool
        """Check if the ID of the file contains any slashes ('/').

        Returns:
            bool. Whether the file's ID contains slashes or not.
        """
        file_id = self.get_file_id_from_loaded_file_data(self.current_file)
        if file_id and '/' in file_id:
            self.is_valid = False
            print_error(Errors.file_id_contains_slashes())
            return False
        return True

    def is_id_modified(self):
        # type: () -> bool
        """Check if the ID of the file has been changed.


        Returns:
            (bool): Whether the file's ID has been modified or not.
        """
        if not self.old_file:
            return False

        old_version_id = self.get_file_id_from_loaded_file_data(self.old_file)
        new_file_id = self.get_file_id_from_loaded_file_data(self.current_file)
        return not (new_file_id == old_version_id)

    def is_valid_fromversion_on_modified(self):
        # type: () -> bool
        """Check that the fromversion property was not changed on existing Content files.

        Returns:
            (bool): Whether the files' fromversion as been modified or not.
        """
        if not self.old_file:
            return True

        from_version_new = self.current_file.get("fromversion") or self.current_file.get("fromVersion")
        from_version_old = self.old_file.get("fromversion") or self.old_file.get("fromVersion")

        if from_version_old != from_version_new:
            print_error(Errors.from_version_modified(self.file_path))
            self.is_valid = False
            return False
        return True

    def load_data_from_file(self):
        # type: () -> dict
        """Loads data according to function defined in FILE_SUFFIX_TO_LOAD_FUNCTION
        Returns:
             (dict)
        """
        file_extension = os.path.splitext(self.file_path)[1]
        if file_extension not in self.FILE_SUFFIX_TO_LOAD_FUNCTION:
            print_error(Errors.wrong_file_extension(file_extension, self.FILE_SUFFIX_TO_LOAD_FUNCTION.keys()))
        load_function = self.FILE_SUFFIX_TO_LOAD_FUNCTION[file_extension]
        with open(self.file_path, 'r') as file_obj:
            loaded_file_data = load_function(file_obj)  # type: ignore
            return loaded_file_data

    def get_file_type(self):
        # type: () -> Optional[str]
        """Gets file type based on regex or scheme_name

        Returns:
            str if valid filepath, else None
        """
        # If scheme_name exists, already found that the file is in the right path
        if self.scheme_name:
            return self.scheme_name
        for file_type, regexes in self.PATHS_TO_VALIDATE.items():
            for regex in regexes:
                if re.search(regex, self.file_path, re.IGNORECASE):
                    return file_type
        self.is_valid = False
        print_error(Errors.wrong_path(self.file_path))
        return None

    def is_valid_file_path(self):
        """Returns is valid filepath exists.
        Can be only if file_type or scheme_name exists (runs from init)

        Returns:
            True if valid file path else False
        """
        return bool(self.scheme_name or self.file_type)
