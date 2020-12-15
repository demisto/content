import json
from ast import literal_eval
import functools
import urllib
from collections import OrderedDict
from os import path
from copy import deepcopy
from typing import List, Union
from mitmproxy import ctx, flow
from mitmproxy.http import HTTPRequest
from mitmproxy.script import concurrent
from mitmproxy.addons.serverplayback import ServerPlayback
from time import ctime
from dateparser import parse
import logging

logging.basicConfig(level=logging.DEBUG,
                    format='[%(asctime)s] - [%(funcName)s] - %(message)s')


def record_concurrently(replaying: bool = False):
    """
    A decorator to return a decorator that just executes the function it decorates normally if 'replaying' is true,
    (AKA mitmdump is executing in server-replay mode or reading in a mock file and cleaning it and saving the cleaned
    mock to a new file), otherwise pass the 'concurrent' decorator so that when mitmdump is executing in recording
    mode, that requests will be processed concurrently and not be blocking which can cause proxy errors during
    recording if multiple requests are made in a short timespan.

    Arguments:
        replaying (bool): True if timestamp replacer script is running in server playback mode or cleaning a mock file

    Returns:
        (function): decorator
    """
    logging.info(f'replaying={replaying}')
    if replaying:
        def nonconcurrent_decorator(func):
            @functools.wraps(func)
            def passthrough_wrapper(*args, **kwargs):
                value = func(*args, **kwargs)
                return value

            return passthrough_wrapper

        return nonconcurrent_decorator
    else:
        return concurrent


class TimestampReplacer:
    def __init__(self):
        self.count = 0
        self.constant = 'constant_value'
        self.json_keys = set()
        self.form_keys = set()
        self.query_keys = set()
        self.bad_keys_filepath = ''
        self.detect_timestamps = False

    def load(self, loader):
        loader.add_option(
            name='detect_timestamps',
            typespec=bool,
            default=False,
            help="""
            Set to True only if recording a mock file. Used to determine which keys need to be replaced in incoming
            request bodies during a mock playback.
            """
        )
        loader.add_option(
            name='keys_filepath',
            typespec=str,
            default='problematic_keys.json',  # disable-secrets-detection
            help="""
            The path to the file that contains the problematic keys for the test playbook recording that resides
            in the same directory.
            """
        )
        loader.add_option(
            name='script_mode',
            typespec=str,
            default='playback',
            help="""
            The mode that timestamp_replacer.py is being executed in. The options are 'record', 'clean', and
            'playback'. If no option is provided, defaults to 'playback'.
            """
        )
        loader.add_option(
            name='debug',
            typespec=bool,
            default=False,
            help="""
            Set to True to print out additional information for each request that comes in.
            """
        )

    def running(self):
        if ctx.options.debug:
            logging.info(f'ctx.options={ctx.options}')

        self.bad_keys_filepath = ctx.options.keys_filepath
        if ctx.options.detect_timestamps:
            logging.info('Detecting Timestamp Fields')
            self.detect_timestamps = True
        self.load_problematic_keys()

    def _debug_request(self, flow: flow.Flow) -> None:
        """Print details of the request"""
        req = flow.request
        logging.info(f'{req.method} {req.pretty_url}')
        _, _, path, _, query, _ = urllib.parse.urlparse(req.url)
        queriesArray = urllib.parse.parse_qsl(query, keep_blank_values=True)
        logging.info(f'queriesArray={queriesArray}')
        if req.multipart_form:
            logging.info(f'multipart_form data = {req.multipart_form.items()}')
        if req.urlencoded_form:
            logging.info(f'urlencoded_form data = {req.urlencoded_form.items()}')
        logging.info(f'hashed_data={ServerPlayback._hash(self, flow)}')

    # @record_concurrently(
    #     replaying=bool(
    #         ctx.options.server_replay or (ctx.options.rfile and ctx.options.save_stream_file)
    #     )
    # )
    def request(self, flow: flow.Flow) -> None:
        self.count += 1
        if ctx.options.debug:
            self._debug_request(flow)
        req = flow.request
        if ctx.options.script_mode == 'record':
            if ctx.options.detect_timestamps:
                self.run_all_key_detections(req)
                logging.info('updating problem_keys file at "{}"'.format(self.bad_keys_filepath))
                self.update_problem_keys_file()
        elif ctx.options.script_mode in {'clean', 'playback'}:
            logging.info(f'mode={ctx.options.script_mode} cleaning problematic key values from the request')
            self.clean_bad_keys(req)

    def clean_bad_keys(self, req: HTTPRequest) -> None:
        """Modify the request so that values of problematic keys are constant data

        Args:
            req (HTTPRequest): The request to modify
        """
        self.clean_url_query(req)
        self.clean_urlencoded_form(req)
        self.clean_multipart_form(req)
        self.clean_json_body(req)

    def clean_url_query(self, req: HTTPRequest) -> None:
        """Replace any problematic values of query parameters with constant data

        Args:
            req (HTTPRequest): The request to modify
        """
        query_data = req._get_query()
        logging.info('fetched query_data: {}'.format(query_data))
        updated_query_data = []
        if query_data and self.query_keys:
            for key, val in query_data:
                if key in self.query_keys:
                    updated_query_data.append((key, self.constant))
                else:
                    updated_query_data.append((key, val))
            req._set_query(updated_query_data)
            logging.info(f'updated query_data: {req._get_query()}')

    def clean_urlencoded_form(self, req: HTTPRequest) -> None:
        """Replace any problematic values of urlencoded form keys with constant data

        Args:
            req (HTTPRequest): The request to modify
        """
        if req.urlencoded_form and self.form_keys:
            updated_urlencoded_form_data = []
            for key, val in req.urlencoded_form.items(multi=True):
                if key in self.form_keys:
                    updated_urlencoded_form_data.append((key, self.constant))
                else:
                    updated_urlencoded_form_data.append((key, val))
            req._set_urlencoded_form(updated_urlencoded_form_data)

    def clean_multipart_form(self, req: HTTPRequest) -> None:
        """Replace any problematic values of multipart form keys with constant data

        Args:
            req (HTTPRequest): The request to modify
        """
        if req.multipart_form and self.form_keys:
            updated_multipart_form_data = []
            for key, val in req.multipart_form.items(multi=True):
                if key in self.form_keys:
                    updated_multipart_form_data.append((key, self.constant))
                else:
                    updated_multipart_form_data.append((key, val))
            req._set_multipart_form(updated_multipart_form_data)

    def clean_json_body(self, req: HTTPRequest) -> None:
        """Replace any problematic values of keys in the request's json body (if it has one)

        Args:
            req (HTTPRequest): The request to modify
        """
        if req.method == 'POST':
            raw_content = req.raw_content
            if raw_content is not None:
                try:
                    content = raw_content.decode()
                except UnicodeDecodeError:
                    logging.error('Failed to decode request content')
                    content = ''
            else:
                content = ''
            logging.info(f'cleaning json body: content={content}')
            json_data = content.startswith('{')
            if json_data:
                try:
                    content = OrderedDict(literal_eval(content))
                    self.modify_json_body(req, content)
                    return
                except Exception:
                    logging.exception(f'failed to run literal_eval on content {content}')
                try:
                    logging.info('parsing the request body with "literal_eval" failed - trying with "json.loads"')
                    content = json.loads(content, object_pairs_hook=OrderedDict)
                    self.modify_json_body(req, content)
                except Exception:
                    logging.exception(f'failed to run json.loads on content {content}')

    def modify_json_body(self, req: HTTPRequest, json_body: dict) -> None:
        """Modify the json body of a request by replacing any timestamp data with constant data

        Args:
            req (HTTPRequest): The request whose json body will be modified.
            json_body (dict): The request body to modify.
        """
        original_content = deepcopy(json_body)
        modified = False
        keys_to_replace = self.json_keys
        logging.info('{}'.format(keys_to_replace))
        for key_path in keys_to_replace:
            body = json_body
            keys = key_path.split('.')
            logging.info('keypath parts: {}'.format(keys))
            lastkey = keys[-1]
            logging.info('lastkey: {}'.format(lastkey))
            skip_key = False
            for k in keys[:-1]:
                if k in body:
                    body = body[k]
                elif isinstance(body, list) and k.isdigit():
                    if int(k) > len(body) - 1:
                        skip_key = True
                        break
                    body = body[int(k)]
                else:
                    skip_key = True
                    break
            if not skip_key:
                if lastkey in body:
                    logging.info('modifying request to "{}"'.format(req.pretty_url))
                    body[lastkey] = self.constant
                    modified = True
                elif isinstance(body, list) and lastkey.isdigit() and int(lastkey) <= len(body) - 1:
                    logging.info('modifying request to "{}"'.format(req.pretty_url))
                    body[int(lastkey)] = self.constant
                    modified = True
        if modified:
            logging.info('original request body:\n{}'.format(json.dumps(original_content, indent=4)))
            logging.info('modified request body:\n{}'.format(json.dumps(json_body, indent=4)))
            req.set_content(json.dumps(json_body).encode())

    def run_all_key_detections(self, req: HTTPRequest) -> None:
        """Used to detect problematic keys in
        1. request query parameters
        2. urlencoded forms parameters and multipart forms parameters
        3. json request body

        Args:
            req (HTTPRequest): The request to inspect for problematic keys
        """
        self.handle_url_query(req)
        self.handle_urlencoded_form(req)
        self.handle_multipart_form(req)
        self.handle_json_body(req)

    def handle_url_query(self, req: HTTPRequest) -> None:
        query_data = req._get_query()
        logging.info('query_data: {}'.format(query_data))
        for key, val in query_data:
            # don't bother trying to interpret an argument less than 4 characters as some type of timestamp
            if len(val) > 4:
                if self.safely_parse(val):
                    self.query_keys.add(key)

    def handle_multipart_form(self, req: HTTPRequest) -> None:
        """Used when detecting what keys in a multipart form to replace with constants.

        Args:
            req (HTTPRequest): The request to inspect
        """
        if req.multipart_form:
            for key, val in req.multipart_form.items(multi=True):
                # don't bother trying to interpret an argument less than 4 characters as some type of timestamp
                if len(val) > 4:
                    if self.safely_parse(val):
                        self.form_keys.add(key)

    def handle_urlencoded_form(self, req: HTTPRequest) -> None:
        """Used when detecting what keys in an url encoded parameters to replace with constants.

        Args:
            req (HTTPRequest): The request to inspect
        """
        if req.urlencoded_form:
            for key, val in req.urlencoded_form.items(multi=True):
                # don't bother trying to interpret an argument less than 4 characters as some type of timestamp
                if len(val) > 4:
                    if self.safely_parse(val):
                        self.form_keys.add(key)

    def handle_json_body(self, req: HTTPRequest) -> None:
        """Used when detecting what keys in a request's json body to replace with constants.

        Args:
            req (HTTPRequest): The request to inspect
        """
        if req.method == 'POST':
            raw_content = req.raw_content
            if raw_content is not None:
                try:
                    content = raw_content.decode()
                except UnicodeDecodeError:
                    logging.error('Failed to decode request content')
                    content = ''
            else:
                content = ''
            logging.info(f'handling json body: content={content}')
            json_data = content.startswith('{')
            if json_data:
                try:
                    content = OrderedDict(literal_eval(content))
                    json_keys = self.determine_problematic_keys(content)
                    self.json_keys.update(json_keys)
                    return
                except Exception:
                    logging.exception(f'failed to run literal_eval content: {content}')
                try:
                    logging.info('parsing the request body with "literal_eval" failed - trying with "json.loads"')
                    content = json.loads(content, object_pairs_hook=OrderedDict)
                    json_keys = self.determine_problematic_keys(content)
                    self.json_keys.update(json_keys)
                except Exception:
                    logging.exception(f'failed to run json.loads on content {content}')

    def determine_problematic_keys(self, content: dict) -> List[str]:
        """Given a json request body, return the keys (in dot notation) whose values are potentially timestamp data.

        Args:
            content (dict): The json request body to iterate through and find problematic timestamp data.

        Returns:
            List[str]: A list of keys (in dot notation, e.g. 'query.filter.time' is an example of what could be one
                problematic key) whose values are potentially timestamp data.
        """
        def travel_dict(obj: Union[dict, list], key_path='') -> List[str]:
            bad_key_paths = []
            if isinstance(obj, dict):
                for key, val in obj.items():
                    sub_key_path = '{}.{}'.format(key_path, key) if key_path else key
                    if isinstance(val, (list, dict)):
                        bad_key_paths.extend(travel_dict(val, sub_key_path))
                    else:
                        is_string = isinstance(val, str) and len(val) > 4
                        possible_timestamp = isinstance(val, (int, float)) and len(str(val)) >= 8
                        if is_string or possible_timestamp:
                            for_eval = val
                            if possible_timestamp:
                                if isinstance(for_eval, float):
                                    digits = str(val).split('.')
                                    for_eval = digits[0]
                                if len(str(for_eval)) < 13:
                                    parsed_date = self.safely_parse(ctime(val))
                                else:
                                    parsed_date = self.safely_parse(ctime(val / 1000.0))
                            else:
                                parsed_date = self.safely_parse(val)
                            # if parsed_date is not None then successfully interpreted value as some sort of
                            # time related thingieding
                            if parsed_date:
                                bad_key_paths.append(sub_key_path)
            elif isinstance(obj, list):
                for i, val in enumerate(obj):
                    sub_key_path = '{}.{}'.format(key_path, i) if key_path else i
                    if isinstance(val, (list, dict)):
                        bad_key_paths.extend(travel_dict(val, sub_key_path))
                    else:
                        is_string = isinstance(val, str) and len(val) > 4
                        possible_timestamp = isinstance(val, (int, float)) and len(str(val)) >= 8
                        if is_string or possible_timestamp:
                            for_eval = val
                            if possible_timestamp:
                                if isinstance(for_eval, float):
                                    digits = str(val).split('.')
                                    for_eval = digits[0]
                                if len(str(for_eval)) < 13:
                                    parsed_date = self.safely_parse(ctime(val))
                                else:
                                    parsed_date = self.safely_parse(ctime(val / 1000.0))
                            else:
                                parsed_date = self.safely_parse(val)
                            # if parsed_date is not None then successfully interpreted value as some sort of
                            # time related thingieding
                            if parsed_date:
                                bad_key_paths.append(sub_key_path)
            return bad_key_paths

        bad_keys = travel_dict(content)
        return bad_keys

    def update_problem_keys_file(self):
        """Update the problem keys dictionary at the keys_filepath with new problematic keys"""
        existing_problem_keys = self.read_in_problematic_keys()
        for key, val in existing_problem_keys.items():
            if key == 'keys_to_replace':
                existing_problem_keys[key] = ' '.join(set(val.split()).union(self.json_keys))
            elif key == 'server_replay_ignore_payload_params':
                existing_problem_keys[key] = ' '.join(set(val.split()).union(self.form_keys))
            elif key == 'server_replay_ignore_params':
                existing_problem_keys[key] = ' '.join(set(val.split()).union(self.query_keys))
        self.write_out_problematic_keys(existing_problem_keys)

    def read_in_problematic_keys(self):
        """Load problematic keys dictionary from the keys_filepath argument filepath in content-test-data repo
        if it exists. Otherwise, return the dictionary with empty values.
        """
        logging.info('executing "read_in_problematic_keys" method')
        repo_bad_keys_filepath = self.bad_keys_filepath.replace('/tmp/Mocks', 'content-test-data')
        logging.info('reading in problematic keys data from "{}"'.format(repo_bad_keys_filepath))
        if not path.exists(self.bad_keys_filepath) and path.exists(repo_bad_keys_filepath):
            with open(repo_bad_keys_filepath, 'r') as fp:
                problem_keys = json.load(fp)
        elif path.exists(self.bad_keys_filepath):
            with open(self.bad_keys_filepath, 'r') as fp:
                problem_keys = json.load(fp)
        else:
            problem_keys = {
                'keys_to_replace': '',
                'server_replay_ignore_params': '',
                'server_replay_ignore_payload_params': ''
            }
        return problem_keys

    def write_out_problematic_keys(self, problem_keys: dict):
        """Write updated problematic keys dictionary back to the file at the keys_filepath argument

        Args:
            problem_keys (dict): Updated dictionary of problematic keys
        """
        with open(self.bad_keys_filepath, 'w') as bad_keys_file:
            bad_keys_file.write(json.dumps(problem_keys, indent=4))

    def load_problematic_keys(self):
        """Load problematic keys from the keys_filepath argument filepath if it exists. Only necessary when running
        mitmdump in playback mode. Resets command line options with the key value pairs from the loaded dictionary.
        """
        logging.info('executing "load_problematic_keys" method')
        if path.exists(self.bad_keys_filepath):
            logging.info('"{}" path exists - loading bad keys'.format(self.bad_keys_filepath))

            problem_keys = json.load(open(self.bad_keys_filepath, 'r'))

            query_keys = problem_keys.get('server_replay_ignore_params')
            self.query_keys.update(query_keys.split() if isinstance(query_keys, str) else query_keys)
            form_keys = problem_keys.get('server_replay_ignore_payload_params')
            self.form_keys.update(form_keys.split() if isinstance(form_keys, str) else form_keys)
            json_keys = problem_keys.get('keys_to_replace')
            self.json_keys.update(json_keys.split() if isinstance(json_keys, str) else json_keys)

            logging.info('bad keys loaded\n---------------')
            logging.info(f'self.query_keys={self.query_keys}')
            logging.info(f'self.form_keys={self.form_keys}')
            logging.info(f'self.json_keys={self.json_keys}')
        else:
            logging.info('"{}" path doesn\'t exist - no bad keys to set'.format(self.bad_keys_filepath))
            logging.info('not setting bad keys from file')

    @staticmethod
    def safely_parse(val):
        """
        Safely tries to parse a value as a datetime object.
        If it fails - logs the error and the malformed output.
        Args:
            val: The val to parse

        Returns:
            True if the val was parsed to datetime object and False otherwise
        """
        try:
            if parse(val):
                return True
        except Exception:
            logging.exception(f'Failed to parse as date object: {val}')
        return False


# mitmproxy picks up the contents of the addons global list and loads what it finds into the addons mechanism.
addons = [TimestampReplacer()]
