import demistomock as demisto
from CommonServerPython import *  # noqa: F401
import pytest
import pytest_mock
import os
import io
import bottle
import json
import base64
import zipfile
import importlib
import uuid
import copy
import random
import math
import string
import urllib.parse
import WebFileRepository
import freezegun
from typing import Any


def equals_object(obj1, obj2) -> bool:
    if type(obj1) is not type(obj2):
        return False
    elif isinstance(obj1, dict):
        for k1, v1 in obj1.items():
            if k1 not in obj2:
                return False
            if not equals_object(v1, obj2[k1]):
                return False
        return not (set(obj1.keys()) ^ set(obj2.keys()))
    elif isinstance(obj1, list):
        # Compare lists (ignore order)
        list2 = list(obj2)
        for _i1, v1 in enumerate(obj1):
            for i2, v2 in enumerate(list2):
                if equals_object(v1, v2):
                    list2.pop(i2)
                    break
            else:
                return False
        return not list2
    else:
        return obj1 == obj2


class MockIntegrationContext:
    @staticmethod
    def encode_values(ctx: dict[str, Any]) -> dict[str, str]:
        return {
            k: json.dumps(v) if k.startswith(os.sep) and not isinstance(v, str) else v
            for k, v in ctx.items()
        }

    @staticmethod
    def decode_values(ctx: dict[str, Any]) -> dict[str, Any]:
        return {
            k: json.loads(v) if k.startswith(os.sep) and isinstance(v, str) else v
            for k, v in ctx.items()
        }

    def __init__(self,
                 ctx: dict[str, Any],
                 mocker: Optional[pytest_mock.plugin.MockerFixture] = None):
        self.__ctx = MockIntegrationContext.encode_values(ctx)
        if mocker:
            mocker.patch('WebFileRepository.get_integration_context',
                         side_effect=self.get_integration_context)
            mocker.patch('WebFileRepository.set_integration_context',
                         side_effect=self.set_integration_context)

    def get_integration_context(self) -> dict[str, str]:
        return copy.deepcopy(self.__ctx)

    def set_integration_context(self, ctx: dict[str, str]):
        self.__ctx = copy.deepcopy(ctx)

    def equals(self, ctx: dict[str, Any]) -> bool:
        return equals_object(MockIntegrationContext.decode_values(self.__ctx),
                             MockIntegrationContext.decode_values(ctx))

    def print(self) -> None:
        print(json.dumps(MockIntegrationContext.decode_values(self.__ctx), indent=2))


class MockUUID:
    def __init__(self,
                 mocker: pytest_mock.plugin.MockerFixture):
        self.__count = 0
        mocker.patch('uuid.uuid4', side_effect=self.uuid4)

    def uuid4(self) -> uuid.UUID:
        u = uuid.UUID(int=self.__count)
        self.__count += 1
        return u


class MockBaseClient:
    def __init__(self,
                 mocker: pytest_mock.plugin.MockerFixture,
                 headers: dict[str, str],
                 content: bytes = None,
                 json_data: Any = None):
        self.__headers = headers
        self.__content = json.dumps(json_data).encode() if content is None else content
        mocker.patch('CommonServerPython.BaseClient._http_request', side_effect=self._http_request)

    def _http_request(self, method, url_suffix='', full_url=None, headers=None, auth=None, json_data=None,
                      params=None, data=None, files=None, timeout=None, resp_type='json', ok_codes=None,
                      return_empty_response=False, retries=0, status_list_to_retry=None,
                      backoff_factor=5, raise_on_redirect=False, raise_on_status=False,
                      error_handler=None, empty_valid_codes=None, **kwargs):

        class MockRequestsResponse:
            def __init__(self, headers: dict[str, str], content: bytes):
                self.headers = headers
                self.content = content

            def json(self):
                return json.loads(self.content.decode())

        if resp_type == 'json':
            return json.loads(self.__content.decode())
        elif resp_type == 'json':
            return self.__content
        else:
            return MockRequestsResponse(headers=self.__headers,
                                        content=self.__content)


def MockFileResult(filename, data, file_type=None):
    if file_type is None:
        file_type = entryTypes['file']
    return {'Contents': '',
            'ContentsFormat': formats['text'],
            'Type': file_type,
            'File': filename,
            'FileID': 'fileid'}


@pytest.mark.parametrize(argnames='filename, content_type',
                         argvalues=[
                             ('datatables.min.css', 'text/css'),
                             ('datatables.min.js', 'text/javascript'),
                             ('fi_file.png', 'image/png'),
                             ('fi_folder.png', 'image/png'),
                             ('fi_parent.png', 'image/png'),
                             ('fi_unknown.png', 'image/png'),
                         ])
def test_process_root_get_resource(mocker, filename, content_type):
    """
        Given:
            A resource file to get

        When:
            Running script to get a resource file.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'longRunningPort': '8000',
        'rwCredentials': {},
        'roCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    })
    importlib.reload(WebFileRepository)

    bottle.request = bottle.LocalRequest()
    bottle.request.query.q = 'resource'
    bottle.request.query.name = filename
    response = WebFileRepository.process_root_get()
    assert response.status_code == 200
    assert response.content_type == content_type


@pytest.mark.parametrize(argnames='integration_context_filename, '
                                  'storage_protection, '
                                  'max_storage_size, '
                                  'max_sandbox_size, '
                                  'sandbox_usage, '
                                  'storage_usage',
                         argvalues=[
                             ('./test_data/integration_ctx_empty.json',
                              'read/write',
                              '10000',
                              '100000',
                              0,
                              0
                              )
                         ])
def test_process_root_get_status(mocker,
                                 integration_context_filename,
                                 storage_protection,
                                 max_storage_size,
                                 max_sandbox_size,
                                 sandbox_usage,
                                 storage_usage):
    """
        Given:
            The repository and status parameters

        When:
            Running script to list files in the repository.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': storage_protection,
        'maxStorageSize': max_storage_size,
        'maxSandboxSize': max_sandbox_size,
    })
    importlib.reload(WebFileRepository)

    with open(integration_context_filename) as f:
        MockIntegrationContext(json.load(f), mocker)

    bottle.request = bottle.LocalRequest()
    bottle.request.query.q = 'status'
    response = WebFileRepository.process_root_get()
    assert response.status_code == 200
    status = response.body
    assert status['storage_protection'] == storage_protection
    assert status['max_storage_size'] == int(max_storage_size)
    assert status['max_sandbox_size'] == int(max_sandbox_size)
    assert status['sandbox_usage'] == sandbox_usage
    assert status['storage_usage'] == storage_usage


@pytest.mark.parametrize(argnames='integration_context_filename, dir_name, recursive, output_filename',
                         argvalues=[
                             ('./test_data/integration_ctx_empty.json', '/', False, './test_data/ls_out_01.json'),
                             ('./test_data/integration_ctx_common.json', '/', False, './test_data/ls_out_02.json'),
                             ('./test_data/integration_ctx_common.json', '/', True, './test_data/ls_out_03.json'),
                             ('./test_data/integration_ctx_common.json', '/x', False, './test_data/ls_out_04.json'),
                             ('./test_data/integration_ctx_common.json', '/x/あいうえお', False, './test_data/ls_out_05.json'),
                             ('./test_data/integration_ctx_common.json', '/x/あいうえお', False, './test_data/ls_out_05.json'),
                             ('./test_data/integration_ctx_common.json', '/not-found', False, './test_data/ls_out_06.json'),
                         ])
def test_process_root_get_ls(mocker, integration_context_filename, dir_name, recursive, output_filename):
    """
        Given:
            The repository and name of a directory

        When:
            Running script to list files in the repository.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    })
    importlib.reload(WebFileRepository)

    with open(integration_context_filename) as f:
        MockIntegrationContext(json.load(f), mocker)

    with open(output_filename) as f:
        expected = json.load(f)

    bottle.request = bottle.LocalRequest()
    bottle.request.query.q = 'ls'
    bottle.request.query.dir = dir_name
    bottle.request.query.recursive = 'true' if recursive else 'false'
    response = WebFileRepository.process_root_get()
    assert response.status_code == 200
    assert equals_object(response.body, expected)


@pytest.mark.parametrize(
    argnames="integration_context_filename, path, output_filename",
    argvalues=[
        (
            "./test_data/integration_ctx_common.json",
            "/a.dat",
            "./test_data/download_out_01.dat",
        ),
        (
            "./test_data/integration_ctx_common.json",
            "/x/XYZ/アイウエオ.txt",
            "./test_data/download_out_02.dat",
        ),
    ],
)
def test_process_root_get_download(mocker, integration_context_filename, path, output_filename):
    """
        Given:
            The repository and a file path to download

        When:
            Running script to download the file.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    })
    importlib.reload(WebFileRepository)

    with open(integration_context_filename) as f:
        MockIntegrationContext(json.load(f), mocker)

    bottle.request = bottle.LocalRequest()
    bottle.request.query.q = 'download'
    bottle.request.query.path = path
    response = WebFileRepository.process_root_get()

    assert response.status_code == 200
    with open(output_filename, 'rb') as f:
        assert f.read() == b''.join(response.body)


@pytest.mark.parametrize(argnames='integration_context_filename, path',
                         argvalues=[
                             ('./test_data/integration_ctx_common.json', '/zzz.dat'),
                         ])
def test_process_root_get_download_not_found(mocker, integration_context_filename, path):
    """
        Given:
            The repository and a file path doesn't exist

        When:
            Running script to download the file.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    })
    importlib.reload(WebFileRepository)

    with open(integration_context_filename) as f:
        MockIntegrationContext(json.load(f), mocker)

    bottle.request = bottle.LocalRequest()
    bottle.request.query.q = 'download'
    bottle.request.query.path = path

    with pytest.raises(bottle.HTTPError, match='.*404.*'):
        WebFileRepository.process_root_get()


@pytest.mark.parametrize(argnames='integration_context_filename, filenames',
                         argvalues=[
                             ('./test_data/integration_ctx_common.json',
                              [
                                  'a.dat',
                                  'b.dat',
                                  'c.dat',
                                  'x/XYZ/アイウエオ.txt',
                                  'x/d.dat',
                                  'x/あいうえお/e.dat',
                                  'x/あいうえお/f.dat',
                                  'y/g.dat',
                                  'z.dat',
                              ]
                              ),
                         ])
def test_process_root_get_archive_zip(mocker, integration_context_filename, filenames):
    """
        Given:
            The repository

        When:
            Running script to archive files.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    })
    importlib.reload(WebFileRepository)

    with open(integration_context_filename) as f:
        integration_context = MockIntegrationContext(json.load(f), mocker)
        ctx = integration_context.get_integration_context()

    bottle.request = bottle.LocalRequest()
    bottle.request.query.q = 'archive-all'
    response = WebFileRepository.process_root_get()

    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(b''.join(response.body)), 'r') as z:
        for filename in filenames:
            attrs = json.loads(ctx.get(os.sep + filename))
            assert attrs['size'] == len(z.read(filename))


def test_process_root_get_html_main(mocker):
    """
        Given:
            No query parameters to get

        When:
            Running script to get the main html.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    })
    importlib.reload(WebFileRepository)

    bottle.request = bottle.LocalRequest()
    response = WebFileRepository.process_root_get()

    assert response.status_code == 200
    assert response.body == WebFileRepository.HTML_MAIN


@pytest.mark.parametrize(argnames='integration_context_filename, '
                                  'storage_protection, '
                                  'user_permission, '
                                  'request_permission, '
                                  'ok',
                         argvalues=[
                             ('./test_data/integration_ctx_common.json',
                              'read/write',
                              'read/write',
                              'write',
                              True,
                              ),
                             ('./test_data/integration_ctx_common.json',
                              'read/write',
                              'read',
                              'write',
                              False,
                              ),
                             ('./test_data/integration_ctx_common.json',
                              'read-only',
                              'read',
                              'read',
                              True,
                              ),
                             ('./test_data/integration_ctx_common.json',
                              'read-only',
                              None,
                              'read',
                              False,
                              ),
                             ('./test_data/integration_ctx_common.json',
                              'sandbox',
                              'read/write',
                              'write',
                              True,
                              ),
                             ('./test_data/integration_ctx_common.json',
                              'sandbox',
                              None,
                              'read',
                              False,
                              ),
                         ])
def test_process_root_post_health(mocker,
                                  integration_context_filename,
                                  storage_protection,
                                  user_permission,
                                  request_permission,
                                  ok):
    """
        Given:
            The repository and request parameters with 'health'

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'longRunningPort': '8000',
        'rwCredentials': {
            'identifier': 'RWuser',
            'password': 'password',
        },
        'roCredentials': {
            'identifier': 'ROuser',
            'password': 'password',
        },
        'authenticationMethod': 'Basic',
        'publicReadAccess': False,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': storage_protection,
        'maxStorageSize': None,
        'maxSandboxSize': None,
    })
    importlib.reload(WebFileRepository)

    rw_auth_header = f"Basic {base64.b64encode(b'RWuser:password').decode()}"
    ro_auth_header = f"Basic {base64.b64encode(b'ROuser:password').decode()}"

    with open(integration_context_filename) as f:
        MockIntegrationContext(json.load(f), mocker)

    post_data = json.dumps({
        'q': 'health',
        'permission': request_permission
    }).encode()

    environ = {
        'REQUEST_METHOD': 'POST',
        'CONTENT_LENGTH': len(post_data),
        'PATH_INFO': '/',
        'CONTENT_TYPE': 'application/json',
        'wsgi.input': io.BytesIO(post_data),
    }

    if user_permission == 'read/write':
        environ['HTTP_AUTHORIZATION'] = rw_auth_header
    elif user_permission == 'read':
        environ['HTTP_AUTHORIZATION'] = ro_auth_header

    bottle.request = bottle.LocalRequest(environ)

    response = WebFileRepository.process_root_post()
    if ok:
        assert response.status_code == 200
        assert response.body.get('success')
    else:
        assert response.status_code == 401


@pytest.mark.parametrize(argnames='integration_context_filename, '
                                  'storage_protection',
                         argvalues=[
                             ('./test_data/integration_ctx_common.json',
                              'read/write'
                              ),
                             ('./test_data/integration_ctx_common.json',
                              'sandbox'
                              ),
                         ])
def test_process_root_post_cleanup(mocker,
                                   integration_context_filename,
                                   storage_protection):
    """
        Given:
            The repository and request parameters with 'cleanup'

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': storage_protection,
        'maxStorageSize': None,
        'maxSandboxSize': None,
    })
    importlib.reload(WebFileRepository)

    with open(integration_context_filename) as f:
        integration_context = MockIntegrationContext(json.load(f), mocker)

    post_data = json.dumps({
        'q': 'cleanup'
    }).encode()

    environ = {
        'REQUEST_METHOD': 'POST',
        'CONTENT_LENGTH': len(post_data),
        'PATH_INFO': '/',
        'CONTENT_TYPE': 'application/json',
        'wsgi.input': io.BytesIO(post_data),
    }
    bottle.request = bottle.LocalRequest(environ)

    response = WebFileRepository.process_root_post()
    assert response.status_code == 200

    if storage_protection == 'read-only':
        assert response.body.get('success') is False
        assert 'read-only' in response.body.get('message')
    elif storage_protection == 'read/write':
        assert response.body.get('success') is True
        assert integration_context.get_integration_context() == {}
    else:
        bottle.request = bottle.LocalRequest()
        bottle.request.query.q = 'ls'
        bottle.request.query.dir = '/'
        bottle.request.query.recursive = 'true'
        response = WebFileRepository.process_root_get()
        assert response.status_code == 200
        assert equals_object(response.body, {'data': []})


@pytest.mark.parametrize(argnames='integration_context_filename_before, '
                                  'integration_context_filename_after, '
                                  'storage_protection',
                         argvalues=[
                             ('./test_data/integration_ctx_common.json',
                              './test_data/integration_ctx_empty.json',
                              'read/write',
                              ),
                             ('./test_data/integration_ctx_common.json',
                              './test_data/integration_ctx_common.json',
                              'sandbox',
                              ),
                         ])
def test_process_root_post_reset(mocker,
                                 integration_context_filename_before,
                                 integration_context_filename_after,
                                 storage_protection):
    """
        Given:
            The repository and request parameters with 'reset'.

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': storage_protection,
        'maxStorageSize': None,
        'maxSandboxSize': None,
    })
    importlib.reload(WebFileRepository)

    with open(integration_context_filename_before) as f:
        integration_context = MockIntegrationContext(json.load(f), mocker)

    # Modify the repository
    post_data = json.dumps({
        'q': 'delete',
        'path': ['/a.dat']
    }).encode()

    environ = {
        'REQUEST_METHOD': 'POST',
        'CONTENT_LENGTH': len(post_data),
        'PATH_INFO': '/',
        'CONTENT_TYPE': 'application/json',
        'wsgi.input': io.BytesIO(post_data),
    }
    bottle.request = bottle.LocalRequest(environ)

    response = WebFileRepository.process_root_post()
    assert response.status_code == 200
    assert response.body.get('success') is True

    # Reset the repository
    post_data = json.dumps({
        'q': 'reset'
    }).encode()

    environ = {
        'REQUEST_METHOD': 'POST',
        'CONTENT_LENGTH': len(post_data),
        'PATH_INFO': '/',
        'CONTENT_TYPE': 'application/json',
        'wsgi.input': io.BytesIO(post_data),
    }
    bottle.request = bottle.LocalRequest(environ)

    response = WebFileRepository.process_root_post()
    assert response.status_code == 200
    assert response.body.get('success') is True
    with open(integration_context_filename_after) as f:
        assert integration_context.equals(json.load(f))


def test_process_root_post_reset_in_read_only(mocker):
    """
        Given:
            The repository and request parameters with 'reset' in read-only mode.

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read-only',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    })
    importlib.reload(WebFileRepository)

    with open('./test_data/integration_ctx_common.json') as f:
        MockIntegrationContext(json.load(f), mocker)

    # Reset the repository
    post_data = json.dumps({
        'q': 'reset'
    }).encode()

    environ = {
        'REQUEST_METHOD': 'POST',
        'CONTENT_LENGTH': len(post_data),
        'PATH_INFO': '/',
        'CONTENT_TYPE': 'application/json',
        'wsgi.input': io.BytesIO(post_data),
    }
    bottle.request = bottle.LocalRequest(environ)

    response = WebFileRepository.process_root_post()
    assert response.status_code == 200
    assert response.body.get('success') is False
    assert 'read-only' in response.body.get('message')


@pytest.mark.parametrize(argnames='integration_context_filename_before, '
                                  'path_list, '
                                  'integration_context_filename_after',
                         argvalues=[
                             ('./test_data/integration_ctx_common.json',
                              ['/a.dat'],
                              './test_data/delete_out_01.json',
                              ),
                             ('./test_data/integration_ctx_common.json',
                              ['/a.dat', '/x/XYZ/アイウエオ.txt'],
                              './test_data/delete_out_02.json',
                              ),
                             ('./test_data/integration_ctx_common.json',
                              ['/a.dat', '/x'],
                              './test_data/delete_out_03.json',
                              ),
                         ])
def test_process_root_post_delete(mocker,
                                  integration_context_filename_before,
                                  path_list,
                                  integration_context_filename_after):
    """
        Given:
            The repository and request parameters with 'delete'

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    })
    importlib.reload(WebFileRepository)

    with open(integration_context_filename_before) as f:
        integration_context = MockIntegrationContext(json.load(f), mocker)

    post_data = json.dumps({
        'q': 'delete',
        'path': path_list
    }).encode()

    environ = {
        'REQUEST_METHOD': 'POST',
        'CONTENT_LENGTH': len(post_data),
        'PATH_INFO': '/',
        'CONTENT_TYPE': 'application/json',
        'wsgi.input': io.BytesIO(post_data),
    }
    bottle.request = bottle.LocalRequest(environ)

    response = WebFileRepository.process_root_post()
    assert response.status_code == 200
    assert response.body.get('success') is True
    with open(integration_context_filename_after) as f:
        assert integration_context.equals(json.load(f))


def test_process_root_post_delete_in_read_only(mocker):
    """
        Given:
            The repository and request parameters with 'delete' in read-only mode

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read-only',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    })
    importlib.reload(WebFileRepository)

    with open('./test_data/integration_ctx_common.json') as f:
        MockIntegrationContext(json.load(f), mocker)

    post_data = json.dumps({
        'q': 'delete',
        'path': ['/a.dat']
    }).encode()

    environ = {
        'REQUEST_METHOD': 'POST',
        'CONTENT_LENGTH': len(post_data),
        'PATH_INFO': '/',
        'CONTENT_TYPE': 'application/json',
        'wsgi.input': io.BytesIO(post_data),
    }
    bottle.request = bottle.LocalRequest(environ)

    response = WebFileRepository.process_root_post()
    assert response.status_code == 200
    assert response.body.get('success') is False
    assert 'read-only' in response.body.get('message')


@freezegun.freeze_time('2022-01-23 12:34:56')
@pytest.mark.parametrize(argnames='integration_context_filename_before, '
                                  'file_list, '
                                  'upload_dir, '
                                  'extract_archive, '
                                  'integration_context_filename_after',
                         argvalues=[
                             ('./test_data/integration_ctx_empty.json',
                              ['./test_data/upload_file.txt'],
                              '/',
                              False,
                              './test_data/upload_out_01.json',
                              ),
                             ('./test_data/integration_ctx_empty.json',
                              ['./test_data/upload_file.txt', './test_data/upload_file.dat'],
                              '/',
                              False,
                              './test_data/upload_out_02.json',
                              ),
                             ('./test_data/integration_ctx_empty.json',
                              ['./test_data/upload_file.zip'],
                              '/',
                              True,
                              './test_data/upload_out_03.json',
                              ),
                             ('./test_data/integration_ctx_empty.json',
                              ['./test_data/upload_file.tar.gz'],
                              '/',
                              True,
                              './test_data/upload_out_04.json',
                              ),
                             ('./test_data/integration_ctx_empty.json',
                              ['./test_data/upload_file.txt'],
                              '/あいうえお',
                              False,
                              './test_data/upload_out_05.json',
                              ),
                         ])
def test_process_root_post_upload(mocker,
                                  integration_context_filename_before,
                                  file_list,
                                  upload_dir,
                                  extract_archive,
                                  integration_context_filename_after):
    """
        Given:
            The repository and request parameters with 'upload'

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    })
    MockUUID(mocker)

    importlib.reload(WebFileRepository)

    with open(integration_context_filename_before) as f:
        integration_context = MockIntegrationContext(json.load(f), mocker)

    boundary = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
    post_data = b''
    for file_path in file_list:
        file_name = os.path.basename(file_path)
        post_data += '\r\n'.join([
            '',
            f'--{boundary}',
            f'Content-Disposition: form-data; name="file"; filename="{file_name}"',
            'Content-Type: application/octet-stream',
            '\r\n',
        ]).encode()

        with open(file_path, 'rb') as f:
            post_data += f.read()

    post_data += '\r\n'.join([
        '',
        f'--{boundary}',
        'Content-Disposition: form-data; name="dir"',
        '',
        upload_dir
    ]).encode()

    post_data += '\r\n'.join([
        '',
        f'--{boundary}',
        'Content-Disposition: form-data; name="extract"',
        '',
        'true' if extract_archive else 'false'
    ]).encode()

    post_data += '\r\n'.join([
        '',
        f'--{boundary}',
        'Content-Disposition: form-data; name="q"',
        '',
        'upload'
    ]).encode()

    post_data += f'\r\n--{boundary}--\r\n'.encode()

    environ = {
        'REQUEST_METHOD': 'POST',
        'CONTENT_LENGTH': len(post_data),
        'PATH_INFO': '/',
        'CONTENT_TYPE': f'multipart/form-data; boundary={boundary}',
        'wsgi.input': io.BytesIO(post_data),
    }
    bottle.request = bottle.LocalRequest(environ)

    response = WebFileRepository.process_root_post()
    assert response.status_code == 200
    assert response.body.get('success') is True
    with open(integration_context_filename_after) as f:
        assert integration_context.equals(json.load(f))


@freezegun.freeze_time('2022-01-23 12:34:56')
@pytest.mark.parametrize(
    argnames=(
        'integration_context_filename_before, '
        'file_list, '
        'upload_dir, '
        'extract_archive, '
        'integration_context_filename_after'
    ),
    argvalues=[
        (
            './test_data/integration_ctx_empty.json',
            ['./test_data/upload_file.txt'],
            '/',
            False,
            './test_data/upload_out_01.json',
        ),
        (
            './test_data/integration_ctx_empty.json',
            ['./test_data/upload_file.txt', './test_data/upload_file.dat'],
            '/',
            False,
            './test_data/upload_out_02.json',
        ),
        (
            './test_data/integration_ctx_empty.json',
            ['./test_data/upload_file.zip'],
            '/',
            True,
            './test_data/upload_out_03.json',
        ),
        (
            './test_data/integration_ctx_empty.json',
            ['./test_data/upload_file.tar.gz'],
            '/',
            True,
            './test_data/upload_out_04.json',
        ),
        (
            './test_data/integration_ctx_empty.json',
            ['./test_data/upload_file.txt'],
            '/あいうえお',
            False,
            './test_data/upload_out_05.json',
        ),
    ]
)
def test_process_root_post_upload_chunk(
    mocker,
    integration_context_filename_before,
    file_list,
    upload_dir,
    extract_archive,
    integration_context_filename_after
):
    """
        Given:
            The repository and request parameters with 'upload'

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    })
    MockUUID(mocker)

    importlib.reload(WebFileRepository)

    with open(integration_context_filename_before) as f:
        integration_context = MockIntegrationContext(json.load(f), mocker)

    for file_path in file_list:
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        with open(file_path, 'rb') as f:
            chunk_size = int(file_size / 3)
            chunk_num = math.ceil(file_size / chunk_size)
            chunk_sid = ''.join([random.choice(string.digits) for i in range(16)])

            for chunk_index in range(0, chunk_num):
                chunk = f.read(chunk_size)

                boundary = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
                post_data = '\r\n'.join([
                    '',
                    f'--{boundary}',
                    f'Content-Disposition: form-data; name="file"; filename="{file_name}"',
                    'Content-Type: application/octet-stream',
                    '\r\n',
                ]).encode()

                post_data += chunk

                if chunk_index < chunk_num - 1:
                    form_params = {
                        'q': 'upload',
                        'dir': upload_dir,
                        'chunk_sid': chunk_sid,
                        'chunk_index': chunk_index,
                    }
                else:
                    form_params = {
                        'q': 'upload',
                        'dir': upload_dir,
                        'chunk_sid': chunk_sid,
                        'chunk_index': chunk_index,
                        'last_chunk': 'true',
                        'file_size': file_size,
                        'extract': 'true' if extract_archive else 'false'
                    }

                for k, v in form_params.items():
                    post_data += '\r\n'.join([
                        '',
                        f'--{boundary}',
                        f'Content-Disposition: form-data; name="{k}"',
                        '',
                        str(v)
                    ]).encode()

                post_data += f'\r\n--{boundary}--\r\n'.encode()

                environ = {
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_LENGTH': len(post_data),
                    'PATH_INFO': '/',
                    'CONTENT_TYPE': f'multipart/form-data; boundary={boundary}',
                    'wsgi.input': io.BytesIO(post_data),
                }
                bottle.request = bottle.LocalRequest(environ)

                response = WebFileRepository.process_root_post()
                assert response.status_code == 200
                assert response.body.get('success') is True

    with open(integration_context_filename_after) as f:
        assert integration_context.equals(json.load(f))


@freezegun.freeze_time('2022-01-23 12:34:56')
@pytest.mark.parametrize(argnames='storage_limit, '
                                  'sandbox_limit, '
                                  'storage_protection',
                         argvalues=[
                             ('10', '20', 'read/write'),
                             ('10', '20', 'sandbox'),
                         ])
def test_process_root_post_upload_limit(mocker,
                                        storage_limit,
                                        sandbox_limit,
                                        storage_protection):
    """
        Given:
            The storage/sandbox limit, and upload a file over the limit.

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': storage_protection,
        'maxStorageSize': storage_limit,
        'maxSandboxSize': sandbox_limit,
    })
    importlib.reload(WebFileRepository)

    boundary = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
    post_data = '\r\n'.join([
        '',
        f'--{boundary}',
        'Content-Disposition: form-data; name="file"; filename="test.dat"',
        'Content-Type: application/octet-stream',
        '\r\n',
    ]).encode()

    post_data += random.randbytes(int(storage_limit) * 100)

    post_data += '\r\n'.join([
        '',
        f'--{boundary}',
        'Content-Disposition: form-data; name="dir"',
        '',
        '/'
    ]).encode()

    post_data += '\r\n'.join([
        '',
        f'--{boundary}',
        'Content-Disposition: form-data; name="extract"',
        '',
        'false'
    ]).encode()

    post_data += '\r\n'.join([
        '',
        f'--{boundary}',
        'Content-Disposition: form-data; name="q"',
        '',
        'upload'
    ]).encode()

    post_data += f'\r\n--{boundary}--\r\n'.encode()

    environ = {
        'REQUEST_METHOD': 'POST',
        'CONTENT_LENGTH': len(post_data),
        'PATH_INFO': '/',
        'CONTENT_TYPE': f'multipart/form-data; boundary={boundary}',
        'wsgi.input': io.BytesIO(post_data),
    }
    bottle.request = bottle.LocalRequest(environ)

    response = WebFileRepository.process_root_post()
    assert response.status_code == 200
    assert response.body.get('success') is False
    assert 'limit exceeded' in response.body.get('message')


def test_process_root_post_upload_in_read_only(mocker):
    """
        Given:
            The storage/sandbox limit, and upload a file in read-only mode.

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read-only',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    })
    importlib.reload(WebFileRepository)

    boundary = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
    post_data = '\r\n'.join([
        '',
        f'--{boundary}',
        'Content-Disposition: form-data; name="file"; filename="test.dat"',
        'Content-Type: application/octet-stream',
        '\r\n',
    ]).encode()

    post_data += random.randbytes(100)

    post_data += '\r\n'.join([
        '',
        f'--{boundary}',
        'Content-Disposition: form-data; name="dir"',
        '',
        '/'
    ]).encode()

    post_data += '\r\n'.join([
        '',
        f'--{boundary}',
        'Content-Disposition: form-data; name="extract"',
        '',
        'false'
    ]).encode()

    post_data += '\r\n'.join([
        '',
        f'--{boundary}',
        'Content-Disposition: form-data; name="q"',
        '',
        'upload'
    ]).encode()

    post_data += f'\r\n--{boundary}--\r\n'.encode()

    environ = {
        'REQUEST_METHOD': 'POST',
        'CONTENT_LENGTH': len(post_data),
        'PATH_INFO': '/',
        'CONTENT_TYPE': f'multipart/form-data; boundary={boundary}',
        'wsgi.input': io.BytesIO(post_data),
    }
    bottle.request = bottle.LocalRequest(environ)

    response = WebFileRepository.process_root_post()
    assert response.status_code == 200
    assert response.body.get('success') is False
    assert 'read-only' in response.body.get('message')


def test_command_status(mocker):
    """
        Given:
            Patterns of parameters for command_list_files

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    params = {
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    }
    mocker.patch.object(demisto, 'params', return_value=params)

    server_resp = {
        'storage_protection': 'read/write',
        'max_storage_size': 1000,
        'max_sandbox_size': 2000,
        'storage_usage': 200,
        'sandbox_usage': 100,
    }
    client = MockBaseClient(mocker, headers={}, json_data=server_resp)
    mocker.patch.object(WebFileRepository, 'new_client', return_value=client)

    importlib.reload(WebFileRepository)

    settings = WebFileRepository.Settings(params)
    res = WebFileRepository.command_status({}, settings).to_context()

    ec = demisto.get(res, 'EntryContext').get('WebFileRepository.Status')
    assert ec.get('StorageUsage') == server_resp.get('storage_usage')
    assert ec.get('SandboxUsage') == server_resp.get('sandbox_usage')
    assert ec.get('StorageProtection') == server_resp.get('storage_protection')


def test_command_cleanup(mocker):
    """
        Given:
            No parameters for command_cleanup

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    params = {
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    }
    mocker.patch.object(demisto, 'params', return_value=params)

    client = MockBaseClient(mocker, headers={}, json_data={
        'success': True,
        'message': ''
    })
    mocker.patch.object(WebFileRepository, 'new_client', return_value=client)

    importlib.reload(WebFileRepository)

    settings = WebFileRepository.Settings(params)
    res = WebFileRepository.command_cleanup({}, settings)
    assert 'Done' in res


def test_command_reset(mocker):
    """
        Given:
            No parameters for command_reset

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    params = {
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    }
    mocker.patch.object(demisto, 'params', return_value=params)

    client = MockBaseClient(mocker, headers={}, json_data={
        'success': True,
        'message': ''
    })
    mocker.patch.object(WebFileRepository, 'new_client', return_value=client)

    importlib.reload(WebFileRepository)

    settings = WebFileRepository.Settings(params)
    res = WebFileRepository.command_reset({}, settings)
    assert 'Done' in res


@pytest.mark.parametrize(argnames='file_name, '
                                  'input_data, '
                                  'encoding, '
                                  'file_data',
                         argvalues=[
                             ('test.txt', 'aaaa', 'utf-8', b'aaaa'),
                             ('test.txt', None, 'utf-8', b''),
                             ('test.bin', 'aaaa', 'base64', b'\x69\xA6\x9A'),
                             ('test.bin', None, 'base64', b''),
                         ])
def test_command_upload_as_file(mocker, file_name, input_data, encoding, file_data):
    """
        Given:
            Some data patterns for command_upload_as_file

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    params = {
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    }
    mocker.patch.object(demisto, 'params', return_value=params)

    class _MockBaseClient:
        def __init__(
            self,
            mocker: pytest_mock.plugin.MockerFixture,
            headers: dict[str, str],
            file_name: str,
            file_data: bytes,
            json_data: Any
        ):
            self.__headers = headers
            self.__file_name = file_name
            self.__file_data = file_data
            self.__content = json.dumps(json_data).encode()
            mocker.patch('CommonServerPython.BaseClient._http_request', side_effect=self._http_request)

        def _http_request(
            self, method, url_suffix='', full_url=None, headers=None, auth=None, json_data=None,
            params=None, data=None, files=None, timeout=None, resp_type='json', ok_codes=None,
            return_empty_response=False, retries=0, status_list_to_retry=None,
            backoff_factor=5, raise_on_redirect=False, raise_on_status=False,
            error_handler=None, empty_valid_codes=None, **kwargs
        ):
            class MockRequestsResponse:
                def __init__(self, headers: dict[str, str], content: bytes):
                    self.headers = headers
                    self.content = content

                def json(self):
                    return json.loads(self.content.decode())

            if len(files) != 1:
                raise ValueError(f'Invalid number of files - {len(files)}')

            key, (name, data) = files[0]
            if key != 'file':
                raise ValueError('file is not given.')

            if name != self.__file_name:
                raise ValueError(f'file name is invalid - {name}')

            if data != self.__file_data:
                raise ValueError(f'file data is invalid - {data}')

            if resp_type == 'json':
                return json.loads(self.__content.decode())
            elif resp_type == 'json':
                return self.__content
            else:
                return MockRequestsResponse(headers=self.__headers,
                                            content=self.__content)

    client = _MockBaseClient(mocker,
                             headers={},
                             file_name=file_name,
                             file_data=file_data,
                             json_data={
                                 'success': True,
                                 'message': ''
                             }
                             )
    mocker.patch.object(WebFileRepository, 'new_client', return_value=client)

    importlib.reload(WebFileRepository)

    args = assign_params(
        file_name=file_name,
        data=input_data,
        encoding=encoding
    )
    settings = WebFileRepository.Settings(params)
    res = WebFileRepository.command_upload_as_file(args, settings)
    assert 'Done' in res


@pytest.mark.parametrize(argnames='entry_id, '
                                  'name',
                         argvalues=[
                             ('0000', None),
                             ('0000', 'name'),
                         ])
def test_command_upload_file(mocker, entry_id, name):
    """
        Given:
            Some patterns of entry_ids for command_upload_file

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    params = {
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'getFilePath', return_value={
        'name': 'upload_file.dat',
        'path': 'test_data/upload_file.dat'
    })

    client = MockBaseClient(mocker, headers={}, json_data={
        'success': True,
        'message': ''
    })
    mocker.patch.object(WebFileRepository, 'new_client', return_value=client)

    importlib.reload(WebFileRepository)

    args = assign_params(
        entry_id=entry_id,
        name=name
    )
    settings = WebFileRepository.Settings(params)
    res = WebFileRepository.command_upload_file(args, settings)
    assert 'Done' in res


@pytest.mark.parametrize(argnames='entry_ids',
                         argvalues=[
                             ('0000'),
                             ('0000,1111,2222'),
                             (['0000', '1111', '2222']),
                         ])
def test_command_upload_files(mocker, entry_ids):
    """
        Given:
            Some patterns of entry_ids for command_upload_files

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    params = {
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'getFilePath', return_value={
        'name': 'upload_file.dat',
        'path': 'test_data/upload_file.dat'
    })

    client = MockBaseClient(mocker, headers={}, json_data={
        'success': True,
        'message': ''
    })
    mocker.patch.object(WebFileRepository, 'new_client', return_value=client)

    importlib.reload(WebFileRepository)

    args = {
        'entry_ids': entry_ids
    }
    settings = WebFileRepository.Settings(params)
    res = WebFileRepository.command_upload_files(args, settings)
    assert 'Done' in res


@pytest.mark.parametrize(argnames='directory, '
                                  'recursive, '
                                  'response_filename, '
                                  'results_filename',
                         argvalues=[
                             ('/',
                              False,
                              'test_data/list_files_svrresp_01.json',
                              'test_data/list_files_results_01.json'),
                             ('/',
                              True,
                              'test_data/list_files_svrresp_02.json',
                              'test_data/list_files_results_02.json'),
                         ])
def test_command_list_files(mocker,
                            directory,
                            recursive,
                            response_filename,
                            results_filename):
    """
        Given:
            Patterns of parameters for command_list_files

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    params = {
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    }
    mocker.patch.object(demisto, 'params', return_value=params)

    with open(response_filename) as f:
        server_resp = json.load(f)

    client = MockBaseClient(mocker, headers={}, json_data=server_resp)
    mocker.patch.object(WebFileRepository, 'new_client', return_value=client)

    importlib.reload(WebFileRepository)

    args = {
        'directory': directory,
        'recursive': recursive
    }
    keys = ('Type', 'ContentFormat', 'Contents', 'EntryContext')
    settings = WebFileRepository.Settings(params)
    res = WebFileRepository.command_list_files(args, settings).to_context()
    res = {k: v for k, v in res.items() if k in keys}

    with open(results_filename) as f:
        expected = {k: v for k, v in json.load(f).items() if k in keys}

    assert equals_object(res, expected)


@pytest.mark.parametrize(argnames='paths',
                         argvalues=[
                             ('/0000.dat'),
                             ('/0000.dat,/1111.dat,/2222.dat'),
                             (['/0000.dat', '/1111.dat', '/2222.dat']),
                         ])
def test_command_remove_files(mocker, paths):
    """
        Given:
            Some patterns of paths for command_reset

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    params = {
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    }
    mocker.patch.object(demisto, 'params', return_value=params)

    client = MockBaseClient(mocker, headers={}, json_data={
        'success': True,
        'message': ''
    })
    mocker.patch.object(WebFileRepository, 'new_client', return_value=client)

    importlib.reload(WebFileRepository)

    args = {
        'paths': paths
    }
    settings = WebFileRepository.Settings(params)
    res = WebFileRepository.command_remove_files(args, settings)
    assert 'Done' in res


@pytest.mark.parametrize(argnames='path, '
                                  'save_as, '
                                  'content_filename',
                         argvalues=[
                             ('/test.dat',
                              'aaa.dat',
                              'test_data/download_file.dat'
                              ),
                             ('/あいうえお.dat',
                              None,
                              'test_data/download_file.dat'
                              ),
                             ('/あいうえお.dat',
                              'アイウエオ.txt',
                              'test_data/download_file.dat'
                              ),
                         ])
def test_command_download_file(mocker, path, save_as, content_filename):
    """
        Given:
            Some patterns of parameters for command_download_file

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    params = {
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'results')
    mocker.patch('CommonServerPython.fileResult', side_effect=MockFileResult)

    filename = os.path.basename(path)
    encoded_name = urllib.parse.quote(filename, encoding='utf-8')
    headers = {
        'Content-Disposition': f'attachment; filename*=utf-8\'\'{encoded_name}'
    }
    with open(content_filename, 'rb') as f:
        content = f.read()

    client = MockBaseClient(mocker, headers=headers, content=content)
    mocker.patch.object(WebFileRepository, 'new_client', return_value=client)

    importlib.reload(WebFileRepository)

    args = {
        'path': path,
        'save_as': save_as
    }
    settings = WebFileRepository.Settings(params)
    res = WebFileRepository.command_download_file(args, settings)
    filename = save_as if save_as else filename
    assert res['Type'] == entryTypes['file']
    assert res['File'] == filename


@pytest.mark.parametrize(argnames='path, '
                                  'encoding, '
                                  'content, '
                                  'results_filename',
                         argvalues=[
                             ('/test.dat',
                              None,
                              'Hello!',
                              'test_data/download_as_text_01.json'
                              ),
                             ('/test.dat',
                              'utf-8',
                              'Hello!',
                              'test_data/download_as_text_01.json'
                              ),
                             ('/test.dat',
                              'base64',
                              'Hello!',
                              'test_data/download_as_text_02.json'
                              ),
                             ('test.dat',
                              None,
                              'Hello!',
                              'test_data/download_as_text_01.json'
                              ),
                             ('test.dat',
                              'utf-8',
                              'Hello!',
                              'test_data/download_as_text_01.json'
                              ),
                             ('test.dat',
                              'base64',
                              'Hello!',
                              'test_data/download_as_text_02.json'
                              ),
                         ])
def test_command_download_as_text(mocker, path, encoding, content, results_filename):
    """
        Given:
            Some patterns of parameters for command_download_as_text

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    params = {
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    }
    mocker.patch.object(demisto, 'params', return_value=params)

    client = MockBaseClient(mocker, headers={}, content=content.encode('utf-8'))
    mocker.patch.object(WebFileRepository, 'new_client', return_value=client)

    importlib.reload(WebFileRepository)

    args = assign_params(
        path=path,
        encoding=encoding
    )
    settings = WebFileRepository.Settings(params)
    res = WebFileRepository.command_download_as_text(args, settings).to_context()

    keys = ('Type', 'ContentFormat', 'Contents', 'EntryContext')
    res = {k: v for k, v in res.items() if k in keys}

    with open(results_filename) as f:
        expected = {k: v for k, v in json.load(f).items() if k in keys}

    assert equals_object(res, expected)


@pytest.mark.parametrize(argnames='save_as, '
                                  'content_filename',
                         argvalues=[
                             ('aaa.dat',
                              'test_data/download_file.dat'
                              ),
                             (None,
                              'test_data/download_file.dat'
                              ),
                             ('アイウエオ.txt',
                              'test_data/download_file.dat'
                              ),
                         ])
def test_command_archive_zip(mocker, save_as, content_filename):
    """
        Given:
            Some patterns of parameters for command_archive_zip

        When:
            Running script to send a request.

        Then:
            Validate the right response returns.
    """
    params = {
        'longRunningPort': '8000',
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'results')
    mocker.patch('CommonServerPython.fileResult', side_effect=MockFileResult)

    filename = 'archive.zip'
    headers = {
        'Content-Disposition': f'attachment; filename="{filename}"'
    }
    with open(content_filename, 'rb') as f:
        content = f.read()

    client = MockBaseClient(mocker, headers=headers, content=content)
    mocker.patch.object(WebFileRepository, 'new_client', return_value=client)

    importlib.reload(WebFileRepository)

    args = {
        'save_as': save_as
    }
    settings = WebFileRepository.Settings(params)
    res = WebFileRepository.command_archive_zip(args, settings)

    filename = save_as if save_as else filename
    assert res['Type'] == entryTypes['file']
    assert res['File'] == filename


@pytest.mark.parametrize(argnames='mimetypes_input_filename, '
                                  'mimetypes_output_filename, '
                                  'merge_mime_types',
                         argvalues=[
                             ('./test_data/mime_types_style_01.json',
                              './test_data/mime_types_out_overwrite.json',
                              False,
                              ),
                             ('./test_data/mime_types_style_02.txt',
                              './test_data/mime_types_out_overwrite.json',
                              False,
                              ),
                             ('./test_data/mime_types_style_03.txt',
                              './test_data/mime_types_out_overwrite.json',
                              False,
                              ),
                             ('./test_data/mime_types_style_01.json',
                              './test_data/mime_types_out_merge.json',
                              True,
                              ),
                             ('./test_data/mime_types_style_02.txt',
                              './test_data/mime_types_out_merge.json',
                              True,
                              ),
                             ('./test_data/mime_types_style_03.txt',
                              './test_data/mime_types_out_merge.json',
                              True,
                              ),
                         ])
def test_parse_mime_types(mocker,
                          mimetypes_input_filename,
                          mimetypes_output_filename,
                          merge_mime_types):
    """
        Given:
            The MIME types file

        When:
            Running script to initialize with the MIME types.

        Then:
            Validate the right response returns.
    """
    with open(mimetypes_input_filename) as f:
        input_mime_types = f.read()

    mocker.patch.object(demisto, 'params', return_value={
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': input_mime_types,
        'mergeMimeTypes': merge_mime_types,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    })
    importlib.reload(WebFileRepository)

    with open(mimetypes_output_filename) as f:
        assert equals_object(WebFileRepository.SETTINGS.ext_to_mimetype, json.loads(f.read()))


@pytest.mark.parametrize(argnames='attachment_exts_input, '
                                  'attachment_exts_output',
                         argvalues=[
                             ('exe, bat, dat, zip, 7z',
                              [".exe", ".bat", ".dat", ".zip", ".7z"],
                              ),
                             ('.exe, .bat, .dat, .zip, .7z',
                              [".exe", ".bat", ".dat", ".zip", ".7z"],
                              ),
                             ('exe bat dat zip 7z',
                              [".exe", ".bat", ".dat", ".zip", ".7z"],
                              ),
                             ('.exe .bat .dat .zip .7z',
                              [".exe", ".bat", ".dat", ".zip", ".7z"],
                              ),
                             ('.exe .bat .dat .zip .7z *',
                              [".exe", ".bat", ".dat", ".zip", ".7z", "*"],
                              ),
                         ])
def test_parse_attachment_exts(mocker,
                               attachment_exts_input,
                               attachment_exts_output):
    """
        Given:
            The attachment extensions text

        When:
            Running script to initialize with the attachment extensions.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'rwCredentials': {},
        'authenticationMethod': None,
        'publicReadAccess': True,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': attachment_exts_input,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    })
    importlib.reload(WebFileRepository)

    attachment_exts = list(WebFileRepository.SETTINGS.attachment_exts)
    assert equals_object(attachment_exts, attachment_exts_output)


@pytest.mark.parametrize(argnames='rw_identifier, '
                                  'rw_password, '
                                  'ro_identifier, '
                                  'ro_password, '
                                  'require_write, '
                                  'public_read_access, '
                                  'request_method, '
                                  'auth_method, '
                                  'auth_header, '
                                  'auth_ok',
                         argvalues=[
                             # Given:
                             #   - read/write credentials
                             #   - right credentials
                             #
                             # When:
                             #   - basic auth
                             #   - having permissions
                             #     (request write to read/write permissions)
                             #
                             # Then:
                             #   - Auth OK
                             ('test',
                              'password',
                              None,
                              None,
                              True,
                              False,
                              'POST',
                              'Basic',
                              'Basic dGVzdDpwYXNzd29yZA==',
                              True
                              ),
                             # Given:
                             #   - read/write credentials (empty string)
                             #   - right credentials
                             #
                             # When:
                             #   - basic auth
                             #   - having permissions
                             #     (request write to read/write permissions)
                             #
                             # Then:
                             #   - Auth OK
                             ('',
                              '',
                              None,
                              None,
                              True,
                              False,
                              'POST',
                              'Basic',
                              'Basic Og==',
                              True
                              ),
                             # Given:
                             #   - read-only credentials
                             #   - right credentials
                             #
                             # When:
                             #   - basic auth
                             #   - having permissions
                             #     (request read to read-only permissions)
                             #
                             # Then:
                             #   - Auth OK
                             (None,
                              None,
                              'test',
                              'password',
                              False,
                              False,
                              'POST',
                              'Basic',
                              'Basic dGVzdDpwYXNzd29yZA==',
                              True
                              ),
                             # Given:
                             #   - read-only credentials
                             #   - right credentials
                             #
                             # When:
                             #   - basic auth
                             #   - no permissions
                             #     (request write to read-only permissions)
                             #
                             # Then:
                             #   - Auth NG
                             (None,
                              None,
                              'test',
                              'password',
                              True,
                              False,
                              'POST',
                              'Basic',
                              'Basic dGVzdDpwYXNzd29yZA==',
                              False
                              ),
                             # Given:
                             #   - read/write credentials
                             #   - wrong credentials
                             #
                             # When:
                             #   - basic auth
                             #   - having permissions
                             #     (request write to read/write permissions)
                             #
                             # Then:
                             #   - Auth NG
                             ('test',
                              'password1',
                              None,
                              None,
                              True,
                              False,
                              'POST',
                              'Basic',
                              'Basic dGVzdDpwYXNzd29yZA==',
                              False
                              ),
                             # Given:
                             #   - read/write credentials
                             #   - read-only credentials
                             #   - right credentials
                             #
                             # When:
                             #   - basic auth
                             #   - having permissions
                             #     (request write to read/write permissions)
                             #
                             # Then:
                             #   - Auth OK
                             ('test',
                              'password',
                              'test',
                              'password',
                              True,
                              False,
                              'POST',
                              'Basic',
                              'Basic dGVzdDpwYXNzd29yZA==',
                              True
                              ),
                             # Given:
                             #   - read/write credentials
                             #   - right credentials
                             #
                             # When:
                             #   - digest auth (md5)
                             #   - having permissions
                             #     (request write to read/write permissions)
                             #
                             # Then:
                             #   - Auth OK
                             ('test',
                              'password',
                              None,
                              None,
                              True,
                              False,
                              'POST',
                              'Digest-md5',
                              'Digest username="test",'
                              ' realm="protected area",'
                              ' nonce="1669998243:1d385c2a503eb73bdfff5824eefc3007",'
                              ' uri="/",'
                              ' algorithm=MD5,'
                              ' response="f888d3020d56ac3c81952c96f7115b47",'
                              ' qop=auth,'
                              ' nc=00000001,'
                              ' cnonce="082c875dcb2ca740"',
                              True
                              ),
                             # Given:
                             #   - read/write credentials (empty string)
                             #   - right credentials
                             #
                             # When:
                             #   - digest auth (md5)
                             #   - having permissions
                             #     (request write to read/write permissions)
                             #
                             # Then:
                             #   - Auth OK
                             ('',
                              '',
                              None,
                              None,
                              True,
                              False,
                              'GET',
                              'Digest-md5',
                              'Digest username="",'
                              ' realm="protected area",'
                              ' nonce="1670654640:61b81bfd7435f5844f77e33c69aa001d",'
                              ' uri="/",'
                              ' algorithm=MD5,'
                              ' response="4e38538b9c6244ff7a5cbe3b5a1eacc7",'
                              ' qop=auth,'
                              ' nc=00000001,'
                              ' cnonce="55257458a653e256"',
                              True
                              ),
                             # Given:
                             #   - read-only credentials
                             #   - right credentials
                             #
                             # When:
                             #   - digest auth (md5)
                             #   - having permissions
                             #     (request read to read-only permissions)
                             #
                             # Then:
                             #   - Auth OK
                             (None,
                              None,
                              'test',
                              'password',
                              False,
                              False,
                              'POST',
                              'Digest-md5',
                              'Digest username="test",'
                              ' realm="protected area",'
                              ' nonce="1669998243:1d385c2a503eb73bdfff5824eefc3007",'
                              ' uri="/",'
                              ' algorithm=MD5,'
                              ' response="f888d3020d56ac3c81952c96f7115b47",'
                              ' qop=auth,'
                              ' nc=00000001,'
                              ' cnonce="082c875dcb2ca740"',
                              True
                              ),
                             # Given:
                             #   - read-only credentials
                             #   - right credentials
                             #
                             # When:
                             #   - digest auth (md5)
                             #   - no permissions
                             #     (request write to read-only permissions)
                             #
                             # Then:
                             #   - Auth NG
                             (None,
                              None,
                              'test',
                              'password',
                              True,
                              False,
                              'POST',
                              'Digest-md5',
                              'Digest username="test",'
                              ' realm="protected area",'
                              ' nonce="1669998243:1d385c2a503eb73bdfff5824eefc3007",'
                              ' uri="/",'
                              ' algorithm=MD5,'
                              ' response="f888d3020d56ac3c81952c96f7115b47",'
                              ' qop=auth,'
                              ' nc=00000001,'
                              ' cnonce="082c875dcb2ca740"',
                              False
                              ),
                             # Given:
                             #   - read/write credentials
                             #   - wrong credentials
                             #
                             # When:
                             #   - digest auth (md5)
                             #   - having permissions
                             #     (request write to read/write permissions)
                             #
                             # Then:
                             #   - Auth NG
                             ('test',
                              'password1',
                              None,
                              None,
                              True,
                              False,
                              'POST',
                              'Digest-md5',
                              'Digest username="test",'
                              ' realm="protected area",'
                              ' nonce="1669998243:1d385c2a503eb73bdfff5824eefc3007",'
                              ' uri="/",'
                              ' algorithm=MD5,'
                              ' response="f888d3020d56ac3c81952c96f7115b47",'
                              ' qop=auth,'
                              ' nc=00000001,'
                              ' cnonce="082c875dcb2ca740"',
                              False
                              ),
                             # Given:
                             #   - read/write credentials
                             #   - right credentials
                             #
                             # When:
                             #   - digest auth (sha256)
                             #   - having permissions
                             #     (request write to read/write permissions)
                             #
                             # Then:
                             #   - Auth OK
                             ('test',
                              'password',
                              None,
                              None,
                              True,
                              False,
                              'POST',
                              'Digest-sha256',
                              'Digest username="test",'
                              ' realm="protected area",'
                              ' nonce="1669998369:e3b6f13700a2c135f7c6cf8f129fc4f0",'
                              ' uri="/",'
                              ' algorithm=SHA-256,'
                              ' response="2e168e4fbbe57265a8bc03bb7e0c6357c27e760f089c81489c3039e3b2a31e9d",'
                              ' qop=auth,'
                              ' nc=00000002,'
                              ' cnonce="2b8d329a8571b99a"',
                              True
                              ),
                             # Given:
                             #   - read/write credentials
                             #   - wrong credentials
                             #
                             # When:
                             #   - digest auth (sha256)
                             #   - having permissions
                             #     (request write to read/write permissions)
                             #
                             # Then:
                             #   - Auth NG
                             ('test',
                              'password1',
                              None,
                              None,
                              True,
                              False,
                              'POST',
                              'Digest-sha256',
                              'Digest username="test",'
                              ' realm="protected area",'
                              ' nonce="1669998369:e3b6f13700a2c135f7c6cf8f129fc4f0",'
                              ' uri="/",'
                              ' algorithm=SHA-256,'
                              ' response="2e168e4fbbe57265a8bc03bb7e0c6357c27e760f089c81489c3039e3b2a31e9d",'
                              ' qop=auth,'
                              ' nc=00000002,'
                              ' cnonce="2b8d329a8571b99a"',
                              False
                              ),
                             # Given:
                             #   - read/write credentials
                             #
                             # When:
                             #   - basic auth
                             #   - public read access
                             #   - having permissions
                             #     (request read to read-only permissions)
                             #   - doesn't send credentials
                             #
                             # Then:
                             #   - Auth NG
                             ('test',
                              'password',
                              None,
                              None,
                              False,
                              False,
                              'POST',
                              'Basic',
                              '',
                              False
                              ),
                         ])
def test_handle_auth(mocker,
                     rw_identifier,
                     rw_password,
                     ro_identifier,
                     ro_password,
                     require_write,
                     public_read_access,
                     request_method,
                     auth_method,
                     auth_header,
                     auth_ok):
    """
        Given:
            The authentication method and parameters.

        When:
            Running script to request the authentication.

        Then:
            Validate the right response returns.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'rwCredentials': {
            'identifier': rw_identifier,
            'password': rw_password
        },
        'roCredentials': {
            'identifier': ro_identifier,
            'password': ro_password
        },
        'authenticationMethod': auth_method,
        'publicReadAccess': public_read_access,
        'mimeTypes': None,
        'mergeMimeTypes': True,
        'attachmentExtensions': None,
        'storageProtection': 'read/write',
        'maxStorageSize': None,
        'maxSandboxSize': None,
    })
    importlib.reload(WebFileRepository)

    auth_method, _, auth_value = auth_header.partition(' ')
    if auth_method == 'Digest':
        def __new_nonce(nonce) -> tuple[int, str]:
            gen_time, _, _ = nonce.partition(':')
            return int(gen_time), nonce

        auth_params = urllib.request.parse_keqv_list(urllib.request.parse_http_list(auth_value))
        mocker.patch.object(WebFileRepository.NONCE_MANAGER, '_NonceManager__new_nonce',
                            side_effect=lambda: __new_nonce(auth_params['nonce']))

        WebFileRepository.NONCE_MANAGER._NonceManager__expires = 60 * 60 * 24 * 3650
        WebFileRepository.NONCE_MANAGER.gen_nonce()

    environ = {
        'REQUEST_METHOD': request_method,
        'PATH_INFO': '/',
        'HTTP_AUTHORIZATION': auth_header
    }
    request = bottle.LocalRequest(environ)
    handler = WebFileRepository.ServiceHandler(WebFileRepository.SETTINGS,
                                               WebFileRepository.MASTER_REPOSITORY)
    if require_write:
        permission = WebFileRepository.PERMISSION.WRITE
    else:
        permission = WebFileRepository.PERMISSION.READ

    response = handler.authenticate(request, permission)
    if auth_ok:
        assert response is None
    else:
        assert response.status == 401 or '401' in response.status
