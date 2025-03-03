import rasterize
from rasterize import *
import demistomock as demisto
from CommonServerPython import entryTypes
from tempfile import NamedTemporaryFile
from pytest_mock import MockerFixture
from unittest.mock import MagicMock
import os
import logging
import http.server
import time
import threading
import pytest
import requests
import json

# disable warning from urllib3. these are emitted when python driver can't connect to chrome yet
logging.getLogger("urllib3").setLevel(logging.ERROR)

RETURN_ERROR_TARGET = 'rasterize.return_error'


def util_read_tsv(file_path):
    with open(file_path) as file:
        ret_value = file.read()
        return ret_value


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_rasterize_email_image(caplog, capfd, mocker):
    with capfd.disabled() and NamedTemporaryFile('w+') as f:
        f.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        path = os.path.realpath(f.name)
        f.flush()
        mocker.patch.object(rasterize, 'support_multithreading')
        perform_rasterize(path=f'file://{path}', width=250, height=250, rasterize_type=RasterizeType.PNG)
        caplog.clear()


def test_rasterize_email_image_array(caplog, capfd, mocker):
    with capfd.disabled() and NamedTemporaryFile('w+') as f:
        f.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        path = os.path.realpath(f.name)
        f.flush()
        mocker.patch.object(rasterize, 'support_multithreading')
        perform_rasterize(path=[f'file://{path}'], width=250, height=250, rasterize_type=RasterizeType.PNG)
        caplog.clear()


def test_rasterize_email_pdf(caplog, capfd, mocker):
    with capfd.disabled() and NamedTemporaryFile('w+') as f:
        f.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        path = os.path.realpath(f.name)
        f.flush()
        mocker.patch.object(rasterize, 'support_multithreading')
        perform_rasterize(path=f'file://{path}', width=250, height=250, rasterize_type=RasterizeType.PDF)
        caplog.clear()


def test_rasterize_email_pdf_offline(caplog, capfd, mocker):
    with capfd.disabled() and NamedTemporaryFile('w+') as f:
        f.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        path = os.path.realpath(f.name)
        f.flush()
        mocker.patch.object(rasterize, 'support_multithreading')
        perform_rasterize(path=f'file://{path}', width=250, height=250, rasterize_type=RasterizeType.PDF)
        caplog.clear()


def test_get_chrome_options():
    res = get_chrome_options(CHROME_OPTIONS, '')
    assert res == CHROME_OPTIONS

    res = get_chrome_options(CHROME_OPTIONS, '[--disable-dev-shm-usage],--disable-auto-reload, --headless')
    assert '--disable-dev-shm-usage' not in res
    assert '--no-sandbox' in res  # part of default options
    assert '--disable-auto-reload' in res
    assert len([x for x in res if x == '--headless']) == 1  # should have only one headless option

    res = get_chrome_options(CHROME_OPTIONS, r'--user-agent=test\,comma')
    assert len([x for x in res if x.startswith('--user-agent')]) == 1
    assert '--user-agent=test,comma' in res

    res = get_chrome_options(CHROME_OPTIONS, r'[--user-agent]')  # remove user agent
    assert len([x for x in res if x.startswith('--user-agent')]) == 0


def test_rasterize_large_html(capfd, mocker):
    with capfd.disabled():
        path = os.path.realpath('test_data/large.html')
        mocker.patch.object(rasterize, 'support_multithreading')
        res = perform_rasterize(path=f'file://{path}', width=250, height=250, rasterize_type=RasterizeType.PNG)
        assert res


def test_rasterize_html(mocker, capfd):
    with capfd.disabled():
        path = os.path.realpath('test_data/file.html')
        mocker.patch.object(demisto, 'args', return_value={'EntryID': 'test'})
        mocker.patch.object(demisto, 'getFilePath', return_value={"path": path})
        mocker.patch.object(os, 'rename')
        mocker.patch.object(os.path, 'realpath', return_value=f'{os.getcwd()}/test_data/file.html')
        mocker_output = mocker.patch('rasterize.return_results')
        mocker.patch.object(rasterize, 'support_multithreading')
        rasterize_html_command()
        assert mocker_output.call_args.args[0]['File'] == 'email.png'


@pytest.fixture
def http_wait_server():
    # Simple http handler which waits 10 seconds before responding
    class WaitHanlder(http.server.BaseHTTPRequestHandler):

        def do_HEAD(self):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

        def do_GET(self):
            time.sleep(10)
            try:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes("<html><head><title>Test wait handler</title></head>"
                                       "<body><p>Test Wait</p></body></html>", 'utf-8'))
                self.flush_headers()
            except BrokenPipeError:  # ignore broken pipe as socket might have been closed
                pass

        # disable logging

        def log_message(self, format, *args):
            pass

    with http.server.ThreadingHTTPServer(('', 10888), WaitHanlder) as server:
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.start()
        yield
        server.shutdown()
        server_thread.join()


# Some web servers can block the connection after the http is sent
# In this case chromium will hang. An example for this is:
# curl -v -H 'user-agent: HeadlessChrome' --max-time 10  "http://www.grainger.com/"  # disable-secrets-detection
# This tests access a server which waits for 10 seconds and makes sure we timeout
@pytest.mark.filterwarnings('ignore::ResourceWarning')
def test_rasterize_url_long_load(mocker: MockerFixture, http_wait_server, capfd):
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    time.sleep(1)  # give time to the server to start
    with capfd.disabled():
        mocker.patch.object(rasterize, 'support_multithreading')
        perform_rasterize('http://localhost:10888', width=250, height=250,
                          rasterize_type=RasterizeType.PNG, navigation_timeout=5)
        assert return_error_mock.call_count == 1
        # call_args last call with a tuple of args list and kwargs
        # err_msg = return_error_mock.call_args[0][0]
        # assert 'Timeout exception' in err_msg
        return_error_mock.reset_mock()
        # test that with a higher value we get a response
        assert perform_rasterize('http://localhost:10888', width=250, height=250, rasterize_type=RasterizeType.PNG)
        assert not return_error_mock.called


@pytest.mark.filterwarnings('ignore::ResourceWarning')
def test_rasterize_image_to_pdf(mocker):
    path = os.path.realpath('test_data/image.png')
    mocker.patch.object(demisto, 'args', return_value={'EntryID': 'test'})
    mocker.patch.object(demisto, 'getFilePath', return_value={"path": path})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(rasterize, 'support_multithreading')
    rasterize_image_command()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0][0]['Type'] == entryTypes['entryInfoFile']


TEST_DATA = [
    (
        'test_data/many_pages.pdf',
        21,
        21,
        None
    ),
    (
        'test_data/many_pages.pdf',
        20,
        20,
        None
    ),
    (
        'test_data/many_pages.pdf',
        '*',
        51,
        None
    ),
    (
        'test_data/test_pw_mathias.pdf',
        '*',
        1,
        'mathias',
    )
]


@pytest.mark.parametrize('file_path, max_pages, expected_length, pw', TEST_DATA)
def test_convert_pdf_to_jpeg(file_path, max_pages, expected_length, pw):
    res = convert_pdf_to_jpeg(file_path, max_pages, pw)

    assert type(res) is list
    assert len(res) == expected_length


@pytest.mark.parametrize('width, height, expected_width, expected_height', [
    (8001, 700, 8000, 700),
    (700, 80001, 700, 8000),
    (700, 600, 700, 600)
])
def test_get_width_height(width, height, expected_width, expected_height):
    """
        Given:
            1. A width that is larger than the safeguard limit, and a valid height
            2. A height that is larger than the safeguard limit, and a valid width
            3. Valid width and height
        When:
            - Running the 'heck_width_and_height' function.
        Then:
            Verify that:
            1. The resulted width is the safeguard limit (8000px) and the height remains as it was.
            2. The resulted height is the safeguard limit (8000px) and the width remains as it was.
            3. Both width and height remain as they were.
    """
    args = {
        'width': str(width),
        'height': str(height)
    }
    w, h = get_width_height(args)
    assert w == expected_width
    assert h == expected_height


class TestRasterizeIncludeUrl:
    class MockChromeOptions:

        def __init__(self) -> None:
            self.options = []

        def add_argument(self, arg):
            self.options.append(arg)

    class MockChrome:

        def __init__(self, options, service) -> None:
            self.options = options.options
            self.page_source = ''
            self.session_id = 'session_id'

        def set_page_load_timeout(self, max_page_load_time):
            pass

        def get(self, path):
            pass

        def maximize_window(self):
            pass

        def implicitly_wait(self, arg):
            pass

        def set_window_size(self, width, height):
            pass

        def get_screenshot_as_png(self):
            return 'image'

        def quit(self):
            pass

    @pytest.mark.parametrize('include_url', [False, True])
    def test_sanity_rasterize_with_include_url(self, mocker, include_url, capfd):
        """
            Given:
                - A parameter that mention whether to include the URL bar in the screenshot.
            When:
                - Running the 'rasterize' function.
            Then:
                - Verify that it runs as expected.
        """
        mocker.patch('os.remove')

        with capfd.disabled(), NamedTemporaryFile('w+') as f:
            f.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                    '</head><body><br>---------- TEST FILE ----------<br></body></html>')
            path = os.path.realpath(f.name)
            f.flush()

            mocker.patch.object(rasterize, 'support_multithreading')
            image = perform_rasterize(path=f'file://{path}', width=250, height=250, rasterize_type=RasterizeType.PNG,
                                      include_url=include_url)
            assert image


def test_log_warning():
    """
    Given   pypdf's logger instance
    When    checking the logger's level.
    Then    make sure the level is ERROR
    """
    import logging
    from rasterize import pypdf_logger
    assert pypdf_logger.level == logging.ERROR
    assert pypdf_logger.level == logging.ERROR


def test_excepthook_recv_loop(mocker):
    """
    Given   Exceptions that might happen after the tab was closed.
    When    A chromium tab is closed.
    Then    make sure the right info is logged.
    """
    mock_args = type('mock_args', (), dict.fromkeys(('exc_type', 'exc_value')))
    demisto_info = mocker.patch.object(demisto, 'info')

    excepthook_recv_loop(mock_args)

    demisto_info.assert_any_call('Unsuppressed Exception in _recv_loop: args.exc_type=None')
    demisto_info.assert_any_call('Unsuppressed Exception in _recv_loop: args.exc_type=None, empty exc_value')


def test_poppler_version():
    import pdf2image
    poppler_version = pdf2image.pdf2image._get_poppler_version("pdftoppm")
    assert poppler_version[0] > 20


def test_get_list_item():
    from rasterize import get_list_item

    my_list = ['a', 'b', 'c']

    assert get_list_item(my_list, 0, "FOO") == 'a'
    assert get_list_item(my_list, 1, "FOO") == 'b'
    assert get_list_item(my_list, 2, "FOO") == 'c'
    assert get_list_item(my_list, 3, "FOO") == 'FOO'
    assert get_list_item(my_list, 4, "FOO") == 'FOO'


def test_add_filename_suffix():
    from rasterize import add_filename_suffix

    my_list = ['a', 'b', 'c']
    my_list_with_suffix = add_filename_suffix(my_list, 'sfx')

    assert len(my_list) == len(my_list_with_suffix)
    for current_element_index, _ in enumerate(my_list):
        assert f'{my_list[current_element_index]}.sfx' == my_list_with_suffix[current_element_index]


def test_get_output_filenames():
    from rasterize import get_list_item, add_filename_suffix

    file_name = ['foo_01', 'foo_02', 'foo_03']
    file_names = argToList(file_name)
    file_names = add_filename_suffix(file_names, 'png')

    assert get_list_item(file_names, 0, "FOO.png") == 'foo_01.png'
    assert get_list_item(file_names, 1, "FOO.png") == 'foo_02.png'
    assert get_list_item(file_names, 2, "FOO.png") == 'foo_03.png'
    assert get_list_item(file_names, 3, "FOO.png") == 'FOO.png'
    assert get_list_item(file_names, 4, "FOO.png") == 'FOO.png'


def test_chrome_manager_case_chrome_instances_file_is_empty(mocker):
    """
    Given   instance id and chrome options
    When    chrome instances file is empty
    Then    make sure code running into case 1 calling generate_new_chrome_instance which return browser and chrome port.
    """
    from rasterize import chrome_manager

    instance_id = "new_instance_id"
    chrome_options = "new_chrome_options"

    mock_context = {
        'context': {
            'IntegrationInstanceID': instance_id
        }
    }

    params = {
        'chrome_options': chrome_options
    }

    mocker.patch.object(demisto, 'callingContext', mock_context)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(rasterize, 'read_json_file', return_value={})
    generate_new_chrome_instance_mocker = mocker.patch.object(rasterize, 'generate_new_chrome_instance',
                                                              return_value=["browser_object", "chrome_port"])
    terminate_chrome_mocker = mocker.patch.object(rasterize, 'terminate_chrome', return_value=None)
    browser, chrome_port = chrome_manager()

    assert generate_new_chrome_instance_mocker.call_count == 1
    assert generate_new_chrome_instance_mocker.called_with(instance_id, chrome_options)
    assert terminate_chrome_mocker.call_count == 0
    assert browser == "browser_object"
    assert chrome_port == "chrome_port"


def test_chrome_manager_case_chromes_options_exist_and_instance_id_not_linked(mocker):
    """
    Given   instance id that does not exist and chrome options that exist in the chrome instances file
    When    chrome instances file is not empty and instance id is not linked to the chrome options
    Then    make sure code running into case 2 and calling generate_new_chrome_instance which return browser and chrome port.
    """
    from rasterize import chrome_manager, read_json_file

    instance_id = "instance_id_that_does_not_exist"
    chrome_options = "chrome_options2"

    mock_context = {
        'context': {
            'IntegrationInstanceID': instance_id
        }
    }

    params = {
        'chrome_options': chrome_options
    }

    mock_file_content = read_json_file("test_data/chrome_instances.json")
    mocker.patch.object(demisto, 'callingContext', mock_context)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(rasterize, 'read_json_file', return_value=mock_file_content)
    generate_new_chrome_instance_mocker = mocker.patch.object(rasterize, 'generate_new_chrome_instance',
                                                              return_value=["browser_object", "chrome_port"])
    terminate_chrome_mocker = mocker.patch.object(rasterize, 'terminate_chrome', return_value=None)
    browser, chrome_port = chrome_manager()

    assert generate_new_chrome_instance_mocker.call_count == 1
    assert generate_new_chrome_instance_mocker.called_with(instance_id, chrome_options)
    assert terminate_chrome_mocker.call_count == 0
    assert browser == "browser_object"
    assert chrome_port == "chrome_port"


def test_chrome_manager_case_new_chrome_options_and_instance_id(mocker):
    """
    Given   instance id and chrome options does not exist in the chrome instances file
    When    chrome instances file is not empty
    Then    make sure code running into case 3 and calling generate_new_chrome_instance which return browser and chrome port.
    """
    from rasterize import chrome_manager, read_json_file

    instance_id = "instance_id_that_does_not_exist"
    chrome_options = "chrome_options_that_does_not_exist"

    mock_context = {
        'context': {
            'IntegrationInstanceID': instance_id
        }
    }

    params = {
        'chrome_options': chrome_options
    }

    mock_file_content = read_json_file("test_data/chrome_instances.json")

    mocker.patch.object(demisto, 'callingContext', mock_context)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(rasterize, 'read_json_file', return_value=mock_file_content)
    generate_new_chrome_instance_mocker = mocker.patch.object(rasterize, 'generate_new_chrome_instance',
                                                              return_value=["browser_object", "chrome_port"])
    terminate_chrome_mocker = mocker.patch.object(rasterize, 'terminate_chrome', return_value=None)
    browser, chrome_port = chrome_manager()

    assert generate_new_chrome_instance_mocker.call_count == 1
    assert generate_new_chrome_instance_mocker.called_with(instance_id, chrome_options)
    assert terminate_chrome_mocker.call_count == 0
    assert browser == "browser_object"
    assert chrome_port == "chrome_port"


def test_chrome_manager_case_instance_id_exist_but_new_chrome_options(mocker):
    """
    Given   instance id exist and chrome options does not exist in the chrome instances file
    When    chrome instances file is not empty and instance id has different chrome options
    Then    make sure code running into case 4, terminating old chrome port, generating new one,
            and update the chrome instances file.
    """
    from rasterize import chrome_manager, read_json_file

    instance_id = "22222222-2222-2222-2222-222222222222"  # exist
    chrome_options = "chrome_options_that_does_not_exist"

    mock_context = {
        'context': {
            'IntegrationInstanceID': instance_id
        }
    }

    params = {
        'chrome_options': chrome_options
    }

    mock_file_content = read_json_file("test_data/chrome_instances.json")

    mocker.patch.object(demisto, 'callingContext', mock_context)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(rasterize, 'read_json_file', return_value=mock_file_content)

    mocker.patch.object(rasterize, 'get_chrome_browser', return_value=None)
    terminate_chrome_mocker = mocker.patch.object(rasterize, 'terminate_chrome', return_value=None)
    generate_new_chrome_instance_mocker = mocker.patch.object(rasterize, 'generate_new_chrome_instance',
                                                              return_value=["browser_object", "chrome_port"])
    browser, chrome_port = chrome_manager()

    assert terminate_chrome_mocker.call_count == 1
    assert generate_new_chrome_instance_mocker.call_count == 1
    assert generate_new_chrome_instance_mocker.called_with(instance_id, chrome_options)
    assert browser == "browser_object"
    assert chrome_port == "chrome_port"


def test_chrome_manager_case_instance_id_and_chrome_options_exist_and_linked(mocker):
    """
    Given   instance id and chrome options
    When    chrome instances file is not empty, and instance id and chrome options linked.
    Then    make sure code running into case 5 and using the browser that already in used.
    """
    from rasterize import chrome_manager, read_json_file

    instance_id = "22222222-2222-2222-2222-222222222222"  # exist
    chrome_options = "chrome_options2"

    mock_context = {
        'context': {
            'IntegrationInstanceID': instance_id
        }
    }

    params = {
        'chrome_options': chrome_options
    }

    mock_file_content = read_json_file("test_data/chrome_instances.json")

    mocker.patch.object(demisto, 'callingContext', mock_context)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(rasterize, 'read_json_file', return_value=mock_file_content)

    mocker.patch.object(rasterize, 'get_chrome_browser', return_value="browser_object")
    terminate_chrome_mocker = mocker.patch.object(rasterize, 'terminate_chrome', return_value=None)
    generate_new_chrome_instance_mocker = mocker.patch.object(rasterize, 'generate_new_chrome_instance',
                                                              return_value=["browser_object", "chrome_port"])
    browser, chrome_port = chrome_manager()
    assert terminate_chrome_mocker.call_count == 0
    assert generate_new_chrome_instance_mocker.call_count == 0
    assert browser == "browser_object"
    assert chrome_port == "2222"


def test_generate_chrome_port():
    """
    Given   first_chrome_port and max_chromes_count
    When    needed to generate new chrome port
    Then    make sure the function generate valid chrome port.
    """
    from rasterize import generate_chrome_port
    port = generate_chrome_port()
    assert 0 <= len(port) <= 5


def test_generate_chrome_port_no_port_available(mocker):
    """
    Given   first_chrome_port and max_chromes_count that creates empty range
    When    needed to generate new chrome port
    Then    make sure the function will raise an error and return None
    """
    from rasterize import generate_chrome_port
    rasterize.FIRST_CHROME_PORT = 0
    rasterize.MAX_CHROMES_COUNT = 0
    mock_return_error = mocker.patch.object(demisto, 'error', return_value=None)
    port = generate_chrome_port()
    assert mock_return_error.call_count == 1
    assert not port


def test_get_chrome_browser_error(mocker: MockerFixture):
    """
    Given   A connection error.
    When    Launching a pychrome browser.
    Then    Make sure the error is caught and debugged properly.
    """
    from rasterize import get_chrome_browser

    def raise_connection_error(url):
        raise requests.exceptions.ConnectionError('connection error')
    mocker.patch.object(rasterize, 'count_running_chromes', return_value=1)
    mocker.patch('pychrome.Browser', side_effect=raise_connection_error)
    mocker.patch('time.sleep')
    debug = mocker.patch.object(demisto, 'debug')

    res = get_chrome_browser('port')

    assert res is None
    debug.assert_called_with(
        "Failed to connect to Chrome on port port on iteration 4. ConnectionError,"
        " exp_str='connection error', exp=ConnectionError('connection error')")


def test_backoff(mocker):
    """
    Given   Waiting for a process to complete.
    When    Launching a pychrome browser.
    Then    Make sure to wait the required amount.
    """
    from rasterize import backoff

    sleep_mock = mocker.patch('time.sleep')

    res = backoff(None, 2, 1)

    assert res == (None, 2)
    sleep_mock.assert_called_with(1)


def test_is_mailto_urls(mocker: MockerFixture):
    """
    Given   A mailto URL is called.
    When    Attempting to make a screenshot.
    Then    Make sure the correct output is returned.
    """
    from rasterize import screenshot_image

    mocker.patch(
        'rasterize.navigate_to_path',
        return_results=type('PychromeEventHandler', (), {'is_mailto': True})
    )

    res = screenshot_image(None, None, 'url', None, None)

    assert res == (None, 'URLs that start with "mailto:" cannot be rasterized.\nURL: url')


def test_increase_counter_chrome_instances_file(mocker):
    """
    Given:
        - A new Chrome instance content
        - A valid Chrome port
        - An increase counter
        - A terminate port
    When:
        - Executing the increase_counter_chrome_instances_file function
    Then:
        - The function writes to the correct file and increase the "RASTERIZATION_COUNT" by 1
    """
    from rasterize import increase_counter_chrome_instances_file, RASTERIZATION_COUNT
    from unittest.mock import mock_open
    mocker.patch("os.path.exists", return_value=True)
    mock_file_content = util_load_json("test_data/chrome_instances.json")
    expected_rasterization_count = mock_file_content['2222'][RASTERIZATION_COUNT] + 1
    mock_file = mock_open()
    mocker.patch("builtins.open", mock_file)
    mocker.patch.object(json, 'load', return_value=mock_file_content)
    mocker_json = mocker.patch("json.dump")
    increase_counter_chrome_instances_file(chrome_port="2222")
    assert mocker_json.called
    assert expected_rasterization_count == mocker_json.call_args[0][0]['2222'][RASTERIZATION_COUNT]


def test_add_new_chrome_instance(mocker):
    """
    Given:
        - A new Chrome instance content
    When:
        - Executing the add_new_chrome_instance function
    Then:
        - The function writes to the correct file the new chrome instance.
    """
    from rasterize import add_new_chrome_instance
    from unittest.mock import mock_open
    mocker.patch("os.path.exists", return_value=True)
    mock_file_content = util_load_json("test_data/chrome_instances.json")
    mock_file = mock_open()
    mocker.patch("builtins.open", mock_file)
    mocker.patch.object(json, 'load', return_value=mock_file_content)
    mocker_json = mocker.patch("json.dump")
    add_new_chrome_instance(new_chrome_instance_content={"9345": {
        "instance_id": "44444444-4444-4444-4444-444444444444",
        "chrome_options": "chrome_options4",
        "rasterize_count": 1
    }})
    assert mocker_json.called
    assert '9345' in mocker_json.call_args[0][0]


def test_terminate_port_chrome_instances_file(mocker):
    """
    Given:
        - A port to terminate.
    When:
        - Executing the terminate_port_chrome_instances_file function
    Then:
        - The function writes to the correct file the data without the port to terminate.
    """
    from rasterize import terminate_port_chrome_instances_file
    from unittest.mock import mock_open
    mocker.patch("os.path.exists", return_value=True)
    mock_file_content = util_load_json("test_data/chrome_instances.json")
    mock_file = mock_open()
    mocker.patch("builtins.open", mock_file)
    mocker.patch.object(json, 'load', return_value=mock_file_content)
    mocker_json = mocker.patch("json.dump")
    terminate_port_chrome_instances_file(chrome_port="2222")
    assert mocker_json.called
    assert '2222' not in mocker_json.call_args[0][0]


def test_write_chrome_instances_empty(mocker):
    """
    Given:
        - A new Chrome instance content(first chrome instance).
    When:
        - Executing the write_chrome_instances_file function
    Then:
        - The function creates and writes to the correct file, calls json.dump with the expected arguments.
    """
    from rasterize import write_chrome_instances_file
    from unittest.mock import mock_open
    mock_file_content = util_load_json("test_data/chrome_instances.json")
    mock_file = mock_open()
    mocker.patch("builtins.open", mock_file)
    mocker_json = mocker.patch.object(json, 'dump', return_value=mock_file_content)
    write_chrome_instances_file(new_chrome_content=mock_file_content)

    assert mocker_json.call_count == 1


def test_read_json_file(mocker):
    """
    Given:
        - A JSON file at 'test_data/chrome_instances.json'
    When:
        - Executing the read_json_file function
    Then:
        - The function reads the JSON file and returns the correct content.
    """
    from rasterize import read_json_file
    mocker.patch("os.path.exists", return_value=True)
    mock_file_content = util_load_json("test_data/chrome_instances.json")
    file_result = read_json_file("test_data/chrome_instances.json")
    assert file_result == mock_file_content


def test_rasterize_mailto(capfd, mocker):
    """
        Given:
            - mailto argument as path.
        When:
            - Running the 'rasterize' function.
        Then:
            - Verify that perform_rasterize exit with the expected error message.
    """
    mocker_output = mocker.patch('rasterize.return_results')

    with pytest.raises(SystemExit) as excinfo, capfd.disabled():
        perform_rasterize(path='mailto:some.person@gmail.com', width=250, height=250, rasterize_type=RasterizeType.PNG)

    assert mocker_output.call_args.args[0].readable_output == 'URLs that start with "mailto:" cannot be rasterized.' \
                                                              '\nURL: [\'mailto:some.person@gmail.com\']'
    assert excinfo.type is SystemExit
    assert excinfo.value.code == 0


def test_handle_request_paused(mocker):
    """
        Given:
            - cloudflare.com as BLOCKED_URLS parameter.
        When:
            - Running the 'handle_request_paused' function.
        Then:
            - Verify that tab.Fetch.failRequest executed with the correct requestId and errorReason Aborted
    """

    mocker.patch('rasterize.BLOCKED_URLS', ['cloudflare.com'])
    kwargs = {'requestId': '1', 'request': {'url': 'cloudflare.com'}}
    mock_tab = MagicMock(spec=pychrome.Tab)
    mock_fetch = mocker.MagicMock()
    mock_fetch.disable = MagicMock()
    mock_fail_request = mocker.patch.object(mock_fetch, 'failRequest', new_callable=MagicMock)
    mock_tab.Fetch = mock_fetch
    tab_event_handler = PychromeEventHandler(None, mock_tab, None)

    tab_event_handler.handle_request_paused(**kwargs)

    assert mock_fail_request.call_args[1]['requestId'] == '1'
    assert mock_fail_request.call_args[1]['errorReason'] == 'Aborted'


def test_chrome_manager_one_port_use_same_port(mocker):
    """
    Given:
        - instance id and chrome options.
    When:
        - Executing the chrome_manager_one_port function
    Then:
        - The function writes to the correct file the data and selects a port that already use the given chrome_option.
    """
    from rasterize import chrome_manager_one_port, read_json_file

    instance_id = "22222222-2222-2222-2222-222222222221"  # not exist
    chrome_options = "chrome_options2"

    mock_context = {
        'context': {
            'IntegrationInstanceID': instance_id
        }
    }

    params = {
        'chrome_options': chrome_options
    }

    mock_file_content = read_json_file("test_data/chrome_instances.json")

    mocker.patch.object(demisto, 'callingContext', mock_context)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(rasterize, 'read_json_file', return_value=mock_file_content)

    mocker.patch.object(rasterize, 'get_chrome_browser', return_value="browser_object")

    browser, chrome_port = chrome_manager_one_port()
    assert browser == "browser_object"
    assert chrome_port == "2222"


def test_chrome_manager_one_port_open_new_port(mocker):
    """
    Given:
        - instance id and chrome options.
    When:
        - Executing the chrome_manager_one_port function
    Then:
        - The function terminate all the ports that are open in chrome_manager, and opens a new chrome port to use.
    """
    from rasterize import chrome_manager_one_port, read_json_file

    instance_id = "22222222-2222-2222-2222-222222222221"  # not exist
    chrome_options = "new_chrome_options"

    mock_context = {
        'context': {
            'IntegrationInstanceID': instance_id
        }
    }

    params = {
        'chrome_options': chrome_options
    }

    mock_file_content = read_json_file("test_data/chrome_instances.json")

    mocker.patch.object(demisto, 'callingContext', mock_context)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(rasterize, 'read_json_file', return_value=mock_file_content)

    mocker.patch.object(rasterize, 'get_chrome_browser', return_value="browser_object")
    terminate_chrome_mocker = mocker.patch.object(rasterize, 'terminate_chrome', return_value=None)
    generate_new_chrome_instance_mocker = mocker.patch.object(rasterize, 'generate_new_chrome_instance',
                                                              return_value=["browser_object", "chrome_port"])

    browser, chrome_port = chrome_manager_one_port()
    assert terminate_chrome_mocker.call_count == 3
    assert generate_new_chrome_instance_mocker.call_count == 1
    assert browser == "browser_object"
    assert chrome_port == "chrome_port"


def test_rasterize_email_command_default_arge(mocker):
    """
    Given: A valid HTML email body
    When: The rasterize_email_command function is called
    Then: The function should generate a PNG (default) image and return it as a file result
    """
    from rasterize import rasterize_email_command

    mock_args = {
        'htmlBody': '<p>Test email body</p>',
        'width': '1000px',
        'height': '1500px',
    }
    mocker.patch.object(demisto, 'args', return_value=mock_args)
    mock_perform_rasterize = mocker.patch('rasterize.perform_rasterize', return_value=[('image_data', None)])
    mock_file_result = mocker.patch('rasterize.fileResult', return_value={'Type': 'image'})
    mock_uuid = mocker.patch('rasterize.uuid.uuid4', return_value='abcd-1234')
    mocker.patch.object(demisto, 'results')

    rasterize_email_command()

    mock_file_result.assert_called_once_with(filename=f'{mock_uuid.return_value}.png', data='image_data')
    mock_perform_rasterize.assert_called_once_with(
        path=mocker.ANY,
        rasterize_type=RasterizeType.PNG,
        width=1000,
        height=1500,
        offline_mode=False,
        navigation_timeout=180,
        full_screen=False
    )


def test_rasterize_email_command_png(mocker):
    """
    Given: A valid HTML email body and PNG output type
    When: The rasterize_email_command function is called
    Then: The function should generate a PNG image and return it as a file result
    """
    from rasterize import rasterize_email_command

    mock_args = {
        'htmlBody': '<p>Test email body</p>',
        'width': '800',
        'height': '600',
        'file_name': 'test_email'
    }
    mocker.patch.object(demisto, 'args', return_value=mock_args)
    mocker.patch('rasterize.perform_rasterize', return_value=[('image_data', None)])
    mock_file_result = mocker.patch('rasterize.fileResult', return_value={'Type': 'image'})
    mock_results = mocker.patch.object(demisto, 'results')

    rasterize_email_command()

    mock_file_result.assert_called_once_with(filename='test_email.png', data='image_data')
    mock_results.assert_called_once()


def test_rasterize_email_command_pdf(mocker):
    """
    Given: A valid HTML email body and PDF output type
    When: The rasterize_email_command function is called
    Then: The function should generate a PDF file and return it as a file result
    """
    from rasterize import rasterize_email_command

    mock_args = {
        'htmlBody': '<p>Test email body</p>',
        'width': '800',
        'height': '600',
        'type': 'pdf',
        'file_name': 'test_email'
    }
    mocker.patch.object(demisto, 'args', return_value=mock_args)
    mocker.patch('rasterize.perform_rasterize', return_value=[('pdf_data', None)])
    mock_file_result = mocker.patch('rasterize.fileResult', return_value={'Type': 'file'})
    mock_results = mocker.patch.object(demisto, 'results')

    rasterize_email_command()

    mock_file_result.assert_called_once_with(filename='test_email.pdf', data='pdf_data')
    mock_results.assert_called_once()


def test_rasterize_email_command_full_screen(mocker):
    """
    Given: A valid HTML email body and full_screen option set to true
    When: The rasterize_email_command function is called
    Then: The perform_rasterize function should be called with full_screen=True
    """
    from rasterize import rasterize_email_command

    mock_args = {
        'htmlBody': '<p>Test email body</p>',
        'full_screen': 'true',
        'type': 'png',
        'file_name': 'test_email'
    }
    mocker.patch.object(demisto, 'args', return_value=mock_args)
    mock_perform_rasterize = mocker.patch('rasterize.perform_rasterize', return_value=[('image_data', None)])
    mock_file_result = mocker.patch('rasterize.fileResult', return_value={'Type': 'image'})
    mocker.patch.object(demisto, 'results')

    rasterize_email_command()

    mock_file_result.assert_called_once_with(filename='test_email.png', data='image_data')
    mock_perform_rasterize.assert_called_once_with(
        path=mocker.ANY,
        rasterize_type=mocker.ANY,
        width=mocker.ANY,
        height=mocker.ANY,
        offline_mode=mocker.ANY,
        navigation_timeout=mocker.ANY,
        full_screen=True
    )


def test_rasterize_email_command_offline_mode(mocker):
    """
    Given: A valid HTML email body and offline mode set to true
    When: The rasterize_email_command function is called
    Then: The perform_rasterize function should be called with offline_mode=True
    """
    from rasterize import rasterize_email_command

    mock_args = {
        'htmlBody': '<p>Test email body</p>',
        'offline': 'true',
        'type': 'png',
        'file_name': 'test_email'
    }
    mocker.patch.object(demisto, 'args', return_value=mock_args)
    mock_perform_rasterize = mocker.patch('rasterize.perform_rasterize', return_value=[('image_data', None)])
    mocker.patch('rasterize.fileResult', return_value={'Type': 'image'})
    mocker.patch.object(demisto, 'results')

    rasterize_email_command()

    mock_perform_rasterize.assert_called_once_with(
        path=mocker.ANY,
        rasterize_type=mocker.ANY,
        width=mocker.ANY,
        height=mocker.ANY,
        offline_mode=True,
        navigation_timeout=mocker.ANY,
        full_screen=mocker.ANY
    )


def test_rasterize_email_command_custom_navigation_timeout(mocker):
    """
    Given: A valid HTML email body and a custom navigation timeout
    When: The rasterize_email_command function is called
    Then: The perform_rasterize function should be called with the specified navigation_timeout
    """
    from rasterize import rasterize_email_command

    mock_args = {
        'htmlBody': '<p>Test email body</p>',
        'max_page_load_time': '30',
        'type': 'png',
        'file_name': 'test_email'
    }
    mocker.patch.object(demisto, 'args', return_value=mock_args)
    mock_perform_rasterize = mocker.patch('rasterize.perform_rasterize', return_value=[('image_data', None)])
    mocker.patch('rasterize.fileResult', return_value={'Type': 'image'})
    mocker.patch.object(demisto, 'results')

    rasterize_email_command()

    mock_perform_rasterize.assert_called_once_with(
        path=mocker.ANY,
        rasterize_type=mocker.ANY,
        width=mocker.ANY,
        height=mocker.ANY,
        offline_mode=mocker.ANY,
        navigation_timeout=30,
        full_screen=mocker.ANY
    )


def test_rasterize_email_command_error_handling(mocker):
    """
    Given: A scenario where perform_rasterize raises an exception
    When: The rasterize_email_command function is called
    Then: The function should log the error and return an error message
    """
    from rasterize import rasterize_email_command

    mock_args = {
        'htmlBody': '<p>Test email body</p>',
        'type': 'png',
        'file_name': 'test_email'
    }
    mocker.patch.object(demisto, 'args', return_value=mock_args)
    mocker.patch('rasterize.perform_rasterize', side_effect=Exception('Test error'))
    mock_error = mocker.patch.object(demisto, 'error')

    with pytest.raises(SystemExit):
        rasterize_email_command()

    mock_error.assert_called_once_with('Test error')
