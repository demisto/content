from rasterize import (rasterize, find_zombie_processes, merge_options, DEFAULT_CHROME_OPTIONS, rasterize_image_command,
                       RasterizeMode, RasterizeType, init_driver, rasterize_html_command)
import demistomock as demisto
from CommonServerPython import entryTypes
from tempfile import NamedTemporaryFile
import subprocess
import os
import logging
import http.server
import time
import threading
import pytest
from selenium import webdriver
from pyvirtualdisplay import Display
from unittest.mock import mock_open, Mock

# disable warning from urllib3. these are emitted when python driver can't connect to chrome yet
logging.getLogger("urllib3").setLevel(logging.ERROR)

RETURN_ERROR_TARGET = 'rasterize.return_error'


@pytest.mark.parametrize("r_mode", [RasterizeMode.WEBDRIVER_ONLY, RasterizeMode.HEADLESS_CLI_ONLY])
def test_rasterize_email_image(r_mode, caplog):
    with NamedTemporaryFile('w+') as f:
        f.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        path = os.path.realpath(f.name)
        f.flush()
        rasterize(path=f'file://{path}', width=250, height=250, r_type=RasterizeType.PNG, r_mode=r_mode)
        caplog.clear()


@pytest.mark.parametrize("r_mode", [RasterizeMode.WEBDRIVER_ONLY, RasterizeMode.HEADLESS_CLI_ONLY])
def test_rasterize_email_pdf(r_mode, caplog):
    with NamedTemporaryFile('w+') as f:
        f.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        path = os.path.realpath(f.name)
        f.flush()
        rasterize(path=f'file://{path}', width=250, height=250, r_type=RasterizeType.PDF, offline_mode=False,
                  r_mode=r_mode)
        caplog.clear()


def test_rasterize_email_pdf_offline(caplog):
    with NamedTemporaryFile('w+') as f:
        f.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        path = os.path.realpath(f.name)
        f.flush()
        rasterize(path=f'file://{path}', width=250, height=250, r_type=RasterizeType.PDF, offline_mode=True)
        caplog.clear()


def test_rasterize_no_defunct_processes(caplog):
    with NamedTemporaryFile('w+') as f:
        f.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        path = os.path.realpath(f.name)
        f.flush()
        rasterize(path=f'file://{path}', width=250, height=250, r_type=RasterizeType.PDF, offline_mode=False)
        process = subprocess.Popen(['ps', '-aux'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True)
        processes_str, _ = process.communicate()
        processes = processes_str.split('\n')
        defunct_process_list = [process for process in processes if 'defunct' in process]
        assert not defunct_process_list

        zombies, output = find_zombie_processes()
        assert not zombies
        assert 'defunct' not in output
        caplog.clear()


@pytest.mark.filterwarnings('ignore::ResourceWarning')
def test_find_zombie_processes(mocker):
    ps_output = '''   PID  PPID S CMD
    1     0 S python /tmp/pyrunner/_script_docker_python_loop.py
   39     1 Z [soffice.bin] <defunct>
   55     1 Z [gpgconf] <defunct>
   57     1 Z [gpgconf] <defunct>
   59     1 Z [gpg] <defunct>
   61     1 Z [gpgsm] <defunct>
   63     1 Z [gpgconf] <defunct>
   98     1 Z [gpgconf] <defunct>
  100     1 Z [gpgconf] <defunct>
  102     1 Z [gpg] <defunct>
'''
    mocker.patch.object(subprocess, 'check_output', return_value=ps_output)
    mocker.patch.object(os, 'getpid', return_value=1)
    zombies, output = find_zombie_processes()

    assert len(zombies) == 9
    assert output == ps_output


def test_merge_options():
    res = merge_options(DEFAULT_CHROME_OPTIONS, '')
    assert res == DEFAULT_CHROME_OPTIONS
    res = merge_options(DEFAULT_CHROME_OPTIONS, '[--disable-dev-shm-usage],--disable-auto-reload, --headless')
    assert '--disable-dev-shm-usage' not in res
    assert '--no-sandbox' in res  # part of default options
    assert '--disable-auto-reload' in res
    assert len([x for x in res if x == '--headless']) == 1  # should have only one headless option
    res = merge_options(DEFAULT_CHROME_OPTIONS, r'--user-agent=test\,comma')
    assert len([x for x in res if x.startswith('--user-agent')]) == 1
    assert '--user-agent=test,comma' in res
    res = merge_options(DEFAULT_CHROME_OPTIONS, r'[--user-agent]')  # remove user agent
    assert len([x for x in res if x.startswith('--user-agent')]) == 0


@pytest.mark.parametrize("r_mode", [RasterizeMode.WEBDRIVER_ONLY, RasterizeMode.HEADLESS_CLI_ONLY])
def test_rasterize_large_html(r_mode):
    path = os.path.realpath('test_data/large.html')
    res = rasterize(path=f'file://{path}', width=250, height=250, r_type=RasterizeType.PNG, r_mode=r_mode)
    assert res


def test_rasterize_html(mocker):
    path = os.path.realpath('test_data/file.html')
    mocker.patch.object(demisto, 'args', return_value={'EntryID': 'test'})
    mocker.patch.object(demisto, 'getFilePath', return_value={"path": path})
    mocker.patch.object(os, 'rename')
    mocker.patch.object(os.path, 'realpath', return_value=f'{os.getcwd()}/test_data/file.html')
    mocker_output = mocker.patch('rasterize.return_results')
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
@pytest.mark.parametrize("r_mode", [RasterizeMode.WEBDRIVER_ONLY, RasterizeMode.HEADLESS_CLI_ONLY,
                                    RasterizeMode.WEBDRIVER_PREFERED, RasterizeMode.HEADLESS_CLI_PREFERED])
def test_rasterize_url_long_load(r_mode, mocker, http_wait_server):
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    time.sleep(1)  # give time to the servrer to start
    rasterize('http://localhost:10888', width=250, height=250, r_type=RasterizeType.PNG, max_page_load_time=5,
              r_mode=r_mode)
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert 'Timeout exception' in err_msg
    return_error_mock.reset_mock()
    # test that with a higher value we get a response
    assert rasterize('http://localhost:10888', width=250, height=250, r_type=RasterizeType.PNG,
                     max_page_load_time=0, r_mode=r_mode)
    assert not return_error_mock.called


@pytest.mark.filterwarnings('ignore::ResourceWarning')
def test_rasterize_image_to_pdf(mocker):
    path = os.path.realpath('test_data/image.png')
    mocker.patch.object(demisto, 'args', return_value={'EntryID': 'test'})
    mocker.patch.object(demisto, 'getFilePath', return_value={"path": path})
    mocker.patch.object(demisto, 'results')
    rasterize_image_command()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['entryInfoFile']


TEST_DATA = [
    (
        'test_data/many_pages.pdf',
        21,
        2,
        None
    ),
    (
        'test_data/many_pages.pdf',
        20,
        1,
        None
    ),
    (
        'test_data/many_pages.pdf',
        '*',
        3,
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
    from rasterize import convert_pdf_to_jpeg
    res = convert_pdf_to_jpeg(file_path, max_pages, pw)

    assert type(res) == list
    assert len(res) == expected_length


@pytest.mark.parametrize('width, height, expected_width, expected_height', [
    (8001, 700, 8000, 700),
    (700, 80001, 700, 8000),
    (700, 600, 700, 600)
])
def test_check_width_and_height(width, height, expected_width, expected_height):
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
    from rasterize import check_width_and_height
    w, h = check_width_and_height(width, height)
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
    def test_headless_chrome_option(self, mocker, include_url):
        """
            Given:
                - A parameter that mention whether to include the URL bar in the screenshot.
            When:
                - Running the 'rasterize' function.
            Then:
                - Verify that it runs as expected.
        """
        mocker.patch.object(Display, 'start', retuen_value=None)
        mocker.patch.object(webdriver, 'Chrome', side_effect=self.MockChrome)
        mocker.patch.object(webdriver, 'ChromeOptions', side_effect=self.MockChromeOptions)

        driver = init_driver(include_url=include_url)

        assert ("--headless" in driver.options) != include_url

    @pytest.mark.parametrize('include_url', [False, True])
    def test_sanity_rasterize_with_include_url(self, mocker, include_url):
        """
            Given:
                - A parameter that mention whether to include the URL bar in the screenshot.
            When:
                - Running the 'rasterize' function.
            Then:
                - Verify that it runs as expected.
        """
        mocker.patch.object(Display, 'start', retuen_value=None)
        mocker.patch.object(Display, 'stop', retuen_value=None)
        mocker.patch.object(webdriver, 'Chrome', side_effect=self.MockChrome)
        mocker.patch.object(webdriver, 'ChromeOptions', side_effect=self.MockChromeOptions)

        mocker.patch('subprocess.run')
        mocker.patch('builtins.open', mock_open(read_data='image_sha'))
        mocker.patch('os.remove')

        image = rasterize(path='path', width=250, height=250, r_type=RasterizeType.PNG,
                          r_mode=RasterizeMode.WEBDRIVER_ONLY,
                          include_url=include_url)
        assert image


def test_rasterize_html_no_internet_access(mocker):
    """
    Validates that when calling the command rasterize_html_command
    No http requests are executed. - CIAC-8142
    """
    import requests
    mock = Mock()
    requests.get = mock
    path = os.path.realpath('test_data/file.html')
    mocker.patch.object(demisto, 'args', return_value={'EntryID': 'test'})
    mocker.patch.object(demisto, 'getFilePath', return_value={"path": path})
    mocker.patch.object(os, 'rename')
    mocker.patch.object(os.path, 'realpath', return_value=f'{os.getcwd()}/test_data/file.html')
    mocker_output = mocker.patch('rasterize.return_results')
    rasterize_html_command()
    assert mocker_output.call_args.args[0]['File'] == 'email.png'
    assert not mock.called
