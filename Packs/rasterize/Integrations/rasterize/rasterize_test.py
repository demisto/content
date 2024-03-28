import rasterize
from rasterize import *
import demistomock as demisto
from CommonServerPython import entryTypes
from tempfile import NamedTemporaryFile
import os
import logging
import http.server
import time
import threading
import pytest

# disable warning from urllib3. these are emitted when python driver can't connect to chrome yet
logging.getLogger("urllib3").setLevel(logging.ERROR)

RETURN_ERROR_TARGET = 'rasterize.return_error'


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
def test_rasterize_url_long_load(mocker, http_wait_server, capfd):
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    time.sleep(1)  # give time to the servrer to start
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

    assert type(res) == list
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
