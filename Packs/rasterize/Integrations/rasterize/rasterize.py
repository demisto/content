import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import base64
import os
import pychrome
import subprocess
import tempfile
import threading
import time
import traceback
import psutil
from enum import Enum
from threading import Event

from pdf2image import convert_from_path
from PIL import Image
from PyPDF2 import PdfReader


# region constants and configurations

# Chrome respects proxy env params
handle_proxy()
# Make sure our python code doesn't go through a proxy when communicating with chrome webdriver
os.environ['no_proxy'] = 'localhost,127.0.0.1'
# Needed for cases that rasterize is running with non-root user (docker hardening)
os.environ['HOME'] = tempfile.gettempdir()

# TODO: pass this to the start chrome shell script
CHROME_EXE = os.getenv('CHROME_EXE', '/opt/google/chrome/google-chrome')

# TODO: decide on a return error strategy (see return error or warning method) basically "should we fail silently"
WITH_ERRORS = demisto.params().get('with_error', True)

# The default wait time before taking a screenshot
DEFAULT_WAIT_TIME = max(int(demisto.params().get('wait_time', 0)), 0)
DEFAULT_PAGE_LOAD_TIME = int(demisto.params().get('max_page_load_time', 180))

# TODO: decide if we want to reuse it in several places
DEFAULT_RETRIES_COUNT = 4
DEFAULT_RETRY_WAIT_IN_SECONDS = 3
PAGES_LIMITATION = 20

# Consts for custom width and height
MAX_FULLSCREEN_WIDTH = 8000
MAX_FULLSCREEN_HEIGHT = 8000
DEFAULT_WIDTH, DEFAULT_HEIGHT = 600, 800

# Local Chrome
PORT = "9222"
LOCAL_HOST = "http://127.0.0.1"
LOCAL_CHROME_URL = f"{LOCAL_HOST}:{PORT}"


class RasterizeType(Enum):
    PNG = 'png'
    PDF = 'pdf'
    # TODO: handle JSON and selenium functions
    JSON = 'json'


# endregion

# region utility classes

class TabLifecycleManager:
    def __init__(self, browser):
        self.browser = browser
        self.tab = None

    def __enter__(self):
        self.tab = self.browser.new_tab()
        self.tab.start()
        self.tab.Page.enable()
        return self.tab

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.tab:
            self.tab.stop()
            self.browser.close_tab(self.tab.id)


class PychromeEventHandler:
    screen_lock = threading.Lock()

    def __init__(self, browser, tab, tab_ready):
        self.browser = browser
        self.tab = tab
        self.tab_ready = tab_ready
        self.start_frame = None

    def frame_started_loading(self, frameId):
        if not self.start_frame:
            self.start_frame = frameId

    def frame_stopped_loading(self, frameId):
        demisto.debug('frame_stopped_loading')
        if self.start_frame == frameId:
            try:
                self.tab.Page.stopLoading()

                with self.screen_lock:
                    # must activate current tab
                    demisto.debug(self.browser.activate_tab(self.tab.id))
                    self.tab_ready.set()
                    demisto.debug('frame_stopped_loading, Sent tab_ready.set')
            except Exception as e:  # pragma: no cover
                demisto.error(f'Failed stop loading the page: {self.tab=}, {frameId=}, {e=}')

# endregion


def get_running_chrome_processes() -> list[psutil.Process]:
    chrome_identifiers = ["chrom", "headless", f"--remote-debugging-port={PORT}"]
    current_process = psutil.Process()
    child_processes = current_process.children(recursive=True)

    headless_chrome_processes = []
    for process in child_processes:
        try:
            cmdline = process.cmdline()
            if all(identifier in cmdline for identifier in chrome_identifiers):
                headless_chrome_processes.append(process)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return headless_chrome_processes


def get_active_chrome_processes_count():
    try:
        return len(get_running_chrome_processes())
    except Exception as ex:
        demisto.info(f'Error getting Chrome processes: {ex}')
        return 0


def start_chrome_headless():
    try:
        subprocess.run(['bash', '/start_chrome_headless.sh'],
                       text=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        demisto.debug('Chrome headless started')
    except Exception as ex:
        demisto.info(f'Error starting Chrome headless: {ex}')


def kill_all_chrome_processes():
    try:
        chrome_processes = get_running_chrome_processes()
        demisto.debug(f'kill_all_chrome_processes, Found {len(chrome_processes)} Chrome processes')

        for process in chrome_processes:
            try:
                process.terminate()
                demisto.debug(f'Terminated Chrome process with PID: {process.pid}')
            except psutil.NoSuchProcess:
                demisto.debug(f'Chrome process with PID: {process.pid} no longer exists')
            except psutil.AccessDenied:
                demisto.debug(f'Access denied when trying to terminate Chrome process with PID: {process.pid}')
                process.kill()  # Force kill the process
                demisto.debug(f'Force killed Chrome process with PID: {process.pid}')
            except Exception as e:
                demisto.debug(f'Error killing Chrome process with PID: {process.pid}: {e}')

    except Exception as ex:
        demisto.info(f'Error killing Chrome processes: {ex}')


def ensure_chrome_running():  # pragma: no cover
    for _ in range(DEFAULT_RETRIES_COUNT):
        count = get_active_chrome_processes_count()
        demisto.debug(f'ensure_chrome_running, {count=}')

        if count == 1:
            demisto.debug('One Chrome instance running. Returning True.')
            return True
        elif count == 0:
            start_chrome_headless()
        else:  # clean environment in case more than one browser is active
            kill_all_chrome_processes()

        time.sleep(DEFAULT_RETRY_WAIT_IN_SECONDS)  # pylint: disable=E9003

    demisto.info(f'Max retries ({DEFAULT_RETRIES_COUNT}) reached, Chrome headless is not running correctly')
    return False


def setup_tab_event(browser, tab):
    tab_ready_event = Event()
    tab_event_handler = PychromeEventHandler(browser, tab, tab_ready_event)
    tab.Page.frameStartedLoading = tab_event_handler.frame_started_loading
    tab.Page.frameStoppedLoading = tab_event_handler.frame_stopped_loading

    return tab_ready_event


def navigate_to_path(browser, tab, path, wait_time, navigation_timeout):  # pragma: no cover
    tab_ready_event = setup_tab_event(browser, tab)

    try:
        demisto.debug('Preparing tab for navigation')

        demisto.debug(f'Starting tab navigation to given path: {path}')

        if navigation_timeout > 0:
            tab.Page.navigate(url=path, _timeout=navigation_timeout)
        else:
            tab.Page.navigate(url=path)

        success_flag = tab_ready_event.wait(navigation_timeout)

        if not success_flag:
            message = f'Timeout of {navigation_timeout} seconds reached while waiting for {path}'
            demisto.error(message)
            return_error(message)

        time.sleep(wait_time)  # pylint: disable=E9003

    except Exception as ex:
        message = f'Unhandled exception: {ex} thrown while trying to navigate to {path}'
        demisto.error(message)
        return_error(message)


def screenshot_image(browser, tab, path, wait_time, navigation_timeout):  # pragma: no cover
    navigate_to_path(browser, tab, path, wait_time, navigation_timeout)
    ret_value = base64.b64decode(tab.Page.captureScreenshot()['data'])
    return ret_value


def screenshot_pdf(browser, tab, path, wait_time, navigation_timeout, include_url):  # pragma: no cover
    navigate_to_path(browser, tab, path, wait_time, navigation_timeout)
    header_template = ''
    if include_url:
        header_template = "<span class=url></span>"
    ret_value = base64.b64decode(tab.Page.printToPDF(headerTemplate=header_template)['data'])
    return ret_value


# TODO: support width and height
def rasterize(path: str,
              rasterize_type: RasterizeType = RasterizeType.PNG,
              wait_time: int = DEFAULT_WAIT_TIME,
              offline_mode: bool = False,
              navigation_timeout: int = DEFAULT_PAGE_LOAD_TIME,
              include_url: bool = False,
              width=DEFAULT_WIDTH,
              height=DEFAULT_HEIGHT,
              ):
    """
    Capturing a snapshot of a path (url/file), using Chrome Driver
    :param offline_mode: when set to True, will block any outgoing communication
    :param path: file path, or website url
    :param rasterize_type: result type: .png/.pdf
    :param wait_time: time in seconds to wait before taking a screenshot
    :param navigation_timeout: amount of time to wait for a page load to complete before throwing an error
    :param include_url: should the URL be included in the output image/PDF
    :param width: window width
    :param height: window height
    """

    if ensure_chrome_running():
        browser = pychrome.Browser(url=LOCAL_CHROME_URL)
        with TabLifecycleManager(browser) as tab:
            if offline_mode:
                tab.call_method("Network.disable")
            else:
                tab.call_method("Network.enable")
            # tab.call_method("Browser.Bounds.width=600")
            tab.call_method("Emulation.setVisibleSize", width=width, height=height)

            if rasterize_type == RasterizeType.PNG:
                return screenshot_image(browser, tab, path, wait_time=wait_time, navigation_timeout=navigation_timeout)

            elif rasterize_type == RasterizeType.PDF:
                return screenshot_pdf(browser, tab, path, wait_time=wait_time, navigation_timeout=navigation_timeout,
                                      include_url=include_url)
            else:
                message = 'Unsupported rasterization type {rasterize_type}'
                demisto.error(message)
                return_error(message)

    else:
        message = 'Could not use local Chrome for rasterize command'
        demisto.error(message)
        return_error(message)


def return_err_or_warn(msg):  # pragma: no cover
    return_error(msg) if WITH_ERRORS else return_warning(msg, exit=True)


# region CommandHandlers
def rasterize_image_command():
    args = demisto.args()
    entry_id = args.get('EntryID')
    width, height = get_width_height(demisto.args())

    file_name = args.get('file_name', entry_id)

    file_path = demisto.getFilePath(entry_id).get('path')
    file_name = f'{file_name}.pdf'

    with open(file_path, 'rb') as f:
        output = rasterize(path=f'file://{os.path.realpath(f.name)}', width=width, height=height,
                           rasterize_type=RasterizeType.PDF)
        res = fileResult(filename=file_name, data=output, file_type=entryTypes['entryInfoFile'])
        demisto.results(res)


def rasterize_email_command():  # pragma: no cover
    html_body = demisto.args().get('htmlBody')
    width, height = get_width_height(demisto.args())
    offline = demisto.args().get('offline', 'false') == 'true'
    rasterize_type = RasterizeType(demisto.args().get('type', 'png').lower())
    file_name = demisto.args().get('file_name', 'email')
    navigation_timeout = int(demisto.args().get('max_page_load_time', DEFAULT_PAGE_LOAD_TIME))
    file_name = f'{file_name}.{rasterize_type}'

    with open('htmlBody.html', 'w', encoding='utf-8-sig') as f:
        f.write(f'<html style="background:white";>{html_body}</html>')

    path = f'file://{os.path.realpath(f.name)}'

    output = rasterize(path=path, rasterize_type=rasterize_type, width=width, height=height, offline_mode=offline,
                       navigation_timeout=navigation_timeout)

    res = fileResult(filename=file_name, data=output)

    if rasterize_type == RasterizeType.PNG:
        res['Type'] = entryTypes['image']

    demisto.results(res)


def convert_pdf_to_jpeg(path: str, max_pages: str, password: str):
    """
    Converts a PDF file into a jpeg image
    :param path: file's path
    :param max_pages: max pages to render,
    :param password: PDF password
    :return: A list of stream of combined images
    """
    demisto.debug(f'Loading file at Path: {path}')
    input_pdf = PdfReader(open(path, "rb"), strict=False, password=password)
    pages = len(input_pdf.pages) if max_pages == "*" else min(int(max_pages), len(input_pdf.pages))

    with tempfile.TemporaryDirectory() as output_folder:
        demisto.debug('Converting PDF')
        convert_from_path(
            pdf_path=path,
            fmt='jpeg',
            first_page=1,
            last_page=pages,
            output_folder=output_folder,
            userpw=password,
            output_file='converted_pdf_'
        )
        demisto.debug('Converting PDF - COMPLETED')

        images = []
        for page in sorted(os.listdir(output_folder)):
            if os.path.isfile(os.path.join(output_folder, page)) and 'converted_pdf_' in page:
                images.append(Image.open(os.path.join(output_folder, page)))

        return images


def rasterize_pdf_command():  # pragma: no cover
    entry_id = demisto.args().get('EntryID')
    password = demisto.args().get('pdfPassword')
    max_pages = demisto.args().get('maxPages', 30)
    file_name = demisto.args().get('file_name', 'image')

    file_path = demisto.getFilePath(entry_id).get('path')

    file_name = f'{file_name}.jpeg'

    with open(file_path, 'rb') as f:
        images = convert_pdf_to_jpeg(path=os.path.realpath(f.name), max_pages=max_pages, password=password)
        results = []

        for image in images:
            res = fileResult(filename=file_name, data=image)
            res['Type'] = entryTypes['image']
            results.append(res)

        demisto.results(results)


def rasterize_html_command():
    args = demisto.args()
    entry_id = args.get('EntryID')
    width, height = get_width_height(demisto.args())
    rasterize_type = args.get('type', 'png').lower()

    file_name = args.get('file_name', 'email')
    wait_time = int(args.get('wait_time', 0))

    file_name = f'{file_name}.{rasterize_type}'
    file_path = demisto.getFilePath(entry_id).get('path')
    os.rename(f'./{file_path}', 'file.html')

    output = rasterize(path=f"file://{os.path.realpath('file.html')}", width=width, height=height,
                       rasterize_type=rasterize_type, wait_time=wait_time)

    res = fileResult(filename=file_name, data=output)
    if rasterize_type == 'png':
        res['Type'] = entryTypes['image']
    return_results(res)


def module_test():  # pragma: no cover
    # setting up a mock email file
    with tempfile.NamedTemporaryFile('w+') as test_file:
        test_file.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                        '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        test_file.flush()
        file_path = f'file://{os.path.realpath(test_file.name)}'

        # rasterizing the file
        rasterize(path=file_path)

    demisto.results('ok')


def rasterize_command():  # pragma: no cover
    url = demisto.getArg('url')
    width, height = get_width_height(demisto.args())
    rasterize_type = RasterizeType(demisto.args().get('type', 'png').lower())
    wait_time = int(demisto.args().get('wait_time', 0))
    navigation_timeout = int(demisto.args().get('max_page_load_time', DEFAULT_PAGE_LOAD_TIME))
    file_name = demisto.args().get('file_name', 'url')
    include_url = argToBoolean(demisto.args().get('include_url', False))

    if not (url.startswith('http')):
        url = f'http://{url}'
    file_name = f'{file_name}.{"pdf" if rasterize_type == RasterizeType.PDF else "png"}'  # type: ignore

    output = rasterize(path=url, rasterize_type=rasterize_type, wait_time=wait_time, navigation_timeout=navigation_timeout,
                       include_url=include_url)

    if rasterize_type == RasterizeType.JSON:
        return_results(CommandResults(raw_response=output, readable_output="Successfully rasterize url: " + url))
        return

    res = fileResult(filename=file_name, data=output)
    if rasterize_type == RasterizeType.PNG:
        res['Type'] = entryTypes['image']

    demisto.results(res)

# endregion


def get_width_height(args: dict):
    """
    Get commomn args.
    :param args: dict to get args from
    :return: width, height, rasterize mode
    """
    width = int(args.get('width', f"{DEFAULT_WIDTH} px").rstrip('px'))
    height = int(args.get('height', f"{DEFAULT_HEIGHT} px").rstrip('px'))

    # Check that the width and height meet the safeguard limit
    width = min(width, MAX_FULLSCREEN_WIDTH)
    height = min(height, MAX_FULLSCREEN_HEIGHT)

    return width, height


def main():  # pragma: no cover
    try:
        if demisto.command() == 'test-module':
            module_test()

        elif demisto.command() == 'rasterize-image':
            rasterize_image_command()

        elif demisto.command() == 'rasterize-email':
            rasterize_email_command()

        elif demisto.command() == 'rasterize-pdf':
            rasterize_pdf_command()

        elif demisto.command() == 'rasterize-html':
            rasterize_html_command()

        elif demisto.command() == 'rasterize':
            rasterize_command()

        else:
            return_error('Unrecognized command')

    except Exception as ex:
        return_err_or_warn(f'Unexpected exception: {ex}\nTrace:{traceback.format_exc()}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
