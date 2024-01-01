# TODO rasterizeV2-Pre-Release
# TODO V start_chrome_headless.sh in Python
# TODO V Restart the chrome after 500 rasterizations
# TODO V/2 Write the pid in a local file. Use the pid os the subprocess when starting the chrome from Python. Use DevTools, or kill the process
# TODO Backwards Compatibility: Add support for full_Screen
# TODO Backwards Compatibility: Add support for include_url
# TODO Backwards Compatibility: chrome_options, support removal of options


import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import base64
import os
import pychrome
import random
import requests
import subprocess
import tempfile
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
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

CHROME_EXE = os.getenv('CHROME_EXE', '/opt/google/chrome/google-chrome')
USER_AGENT="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36"
USER_CHROME_OPTIONS = demisto.params().get('chrome_options', "")
CHROME_PID = 0

WITH_ERRORS = demisto.params().get('with_error', True)

# The default wait time before taking a screenshot
DEFAULT_WAIT_TIME = max(int(demisto.params().get('wait_time', 0)), 0)
DEFAULT_PAGE_LOAD_TIME = int(demisto.params().get('max_page_load_time', 180))
TAB_CLOSE_WAIT_TIME = 1

# Used it in several places
DEFAULT_RETRIES_COUNT = 3
DEFAULT_RETRY_WAIT_IN_SECONDS = 2
PAGES_LIMITATION = 20

MAX_RASTERIZATIONS_COUNT = int(demisto.args().get('max_rasterizations_count', '500'))

FIRST_CHROME_PORT = 9301
MAX_CHROMES_COUNT = int(demisto.params().get('max_chromes_count', "64"))
# Max number of tabs each Chrome will open before not responding for more requests
MAX_CHROME_TABS_COUNT = int(demisto.params().get('max_chrome_tabs_count', "10"))

# Polling for rasterization commands to complete
DEFAULT_POLLING_INTERVAL = 0.1

# Consts for custom width and height
MAX_FULLSCREEN_WIDTH = 8000
MAX_FULLSCREEN_HEIGHT = 8000
DEFAULT_WIDTH, DEFAULT_HEIGHT = 600, 800

# Local Chrome
LOCAL_CHROME_HOST = "127.0.0.1"

PORT_FILE_PATH = '/var/port.txt'
RASTERIZATIONS_COUNTER_FILE_PATH = '/var/rasterizations_counter.txt'

class RasterizeType(Enum):
    PNG = 'png'
    PDF = 'pdf'
    JSON = 'json'


# endregion

# region utility classes

def excepthook_recv_loop(args):
    """
    Suppressing exceptions that might happen after the tab was closed.
    """
    exc_value = args.exc_value
    if args.exc_type == json.decoder.JSONDecodeError:
        # demisto.debug("Caught a JSONDecodeError exception in _recv_loop, suppressing, json.decoder.JSONDecodeError")
        # if exc_value:
        #     demisto.debug(f"Caught a JSONDecodeError exception in _recv_loop, suppressing, {exc_value}")
        # else:
        #     demisto.debug("Caught a JSONDecodeError exception in _recv_loop, suppressing, empty exc_value")
        pass
    else:
        demisto.info(f"Unsuppressed Exception in _recv_loop: {args.exc_type=}")
        if exc_value:
            demisto.info(f"Unsuppressed Exception in _recv_loop: {args.exc_type=}, {exc_value=}")
        else:
            demisto.info(f"Unsuppressed Exception in _recv_loop: {args.exc_type=}, empty exc_value")


class TabLifecycleManager:
    def __init__(self, browser, chrome_port, offline_mode):
        self.browser = browser
        self.chrome_port = chrome_port
        self.offline_mode = offline_mode
        self.tab = None

    def __enter__(self):
        self.tab = self.browser.new_tab()
        self.tab.start()
        if self.offline_mode:
            self.tab.Network.emulateNetworkConditions(offline=True, latency=-1, downloadThroughput=-1, uploadThroughput=-1)
        else:
            self.tab.Network.emulateNetworkConditions(offline=False, latency=-1, downloadThroughput=-1, uploadThroughput=-1)

        self.tab.Page.enable()
        return self.tab

    def __exit__(self, exc_type, exc_val, exc_tb):  # pylint: disable=unused-argument
        if self.tab:
            tab_id = self.tab.id
            # Suppressing exceptions that might happen after the tab was closed.
            threading.excepthook = excepthook_recv_loop

            try:
                time.sleep(TAB_CLOSE_WAIT_TIME)  # pylint: disable=E9003
                self.tab.Page.disable()
            except Exception as ex:
                demisto.info(f'TabLifecycleManager, __exit__, {self.chrome_port=}, failed to disable page due to {ex}')

            try:
                self.tab.stop()
            except Exception as ex:
                demisto.info(f'TabLifecycleManager, __exit__, {self.chrome_port=}, failed to stop tab {tab_id} due to {ex}')

            try:
                self.browser.close_tab(tab_id)
            except Exception as ex:
                demisto.info(f'TabLifecycleManager, __exit__, {self.chrome_port=}, failed to close tab {tab_id} due to {ex}')

            time.sleep(TAB_CLOSE_WAIT_TIME)  # pylint: disable=E9003


class PychromeEventHandler:
    request_id = None
    screen_lock = threading.Lock()

    def __init__(self, browser, tab, tab_ready_event):
        self.browser = browser
        self.tab = tab
        self.tab_ready_event = tab_ready_event
        self.start_frame = None

    def frame_started_loading(self, frameId):
        if not self.start_frame:
            self.start_frame = frameId
            demisto.debug(f'Frame started loading: {frameId}')

    def frame_stopped_loading(self, frameId):
        if self.start_frame == frameId:
            try:
                with self.screen_lock:
                    self.tab.Page.stopLoading()
                    # Activate current tab
                    activation_result = self.browser.activate_tab(self.tab.id)
                    activation_result, operation_time = backoff(activation_result)
                    self.tab_ready_event.set()
            except pychrome.exceptions.PyChromeException as pce:
                demisto.info(f'Exception when Frame stopped loading: {frameId}, {pce}')

    def network_data_received(self, requestId, timestamp, dataLength, encodedDataLength):  # pylint: disable=unused-argument
        if requestId and not self.request_id:
            self.request_id = requestId

# endregion


def count_running_chromes(port):
    try:
        processes = subprocess.check_output(['ps', 'auxww'],
                                            stderr=subprocess.STDOUT,
                                            text=True).splitlines()

        chrome_identifiers = ["chrom", "headless", f"--remote-debugging-port={port}"]
        chrome_renderer_identifiers = ["--type=renderer"]
        chrome_processes = [process for process in processes
                            if all(identifier in process for identifier in chrome_identifiers)
                            and not any(identifier in process for identifier in chrome_renderer_identifiers)]

        demisto.debug(f'Detected {len(chrome_processes)} Chrome processes running on port {port}')
        return len(chrome_processes)

    except subprocess.CalledProcessError as e:
        demisto.info(f'Error fetching process list: {e.output}')
        return 0
    except Exception as e:
        demisto.info(f'Unexpected exception when fetching process list, error: {e}')
        return 0


def is_chrome_running_locally(port):

    browser_url = f"http://{LOCAL_CHROME_HOST}:{port}"
    for i in range(DEFAULT_RETRIES_COUNT):
        try:
            demisto.debug(f"Trying to connect to {browser_url=}, iteration {i+1}/{DEFAULT_RETRIES_COUNT}")
            browser = pychrome.Browser(url=browser_url)

            # Use list_tab to ping the browser and make sure it's available
            tabs_count = len(browser.list_tab())
            demisto.debug(f"is_chrome_running_locally, {port=}, {tabs_count=}, {MAX_CHROME_TABS_COUNT=}")
            if tabs_count < MAX_CHROME_TABS_COUNT:
                return browser
            else:
                demisto.debug(f"Connected to Chrome on port {port} with {tabs_count} tabs, but {MAX_CHROME_TABS_COUNT=},"
                              " so not using it")
                return None
        except requests.exceptions.ConnectionError as exp:
            exp_str = str(exp)
            connection_refused = 'connection refused'
            if connection_refused in exp_str:
                demisto.debug(f"Failed to connect to Chrome on prot {port} on iteration {i+1}. {connection_refused}")
            else:
                demisto.debug(
                    f"Failed to connect to Chrome on port {port} on iteration {i+1}. ConnectionError, {exp_str=}, {exp=}")

        # mild backoff
        time.sleep(DEFAULT_RETRY_WAIT_IN_SECONDS + i * 2)  # pylint: disable=E9003

    return None


def read_info_file(filename):
    try:
        with open(filename) as file:
            ret_value = file.read()
            demisto.info(f"File '{filename}' contents: {ret_value}.")
            return ret_value
    except FileNotFoundError:
        return None


def write_info_file(filename, contents):
    demisto.info(f"Saving File '{filename}' with {contents}.")
    with open(filename, 'w') as file:
        file.write(f"{contents}")
        demisto.info(f"File '{filename}' saved successfully with {contents}.")


def start_chrome_headless(chrome_port, chrome_binary=CHROME_EXE, user_options=""):
    try:
        # process = subprocess.run(['bash', '/start_chrome_headless.sh',
        #                          '--port', str(chrome_port),
        #                           '--chrome-binary', CHROME_EXE,
        #                           '--user-options', USER_CHROME_OPTIONS],
        #                          text=True,
        #                          stdout=subprocess.DEVNULL,
        #                          stderr=subprocess.DEVNULL)
        # nohup "$chrome_binary" --headless --disable-gpu --no-sandbox --hide-scrollbars --disable-infobars --start-maximized --start-fullscreen $cert_errors_option --disable-dev-shm-usage --user-agent="\"$user_agent\"" "$user_options --remote-debugging-port=$remote_debugging_port" & disown

        logfile = open("/var/chrome_headless.log", 'ab')
        process = subprocess.Popen([chrome_binary,
                                  "--headless",
                                  "--disable-gpu",
                                  "--no-sandbox",
                                  "--hide-scrollbars",
                                  "--disable-infobars",
                                  "--start-maximized",
                                  "--start-fullscreen",
                                  "--ignore-certificate-errors",
                                  "--disable-dev-shm-usage",
                                  f'--user-agent="{USER_AGENT}"',
                                  user_options,
                                  f"--remote-debugging-port={chrome_port}",
                                 ],
                                 stdout=logfile, stderr=subprocess.STDOUT)
        demisto.debug(f'Chrome started on port {chrome_port}, pid: {process.pid},returncode: {process.returncode}')

        if process:
            demisto.debug(f'New Chrome session active on Port {chrome_port}')
            CHROME_PID = process.pid
            # Allow Chrome to initialize
            time.sleep(DEFAULT_RETRY_WAIT_IN_SECONDS)  # pylint: disable=E9003
            browser = is_chrome_running_locally(chrome_port)
            write_info_file(PORT_FILE_PATH, chrome_port)
            return browser, chrome_port
        else:
            demisto.debug(f'Chrome did not start successfully on port {chrome_port}. Return code: {process.returncode}')
    except subprocess.SubprocessError as ex:
        demisto.info(f'Error starting Chrome on port {chrome_port}. Error: {ex}')
    demisto.info('Could not connect to Chrome.')

    return None, None


def terminate_chrome(browser):
    tab = browser.new_tab()
    tab.start()
    # try:
    tab.Browser.close()
    # TODO Kill
    # CHROME_PID
    os.remove(PORT_FILE_PATH)
    # except Exception as e:
    #     demisto.info(f"Exception when closing browser, {type(e)}, {e}")


def ensure_chrome_running():  # pragma: no cover

    # Check if we have a file with the port.
    # If we have a file - Try to use it.
    # If there's no file, or we cannot use it - Find a free port
    browser = None
    chrome_port = read_info_file(PORT_FILE_PATH)
    if chrome_port:
        browser = is_chrome_running_locally(chrome_port)

    if not browser:
        first_chrome_port = FIRST_CHROME_PORT
        ports_list = list(range(first_chrome_port, first_chrome_port + MAX_CHROMES_COUNT))
        random.shuffle(ports_list)
        demisto.debug(f"Searching for Chrome on these ports: {ports_list}")

        for chrome_port in ports_list:
            len_running_chromes = count_running_chromes(chrome_port)
            browser = is_chrome_running_locally(chrome_port)
            demisto.debug(f"Checking port {chrome_port}: {len_running_chromes=}, {browser}")
            if browser and len_running_chromes == 1:
                # There's a Chrome listening on that port, and we're connected to it. Use it
                demisto.debug(f'Connected to Chrome running on port {chrome_port}')
                write_info_file(PORT_FILE_PATH, chrome_port)

                return browser, chrome_port

            if len_running_chromes == 0:
                # There's no Chrome listening on that port, Start a new Chrome there
                demisto.debug(f"No Chrome found on port {chrome_port}")
                break

            if len_running_chromes > 1:
                # There's more than one Chrome listening on that port, so we won't connect to it
                demisto.debug(f"More than one Chrome running on port {chrome_port}, continuing")
                continue
            demisto.debug(f'Could not connect to Chrome on port {chrome_port}')

        if chrome_port == ports_list[-1]:
            demisto.error(f'Max retries ({MAX_CHROMES_COUNT}) reached, could not connect to chrome')
            return None, None

    demisto.debug(f'Initializing a new Chrome session on port {chrome_port}')

    return start_chrome_headless(str(chrome_port))


def setup_tab_event(browser, tab):
    tab_ready_event = Event()
    tab_event_handler = PychromeEventHandler(browser, tab, tab_ready_event)
    tab.Network.dataReceived = tab_event_handler.network_data_received
    tab.Page.frameStartedLoading = tab_event_handler.frame_started_loading
    tab.Page.frameStoppedLoading = tab_event_handler.frame_stopped_loading

    return tab_event_handler, tab_ready_event


def navigate_to_path(browser, tab, path, wait_time, navigation_timeout):  # pragma: no cover
    tab_event_handler, tab_ready_event = setup_tab_event(browser, tab)

    try:
        demisto.debug(f'Starting tab navigation to given path: {path} on {tab.id=}')

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
        demisto.debug(f"Navigated to {path=} on {tab.id=}")
        return tab_event_handler

    except pychrome.exceptions.TimeoutException as ex:
        message = f'Navigation timeout: {ex} thrown while trying to navigate to {path}'
        demisto.error(message)
        return_error(message)
    except pychrome.exceptions.PyChromeException as ex:
        message = f'Exception: {ex} thrown while trying to navigate to {path}'
        demisto.error(message)
        return_error(message)


def backoff(polled_item, wait_time=DEFAULT_WAIT_TIME, polling_interval=DEFAULT_POLLING_INTERVAL):
    operation_time = 0
    while polled_item is None and operation_time < wait_time:
        time.sleep(polling_interval)  # pylint: disable=E9003
        operation_time += polling_interval
    return polled_item, operation_time


def screenshot_image(browser, tab, path, wait_time, navigation_timeout, full_screen=False,
                     include_url=False, include_source=False):  # pragma: no cover
    """
    :param include_source: Whether to include the page source in the response
    """
    tab_event_handler = navigate_to_path(browser, tab, path, wait_time, navigation_timeout)

    page_layout_metrics = tab.Page.getLayoutMetrics()
    demisto.debug(f"{page_layout_metrics=}")
    if full_screen:
        css_content_size = page_layout_metrics['cssContentSize']
        viewport = css_content_size
        viewport['scale'] = 1
        screenshot_data = tab.Page.captureScreenshot(clip=viewport, captureBeyondViewport=True)['data']
    else:
        screenshot_data = tab.Page.captureScreenshot()['data']
    # Make sure that the (asynchronous) screenshot data is available before continuing with execution
    screenshot_data, operation_time = backoff(screenshot_data)
    if screenshot_data:
        demisto.debug(f"Screenshot image of {path=} on {tab.id=}, available after {operation_time} seconds.")
    else:
        demisto.info(f"Screenshot image of {path=} on {tab.id=}, not available available after {operation_time} seconds.")

    ret_value = base64.b64decode(screenshot_data)
    if not ret_value:
        demisto.info(f"Empty snapshot, {screenshot_data=}")
    else:
        demisto.info(f"Captured snapshot, {len(ret_value)=}")

    # Page URL, if needed
    if include_url:
        pass

    # Page source, if needed
    response_body = None
    if include_source:
        request_id, operation_time = backoff(tab_event_handler.request_id)
        if request_id:
            demisto.debug(f"request_id available after {operation_time} seconds.")
        else:
            demisto.info(f"request_id not available available after {operation_time} seconds.")
        demisto.debug(f"Got {request_id=} after {operation_time} seconds.")
        response_body = tab.Network.getResponseBody(requestId=request_id, _timeout=navigation_timeout)['body']
        response_body, operation_time = backoff(response_body)
        if response_body:
            demisto.debug(f"Response Body available after {operation_time} seconds, {len(response_body)=}")
        else:
            demisto.info(f"Response Body not available available after {operation_time} seconds.")

    return ret_value, response_body


def screenshot_pdf(browser, tab, path, wait_time, navigation_timeout, include_url):  # pragma: no cover
    navigate_to_path(browser, tab, path, wait_time, navigation_timeout)
    header_template = ''
    if include_url:
        header_template = "<span class=url></span>"

    pdf_data = tab.Page.printToPDF(headerTemplate=header_template)['data']
    # Make sure that the (asynchronous) PDF data is available before continuing with execution
    pdf_data, operation_time = backoff(pdf_data)
    if pdf_data:
        demisto.debug(f"PDF Data available after {operation_time} seconds.")
    else:
        demisto.info(f"PDF Data not available available after {operation_time} seconds.")

    ret_value = base64.b64decode(pdf_data)
    return ret_value, None


def rasterize_thread(browser, chrome_port, path: str,
              rasterize_type: RasterizeType = RasterizeType.PNG,
              wait_time: int = DEFAULT_WAIT_TIME,
              offline_mode: bool = False,
              navigation_timeout: int = DEFAULT_PAGE_LOAD_TIME,
              include_url: bool = False,
              width=DEFAULT_WIDTH,
              height=DEFAULT_HEIGHT
              ):
    demisto.debug(f'rasterize_thread, starting TabLifecycleManager, {path=}, {rasterize_type=}')
    with TabLifecycleManager(browser, chrome_port, offline_mode) as tab:
        tab.call_method("Emulation.setVisibleSize", width=width, height=height)

        if rasterize_type == RasterizeType.PNG or str(rasterize_type).lower == RasterizeType.PNG.value:
            return screenshot_image(browser, tab, path, wait_time=wait_time, navigation_timeout=navigation_timeout,
                                    include_url=include_url)

        elif rasterize_type == RasterizeType.PDF or str(rasterize_type).lower == RasterizeType.PDF.value:
            return screenshot_pdf(browser, tab, path, wait_time=wait_time, navigation_timeout=navigation_timeout,
                                  include_url=include_url)

        elif rasterize_type == RasterizeType.JSON or str(rasterize_type).lower == RasterizeType.JSON.value:
            return screenshot_image(browser, tab, path, wait_time=wait_time, navigation_timeout=navigation_timeout,
                                    include_url=include_url, include_source=True)
        else:
            message = f'Unsupported rasterization type: {rasterize_type}.'
            demisto.error(message)
            return_error(message)
            return None


def rasterize(path: str,
              rasterize_type: RasterizeType = RasterizeType.PNG,
              wait_time: int = DEFAULT_WAIT_TIME,
              offline_mode: bool = False,
              navigation_timeout: int = DEFAULT_PAGE_LOAD_TIME,
              include_url: bool = False,
              width=DEFAULT_WIDTH,
              height=DEFAULT_HEIGHT
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
    demisto.debug(f"rasterize, {path=}, {rasterize_type=}")
    browser, chrome_port = ensure_chrome_running()
    if browser:
        support_multithreading()
        with ThreadPoolExecutor(max_workers=MAX_CHROME_TABS_COUNT) as executor:
            paths = argToList(path)
            demisto.debug(f"rasterize, {paths=}, {rasterize_type=}")
            rasterization_threads = []
            rasterization_results = []
            for current_path in paths:
                if not (current_path.startswith('http')):
                    current_path = f'http://{current_path}'

                # start a new thread in group of max_tabs
                rasterization_threads.append(executor.submit(rasterize_thread,
                                            browser=browser, chrome_port=chrome_port,
                                            path=current_path, rasterize_type=rasterize_type, wait_time=wait_time,
                                            offline_mode=offline_mode, navigation_timeout=navigation_timeout,
                                            include_url=include_url, width=width, height=height
                                            ))
            # Wait for all tasks to complete
            executor.shutdown(wait=True)
            demisto.info(f"Finished {len(rasterization_threads)} rasterizations, active tabs len: {len(browser.list_tab())}")

            previous_rasterizations_counter_from_file = read_info_file(RASTERIZATIONS_COUNTER_FILE_PATH)
            if previous_rasterizations_counter_from_file:
                total_rasterizations_count = int(previous_rasterizations_counter_from_file) + len(rasterization_threads)
            else:
                total_rasterizations_count = len(rasterization_threads)
            demisto.debug(f"Should kill Chrome? {total_rasterizations_count=}, {MAX_RASTERIZATIONS_COUNT=}, {len(browser.list_tab())=}")
            if total_rasterizations_count > MAX_RASTERIZATIONS_COUNT:
                demisto.info(f"Terminating Chrome after {total_rasterizations_count} rasterizations")
                terminate_chrome(browser)
                demisto.info(f"Terminated Chrome after {total_rasterizations_count} rasterizations")
                write_info_file(RASTERIZATIONS_COUNTER_FILE_PATH, "0")
            else:
                write_info_file(RASTERIZATIONS_COUNTER_FILE_PATH, total_rasterizations_count)

            # Get the results
            for current_thread in rasterization_threads:
                rasterization_results.append(current_thread.result()[0])

            return rasterization_results, None

    else:
        message = 'Could not use local Chrome for rasterize command'
        demisto.error(message)
        return_error(message)
        return None


def return_err_or_warn(msg):  # pragma: no cover
    return_error(msg) if WITH_ERRORS else return_warning(msg, exit=True)


# region CommandHandlers
def rasterize_image_command():
    args = demisto.args()
    # TODO EntryID should be isArray in the YML. Then iterate over all the files after argToList
    entry_id = args.get('EntryID')
    width, height = get_width_height(demisto.args())

    file_name = args.get('file_name', entry_id)

    file_path = demisto.getFilePath(entry_id).get('path')
    file_name = f'{file_name}.pdf'

    with open(file_path, 'rb') as f:
        output, _ = rasterize(path=f'file://{os.path.realpath(f.name)}', width=width, height=height,
                              rasterize_type=RasterizeType.PDF)
        res = []
        for current_output in output:
            res.append(fileResult(filename=file_name, data=current_output, file_type=entryTypes['entryInfoFile']))
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

    rasterize_output, _ = rasterize(path=path, rasterize_type=rasterize_type, width=width, height=height,
                                    offline_mode=offline, navigation_timeout=navigation_timeout)

    res = fileResult(filename=file_name, data=rasterize_output[0])

    if rasterize_type == RasterizeType.PNG or str(rasterize_type).lower == RasterizeType.PNG.value:
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
        convert_from_path(
            pdf_path=path,
            fmt='jpeg',
            first_page=1,
            last_page=pages,
            output_folder=output_folder,
            userpw=password,
            output_file='converted_pdf_'
        )

        images = []
        for page in sorted(os.listdir(output_folder)):
            if os.path.isfile(os.path.join(output_folder, page)) and 'converted_pdf_' in page:
                images.append(Image.open(os.path.join(output_folder, page)))

        return images


def rasterize_pdf_command():  # pragma: no cover
    entry_id = demisto.args().get('EntryID')
    password = demisto.args().get('pdfPassword')
    max_pages = demisto.args().get('maxPages', PAGES_LIMITATION)
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
    # TODO EntryID should be isArray in the YML. Then iterate over all the files after argToList
    # Should we support arrays?
    entry_id = args.get('EntryID')
    width, height = get_width_height(demisto.args())
    rasterize_type = args.get('type', 'png').lower()

    file_name = args.get('file_name', 'email')
    wait_time = int(args.get('wait_time', 0))

    file_name = f'{file_name}.{rasterize_type}'
    file_path = demisto.getFilePath(entry_id).get('path')
    os.rename(f'./{file_path}', 'file.html')

    output, _ = rasterize(path=f"file://{os.path.realpath('file.html')}", width=width, height=height,
                          rasterize_type=rasterize_type, wait_time=wait_time)

    # TODO Should we suport arrays?
    res = fileResult(filename=file_name, data=output[0])
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

    file_extension = "png"
    if rasterize_type == RasterizeType.PDF or str(rasterize_type).lower == RasterizeType.PDF.value:
        file_extension = "pdf"
    file_name = f'{file_name}.{file_extension}'  # type: ignore

    rasterize_output, response_body = rasterize(path=url, rasterize_type=rasterize_type, wait_time=wait_time,
                                                navigation_timeout=navigation_timeout, include_url=include_url)
    demisto.debug(f"rasterize_command response, {rasterize_type=}, {len(rasterize_output)=}")

    if rasterize_type == RasterizeType.JSON or str(rasterize_type).lower == RasterizeType.JSON.value:
        output = {'image_b64': base64.b64encode(rasterize_output).decode('utf8'),
                  'html': response_body, 'current_url': url}
        demisto.results(CommandResults(raw_response=output, readable_output="Successfully rasterize url: " + url))
    else:
        res = []
        for current_output in rasterize_output:
            current_res = fileResult(filename=file_name, data=current_output, file_type=entryTypes['entryInfoFile'])

            if rasterize_type == RasterizeType.PNG or str(rasterize_type).lower == RasterizeType.PNG.value:
                current_res['Type'] = entryTypes['image']

            res.append(current_res)

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
    demisto.debug(f"main, {demisto.command()=}")
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
