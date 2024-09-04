import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import logging
import psutil
import base64
import os
import pychrome
import random
import subprocess
import tempfile
import threading
import time
import traceback
import websocket
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from threading import Event
from io import BytesIO
from PIL import Image, ImageDraw
from pdf2image import convert_from_path
from PyPDF2 import PdfReader

# region constants and configurations

pypdf_logger = logging.getLogger("PyPDF2")
pypdf_logger.setLevel(logging.ERROR)  # Supress warnings, which would come out as XSOAR errors while not being errors

# Chrome respects proxy env params
handle_proxy()
# Make sure our python code doesn't go through a proxy when communicating with Chrome webdriver
os.environ['no_proxy'] = 'localhost,127.0.0.1'
# Needed for cases that rasterize is running with non-root user (docker hardening)
os.environ['HOME'] = tempfile.gettempdir()

CHROME_EXE = os.getenv('CHROME_EXE', '/opt/google/chrome/google-chrome')
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0" \
             " Safari/537.36"
CHROME_OPTIONS = ["--headless",
                  "--disable-gpu",
                  "--no-sandbox",
                  "--hide-scrollbars",
                  "--disable-infobars",
                  "--start-maximized",
                  "--start-fullscreen",
                  "--ignore-certificate-errors",
                  "--disable-dev-shm-usage",
                  f'--user-agent="{USER_AGENT}"',
                  ]

WITH_ERRORS = demisto.params().get('with_error', True)
IS_HTTPS = argToBoolean(demisto.params().get('is_https', False))

# The default wait time before taking a screenshot
DEFAULT_WAIT_TIME = max(int(demisto.params().get('wait_time', 0)), 0)
DEFAULT_PAGE_LOAD_TIME = int(demisto.params().get('max_page_load_time', 180))
TAB_CLOSE_WAIT_TIME = 1

# Used it in several places
DEFAULT_RETRIES_COUNT = 3
DEFAULT_RETRY_WAIT_IN_SECONDS = 2
PAGES_LIMITATION = 20

# rasterize struct

try:
    env_max_rasterizations_count = os.getenv('MAX_RASTERIZATIONS_COUNT', '500')
    MAX_RASTERIZATIONS_COUNT = int(env_max_rasterizations_count)
except Exception as e:
    demisto.info(f'Exception trying to parse MAX_RASTERIZATIONS_COUNT, {e}')
    MAX_RASTERIZATIONS_COUNT = 500

FIRST_CHROME_PORT = 9301

try:
    env_max_chromes_count = os.getenv('MAX_CHROMES_COUNT', '64')
    MAX_CHROMES_COUNT = int(env_max_chromes_count)
except Exception as e:
    demisto.info(f'Exception trying to parse MAX_CHROMES_COUNT, {e}')
    MAX_CHROMES_COUNT = 64

try:
    # Max number of tabs each Chrome will open before not responding for more requests
    env_max_chrome_tabs_count = os.getenv('MAX_CHROME_TABS_COUNT', '10')
    MAX_CHROME_TABS_COUNT = int(env_max_chrome_tabs_count)
except Exception as e:
    demisto.info(f'Exception trying to parse MAX_CHROME_TABS_COUNT, {e}')
    MAX_CHROME_TABS_COUNT = 10

# Polling for rasterization commands to complete
DEFAULT_POLLING_INTERVAL = 0.1

# Consts for custom width and height
MAX_FULLSCREEN_WIDTH = 8000
MAX_FULLSCREEN_HEIGHT = 8000
DEFAULT_WIDTH, DEFAULT_HEIGHT = 600, 800

# Local Chrome
LOCAL_CHROME_HOST = "127.0.0.1"

CHROME_LOG_FILE_PATH = "/var/chrome_headless.log"
CHROME_INSTANCES_FILE_PATH = '/var/chrome_instances.tsv'
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
    demisto.debug(f"excepthook_recv_loop, {args.exc_type=}")
    exc_value = args.exc_value
    if args.exc_type in [json.decoder.JSONDecodeError, websocket._exceptions.WebSocketConnectionClosedException]:
        # Suppress
        demisto.debug(f"Suppressed Exception in _recv_loop: {args.exc_type=}")
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
        try:
            self.tab = self.browser.new_tab()
        except Exception as ex:
            demisto.info(f'TabLifecycleManager, __enter__, {self.chrome_port=}, failed to create a new tab due to {ex}')
            raise ex
        try:
            self.tab.start()
        except Exception as ex:
            demisto.info(f'TabLifecycleManager, __enter__, {self.chrome_port=}, failed to start a new tab due to {ex}')
            raise ex
        try:
            if self.offline_mode:
                self.tab.Network.emulateNetworkConditions(offline=True, latency=-1, downloadThroughput=-1, uploadThroughput=-1)
            else:
                self.tab.Network.emulateNetworkConditions(offline=False, latency=-1, downloadThroughput=-1, uploadThroughput=-1)
        except Exception as ex:
            demisto.info(f'TabLifecycleManager, __enter__, {self.chrome_port=}, failed to set tab NetworkConditions due to {ex}')
            raise ex

        try:
            self.tab.Page.enable()
        except Exception as ex:
            demisto.info(f'TabLifecycleManager, __enter__, {self.chrome_port=}, failed to enable a new tab due to {ex}')
            raise ex
        return self.tab

    def __exit__(self, exc_type, exc_val, exc_tb):  # noqa: F841
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
        self.is_mailto = False

    def page_frame_started_loading(self, frameId):
        demisto.debug(f'PychromeEventHandler.page_frame_started_loading, {frameId=}')
        self.start_frame = frameId
        if self.request_id:
            # We're in redirect
            demisto.debug(f'Frame (reload) started loading: {frameId}, clearing {self.request_id=}')
            self.request_id = None
            self.response_received = False
            # self.start_frame = None
        else:
            demisto.debug(f'Frame started loading: {frameId}, no request_id')

    def network_data_received(self, requestId, timestamp, dataLength, encodedDataLength):  # noqa: F841
        demisto.debug(f'PychromeEventHandler.network_data_received, {requestId=}')
        if requestId and not self.request_id:
            demisto.debug(f'PychromeEventHandler.network_data_received, Using {requestId=}')
            self.request_id = requestId
        else:
            demisto.debug(f'PychromeEventHandler.network_data_received, Not using {requestId=}')

    def page_frame_stopped_loading(self, frameId):
        demisto.debug(f'PychromeEventHandler.page_frame_stopped_loading, {self.start_frame=}, {frameId=}')
        if self.start_frame == frameId:
            demisto.debug('PychromeEventHandler.page_frame_stopped_loading, setting tab_ready_event')
            self.tab_ready_event.set()

    def network_request_will_be_sent(self, documentURL, **kwargs):
        '''Triggered when a request is sent by the browser, catches mailto URLs.'''
        demisto.debug(f'PychromeEventHandler.network_request_will_be_sent, {documentURL=}')
        self.is_mailto = documentURL.lower().startswith('mailto:')
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


def get_chrome_browser(port: str) -> pychrome.Browser | None:
    browser_url = f"http://{LOCAL_CHROME_HOST}:{port}"
    for i in range(DEFAULT_RETRIES_COUNT):
        try:
            demisto.debug(f"Trying to connect to {browser_url=}, iteration {i + 1}/{DEFAULT_RETRIES_COUNT}")
            browser = pychrome.Browser(url=browser_url)

            # Use list_tab to ping the browser and make sure it's available
            tabs_count = len(browser.list_tab())
            demisto.debug(f"get_chrome_browser, {port=}, {tabs_count=}, {MAX_CHROME_TABS_COUNT=}")
            # if tabs_count < MAX_CHROME_TABS_COUNT:
            demisto.debug(f"Connected to Chrome on port {port} with {tabs_count} tabs")
            return browser
        except requests.exceptions.ConnectionError as exp:
            exp_str = str(exp)
            connection_refused = 'connection refused'
            if connection_refused in exp_str:
                demisto.debug(f"Failed to connect to Chrome on port {port} on iteration {i + 1}. {connection_refused}")
            else:
                demisto.debug(
                    f"Failed to connect to Chrome on port {port} on iteration {i + 1}. ConnectionError, {exp_str=}, {exp=}")

        # Mild backoff
        time.sleep(DEFAULT_RETRY_WAIT_IN_SECONDS + i * 2)  # pylint: disable=E9003

    return None


def read_file(filename):
    try:
        with open(filename) as file:
            ret_value = file.read()
            demisto.info(f"File '{filename}' contents: {ret_value}.")
            return ret_value
    except FileNotFoundError:
        demisto.info(f"File '{filename}' does not exist")
        return None


def write_file(filename, contents, overwrite=False):
    demisto.info(f"Saving File '{filename}' with {contents}.")
    mode = 'w' if overwrite else 'a'
    try:
        with open(filename, mode, encoding='utf-8') as file:
            file.write(("\n" if not overwrite else "") + contents)
            demisto.info(f"File '{filename}' saved successfully with {contents}.")
    except Exception as e:
        demisto.info(f"An error occurred while writing to the file '{filename}': {e}")


def opt_name(opt):
    return opt.split('=', 1)[0]


def get_chrome_options(default_options, user_options):
    """Return the command line options for Chrome

    Returns:
        list -- merged options
    """
    demisto.debug(f"get_chrome_options, {default_options=}, {user_options=}")
    if not user_options:
        # Nothing to do
        return default_options.copy()

    user_options = re.split(r'(?<!\\),', user_options)
    demisto.debug(f'user Chrome options: {user_options}')

    options = []
    remove_opts = []
    for opt in user_options:
        opt = opt.strip()
        if opt.startswith('[') and opt.endswith(']'):
            remove_opts.append(opt[1:-1])
        else:
            options.append(opt.replace(r'\,', ','))
    # Remove values (such as in user-agent)
    option_names = [opt_name(x) for x in options]
    # Add filtered defaults only if not in removed and we don't have it already
    options.extend([x for x in default_options if (opt_name(x) not in remove_opts and opt_name(x) not in option_names)])
    return options


def start_chrome_headless(chrome_port, instance_id, chrome_options, chrome_binary=CHROME_EXE, user_options=""):
    try:
        logfile = open(CHROME_LOG_FILE_PATH, 'ab')

        default_chrome_options = CHROME_OPTIONS
        default_chrome_options.append(f"--remote-debugging-port={chrome_port}")
        subprocess_options = [chrome_binary]
        user_chrome_options = demisto.params().get('chrome_options', "")
        subprocess_options.extend(get_chrome_options(default_chrome_options, user_chrome_options))
        demisto.debug(f"Starting Chrome with {subprocess_options=}")

        process = subprocess.Popen(subprocess_options, stdout=logfile, stderr=subprocess.STDOUT)
        demisto.debug(f'Chrome started on port {chrome_port}, pid: {process.pid},returncode: {process.returncode}')

        if process:
            demisto.debug(f'New Chrome session active on Port {chrome_port}')
            # Allow Chrome to initialize
            time.sleep(DEFAULT_RETRY_WAIT_IN_SECONDS)  # pylint: disable=E9003
            browser = get_chrome_browser(chrome_port)
            if browser:
                new_row = f"{chrome_port}\t{instance_id}\t{chrome_options}\trasterizetion_count"
                write_file(CHROME_INSTANCES_FILE_PATH, new_row)
            else:
                process.kill()
                return None, None
            return browser, chrome_port
        else:
            demisto.debug(f'Chrome did not start successfully on port {chrome_port}. Return code: {process.returncode}')
    except subprocess.SubprocessError as ex:
        demisto.info(f'Error starting Chrome on port {chrome_port}. Error: {ex}')
    demisto.info('Could not connect to Chrome.')

    return None, None


def terminate_chrome(chrome_port: str = '', killall: bool = False) -> None:  # pragma: no cover
    """
    Terminates Chrome processes based on the specified criteria.

    This function provides two modes of operation:
    1. If `chrome_port` is specified, it will terminate the Chrome process
       associated with the given port, and `killall` is automatically set to False.
    2. If `chrome_port` is not specified and `killall` is set to True, it will
       terminate all running Chrome processes to ensure efficiency by clearing the cache.

    Args:
        chrome_port (str, optional): The port number of the Chrome process to terminate.
                                     Default is an empty string.
        killall (bool, optional): Flag to terminate all running Chrome processes.
                                  Default is False.

    Returns:
        None
    """
    # get all the processes running on the machine
    processes = subprocess.check_output(['ps', 'auxww'], stderr=subprocess.STDOUT, text=True).splitlines()
    # identifiers the relevant chrome processes
    chrome_renderer_identifiers = ["--type=renderer"]
    chrome_identifiers = ["chrome", "headless", f"--remote-debugging-port={chrome_port}"]
    # filter by the identifiers the relevant processes and get it as list
    process_in_list = [process for process in processes
                       if all(identifier in process for identifier in chrome_identifiers)
                       and not any(identifier in process for identifier in chrome_renderer_identifiers)]

    if killall:
        # fetch the pids of the processes
        pids = [int(process.split()[1]) for process in process_in_list]
    else:
        # fetch the pid of the process. the list contain just one process with the given chrome_port
        process_string_representation = process_in_list[0]
        pids = [int(process_string_representation.split()[1])]

    for pid in pids:
        # for each pid, get the process by it PID and terminate it
        process = psutil.Process(pid)
        if process:
            try:
                demisto.debug(f'terminate_chrome, {process=}')
                process.kill()
            except Exception as e:
                demisto.info(f"Exception when trying to kill chrome with {pid=}, {e}")

    demisto.debug('terminate_chrome, Finish')


def chrome_manager() -> tuple[Any | None, str | None]:
    """
    Manages Chrome instances based on user-specified chrome options and integration instance ID.

    This function performs the following steps:
    1. Retrieves the instance ID of the integration and the Chrome options set by the user.
    2. Checks if the instance ID has been used previously.
        - If the instance ID is new, generates a new Chrome instance with the specified Chrome options.
        - If the instance ID has been used:
            - If the current Chrome options differ from the saved options for this instance ID,
              it terminates the existing Chrome instance and generates a new one with the new options.
            - If the current Chrome options match the saved options for this instance ID,
              it reuses the existing Chrome instance.

    Returns:
        tuple[Any | None, int | None]: A tuple containing:
            - The Browser or None if an error occurred.
            - The chrome port or None if an error occurred.
    """
    # If instance_id or chrome_options are not set, assign 'None' to these variables.
    # This way, when fetching the content from the file, if there was no instance_id or chrome_options before,
    # it can compare between the fetched 'None' string and the 'None' that assigned.
    instance_id = demisto.callingContext.get('context', {}).get('IntegrationInstanceID', 'None') or 'None'
    chrome_options = demisto.params().get('chrome_options') or 'None'
    chrome_instances_contents = read_file(CHROME_INSTANCES_FILE_PATH)
    instance_id_to_chrome_options, instance_id_to_port, instances_id, chromes_options = \
        get_chrome_instances_contents_dictionaries(chrome_instances_contents)

    if not chrome_instances_contents or instance_id not in instances_id:
        # the file is empty or the conf doesn't exists or this is a new instane
        previous_rasterizations_counter_from_file = read_file(RASTERIZATIONS_COUNTER_FILE_PATH)
        if previous_rasterizations_counter_from_file:
            total_rasterizations_count = int(previous_rasterizations_counter_from_file)
            demisto.debug(f"chrome_manager: Checking if Chrome should be terminated, received, {total_rasterizations_count=},"
                          f" {MAX_RASTERIZATIONS_COUNT=}")
            if total_rasterizations_count == MAX_RASTERIZATIONS_COUNT:
                demisto.info(f"Max resterizations count achieved with {total_rasterizations_count=}, terminating Chrome.")
                if instance_id_to_port:
                    terminate_chrome(chrome_port=instance_id_to_port)
                write_file(CHROME_INSTANCES_FILE_PATH, "", overwrite=True)
                write_file(RASTERIZATIONS_COUNTER_FILE_PATH, "0", overwrite=True)
                demisto.debug('chrome_manager COND previous_rasterizations_counter_from_file succeeded')
        return generate_new_chrome_instance(instance_id, chrome_options)

    elif chrome_options != instance_id_to_chrome_options.get(instance_id):
        chrome_port = instance_id_to_port.get(instance_id, '')
        demisto.debug(f'chrome_options changed, terminating {chrome_port=} {instance_id=} {chrome_options=}\
            and starting a new chrome')
        delete_row_with_old_chrome_configurations_from_chrome_instances_file(chrome_instances_contents, instance_id, chrome_port)
        terminate_chrome(chrome_port=chrome_port)
        return generate_new_chrome_instance(instance_id, chrome_options)

    chrome_port = instance_id_to_port.get(instance_id, '')
    browser = get_chrome_browser(chrome_port)
    demisto.debug(f'chrome_manager {chrome_port=}')
    return browser, chrome_port


def get_chrome_instances_contents_dictionaries(chrome_instances_contents: str) -> tuple[
        Dict[str, str], Dict[str, str], List[str], List[str]]:
    """
    Parses the chrome instances content to extract and return two dictionaries and two lists.

    Args:
        chrome_instances_contents: The file content to be parsed.

    Returns:
        tuple: A tuple containing:
            - instance_id_to_chrome_options (dict): A dictionary mapping instance ID to Chrome options.
            - instance_id_to_port (dict): A dictionary mapping instance ID to port.
            - instances_id (list): A list of instances ID extracted from instance_id_to_port keys.
            - chromes_options (list): A list of Chrome options extracted from instance_id_to_chrome_options values.

    The purpose of this method is to transform the file content into dictionaries and lists
    for easier access and manipulation of the data.
    """
    instance_id_to_chrome_options = {}
    instance_id_to_port = {}

    if chrome_instances_contents:
        splitted_chrome_instances_contents = chrome_instances_contents.strip().splitlines()
        for line in splitted_chrome_instances_contents:
            port, instance_id, chrome_options = line.strip().split('\t')
            instance_id_to_chrome_options[instance_id] = chrome_options
            instance_id_to_port[instance_id] = port

    instances_id = list(instance_id_to_port.keys())
    chromes_options = list(instance_id_to_chrome_options.values())
    if instances_id and not chromes_options:
        chromes_options.append('None')
    return instance_id_to_chrome_options, instance_id_to_port, instances_id, chromes_options


def generate_new_chrome_instance(instance_id: str, chrome_options: str) -> tuple[Any | None, str | None]:
    chrome_port = generate_chrome_port()
    return start_chrome_headless(chrome_port, instance_id, chrome_options)


def generate_chrome_port() -> str | None:
    first_chrome_port = FIRST_CHROME_PORT
    ports_list = list(range(first_chrome_port, first_chrome_port + MAX_CHROMES_COUNT))
    random.shuffle(ports_list)
    demisto.debug(f"Searching for Chrome on these ports: {ports_list}")
    for chrome_port in ports_list:
        len_running_chromes = count_running_chromes(chrome_port)
        demisto.debug(f"Found {len_running_chromes=} on port {chrome_port}")

        if len_running_chromes == 0:
            # There's no Chrome listening on that port, Start a new Chrome there
            demisto.debug(f"No Chrome found on port {chrome_port}, using it.")
            return str(chrome_port)

        # There's already a Chrome listening on that port, Don't use it

    demisto.error(f'Max retries ({MAX_CHROMES_COUNT}) reached, could not connect to Chrome')
    return None


def delete_row_with_old_chrome_configurations_from_chrome_instances_file(chrome_instances_contents: str, instance_id: str,
                                                                         chrome_port: str) -> None:
    """
    Removes a specific row from the given content based on the instance ID and port,
    and updates the file with the new content.

    Args:
        chrome_instances_contents (str): The file content to be searched and modified.
        instance_id (str): The instance ID to search for in the content.
        chrome_port (str): The port to search for in the content.

    Returns:
        None

    This function searches for a row in the content that includes the specified instance ID and port.
    Once the row is found, it is deleted from the content. The updated content is then written
    back to the file using the write_file function.
    """
    index_to_delete = -1

    splitted_chrome_instances_contents = chrome_instances_contents.strip().splitlines()
    for index, line in enumerate(splitted_chrome_instances_contents):
        port_from_chrome_instances_file, instance_id_from_chrome_instances_file, chrome_options_from_chrome_instances_file = \
            line.strip().split('\t')
        if port_from_chrome_instances_file == chrome_port and instance_id_from_chrome_instances_file == instance_id:
            index_to_delete = index
            break

    if index_to_delete >= 0:
        del splitted_chrome_instances_contents[index_to_delete]
        chrome_instances_contents = '\n'.join(splitted_chrome_instances_contents)
        write_file(CHROME_INSTANCES_FILE_PATH, chrome_instances_contents, overwrite=True)


def setup_tab_event(browser: pychrome.Browser, tab: pychrome.Tab) -> tuple[PychromeEventHandler, Event]:
    tab_ready_event = Event()
    tab_event_handler = PychromeEventHandler(browser, tab, tab_ready_event)

    tab.Network.enable()
    tab.Network.dataReceived = tab_event_handler.network_data_received
    # tab.Network.responseReceived = tab_event_handler.network_response_received
    tab.Network.requestWillBeSent = tab_event_handler.network_request_will_be_sent

    tab.Page.frameStartedLoading = tab_event_handler.page_frame_started_loading
    tab.Page.frameStoppedLoading = tab_event_handler.page_frame_stopped_loading

    return tab_event_handler, tab_ready_event


def navigate_to_path(browser, tab, path, wait_time, navigation_timeout) -> PychromeEventHandler:  # pragma: no cover
    tab_event_handler, tab_ready_event = setup_tab_event(browser, tab)

    try:
        demisto.info(f'Starting tab navigation to given path: {path} on {tab.id=}')

        allTimeSamplingProfile = tab.Memory.getAllTimeSamplingProfile()
        demisto.debug(f'allTimeSamplingProfile before navigation {allTimeSamplingProfile=} on {tab.id=}')
        heapUsage = tab.Runtime.getHeapUsage()
        demisto.debug(f'heapUsage before navigation {heapUsage=} on {tab.id=}')

        if navigation_timeout > 0:
            tab.Page.navigate(url=path, _timeout=navigation_timeout)
        else:
            tab.Page.navigate(url=path)

        demisto.debug(f'Waiting for tab_ready_event on {tab.id=}')
        success_flag = tab_ready_event.wait(navigation_timeout)
        demisto.debug(f'After waiting for tab_ready_event on {tab.id=}')

        if not success_flag:
            message = f'Timeout of {navigation_timeout} seconds reached while waiting for {path}'
            demisto.error(message)
            return_error(message)

        if wait_time > 0:
            demisto.info(f'Sleeping before capturing screenshot, {wait_time=}')
        else:
            demisto.debug(f'Not sleeping before capturing screenshot, {wait_time=}')
        time.sleep(wait_time)  # pylint: disable=E9003
        demisto.debug(f"Navigated to {path=} on {tab.id=}")

        allTimeSamplingProfile = tab.Memory.getAllTimeSamplingProfile()
        demisto.debug(f'allTimeSamplingProfile after navigation {allTimeSamplingProfile=} on {tab.id=}')
        heapUsage = tab.Runtime.getHeapUsage()
        demisto.debug(f'heapUsage after navigation {heapUsage=} on {tab.id=}')

    except pychrome.exceptions.TimeoutException as ex:
        return_error(f'Navigation timeout: {ex} thrown while trying to navigate to {path}')
    except pychrome.exceptions.PyChromeException as ex:
        return_error(f'Exception: {ex} thrown while trying to navigate to {path}')

    return tab_event_handler


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

    if tab_event_handler.is_mailto:
        return None, f'URLs that start with "mailto:" cannot be rasterized.\nURL: {path}'

    try:
        page_layout_metrics = tab.Page.getLayoutMetrics()
    except Exception as ex:
        demisto.info(f'Failed to get tab LayoutMetrics due to {ex}')
        raise ex

    demisto.debug(f"{page_layout_metrics=}")
    css_content_size = page_layout_metrics['cssContentSize']
    try:
        if full_screen:
            viewport = css_content_size
            viewport['scale'] = 1
            screenshot_data = tab.Page.captureScreenshot(clip=viewport, captureBeyondViewport=True)['data']
        else:
            screenshot_data = tab.Page.captureScreenshot()['data']
    except Exception as ex:
        demisto.info(f'Failed to capture screenshot due to {ex}')
        raise ex
    # Make sure that the (asynchronous) screenshot data is available before continuing with execution
    screenshot_data, operation_time = backoff(screenshot_data)
    if screenshot_data:
        demisto.debug(f"Screenshot image of {path=} on {tab.id=}, available after {operation_time} seconds.")
    else:
        demisto.info(f"Screenshot image of {path=} on {tab.id=}, not available after {operation_time} seconds.")

    allTimeSamplingProfile = tab.Memory.getAllTimeSamplingProfile()
    demisto.debug(f'allTimeSamplingProfile after screenshot {allTimeSamplingProfile=} on {tab.id=}')
    heapUsage = tab.Runtime.getHeapUsage()
    demisto.debug(f'heapUsage after screenshot {heapUsage=} on {tab.id=}')

    captured_image = base64.b64decode(screenshot_data)
    if not captured_image:
        demisto.info(f"Empty snapshot, {screenshot_data=}")
    else:
        demisto.info(f"Captured snapshot, {len(captured_image)=}")

    # Page URL, if needed
    if include_url:
        captured_image_object = Image.open(BytesIO(captured_image))
        image_with_url = Image.new(captured_image_object.mode, (css_content_size['width'], css_content_size['height'] + 20))
        image_with_url.paste(captured_image_object, (0, 20))
        ImageDraw.Draw(image_with_url).text((0, 0), path, fill=(255, 255, 255))
        img_byte_arr = BytesIO()
        image_with_url.save(img_byte_arr, format='PNG')
        img_byte_arr = img_byte_arr.getvalue()
        ret_value = img_byte_arr
    else:
        ret_value = captured_image

    # Page source, if needed
    response_body = ""
    if include_source:
        demisto.debug('screenshot_image, include_source, waiting for request_id')
        request_id, request_id_operation_time = backoff(tab_event_handler.request_id)
        if request_id:
            demisto.debug(f"request_id available after {request_id_operation_time} seconds.")
        else:
            demisto.info(f"request_id not available after {request_id_operation_time} seconds.")
        demisto.debug(f"Got {request_id=} after {request_id_operation_time} seconds.")

        try:
            response_body = tab.Network.getResponseBody(requestId=request_id, _timeout=navigation_timeout)['body']
            demisto.debug(f'screenshot_image, {include_source=}, {response_body=}')

            response_body, operation_time = backoff(response_body)
            if response_body:
                demisto.debug(f"Response Body available after {operation_time} seconds, {len(response_body)=}")
            else:
                demisto.info(f"Response Body not available after {operation_time} seconds.")

        except Exception as ex:  # This exception is raised when a non-existent URL is provided.
            demisto.info(f'Exception when calling Network.getResponseBody with {request_id=}, {ex=}')
            demisto.info(f'Failed to get URL body due to {ex}')
            response_body = 'Failed to get URL body'

    return ret_value, response_body


def screenshot_pdf(browser, tab, path, wait_time, navigation_timeout, include_url):  # pragma: no cover
    navigate_to_path(browser, tab, path, wait_time, navigation_timeout)
    header_template = ''
    if include_url:
        header_template = "<span class=url></span>"

    try:
        pdf_data = tab.Page.printToPDF(headerTemplate=header_template)['data']
    except Exception as ex:
        demisto.info(f'Failed to get PDF due to {ex}')
        raise ex
    # Make sure that the (asynchronous) PDF data is available before continuing with execution
    pdf_data, operation_time = backoff(pdf_data)
    if pdf_data:
        demisto.debug(f"PDF Data available after {operation_time} seconds.")
    else:
        demisto.info(f"PDF Data not available after {operation_time} seconds.")

    ret_value = base64.b64decode(pdf_data)
    return ret_value, None


def rasterize_thread(browser, chrome_port, path: str,
                     rasterize_type: RasterizeType = RasterizeType.PNG,
                     wait_time: int = DEFAULT_WAIT_TIME,
                     offline_mode: bool = False,
                     navigation_timeout: int = DEFAULT_PAGE_LOAD_TIME,
                     include_url: bool = False,
                     full_screen: bool = False,
                     width: int = DEFAULT_WIDTH,
                     height: int = DEFAULT_HEIGHT
                     ):
    demisto.debug(f'rasterize_thread, starting TabLifecycleManager, {path=}, {rasterize_type=}')
    with TabLifecycleManager(browser, chrome_port, offline_mode) as tab:
        try:
            tab.call_method("Emulation.setVisibleSize", width=width, height=height)
        except Exception as ex:
            demisto.info(f'Failed to set the chrome tab size due to {ex}')
            raise ex

        if rasterize_type == RasterizeType.PNG or str(rasterize_type).lower() == RasterizeType.PNG.value:
            return screenshot_image(browser, tab, path, wait_time=wait_time, navigation_timeout=navigation_timeout,
                                    full_screen=full_screen, include_url=include_url)

        elif rasterize_type == RasterizeType.PDF or str(rasterize_type).lower() == RasterizeType.PDF.value:
            return screenshot_pdf(browser, tab, path, wait_time=wait_time, navigation_timeout=navigation_timeout,
                                  include_url=include_url)

        elif rasterize_type == RasterizeType.JSON or str(rasterize_type).lower() == RasterizeType.JSON.value:
            return screenshot_image(browser, tab, path, wait_time=wait_time, navigation_timeout=navigation_timeout,
                                    full_screen=full_screen, include_url=include_url, include_source=True)
        else:
            raise DemistoException(f'Unsupported rasterization type: {rasterize_type}.')


def perform_rasterize(path: str | list[str],
                      rasterize_type: RasterizeType = RasterizeType.PNG,
                      wait_time: int = DEFAULT_WAIT_TIME,
                      offline_mode: bool = False,
                      navigation_timeout: int = DEFAULT_PAGE_LOAD_TIME,
                      include_url: bool = False,
                      full_screen: bool = False,
                      width: int = DEFAULT_WIDTH,
                      height: int = DEFAULT_HEIGHT
                      ):
    """
    Capturing a snapshot of a path (url/file), using Chrome Driver
    :param offline_mode: when set to True, will block any outgoing communication
    :param path: file path, or website url
    :param rasterize_type: result type: .png/.pdf
    :param wait_time: time in seconds to wait before taking a screenshot
    :param navigation_timeout: amount of time to wait for a page load to complete before throwing an error
    :param include_url: should the URL be included in the output image/PDF
    :param full_screen: when set to True, the snapshot will take the whole page
    :param width: window width
    :param height: window height
    """
    demisto.debug(f"rasterize, {path=}, {rasterize_type=}")
    browser, chrome_port = chrome_manager()
    if browser:
        support_multithreading()
        with ThreadPoolExecutor(max_workers=MAX_CHROME_TABS_COUNT) as executor:
            demisto.debug(f'path type is: {type(path)}')
            paths = [path] if isinstance(path, str) else path
            demisto.debug(f"rasterize, {paths=}, {rasterize_type=}")
            rasterization_threads = []
            rasterization_results = []
            for current_path in paths:
                if not current_path.startswith('http') and not current_path.startswith('file:///'):
                    protocol = 'http' + 's' * IS_HTTPS
                    current_path = f'{protocol}://{current_path}'

                # Start a new thread in group of max_tabs
                rasterization_threads.append(
                    executor.submit(
                        rasterize_thread, browser=browser, chrome_port=chrome_port, path=current_path,
                        rasterize_type=rasterize_type, wait_time=wait_time, offline_mode=offline_mode,
                        navigation_timeout=navigation_timeout, include_url=include_url, full_screen=full_screen,
                        width=width, height=height
                    )
                )
            # Wait for all tasks to complete
            executor.shutdown(wait=True)
            demisto.info(
                f"Finished {len(rasterization_threads)} rasterize operations, active tabs len: {len(browser.list_tab())}")

            previous_rasterizations_counter_from_file = read_file(RASTERIZATIONS_COUNTER_FILE_PATH)
            if previous_rasterizations_counter_from_file:
                total_rasterizations_count = int(previous_rasterizations_counter_from_file) + len(rasterization_threads)
            else:
                total_rasterizations_count = len(rasterization_threads)
            write_file(RASTERIZATIONS_COUNTER_FILE_PATH, str(total_rasterizations_count), overwrite=True)

            # Get the results
            for current_thread in rasterization_threads:
                ret_value, response_body = current_thread.result()
                if ret_value:
                    rasterization_results.append((ret_value, response_body))
                else:
                    return_results(CommandResults(
                        readable_output=str(response_body),
                        entry_type=(EntryType.ERROR if WITH_ERRORS else EntryType.WARNING)
                    ))
            return rasterization_results

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
    entry_id = args.get('EntryID')
    width, height = get_width_height(demisto.args())
    full_screen = argToBoolean(demisto.args().get('full_screen', False))

    file_name = args.get('file_name', entry_id)

    file_path = demisto.getFilePath(entry_id).get('path')
    file_name = f'{file_name}.pdf'

    with open(file_path, 'rb') as f:
        output = perform_rasterize(path=f'file://{os.path.realpath(f.name)}', width=width, height=height,
                                   rasterize_type=RasterizeType.PDF, full_screen=full_screen)
        res = []
        for current_output in output:
            res.append(fileResult(filename=file_name, data=current_output[0], file_type=entryTypes['entryInfoFile']))
        demisto.results(res)


def rasterize_email_command():  # pragma: no cover
    html_body = demisto.args().get('htmlBody')
    width, height = get_width_height(demisto.args())
    full_screen = argToBoolean(demisto.args().get('full_screen', False))

    offline = demisto.args().get('offline', 'false') == 'true'

    rasterize_type_arg = demisto.args().get('type', 'png').lower()
    file_name = demisto.args().get('file_name', 'email')
    file_name = f'{file_name}.{rasterize_type_arg}'
    rasterize_type = RasterizeType(rasterize_type_arg)

    navigation_timeout = int(demisto.args().get('max_page_load_time', DEFAULT_PAGE_LOAD_TIME))

    with open('htmlBody.html', 'w', encoding='utf-8-sig') as f:
        f.write(f'<html style="background:white";>{html_body}</html>')

    path = f'file://{os.path.realpath(f.name)}'

    rasterize_output = perform_rasterize(path=path, rasterize_type=rasterize_type, width=width, height=height,
                                         offline_mode=offline, navigation_timeout=navigation_timeout, full_screen=full_screen)

    res = fileResult(filename=file_name, data=rasterize_output[0][0])

    if rasterize_type == RasterizeType.PNG or str(rasterize_type).lower() == RasterizeType.PNG.value:
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
                image = Image.open(os.path.join(output_folder, page))
                output = BytesIO()
                image.save(output, 'JPEG')  # type: ignore
                images.append(output.getvalue())

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
    entry_id = args.get('EntryID')
    width, height = get_width_height(demisto.args())
    full_screen = argToBoolean(demisto.args().get('full_screen', False))

    rasterize_type = args.get('type', 'png').lower()
    file_name = args.get('file_name', 'email')
    wait_time = int(args.get('wait_time', 0))

    file_name = f'{file_name}.{rasterize_type}'
    file_path = demisto.getFilePath(entry_id).get('path')
    os.rename(f'./{file_path}', 'file.html')

    output = perform_rasterize(path=f"file://{os.path.realpath('file.html')}", width=width, height=height,
                               rasterize_type=rasterize_type, wait_time=wait_time, full_screen=full_screen)

    res = fileResult(filename=file_name, data=output[0][0])
    if rasterize_type == 'png':
        res['Type'] = entryTypes['image']
    return_results(res)


def module_test():  # pragma: no cover
    # Setting up a mock email file
    with tempfile.NamedTemporaryFile('w+') as test_file:
        test_file.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                        '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        test_file.flush()
        file_path = f'file://{os.path.realpath(test_file.name)}'

        # Rasterize the file
        perform_rasterize(path=file_path, wait_time=0)

    demisto.results('ok')


def get_list_item(list_of_items: list, index: int, default_value: str):
    if index >= len(list_of_items):
        return default_value

    return list_of_items[index]


def add_filename_suffix(file_names: list, file_extension: str):
    ret_value = []
    for current_filename in file_names:
        ret_value.append(f'{current_filename}.{file_extension}')
    return ret_value


def rasterize_command():  # pragma: no cover
    urls = demisto.getArg('url')
    urls = [urls] if isinstance(urls, str) else urls
    width, height = get_width_height(demisto.args())
    full_screen = argToBoolean(demisto.args().get('full_screen', False))
    rasterize_type = RasterizeType(demisto.args().get('type', 'png').lower())
    wait_time = int(demisto.args().get('wait_time', 0))
    navigation_timeout = int(demisto.args().get('max_page_load_time', DEFAULT_PAGE_LOAD_TIME))
    file_name = demisto.args().get('file_name', 'url')
    include_url = argToBoolean(demisto.args().get('include_url', False))

    file_extension = "png"
    if rasterize_type == RasterizeType.PDF or str(rasterize_type).lower() == RasterizeType.PDF.value:
        file_extension = "pdf"

    demisto.debug(f'file_name type is: {type(file_name)}')
    file_names = argToList(file_name)
    file_names = add_filename_suffix(file_names, file_extension)

    rasterize_output = perform_rasterize(path=urls, rasterize_type=rasterize_type, wait_time=wait_time,
                                         navigation_timeout=navigation_timeout, include_url=include_url,
                                         full_screen=full_screen, width=width, height=height)
    demisto.debug(f"rasterize_command response, {rasterize_type=}, {len(rasterize_output)=}")

    for index, (current_rasterize_output, current_url) in enumerate(zip(rasterize_output, urls)):
        if isinstance(current_rasterize_output, str):
            return_results(CommandResults(
                readable_output=f'Error for URL {current_url!r}:\n{current_rasterize_output}',
                raw_response=current_rasterize_output,
                entry_type=EntryType.ERROR,
            ))
        elif rasterize_type == RasterizeType.JSON or str(rasterize_type).lower() == RasterizeType.JSON.value:
            output = {'image_b64': base64.b64encode(current_rasterize_output[0]).decode('utf8'),
                      'html': current_rasterize_output[1], 'current_url': current_url}
            return_results(CommandResults(raw_response=output, readable_output=f"Successfully rasterize url: {current_url}"))
        else:
            res = []
            current_res = fileResult(filename=get_list_item(file_names, index, f'url.{file_extension}'),
                                     data=current_rasterize_output[0], file_type=entryTypes['entryInfoFile'])

            if rasterize_type == RasterizeType.PNG or str(rasterize_type).lower() == RasterizeType.PNG.value:
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
    demisto.debug(f'Using performance params: {MAX_CHROMES_COUNT=}, {MAX_CHROME_TABS_COUNT=}, {MAX_RASTERIZATIONS_COUNT=}')

    threading.excepthook = excepthook_recv_loop
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
