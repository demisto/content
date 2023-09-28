import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import base64
import os
import re
import subprocess
import tempfile
import time
import traceback
from enum import Enum
from io import BytesIO
from pathlib import Path
from collections.abc import Callable

import numpy as np
from pdf2image import convert_from_path
from PIL import Image
from PyPDF2 import PdfReader
from selenium import webdriver
from pyvirtualdisplay import Display
from selenium.common.exceptions import (InvalidArgumentException,
                                        NoSuchElementException,
                                        TimeoutException)

# Chrome respects proxy env params
handle_proxy()
# Make sure our python code doesn't go through a proxy when communicating with chrome webdriver
os.environ['no_proxy'] = 'localhost,127.0.0.1'
# Needed for cases that rasterize is running with non-root user (docker hardening)
os.environ['HOME'] = tempfile.gettempdir()

WITH_ERRORS = demisto.params().get('with_error', True)
DEFAULT_WAIT_TIME = max(int(demisto.params().get('wait_time', 0)), 0)
DEFAULT_PAGE_LOAD_TIME = int(demisto.params().get('max_page_load_time', 180))

URL_ERROR_MSG = "Can't access the URL. It might be malicious, or unreachable for one of several reasons. " \
                "You can choose to receive this message as error/warning in the instance settings\n"
EMPTY_RESPONSE_ERROR_MSG = "There is nothing to render. This can occur when there is a refused connection." \
                           " Please check your URL."
DEFAULT_W, DEFAULT_H = '600', '800'
DEFAULT_W_WIDE = '1024'
CHROME_USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36'  # noqa
MAX_FULLSCREEN_W = 8000
MAX_FULLSCREEN_H = 8000
DRIVER_LOG = f'{tempfile.gettempdir()}/chromedriver.log'
DEFAULT_CHROME_OPTIONS = [
    '--no-sandbox',
    '--disable-gpu',
    '--hide-scrollbars',
    '--disable_infobars',
    '--start-maximized',
    '--start-fullscreen',
    '--ignore-certificate-errors',
    '--disable-dev-shm-usage',
    f'--user-agent={CHROME_USER_AGENT}'
]

USER_CHROME_OPTIONS = demisto.params().get('chrome_options', "")
PAGES_LIMITATION = 20
CHROME_EXE = os.getenv('CHROME_EXE', '/opt/google/chrome/google-chrome')


class RasterizeMode(Enum):
    WEBDRIVER_PREFERED = 'WebDriver - Preferred'
    WEBDRIVER_ONLY = 'WebDriver - Only'
    HEADLESS_CLI_PREFERED = 'Headless CLI - Preferred'
    HEADLESS_CLI_ONLY = 'Headless CLI - Only'


DEFAULT_MODE = RasterizeMode(demisto.params().get('rasterize_mode', RasterizeMode.WEBDRIVER_PREFERED))


class RasterizeType(Enum):
    PNG = 'png'
    PDF = 'pdf'
    JSON = 'json'


def check_width_and_height(width: int, height: int) -> tuple[int, int]:
    """
    Verifies that the width and height are not greater than the safeguard limit.
    Args:
        width: The given width.
        height: The given height.

    Returns: The checked width and height values - [width, height]
    """
    w = min(width, MAX_FULLSCREEN_W)
    h = min(height, MAX_FULLSCREEN_H)

    return w, h


def return_err_or_warn(msg):
    return_error(msg) if WITH_ERRORS else return_warning(msg, exit=True)


def opt_name(opt):
    return opt.split('=', 1)[0]


def merge_options(default_options, user_options):
    """merge the defualt options and user options

    Arguments:
        default_options {list} -- list of options to use
        user_options {string} -- user configured options comma seperated (comma value can be escaped with \\)

    Returns:
        list -- merged options
    """
    user_options = re.split(r'(?<!\\),', user_options) if user_options else []
    if not user_options:  # nothing to do
        return default_options.copy()
    demisto.debug(f'user chrome options: {user_options}')
    options = []
    remove_opts = []
    for opt in user_options:
        opt = opt.strip()
        if opt.startswith('[') and opt.endswith(']'):
            remove_opts.append(opt[1:-1])
        else:
            options.append(opt.replace(r'\,', ','))
    # remove values (such as in user-agent)
    option_names = [opt_name(x) for x in options]
    # add filtered defaults only if not in removed and we don't have it already
    options.extend([x for x in default_options if (opt_name(x) not in remove_opts and opt_name(x) not in option_names)])
    return options


def check_response(driver):
    EMPTY_PAGE = '<html><head></head><body></body></html>'
    if driver.page_source == EMPTY_PAGE:
        return_err_or_warn(EMPTY_RESPONSE_ERROR_MSG)


def init_display(width: int, height: int):
    """
    Creates virtual display if include_url is set to True

    Args:
        width: desired snapshot width in pixels
        height: desired snapshot height in pixels

    Returns:
        The  display session
    """
    try:
        demisto.debug(f"Starting display with width: {width}, and height: {height}.")
        os.environ['DISPLAY'] = ':0'
        display = Display(visible=0, size=(width, height), backend='xvnc')
        display.start()

    except Exception as ex:
        raise DemistoException(f'Unexpected exception: {ex}\nTrace:{traceback.format_exc()}')

    demisto.debug('Creating display - COMPLETED')
    return display


def init_driver(offline_mode=False, include_url=False):
    """
    Creates headless Google Chrome Web Driver

    Args:
        offline_mode: when set to True, will block any outgoing communication
        include_url: when set to True, will include the URL bar in the image result

    Returns:
        The driver session
    """
    demisto.debug(f'Creating chrome driver. Mode: {"OFFLINE" if offline_mode else "ONLINE"}')
    try:
        chrome_options = webdriver.ChromeOptions()
        for opt in merge_options(DEFAULT_CHROME_OPTIONS, USER_CHROME_OPTIONS):
            chrome_options.add_argument(opt)

        if not include_url:
            chrome_options.add_argument('--headless')
        chrome_service = webdriver.ChromeService(executable_path='/usr/bin/chromedriver', service_args=[
            f'--log-path={DRIVER_LOG}',
        ])
        driver = webdriver.Chrome(options=chrome_options, service=chrome_service)
        if offline_mode:
            driver.set_network_conditions(offline=True, latency=5, throughput=500 * 1024)
    except Exception as ex:
        raise DemistoException(f'Unexpected exception: {ex}\nTrace:{traceback.format_exc()}')

    demisto.debug('Creating chrome driver - COMPLETED')
    return driver


def find_zombie_processes():
    """find zombie proceses
    Returns:
        ([process ids], raw ps output) -- return a tuple of zombie process ids and raw ps output
    """
    ps_out = subprocess.check_output(['ps', '-e', '-o', 'pid,ppid,state,stime,cmd'],
                                     stderr=subprocess.STDOUT, universal_newlines=True)
    lines = ps_out.splitlines()
    pid = str(os.getpid())
    zombies = []
    if len(lines) > 1:
        for line in lines[1:]:
            pinfo = line.split()
            if pinfo[2] == 'Z' and pinfo[1] == pid:  # zombie process
                zombies.append(pinfo[0])
    return zombies, ps_out


def quit_driver_and_display_and_reap_children(driver, display):
    """
    Quits the driver's and display's sessions and reaps all of zombie child processes

    :param driver: The driver session.
    :param display: The display session.

    :return: None
    """

    try:

        try:
            if driver:
                demisto.debug(f'Quitting driver session: {driver.session_id}')
                driver.quit()
        except Exception as edr:
            demisto.error(f"Failed to quit driver. Error: {edr}. Trace: {traceback.format_exc()}")

        try:
            if display:
                demisto.debug("Stopping display")
                display.stop()
        except Exception as edr:
            demisto.error(f"Failed to stop display. Error: {edr}. Trace: {traceback.format_exc()}")

        zombies, ps_out = find_zombie_processes()
        if zombies:  # pragma: no cover
            demisto.info(f'Found zombie processes will waitpid: {ps_out}')
            for pid in zombies:
                waitres = os.waitpid(int(pid), os.WNOHANG)[1]
                demisto.info(f'waitpid result: {waitres}')
        else:
            demisto.debug(f'No zombie processes found for ps output: {ps_out}')
    except Exception as e:
        demisto.error(f'Failed checking for zombie processes: {e}. Trace: {traceback.format_exc()}')


def rasterize(path: str, width: int, height: int, r_type: RasterizeType = RasterizeType.PNG, wait_time: int = 0,
              offline_mode: bool = False, max_page_load_time: int = 180, full_screen: bool = False,
              r_mode: RasterizeMode = RasterizeMode.WEBDRIVER_PREFERED, include_url: bool = False):
    """
    Capturing a snapshot of a path (url/file), using Chrome Driver
    :param offline_mode: when set to True, will block any outgoing communication
    :param path: file path, or website url
    :param width: desired snapshot width in pixels
    :param height: desired snapshot height in pixels
    :param r_type: result type: .png/.pdf
    :param wait_time: time in seconds to wait before taking a screenshot
    :param max_page_load_time: amount of time to wait for a page load to complete before throwing an error
    :param full_screen: when set to True, the snapshot will take the whole page
    :param r_mode: rasterizing mode see: RasterizeMode enum.
    """
    demisto.debug(f'Rasterizing using mode: {r_mode}')
    page_load_time = max_page_load_time if max_page_load_time > 0 else DEFAULT_PAGE_LOAD_TIME
    rasterize_funcs: tuple[Callable, ...] = ()
    if r_mode == RasterizeMode.WEBDRIVER_PREFERED:
        rasterize_funcs = (rasterize_webdriver, rasterize_headless_cmd)
    elif r_mode == RasterizeMode.WEBDRIVER_ONLY:
        rasterize_funcs = (rasterize_webdriver,)
    elif r_mode == RasterizeMode.HEADLESS_CLI_PREFERED:
        rasterize_funcs = (rasterize_headless_cmd, rasterize_webdriver)
    elif r_mode == RasterizeMode.HEADLESS_CLI_ONLY:
        rasterize_funcs = (rasterize_headless_cmd,)
    else:  # should never happen as we use an enum
        demisto.error(f'Unknown rasterize mode: {r_mode}')
        raise ValueError(f'Unknown rasterize mode: {r_mode}')
    try:
        for i, r_func in enumerate(rasterize_funcs):  # type: ignore[var-annotated]
            try:
                return r_func(path=path, width=width, height=height, r_type=r_type, wait_time=wait_time,  # type: ignore[misc]
                              offline_mode=offline_mode, max_page_load_time=page_load_time, full_screen=full_screen,
                              include_url=include_url)
            except Exception as ex:
                if i < (len(rasterize_funcs) - 1):
                    demisto.info(f'Failed rasterize preferred option trying second option. Exception: {ex}')
                else:
                    demisto.info(f'Failed rasterizing using all available options. Raising last exception: {ex}')
                    raise
    except (InvalidArgumentException, NoSuchElementException) as ex:
        if 'invalid argument' in str(ex):
            err_msg = URL_ERROR_MSG + str(ex)
            return_err_or_warn(err_msg)
        else:
            return_err_or_warn(f'Invalid exception: {ex}\nTrace:{traceback.format_exc()}')
    except (TimeoutException, subprocess.TimeoutExpired) as ex:
        return_err_or_warn(f'Timeout exception with max load time of: {page_load_time} seconds. {ex}')
    except Exception as ex:
        err_str = f'General error: {ex}\nTrace:{traceback.format_exc()}'
        demisto.error(err_str)
        return_err_or_warn(err_str)


def rasterize_webdriver(path: str, width: int, height: int, r_type: RasterizeType = RasterizeType.PNG, wait_time: int = 0,
                        offline_mode: bool = False, max_page_load_time: int = 180, full_screen: bool = False,
                        include_url: bool = False):
    """
    Capturing a snapshot of a path (url/file), using Chrome Driver if include_url is set to False,
    otherwise, it uses a virtual Display to display the screen of the linux machine.

    :param offline_mode: when set to True, will block any outgoing communication
    :param path: file path, or website url
    :param width: desired snapshot width in pixels
    :param height: desired snapshot height in pixels
    :param r_type: result type: .png/.pdf
    :param wait_time: time in seconds to wait before taking a screenshot
    :param include_url: when set to True, will include the URL bar in the image result
    """
    driver, display = None, None
    try:

        if include_url:
            display = init_display(width, height)

        driver = init_driver(offline_mode, include_url)

        demisto.debug(f'Navigating to path: {path}. Mode: {"OFFLINE" if offline_mode else "ONLINE"}.'
                      f' page load: {max_page_load_time}')
        driver.set_page_load_timeout(max_page_load_time)
        driver.get(path)

        driver.maximize_window()
        driver.implicitly_wait(5)
        if wait_time > 0 or DEFAULT_WAIT_TIME > 0:
            time.sleep(wait_time or DEFAULT_WAIT_TIME)
        check_response(driver)
        demisto.debug('Navigating to path - COMPLETED')

        if r_type == RasterizeType.PDF:
            output = get_pdf(driver, width, height)
        elif r_type == RasterizeType.JSON:
            html = driver.page_source
            url = driver.current_url
            output = {'image_b64': base64.b64encode(get_image(driver, width, height, full_screen, include_url)).decode('utf8'),
                      'html': html, 'current_url': url}
        else:
            output = get_image(driver, width, height, full_screen, include_url)
        return output
    finally:
        quit_driver_and_display_and_reap_children(driver, display)


def rasterize_headless_cmd(path: str, width: int, height: int, r_type: RasterizeType = RasterizeType.PNG, wait_time: int = 0,
                           offline_mode: bool = False, max_page_load_time: int = 180, full_screen: bool = False,
                           include_url: bool = False):
    if include_url:
        demisto.info('include_url options is ignored in headless cmd mode. Image will not include the url bar.')

    demisto.debug(f'rasterizing headless cmd mode for path: [{path}]')
    if offline_mode:
        raise NotImplementedError(f'offile_mode: {offline_mode} is not supported in Headless CLI mode')
    if full_screen:
        demisto.info(f'full_screen param: [{full_screen}] ignored in headless cmd mode.'
                     f' Will use width: : {width} and height: {height}.')
    cmd_options = merge_options(DEFAULT_CHROME_OPTIONS, USER_CHROME_OPTIONS)
    cmd_options.insert(0, CHROME_EXE)
    cmd_options.append('--headless')
    if width > 0 and height > 0:
        cmd_options.append(f'--window-size={width},{height}')
    # not using --timeout as it would return a screenshot even though it is not complete in some cases
    # if max_page_load_time > 0:
    #     cmd_options.append(f'--timeout={max_page_load_time * 1000}')
    output_file = None
    if r_type == RasterizeType.PDF:
        cmd_options.append('--print-to-pdf')
        output_file = Path(tempfile.gettempdir()) / 'output.pdf'
    elif r_type == RasterizeType.JSON:
        cmd_options.append('--dump-dom')
    else:  # screeshot
        cmd_options.append('--screenshot')
        output_file = Path(tempfile.gettempdir()) / 'screenshot.png'
    # run chrome
    try:
        cmd_options.append(path)
        demisto.debug(f'CMD command: {" ".join(cmd_options)}')
        cmd_timeout = 0 if max_page_load_time <= 0 else max_page_load_time
        res = subprocess.run(cmd_options, cwd=tempfile.gettempdir(), capture_output=True, timeout=cmd_timeout,
                             check=True, text=True)
    except subprocess.TimeoutExpired as te:
        demisto.info(f'chrome headless timeout exception: {te}. Stderr: {te.stderr}')
        raise
    except subprocess.CalledProcessError as ce:
        demisto.error(f'chrome headless called process exception: {ce}. Return code: {ce.returncode}. Stderr: {ce.stderr}')
        raise
    demisto.debug(f'Done rasterizing: [{path}]')
    if is_debug_mode():
        demisto.debug(f'chrome stderr output:{res.stderr}')
    if not output_file:  # json mode
        return {'html': res.stdout, 'current_url': path}
    try:
        with open(output_file, 'rb') as f:
            return f.read()
    finally:
        output_file.unlink(missing_ok=True)


def get_image(driver, width: int, height: int, full_screen: bool, include_url=False):
    """
    Uses the Chrome driver to generate an image out of a currently loaded path
    :param width: desired snapshot width in pixels
    :param height: desired snapshot height in pixels
    :param full_screen: when set to True, the snapshot will take the whole page
                        (safeguard limits defined in MAX_FULLSCREEN_W, MAX_FULLSCREEN_H)
    :param include_url: when set to True, will include the URL bar in the image result
    :return: .png file of the loaded path
    """
    demisto.debug('Capturing screenshot')

    # Set windows size to the given width and height:
    driver.set_window_size(width, height)

    if full_screen:
        # Convention: the calculated values are always larger then the given width and height and smaller than the
        # safeguard limits

        # Calculates the width and height using the scrollbar of the window:
        calc_width = driver.execute_script('return document.body.parentNode.scrollWidth')
        calc_height = driver.execute_script('return document.body.parentNode.scrollHeight')

        # Check that the width and height meet the safeguard limit:
        calc_width, calc_height = check_width_and_height(calc_width, calc_height)
        demisto.info(f'Calculated snapshot width is {calc_width}, calculated snapshot height is {calc_height}.')

        # Reset window size
        driver.set_window_size(calc_width, calc_height)

    image = get_image_screenshot(driver=driver, include_url=include_url)

    driver.quit()

    demisto.debug('Capturing screenshot - COMPLETED')

    return image


def get_image_screenshot(driver, include_url):
    """
    Takes a screenshot using linux display if include_url is set to True and using drive if not, and returns it as an image.

    Args:
        driver: The driver session.
        include_url: when set to True, will take the screenshot of the linux machine's display using the ImageMagick's import tool
                     to include the url bar in the image.

    Returns:
        The readed .png file of the image.
    """

    if include_url:
        try:
            res = subprocess.run('import -window root screenshot.png'.split(' '), text=True, capture_output=True, check=True,
                                 env={'DISPLAY': ':0'})
            demisto.debug(f"Finished taking the screenshot. Stdout: [{res.stdout}] stderr: [{res.stderr}]")

        except subprocess.CalledProcessError as se:
            demisto.error(f'Subprocess exception: {se}. Stderr: [{se.stderr}] stdout: [{se.stdout}]')
            raise

        try:
            with open('screenshot.png', 'rb') as f:
                image = f.read()
        except Exception as e:
            demisto.error(f'Failed to read the screenshot.png image. Exception: {e}')
            raise
        finally:
            os.remove('screenshot.png')
    else:
        image = driver.get_screenshot_as_png()

    return image


def get_pdf(driver, width: int, height: int):
    """
    Uses the Chrome driver to generate an pdf file out of a currently loaded path
    :param width: desired snapshot width in pixels
    :param height: desired snapshot height in pixels
    :return: .pdf file of the loaded path
    """
    demisto.debug('Generating PDF')

    driver.set_window_size(width, height)
    resource = f'{driver.command_executor._url}/session/{driver.session_id}/chromium/send_command_and_get_result'
    body = json.dumps({'cmd': 'Page.printToPDF', 'params': {'landscape': False}})
    response = driver.command_executor._request('POST', resource, body)

    if response.get('status'):
        demisto.results(response.get('status'))
        return_error(response.get('value'))

    data = base64.b64decode(response.get('value').get('data'))
    demisto.debug('Generating PDF - COMPLETED')

    return data


def convert_pdf_to_jpeg(path: str, max_pages: str, password: str, horizontal: bool = False):
    """
    Converts a PDF file into a jpeg image
    :param path: file's path
    :param max_pages: max pages to render,
    :param password: PDF password
    :param horizontal: if True, will combine the pages horizontally
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

        demisto.debug('Combining all pages')
        images = []
        for page in sorted(os.listdir(output_folder)):
            if os.path.isfile(os.path.join(output_folder, page)) and 'converted_pdf_' in page:
                images.append(Image.open(os.path.join(output_folder, page)))
        min_shape = min([(np.sum(page_.size), page_.size) for page_ in images])[1]  # get the minimal width

        # Divide the list of images into separate lists with constant length (20),
        # due to the limitation of images in jpeg format (max size ~65,000 pixels).
        # Create a list of lists (length == 20) of images to combine each list (20 images) to one image
        images_matrix = [images[i:i + PAGES_LIMITATION] for i in range(0, len(images), PAGES_LIMITATION)]

        outputs = []
        for images_list in images_matrix:
            if horizontal:
                # this line takes a ton of memory and doesnt release all of it
                imgs_comb = np.hstack([np.asarray(image.resize(min_shape)) for image in images_list])
            else:
                imgs_comb = np.vstack([np.asarray(image.resize(min_shape)) for image in images_list])

            imgs_comb = Image.fromarray(imgs_comb)
            output = BytesIO()
            imgs_comb.save(output, 'JPEG')  # type: ignore
            demisto.debug('Combining all pages - COMPLETED')
            outputs.append(output.getvalue())

        return outputs


def rasterize_command():
    url = demisto.getArg('url')
    w, h, r_mode = get_common_args(demisto.args())
    r_type = RasterizeType(demisto.args().get('type', 'png').lower())
    wait_time = int(demisto.args().get('wait_time', 0))
    page_load = int(demisto.args().get('max_page_load_time', DEFAULT_PAGE_LOAD_TIME))
    file_name = demisto.args().get('file_name', 'url')
    full_screen = argToBoolean(demisto.args().get('full_screen', False))
    include_url = argToBoolean(demisto.args().get('include_url', False))

    w, h = check_width_and_height(w, h)  # Check that the width and height meet the safeguard limit

    if not (url.startswith('http')):
        url = f'http://{url}'
    file_name = f'{file_name}.{"pdf" if r_type == RasterizeType.PDF else "png"}'  # type: ignore

    output = rasterize(path=url, r_type=r_type, width=w, height=h, wait_time=wait_time, max_page_load_time=page_load,
                       full_screen=full_screen, r_mode=r_mode, include_url=include_url)
    if r_type == RasterizeType.JSON:
        return_results(CommandResults(raw_response=output, readable_output="Successfully rasterize url: " + url))
        return

    res = fileResult(filename=file_name, data=output)
    if r_type == RasterizeType.PNG:
        res['Type'] = entryTypes['image']

    demisto.results(res)


def get_common_args(args: dict):
    """
    Get commomn args.
    :param args: dict to get args from
    :return: width, height, rasterize mode
    """
    w = int(args.get('width', DEFAULT_W).rstrip('px'))
    h = int(args.get('height', DEFAULT_H).rstrip('px'))
    r_mode = RasterizeMode(args.get('mode', DEFAULT_MODE))
    return w, h, r_mode


def rasterize_image_command():
    args = demisto.args()
    entry_id = args.get('EntryID')
    w, h, r_mode = get_common_args(args)
    file_name = args.get('file_name', entry_id)
    full_screen = argToBoolean(demisto.args().get('full_screen', False))

    w, h = check_width_and_height(w, h)  # Check that the width and height meet the safeguard limit

    file_path = demisto.getFilePath(entry_id).get('path')
    file_name = f'{file_name}.pdf'

    with open(file_path, 'rb') as f:
        output = rasterize(path=f'file://{os.path.realpath(f.name)}', width=w, height=h, r_type=RasterizeType.PDF,
                           full_screen=full_screen, r_mode=r_mode)
        res = fileResult(filename=file_name, data=output, file_type=entryTypes['entryInfoFile'])
        demisto.results(res)


def rasterize_email_command():
    html_body = demisto.args().get('htmlBody')
    w, h, r_mode = get_common_args(demisto.args())
    offline = demisto.args().get('offline', 'false') == 'true'
    r_type = RasterizeType(demisto.args().get('type', 'png').lower())
    file_name = demisto.args().get('file_name', 'email')
    html_load = int(demisto.args().get('max_page_load_time', DEFAULT_PAGE_LOAD_TIME))
    full_screen = argToBoolean(demisto.args().get('full_screen', False))

    w, h = check_width_and_height(w, h)  # Check that the width and height meet the safeguard limit

    file_name = f'{file_name}.{"pdf" if r_type == RasterizeType.PDF else "png"}'  # type: ignore
    with open('htmlBody.html', 'w', encoding='utf-8-sig') as f:
        f.write(f'<html style="background:white";>{html_body}</html>')
    path = f'file://{os.path.realpath(f.name)}'

    output = rasterize(path=path, r_type=r_type, width=w, height=h, offline_mode=offline,
                       max_page_load_time=html_load, full_screen=full_screen, r_mode=r_mode)
    res = fileResult(filename=file_name, data=output)
    if r_type == RasterizeType.PNG:
        res['Type'] = entryTypes['image']

    demisto.results(res)


def rasterize_pdf_command():
    entry_id = demisto.args().get('EntryID')
    password = demisto.args().get('pdfPassword')
    max_pages = demisto.args().get('maxPages', 30)
    horizontal = demisto.args().get('horizontal', 'false') == 'true'
    file_name = demisto.args().get('file_name', 'image')

    file_path = demisto.getFilePath(entry_id).get('path')

    file_name = f'{file_name}.jpeg'  # type: ignore

    with open(file_path, 'rb') as f:
        images = convert_pdf_to_jpeg(path=os.path.realpath(f.name), max_pages=max_pages, password=password,
                                     horizontal=horizontal)
        results = []
        for image in images:
            res = fileResult(filename=file_name, data=image)
            res['Type'] = entryTypes['image']
            results.append(res)

        demisto.results(results)


def rasterize_html_command():
    args = demisto.args()
    entry_id = args.get('EntryID')
    w = args.get('width', DEFAULT_W).rstrip('px')
    h = args.get('height', DEFAULT_H).rstrip('px')
    r_type = args.get('type', 'png')
    file_name = args.get('file_name', 'email')
    full_screen = argToBoolean(demisto.args().get('full_screen', False))
    wait_time = int(args.get('wait_time', 0))

    file_name = f'{file_name}.{"pdf" if r_type.lower() == "pdf" else "png"}'  # type: ignore
    file_path = demisto.getFilePath(entry_id).get('path')
    os.rename(f'./{file_path}', 'file.html')

    output = rasterize(path=f"file://{os.path.realpath('file.html')}", width=w, height=h, r_type=r_type,
                       full_screen=full_screen, wait_time=wait_time)

    res = fileResult(filename=file_name, data=output)
    if r_type == 'png':
        res['Type'] = entryTypes['image']
    return_results(res)


def module_test():
    # setting up a mock email file
    with tempfile.NamedTemporaryFile('w+') as test_file:
        test_file.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                        '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        test_file.flush()
        file_path = f'file://{os.path.realpath(test_file.name)}'

        # rasterizing the file
        rasterize(path=file_path, width=250, height=250, r_mode=DEFAULT_MODE)

    demisto.results('ok')


def main():  # pragma: no cover
    try:
        with open(DRIVER_LOG, 'w'):
            pass  # truncate the log file
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
    finally:
        if is_debug_mode():
            with open(DRIVER_LOG) as log:
                demisto.debug('Driver log:' + log.read())


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
