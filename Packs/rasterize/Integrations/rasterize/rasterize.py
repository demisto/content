import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, InvalidArgumentException, TimeoutException
from PyPDF2 import PdfFileReader
from pdf2image import convert_from_path
import numpy as np
from PIL import Image
import tempfile
from io import BytesIO
import base64
import time
import subprocess
import traceback
import re
import os

# Chrome respects proxy env params
handle_proxy()
# Make sure our python code doesn't go through a proxy when communicating with chrome webdriver
os.environ['no_proxy'] = 'localhost,127.0.0.1'

WITH_ERRORS = demisto.params().get('with_error', True)
DEFAULT_WAIT_TIME = max(int(demisto.params().get('wait_time', 0)), 0)
DEFAULT_PAGE_LOAD_TIME = int(demisto.params().get('max_page_load_time', 180))

URL_ERROR_MSG = "Can't access the URL. It might be malicious, or unreachable for one of several reasons. " \
                "You can choose to receive this message as error/warning in the instance settings\n"
EMPTY_RESPONSE_ERROR_MSG = "There is nothing to render. This can occur when there is a refused connection." \
                           " Please check your URL."
DEFAULT_W, DEFAULT_H = '600', '800'
DEFAULT_W_WIDE = '1024'
CHROME_USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.164 Safari/537.36'  # noqa
DRIVER_LOG = f'{tempfile.gettempdir()}/chromedriver.log'
DEFAULT_CHROME_OPTIONS = [
    '--no-sandbox',
    '--headless',
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
    user_options = re.split(r'(?<!\\),', user_options) if user_options else list()
    if not user_options:  # nothing to do
        return default_options
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


def init_driver(offline_mode=False):
    """
    Creates headless Google Chrome Web Driver
    """
    demisto.debug(f'Creating chrome driver. Mode: {"OFFLINE" if offline_mode else "ONLINE"}')
    try:
        chrome_options = webdriver.ChromeOptions()
        for opt in merge_options(DEFAULT_CHROME_OPTIONS, USER_CHROME_OPTIONS):
            chrome_options.add_argument(opt)
        driver = webdriver.Chrome(options=chrome_options, service_args=[
            f'--log-path={DRIVER_LOG}',
        ])
        if offline_mode:
            driver.set_network_conditions(offline=True, latency=5, throughput=500 * 1024)
    except Exception as ex:
        return_error(f'Unexpected exception: {ex}\nTrace:{traceback.format_exc()}')

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


def quit_driver_and_reap_children(driver):
    """
    Quits the driver's session and reaps all of zombie child processes
    :param driver: The driver
    :return: None
    """
    demisto.debug(f'Quitting driver session: {driver.session_id}')
    driver.quit()
    try:
        zombies, ps_out = find_zombie_processes()
        if zombies:
            demisto.info(f'Found zombie processes will waitpid: {ps_out}')
            for pid in zombies:
                waitres = os.waitpid(int(pid), os.WNOHANG)[1]
                demisto.info(f'waitpid result: {waitres}')
        else:
            demisto.debug(f'No zombie processes found for ps output: {ps_out}')
    except Exception as e:
        demisto.error(f'Failed checking for zombie processes: {e}. Trace: {traceback.format_exc()}')


def rasterize(path: str, width: int, height: int, r_type: str = 'png', wait_time: int = 0,
              offline_mode: bool = False, max_page_load_time: int = 180):
    """
    Capturing a snapshot of a path (url/file), using Chrome Driver
    :param offline_mode: when set to True, will block any outgoing communication
    :param path: file path, or website url
    :param width: desired snapshot width in pixels
    :param height: desired snapshot height in pixels
    :param r_type: result type: .png/.pdf
    :param wait_time: time in seconds to wait before taking a screenshot
    """
    driver = init_driver(offline_mode)
    page_load_time = max_page_load_time if max_page_load_time > 0 else DEFAULT_PAGE_LOAD_TIME
    try:
        demisto.debug(f'Navigating to path: {path}. Mode: {"OFFLINE" if offline_mode else "ONLINE"}. page load: {page_load_time}')
        driver.set_page_load_timeout(page_load_time)
        driver.get(path)
        driver.implicitly_wait(5)
        if wait_time > 0 or DEFAULT_WAIT_TIME > 0:
            time.sleep(wait_time or DEFAULT_WAIT_TIME)
        check_response(driver)
        demisto.debug('Navigating to path - COMPLETED')

        if r_type.lower() == 'pdf':
            output = get_pdf(driver, width, height)
        elif r_type.lower() == 'json':
            html = driver.page_source
            output = {'image_b64': base64.b64encode(get_image(driver, width, height)).decode('utf8'),
                      'html': html}
        else:
            output = get_image(driver, width, height)

        return output

    except (InvalidArgumentException, NoSuchElementException) as ex:
        if 'invalid argument' in str(ex):
            err_msg = URL_ERROR_MSG + str(ex)
            return_err_or_warn(err_msg)
        else:
            return_err_or_warn(f'Invalid exception: {ex}\nTrace:{traceback.format_exc()}')
    except TimeoutException as ex:
        return_err_or_warn(f'Timeout exception with max load time of: {page_load_time} seconds. {ex}')
    except Exception as ex:
        err_str = f'General error: {ex}\nTrace:{traceback.format_exc()}'
        demisto.error(err_str)
        return_err_or_warn(err_str)
    finally:
        quit_driver_and_reap_children(driver)


def get_image(driver, width: int, height: int):
    """
    Uses the Chrome driver to generate an image out of a currently loaded path
    :return: .png file of the loaded path
    """
    demisto.debug('Capturing screenshot')

    # Set windows size
    driver.set_window_size(width, height)

    image = driver.get_screenshot_as_png()
    driver.quit()

    demisto.debug('Capturing screenshot - COMPLETED')

    return image


def get_pdf(driver, width: int, height: int):
    """
    Uses the Chrome driver to generate an pdf file out of a currently loaded path
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


def convert_pdf_to_jpeg(path: str, max_pages: int, password: str, horizontal: bool = False):
    """
    Converts a PDF file into a jpeg image
    :param path: file's path
    :param max_pages: max pages to render
    :param password: PDF password
    :param horizontal: if True, will combine the pages horizontally
    :return: A list of stream of combined images
    """
    demisto.debug(f'Loading file at Path: {path}')
    input_pdf = PdfFileReader(open(path, "rb"), strict=False)
    pages = min(max_pages, input_pdf.numPages)

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
    w = demisto.args().get('width', DEFAULT_W_WIDE).rstrip('px')
    h = demisto.args().get('height', DEFAULT_H).rstrip('px')
    r_type = demisto.args().get('type', 'png')
    wait_time = int(demisto.args().get('wait_time', 0))
    page_load = int(demisto.args().get('max_page_load_time', DEFAULT_PAGE_LOAD_TIME))
    file_name = demisto.args().get('file_name', 'url')

    if not (url.startswith('http')):
        url = f'http://{url}'
    file_name = f'{file_name}.{"pdf" if r_type == "pdf" else "png"}'  # type: ignore

    output = rasterize(path=url, r_type=r_type, width=w, height=h, wait_time=wait_time, max_page_load_time=page_load)
    if r_type == 'json':
        return_results(CommandResults(raw_response=output, readable_output="Successfully load image for url: " + url))
        return

    res = fileResult(filename=file_name, data=output)
    if r_type == 'png':
        res['Type'] = entryTypes['image']

    demisto.results(res)


def rasterize_image_command():
    args = demisto.args()
    entry_id = args.get('EntryID')
    w = args.get('width', DEFAULT_W).rstrip('px')
    h = args.get('height', DEFAULT_H).rstrip('px')
    file_name = args.get('file_name', entry_id)

    file_path = demisto.getFilePath(entry_id).get('path')
    file_name = f'{file_name}.pdf'

    with open(file_path, 'rb') as f:
        output = rasterize(path=f'file://{os.path.realpath(f.name)}', width=w, height=h, r_type='pdf')
        res = fileResult(filename=file_name, data=output, file_type=entryTypes['entryInfoFile'])
        demisto.results(res)


def rasterize_email_command():
    html_body = demisto.args().get('htmlBody')
    w = demisto.args().get('width', DEFAULT_W).rstrip('px')
    h = demisto.args().get('height', DEFAULT_H).rstrip('px')
    offline = demisto.args().get('offline', 'false') == 'true'
    r_type = demisto.args().get('type', 'png')
    file_name = demisto.args().get('file_name', 'email')

    file_name = f'{file_name}.{"pdf" if r_type.lower() == "pdf" else "png"}'  # type: ignore
    with open('htmlBody.html', 'w') as f:
        f.write(f'<html style="background:white";>{html_body}</html>')
    path = f'file://{os.path.realpath(f.name)}'

    output = rasterize(path=path, r_type=r_type, width=w, height=h, offline_mode=offline)
    res = fileResult(filename=file_name, data=output)
    if r_type == 'png':
        res['Type'] = entryTypes['image']

    demisto.results(res)


def rasterize_pdf_command():
    entry_id = demisto.args().get('EntryID')
    password = demisto.args().get('pdfPassword')
    max_pages = int(demisto.args().get('maxPages', 30))
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


def module_test():
    # setting up a mock email file
    with tempfile.NamedTemporaryFile('w+') as test_file:
        test_file.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                        '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        test_file.flush()
        file_path = f'file://{os.path.realpath(test_file.name)}'

        # rasterizing the file
        rasterize(path=file_path, width=250, height=250)

    demisto.results('ok')


def main():
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

        elif demisto.command() == 'rasterize':
            rasterize_command()

        else:
            return_error('Unrecognized command')

    except Exception as ex:
        return_err_or_warn(f'Unexpected exception: {ex}\nTrace:{traceback.format_exc()}')
    finally:
        if is_debug_mode():
            demisto.debug(f'os.environ: {os.environ}')
            with open(DRIVER_LOG, 'r') as log:
                demisto.debug('Driver log:' + log.read())


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
