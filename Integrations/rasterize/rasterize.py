import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, InvalidArgumentException
import sys
import base64

PROXY = demisto.getParam('proxy')

if PROXY:
    HTTP_PROXY = os.environ.get('http_proxy')
    HTTPS_PROXY = os.environ.get('https_proxy')

WITH_ERRORS = demisto.params().get('with_error', True)
DEFAULT_STDOUT = sys.stdout

URL_ERROR_MSG = "Can't access the URL. It might be malicious, or unreachable for one of several reasons. " \
                "You can choose to receive this message as error/warning in the instance settings\n"
EMPTY_RESPONSE_ERROR_MSG = "There is nothing to render. This can occur when there is a refused connection." \
                           " Please check your URL."
DEFAULT_W, DEFAULT_H = 600, 800


def check_response(driver):
    EMPTY_PAGE = '<html><head></head><body></body></html>'
    if driver.page_source == EMPTY_PAGE:
        return_error(EMPTY_RESPONSE_ERROR_MSG) if WITH_ERRORS else return_warning(EMPTY_RESPONSE_ERROR_MSG, exit=True)


def init_driver():
    """
    Creates headless Google Chrome Web Driver
    """
    demisto.debug('Creating chrome driver')
    try:
        with open('log.txt', 'w') as log:
            sys.stdout = log
            chrome_options = webdriver.ChromeOptions()
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--hide-scrollbars')
            chrome_options.add_argument('--disable_infobars')
            chrome_options.add_argument('--start-maximized')
            chrome_options.add_argument('--start-fullscreen')
            chrome_options.add_argument('--ignore-certificate-errors')

            driver = webdriver.Chrome(options=chrome_options)

            # remove log
            os.remove(os.path.realpath(log.name))

    except Exception as ex:
        return_error(str(ex))
    finally:
        sys.stdout = DEFAULT_STDOUT

    demisto.debug('Creating chrome driver - COMPLETED')
    return driver


def rasterize(path: str, width: int, height: int, r_type='png'):
    """
    Capturing a snapshot of a path (url/file), using Chrome Driver
    :param path: file path, or website url
    :param width: desired snapshot width in pixels
    :param height: desired snapshot height in pixels
    :param r_type: result type: .png/.pdf
    """
    driver = init_driver()

    try:
        demisto.debug('Navigating to path')

        driver.get(path)
        driver.implicitly_wait(5)
        check_response(driver)

        demisto.debug('Navigating to path - COMPLETED')

        if r_type.lower() == 'pdf':
            output = get_pdf(driver, width, height)
        else:
            output = get_image(driver, width, height)

        return output

    except (InvalidArgumentException, NoSuchElementException) as ex:
        if 'invalid argument' in str(ex):
            err_msg = URL_ERROR_MSG + str(ex)
            return_error(err_msg) if WITH_ERRORS else return_warning(err_msg, exit=True)
        else:
            return_error(str(ex)) if WITH_ERRORS else return_warning(str(ex), exit=True)


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


def rasterize_command():
    url = demisto.getArg('url')
    w = demisto.args().get('width', DEFAULT_W)
    h = demisto.args().get('height', DEFAULT_H)
    r_type = demisto.args().get('type', 'png')

    if not (url.startswith('http')):
        url = f'http://{url}'
    filename = f'url.{"pdf" if r_type == "pdf" else "png"}'  # type: ignore
    proxy_flag = ""
    if PROXY:
        proxy_flag = f"--proxy={HTTPS_PROXY if url.startswith('https') else HTTP_PROXY}"  # type: ignore
    demisto.debug('rasterize proxy settings: ' + proxy_flag)

    output = rasterize(path=url, r_type=r_type, width=w, height=h)
    file = fileResult(filename=filename, data=output)
    if r_type == 'png':
        file['Type'] = entryTypes['image']

    demisto.results(file)


def rasterize_image_command():
    entry_id = demisto.args().get('EntryID')
    w = demisto.args().get('width', DEFAULT_W)
    h = demisto.args().get('height', DEFAULT_H)

    file_path = demisto.getFilePath(entry_id).get('path')
    filename = 'image.png'  # type: ignore

    with open(file_path, 'rb') as f, open('output_image', 'w') as image:
        data = base64.b64encode(f.read()).decode('utf-8')
        image.write(data)
        output = rasterize(path=f'file://{os.path.realpath(f.name)}', width=w, height=h)
        file = fileResult(filename=filename, data=output)
        file['Type'] = entryTypes['image']

        demisto.results(file)


def rasterize_email_command():
    html_body = demisto.args().get('htmlBody')
    w = demisto.args().get('width', DEFAULT_W)
    h = demisto.args().get('height', DEFAULT_H)
    r_type = demisto.args().get('type', 'png')

    filename = f'email.{"pdf" if r_type.lower() == "pdf" else "png"}'  # type: ignore
    with open('htmlBody.html', 'w') as f:
        f.write(f'<html style="background:white";>{html_body}</html>')
    path = f'file://{os.path.realpath(f.name)}'

    output = rasterize(path=path, r_type=r_type, width=w, height=h)
    file = fileResult(filename=filename, data=output)
    if r_type == 'png':
        file['Type'] = entryTypes['image']

    demisto.results(file)


def test():
    # setting up a mock email file
    with open('htmlBodyTest.html', 'w') as test_file:
        test_file.write('<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">'
                        '</head><body><br>---------- TEST FILE ----------<br></body></html>')
        file_path = f'file://{os.path.realpath(test_file.name)}'

    # rasterizing the file
    rasterize(path=file_path, width=250, height=250)

    demisto.results('ok')


def main():
    try:
        if demisto.command() == 'test-module':
            test()

        elif demisto.command() == 'rasterize-image':
            rasterize_image_command()

        elif demisto.command() == 'rasterize-email':
            rasterize_email_command()

        elif demisto.command() == 'rasterize':
            rasterize_command()

        else:
            return_error('Unrecognized command')

    except Exception as ex:
        return_error(str(ex))

    finally:  # just to be extra safe
        sys.stdout = DEFAULT_STDOUT


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
