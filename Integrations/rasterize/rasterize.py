import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import os
import subprocess
import sys
import base64

# pylint: disable=E1103

reload(sys)
sys.setdefaultencoding("utf-8")
PROXY = demisto.getParam("proxy")

if PROXY:
    HTTP_PROXY = os.environ.get("http_proxy")
    HTTPS_PROXY = os.environ.get("https_proxy")

RETURN_CODE = 0
ERROR_MESSAGE = ''

ENTRY_TYPE = entryTypes['error'] if demisto.params().get('with_error', True) else 11  # 11 := entryTypes['warning']


def rasterize_email_request(html, friendly_name):
    global RETURN_CODE, ERROR_MESSAGE

    with open('htmlBody.html', 'w') as f:
        f.write('<html style="background:white";>' + html + '</html>')

    proxy_flag = "--proxy={}".format(HTTP_PROXY) if PROXY else ""
    demisto.debug('rasterize proxy settings: {}'.format(proxy_flag))

    command = ['phantomjs', proxy_flag, '/usr/local/bin/rasterize.js', 'htmlBody.html', friendly_name]
    if demisto.getArg('width') and demisto.getArg('height'):
        command.append(demisto.getArg('width') + '*' + demisto.getArg('height'))
    try:
        demisto.debug(subprocess.check_output(command, stderr=subprocess.STDOUT))  # type: ignore

    except Exception as e:
        RETURN_CODE = -1
        ERROR_MESSAGE = str(e) + '\nYou can choose to receive this errors as warnings in the instance settings'


def rasterize():
    global RETURN_CODE, ERROR_MESSAGE
    RETURN_CODE = 0
    ERROR_MESSAGE = ''
    url = demisto.getArg('url')
    if not (url.startswith("http")):
        url = "http://" + url
    friendly_name = 'url.png'
    if demisto.getArg('type') == 'pdf':
        friendly_name = 'url.pdf'
    proxy_flag = ""
    if PROXY:
        proxy_flag = "--proxy={}".format(HTTPS_PROXY if url.startswith("https") else HTTP_PROXY)  # type: ignore

    demisto.debug('rasterize proxy settings: ' + proxy_flag)
    command = ['phantomjs', proxy_flag, '/usr/local/bin/rasterize.js', url, friendly_name]
    if demisto.getArg('width') and demisto.getArg('height'):
        command.append(demisto.getArg('width') + '*' + demisto.getArg('height'))
    try:
        demisto.debug(subprocess.check_output(command, stderr=subprocess.STDOUT))
    except subprocess.CalledProcessError:
        RETURN_CODE = -1
        ERROR_MESSAGE = "Can't access the URL. It might be malicious, or unreachable for one of several reasons." \
                        "You can choose to receive this errors as warnings in the instance settings"
    if RETURN_CODE == 0:
        file = file_result_existing_file(friendly_name)
        file['Type'] = entryTypes['image']
        demisto.results(file)
    else:
        demisto.results(
            {
                'ContentsFormat': 'text',
                'Type': ENTRY_TYPE,
                'Contents': 'PhantomJS returned - ' + ERROR_MESSAGE
            }
        )


def rasterize_image():
    global RETURN_CODE, ERROR_MESSAGE
    res = demisto.getFilePath(demisto.getArg('EntryID'))
    with open(res['path'], 'r') as f:
        data = f.read()
    b64 = base64.b64encode(data)
    html = '<img src="data:image/png;base64, ' + b64 + '">'
    RETURN_CODE = 0
    friendly_name = 'image.png'
    f = open('htmlImage.html', 'w')
    f.write('<html style="background:white;"><body>' + html + '</body></html>')
    f.close()
    command = ['phantomjs', '/usr/local/bin/rasterize.js', 'htmlImage.html', friendly_name]
    if demisto.getArg('width') and demisto.getArg('height'):
        command.append(demisto.getArg('width') + '*' + demisto.getArg('height'))
    try:
        demisto.debug(subprocess.check_output(command, stderr=subprocess.STDOUT))
    except Exception as e:
        RETURN_CODE = -1
        ERROR_MESSAGE = str(e) + "\nYou can choose to receive this errors as warnings in the instance settings"

    if RETURN_CODE == 0:
        try:
            file = file_result_existing_file(friendly_name)
            file['Type'] = entryTypes['image']
            demisto.results(file)
        except Exception as e:
            demisto.debug(str(e))
            demisto.results({
                'ContentsFormat': 'text',
                'Type': ENTRY_TYPE,
                'Contents': str(e)
            })

    else:
        demisto.results({
            'ContentsFormat': 'text',
            'Type': ENTRY_TYPE,
            'Contents': 'PhantomJS returned - ' + ERROR_MESSAGE
        })


def rasterize_email_command():
    global RETURN_CODE, ERROR_MESSAGE

    html = demisto.getArg('htmlBody')
    friendly_name = 'email.png'
    if demisto.getArg('type') == 'pdf':
        friendly_name = 'email.pdf'
    rasterize_email_request(html, friendly_name)
    if RETURN_CODE == 0:
        try:
            file = file_result_existing_file(friendly_name)
            file['Type'] = entryTypes['image']
            demisto.results(file)
        except Exception as e:
            demisto.debug(str(e))
            demisto.results({
                'ContentsFormat': 'text',
                'Type': ENTRY_TYPE,
                'Contents': str(e)
            })

    else:
        demisto.results({
            'ContentsFormat': 'text',
            'Type': ENTRY_TYPE,
            'Contents': 'PhantomJS returned - ' + ERROR_MESSAGE
        })


try:
    if demisto.command() == 'test-module':
        rasterize_email_request('test text', 'email.png')
        if RETURN_CODE == 0:
            demisto.results('ok')
        else:
            demisto.results(ERROR_MESSAGE)

    elif demisto.command() == 'rasterize-image':
        rasterize_image()

    elif demisto.command() == 'rasterize-email':
        rasterize_email_command()

    elif demisto.command() == 'rasterize':
        rasterize()
    else:
        return_error('Unrecognized command')

except Exception as ex:
    return_error(str(ex))
