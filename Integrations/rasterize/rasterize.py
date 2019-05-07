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
proxy = demisto.get(demisto.params(), "proxy")

if proxy:
    http_proxy = os.environ["http_proxy"]
    https_proxy = os.environ["https_proxy"]

return_code = 0
error_message = ''


def rasterize_email_request(html, friendlyName):
    global return_code
    global error_message

    f = open('htmlBody.html', 'w')
    f.write('<html style="background:white";>' + html + '</html>')
    f.close()

    proxy_flag = ""
    if proxy:
        proxy_flag = "--proxy=" + http_proxy
    demisto.debug('rasterize proxy settings: ' + proxy_flag)

    command = ['phantomjs', proxy_flag, '/usr/local/bin/rasterize.js', 'htmlBody.html', friendlyName]
    if demisto.get(demisto.args(), 'width') and demisto.get(demisto.args(), 'height'):
        command.append(demisto.get(demisto.args(), 'width') + '*' + demisto.get(demisto.args(), 'height'))
    try:
        error_message = subprocess.check_output(command)
    except Exception as e:
        return_code = -1
        error_message = e.message


def rasterize():
    global return_code, error_message, friendlyName, command, file
    return_code = 0
    error_message = ''
    url = demisto.args()['url']
    if not (url.startswith("http")):
        url = "http://" + url
    friendlyName = 'url.png'
    if demisto.get(demisto.args(), 'type') == 'pdf':
        friendlyName = 'url.pdf'
    proxy_flag = ""
    if proxy:
        if url.startswith("https"):
            proxy_flag = "--proxy=" + https_proxy
        else:
            proxy_flag = "--proxy=" + http_proxy
    demisto.debug('rasterize proxy settings: ' + proxy_flag)
    command = ['phantomjs', proxy_flag, '/usr/local/bin/rasterize.js', url, friendlyName]
    if demisto.get(demisto.args(), 'width') and demisto.get(demisto.args(), 'height'):
        command.append(demisto.get(demisto.args(), 'width') + '*' + demisto.get(demisto.args(), 'height'))
    try:
        error_message = subprocess.check_output(command)
    except subprocess.CalledProcessError:
        return_code = -1
        error_message = "Can't access the URL. It might be malicious, or unreachable for one of several reasons."
    if return_code == 0:
        file = file_result_existing_file(friendlyName)
        file['Type'] = entryTypes['image']
        demisto.results(file)
    else:
        demisto.results({'ContentsFormat': 'text', 'Type': entryTypes['error'],
                         'Contents': 'PhantomJS returned - ' + error_message})


def rasterize_image():
    global html, return_code, error_message, friendlyName, command, file
    res = demisto.getFilePath(demisto.args()['EntryID'])
    with open(res['path'], 'r') as f:
        data = f.read()
    b64 = base64.b64encode(data)
    html = '<img src="data:image/png;base64, ' + b64 + '">'
    return_code = 0
    error_message = ''
    friendlyName = 'image.png'
    f = open('htmlImage.html', 'w')
    f.write('<html style="background:white;"><body>' + html + '</body></html>')
    f.close()
    command = ['phantomjs', '/usr/local/bin/rasterize.js', 'htmlImage.html', friendlyName]
    if demisto.get(demisto.args(), 'width') and demisto.get(demisto.args(), 'height'):
        command.append(demisto.get(demisto.args(), 'width') + '*' + demisto.get(demisto.args(), 'height'))
    try:
        error_message = subprocess.check_output(command)
    except Exception as e:
        return_code = -1
        error_message = e.message
    if return_code == 0:
        file = file_result_existing_file(friendlyName)
        file['Type'] = entryTypes['image']
        demisto.results(file)

    else:
        demisto.results({'ContentsFormat': 'text', 'Type': entryTypes['error'],
                         'Contents': 'PhantomJS returned - ' + error_message})


def rasterize_email_command():
    global html, friendlyName, file
    html = demisto.args()['htmlBody']
    friendlyName = 'email.png'
    if demisto.get(demisto.args(), 'type') == 'pdf':
        friendlyName = 'email.pdf'
    rasterize_email_request(html, friendlyName)
    if return_code == 0:
        file = file_result_existing_file(friendlyName)
        file['Type'] = entryTypes['image']
        demisto.results(file)
    else:
        demisto.results({'ContentsFormat': 'text', 'Type': entryTypes['error'],
                         'Contents': 'PhantomJS returned - ' + error_message})


if demisto.command() == 'test-module':
    rasterize_email_request('test text', 'email.png')
    if return_code == 0:
        demisto.results('ok')
    else:
        demisto.results(error_message)

elif demisto.command() == 'rasterize-image':
    rasterize_image()

elif demisto.command() == 'rasterize-email':
    rasterize_email_command()

elif demisto.command() == 'rasterize':
    rasterize()
else:
    demisto.results({'ContentsFormat': 'text', 'Type': entryTypes['error'], 'Contents': 'Unrecognized command'})
