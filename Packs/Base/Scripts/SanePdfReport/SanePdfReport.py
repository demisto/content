import demistomock as demisto
from CommonServerPython import *
import traceback

import os
import shlex
import base64
import random
import string
import subprocess
from pathlib import Path
import threading
import time
import http
from http.server import HTTPServer

WORKING_DIR = Path("/app")
INPUT_FILE_PATH = 'sample.json'
OUTPUT_FILE_PATH = 'out{id}.pdf'
DISABLE_LOGOS = True  # Bugfix before sane-reports can work with image files.
MD_IMAGE_PATH = '/markdown/image'
MD_HTTP_PORT = 10888
SERVER_OBJECT = None
MD_IMAGE_SUPPORT_MIN_VER = '6.5'


def random_string(size=10):
    return ''.join(
        random.choices(string.ascii_uppercase + string.digits, k=size))


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


def quit_driver_and_reap_children(killMarkdownServer):
    try:
        if killMarkdownServer:
            # Kill Markdown artifacts server
            global SERVER_OBJECT
            if SERVER_OBJECT:
                demisto.debug("Shutting down markdown artifacts server")
                SERVER_OBJECT.shutdown()

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


def startServer():
    class fileHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            demisto.debug(f'Handling MD Image request {self.path}')
            if not self.path.startswith(MD_IMAGE_PATH):
                # not a standard xsoar markdown image endpoint
                self.send_response(400)
                self.flush_headers()
                return
            fileID = os.path.split(self.path)[1]
            try:
                res = demisto.getFilePath(fileID)
                file_path = res.get('path')
                if file_path == '':
                    demisto.debug(f'Failed to get markdown file {fileID}, empty filepath returned from xsoar')
                    self.send_response(404)
                    self.flush_headers()
                    return
                name = res.get('name')
                try:
                    self.send_response(200)
                    self.send_header("Content-type", "application/octet-stream")
                    self.send_header("Content-Disposition", f'attachment; filename={name}')
                    self.end_headers()
                    # Open the file
                    with open(f'{file_path}', 'rb') as file:
                        self.wfile.write(file.read())  # Read the file and send the contents
                    self.flush_headers()
                except BrokenPipeError:  # ignore broken pipe as socket might have been closed
                    pass
            except Exception as ex:
                demisto.debug(f'Failed to get markdown file {fileID}. Error: {ex}')
                self.send_response(404)
                self.flush_headers()

    # Make sure the server is created at current directory
    os.chdir('.')
    # Create server object listening the port 10888
    global SERVER_OBJECT
    SERVER_OBJECT = HTTPServer(server_address=('', MD_HTTP_PORT), RequestHandlerClass=fileHandler)
    # Start the web server
    SERVER_OBJECT.serve_forever()


def main():
    try:
        sane_json_b64 = demisto.args().get('sane_pdf_report_base64', '').encode(
            'utf-8')
        orientation = demisto.args().get('orientation', 'portrait')
        resourceTimeout = demisto.args().get('resourceTimeout', '4000')
        reportType = demisto.args().get('reportType', 'pdf')
        headerLeftImage = demisto.args().get('customerLogo', '')
        headerRightImage = demisto.args().get('demistoLogo', '')
        pageSize = demisto.args().get('paperSize', 'letter')
        disableHeaders = demisto.args().get('disableHeaders', '')

        # Note: After headerRightImage the empty one is for legacy argv in server.js
        extra_cmd = f"{orientation} {resourceTimeout} {reportType} " + \
                    f'"{headerLeftImage}" "{headerRightImage}" "" ' + \
                    f'"{pageSize}" "{disableHeaders}"'

        isMDImagesSupported = is_demisto_version_ge(MD_IMAGE_SUPPORT_MIN_VER)
        if isMDImagesSupported:
            # start the server in a background thread
            demisto.debug('Starting markdown artifacts http server...')
            threading.Thread(target=startServer).start()
            time.sleep(5)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('localhost', MD_HTTP_PORT))
            if result == 0:
                demisto.debug('Server is running')
                sock.close()
            else:
                demisto.error('Markdown artifacts server is not responding')
            # add md server address
            mdServerAddress = f'http://localhost:{MD_HTTP_PORT}'
            extra_cmd += f' "" "" "{mdServerAddress}"'

        # Generate a random input file so we won't override on concurrent usage
        input_id = random_string()
        input_file = INPUT_FILE_PATH.format(id=input_id)

        with open(WORKING_DIR / input_file, 'wb') as f:
            f.write(base64.b64decode(sane_json_b64))

        # Generate a random output file so we won't override on concurrent usage
        output_id = random_string()
        output_file = OUTPUT_FILE_PATH.format(id=output_id)

        cmd = ['./reportsServer', input_file, output_file, 'dist'] + shlex.split(
            extra_cmd)

        # Logging things for debugging
        params = f'[orientation="{orientation}",' \
            f' resourceTimeout="{resourceTimeout}",' \
            f' reportType="{reportType}", headerLeftImage="{headerLeftImage}",' \
            f' headerRightImage="{headerRightImage}", pageSize="{pageSize}",' \
            f' disableHeaders="{disableHeaders}"'

        if isMDImagesSupported:
            params += f', markdownArtifactsServerAddress="{mdServerAddress}"'

        LOG(f"Sane-pdf parameters: {params}]")
        cmd_string = " ".join(cmd)
        LOG(f"Sane-pdf cmd: {cmd_string}")
        LOG.print_log()

        # Execute the report creation
        out = subprocess.check_output(cmd, cwd=WORKING_DIR,
                                      stderr=subprocess.STDOUT)
        LOG(f"Sane-pdf output: {str(out)}")

        abspath_output_file = WORKING_DIR / output_file
        with open(abspath_output_file, 'rb') as f:
            encoded = base64.b64encode(f.read()).decode('utf-8', 'ignore')

        os.remove(abspath_output_file)
        return_outputs(readable_output='Successfully generated pdf',
                       outputs={}, raw_response={'data': encoded})

    except subprocess.CalledProcessError as e:
        tb = traceback.format_exc()
        wrap = "=====sane-pdf-reports error====="
        err = f'{wrap}\n{tb}{wrap}, process error: {e.output}\n'
        return_error(f'[SanePdfReports Automation Error - CalledProcessError] - {err}')

    except Exception:
        tb = traceback.format_exc()
        wrap = "=====sane-pdf-reports error====="
        err = f'{wrap}\n{tb}{wrap}\n'
        return_error(f'[SanePdfReports Automation Error - Exception] - {err}')

    finally:
        quit_driver_and_reap_children(isMDImagesSupported)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
