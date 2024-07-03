import demistomock as demisto
from CommonServerPython import *

import shutil
import traceback
import os
import shlex
import base64
import subprocess
from pathlib import Path
import threading
import time
import http
import tempfile
from http.server import HTTPServer


def find_unused_port() -> int:  # pragma: no cover
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('localhost', 0))  # tries to bind any available port on the os
        return sock.getsockname()[1]
    except Exception:
        start_port, end_port = 10000, 30000
        for port in range(start_port, end_port + 1):
            is_connection_success = sock.connect_ex(('localhost', port))
            if is_connection_success == 0:
                demisto.debug(f'Port {port} is already used')
            else:
                demisto.debug(f'Port {port} is free')
                return port
        raise RuntimeError("Could not find available ports")
    finally:
        sock.close()


WORKING_DIR = Path("/app")
DISABLE_LOGOS = True  # Bugfix before sane-reports can work with image files.
MD_IMAGE_PATH = '/markdown/image'
MD_HTTP_PORT = find_unused_port()
SERVER_OBJECT = None
MD_IMAGE_SUPPORT_MIN_VER = '6.5'
TABLE_TEXT_MAX_LENGTH_SUPPORT_MIN_VER = '7.0'
TENANT_ACCOUNT_NAME = get_tenant_account_name()
MD_IMAGE_PATH_SAAS = '/xsoar/markdown/image'
MD_IMAGE_SAAS_VERSION = '8.0'


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


def quit_driver_and_reap_children(killMarkdownServer):  # pragma: no cover
    try:
        if killMarkdownServer:
            # Kill Markdown artifacts server
            global SERVER_OBJECT
            if SERVER_OBJECT:
                demisto.debug("Shutting down markdown artifacts server")
                SERVER_OBJECT.shutdown()

        zombies, ps_out = find_zombie_processes()
        if zombies:  # pragma no cover
            demisto.info(f'Found zombie processes will waitpid: {ps_out}')
            for pid in zombies:
                waitres = os.waitpid(int(pid), os.WNOHANG)[1]
                demisto.info(f'waitpid result: {waitres}')
        else:
            demisto.debug(f'No zombie processes found for ps output: {ps_out}')

    except Exception as e:
        demisto.error(f'Failed checking for zombie processes: {e}. Trace: {traceback.format_exc()}')


def startServer():  # pragma: no cover
    class fileHandler(http.server.BaseHTTPRequestHandler):
        # See: https://docs.python.org/3/library/http.server.html#http.server.BaseHTTPRequestHandler.log_message
        # Need to override otherwise messages are logged to stderr
        def log_message(self, msg, *args):
            demisto.debug("python http server log: " + (msg % args))

        def do_GET(self):
            demisto.debug(f'Handling MD Image request {self.path}')
            img_path = MD_IMAGE_PATH_SAAS if is_demisto_version_ge(MD_IMAGE_SAAS_VERSION) else MD_IMAGE_PATH
            if TENANT_ACCOUNT_NAME:
                markdown_path_prefix = f"/{TENANT_ACCOUNT_NAME}{img_path}"
            else:
                markdown_path_prefix = img_path

            if not self.path.startswith(markdown_path_prefix):
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
                    # Open the file
                    with open(f'{file_path}', 'rb') as file:
                        self.send_response(200)
                        self.send_header("Content-type", "application/octet-stream")
                        self.send_header("Content-Disposition", f'attachment; filename={name}')
                        self.end_headers()
                        self.wfile.write(file.read())  # Read the file and send the contents
                except BrokenPipeError:  # ignore broken pipe as socket might have been closed
                    pass
            except Exception as ex:
                demisto.error(f'Failed to get markdown file: {fileID}, file path: {file_path}. Error: {ex}')
                self.send_response(404)
                self.flush_headers()
    # Create server object listening the port 10888
    global SERVER_OBJECT
    SERVER_OBJECT = HTTPServer(server_address=('', MD_HTTP_PORT), RequestHandlerClass=fileHandler)
    # Start the web server
    demisto.debug(f"starting markdown server on port {MD_HTTP_PORT}")
    SERVER_OBJECT.serve_forever()


def main():  # pragma: no cover
    isMDImagesSupported = is_demisto_version_ge(MD_IMAGE_SUPPORT_MIN_VER)
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
        tableTextMaxLength = demisto.args().get('tableTextMaxLength', '300')
        forceServerFormattedTimeString = demisto.args().get('forceServerFormattedTimeString', 'false')
        addUtf8Bom = demisto.args().get('addUtf8Bom', 'false')

        # Note: After headerRightImage the empty one is for legacy argv in server.js
        extra_cmd = f"{orientation} {resourceTimeout} {reportType} " + \
                    f'"{headerLeftImage}" "{headerRightImage}" "" ' + \
                    f'"{pageSize}" "{disableHeaders}"'

        isMDImagesSupported = is_demisto_version_ge(MD_IMAGE_SUPPORT_MIN_VER)
        if isMDImagesSupported:  # pragma: no cover
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

            isTableTextMaxLengthSupported = is_demisto_version_ge(TABLE_TEXT_MAX_LENGTH_SUPPORT_MIN_VER)

            if isTableTextMaxLengthSupported:
                extra_cmd += f' {tableTextMaxLength}'
            else:
                extra_cmd += ' ""'

            extra_cmd += f' "{forceServerFormattedTimeString}"'
            extra_cmd += f' "{addUtf8Bom}"'

        with tempfile.TemporaryDirectory(suffix='sane-pdf', ignore_cleanup_errors=True) as tmpdir:  # type: ignore[call-overload]
            input_file = tmpdir + '/input.json'
            output_file = tmpdir + '/output.pdf'
            dist_dir = tmpdir + '/dist'

            shutil.copytree(WORKING_DIR / 'dist', dist_dir)

            with open(input_file, 'wb') as f:
                f.write(base64.b64decode(sane_json_b64))

            if headerLeftImage:
                customer_logo_file_path = tmpdir + "/customer-logo-base64.txt"
                with open(customer_logo_file_path, "w") as f:
                    f.write(headerLeftImage)
                extra_cmd = extra_cmd.replace(headerLeftImage, customer_logo_file_path)
                headerLeftImage = customer_logo_file_path

            cmd = ['./reportsServer', input_file, output_file, dist_dir] + shlex.split(
                extra_cmd)

            # Logging things for debugging
            params = f'[orientation="{orientation}",' \
                f' resourceTimeout="{resourceTimeout}",' \
                f' reportType="{reportType}", headerLeftImage="{headerLeftImage}",' \
                f' headerRightImage="{headerRightImage}", pageSize="{pageSize}",' \
                f' disableHeaders="{disableHeaders}", forceServerFormattedTimeString="{forceServerFormattedTimeString}",' \
                f' addUtf8Bom="{addUtf8Bom}"'

            if isMDImagesSupported:
                params += f', markdownArtifactsServerAddress="{mdServerAddress}"'

            demisto.debug(f"Sane-PDF parameters: {params}]")
            cmd_string = " ".join(cmd)
            demisto.debug(f'Sane-PDF report commmad: {cmd_string}')

            # Execute the report creation
            out = subprocess.check_output(cmd, cwd=WORKING_DIR,
                                          stderr=subprocess.STDOUT)
            demisto.debug(f"Sane-pdf output: {str(out)}")

            with open(output_file, 'rb') as f:
                encoded = base64.b64encode(f.read()).decode('utf-8', 'ignore')

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
