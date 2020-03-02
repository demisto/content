import demistomock as demisto
from CommonServerPython import *
import ssl
import signal
import base64
import tempfile

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def proxysg_filter(ctx):
    """
    define category blacklist
    http://example.com/
    end
    """

    body = ""
    for (cat, urls) in ctx.items():
        body += f"define category {cat}\n"
        for url in urls:
            body += f"    {url}\n"
        body += "end\n"
    return body


class RequestHandler(BaseHTTPRequestHandler):
    auth = demisto.getParam('auth')

    def check_auth(self):
        username = self.auth.get('identifier')
        password = self.auth.get('password')
        if username and password:
            auth = base64.b64encode(f'{username}:{password}'.encode()).decode()  # bytes are fun
            if self.headers.get('Authorization') == f'Basic {auth}':
                return True
            else:
                # auth failed
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm=\"Secret\"')
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                return False
        else:
            # no auth needed
            return True

    def do_GET(self):
        if not self.check_auth():
            return

        self.send_response(200)
        self.send_header('Content-type', 'text')
        self.end_headers()

        ctx = demisto.getIntegrationContext()
        format_filter = demisto.getParam('format_filter')
        body = ""
        if format_filter == "Symantec ProxySG":
            body = proxysg_filter(ctx)

        self.wfile.write(body.encode())


def add_url_command(args):
    ctx = demisto.getIntegrationContext()
    cat = args.get('category')
    urls = ctx.setdefault(cat, [])

    urls.append(args.get('url'))

    ctx[cat] = list(set(urls))
    demisto.setIntegrationContext(ctx)

    return_outputs('Done')


def remove_url_command(args):
    ctx = demisto.getIntegrationContext()
    cat = args.get('category')
    urls = ctx.setdefault(cat, [])
    url = args.get('url')
    try:
        urls.remove(url)
    except ValueError:
        return_error(f'{url} not in block list for category {cat}')
        return

    lst = list(set(urls))
    if lst:
        ctx[cat] = list(set(urls))
    else:
        del ctx[cat]
    demisto.setIntegrationContext(ctx)

    return_outputs('Done')


def list_urls_command():
    ctx = demisto.getIntegrationContext()
    return_outputs(None, {"ProxyURL": {"URLs": ctx}}, ctx)


def run_long_running(port):
    port = int(port)

    ssl_cert = demisto.getParam('auth').get('credentials', {}).get('sshkey')
    try:
        httpd = ThreadingHTTPServer(('0.0.0.0', port), RequestHandler)
        if ssl_cert:
            with tempfile.NamedTemporaryFile(delete=False) as fh:
                fh.write(ssl_cert.encode())
            httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True, certfile=fh.name)

        signal.signal(signal.SIGTERM, httpd.shutdown)
        signal.signal(signal.SIGINT, httpd.shutdown)
        if demisto.command() != 'test-module':
            httpd.serve_forever()
    except Exception as e:
        demisto.error(str(e))
        httpd.shutdown()
        raise


def test_module():
    try:
        run_long_running(demisto.getParam('longRunningPort'))
        demisto.results('ok')
    except Exception as ex:
        demisto.results(ex)


def main():
    try:
        if demisto.command() == 'test-module':
            test_module()

        elif demisto.command() == 'proxy-filter-add-url':
            add_url_command(demisto.args())

        elif demisto.command() == 'proxy-filter-del-url':
            remove_url_command(demisto.args())

        elif demisto.command() == 'proxy-filter-list-urls':
            list_urls_command()

        elif demisto.command() == 'long-running-execution':
            run_long_running(demisto.getParam('longRunningPort'))

    except Exception as ex:
        demisto.error(str(ex))
        return_error(f'Failed to run {demisto.command()}. Error: {str(ex)}', ex)
        raise


if __name__ in ("__builtin__", "builtins"):
    main()
