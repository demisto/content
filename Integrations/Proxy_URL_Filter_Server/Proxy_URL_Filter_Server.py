import demistomock as demisto
from CommonServerPython import *
import signal
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
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text')
        self.end_headers()

        ctx = demisto.getIntegrationContext()
        format_filter = demisto.getParam('format_filter')
        body = ""
        if format_filter == "Symantec ProxySG":
            body = proxysg_filter(ctx)

        self.wfile.write(bytes(body, "utf8"))
        return


def add_url_command(args):
    ctx = demisto.getIntegrationContext()
    cat = args.get('category')
    urls = ctx.setdefault(cat, [])

    urls.append(args.get('url'))

    ctx[cat] = list(set(urls))
    demisto.setIntegrationContext(ctx)

    return 'Done'


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

    ctx[cat] = list(set(urls))
    demisto.setIntegrationContext(ctx)

    return 'Done'


def run_long_running(port):
    try:
        httpd = ThreadingHTTPServer(('0.0.0.0', port), RequestHandler)
        signal.signal(signal.SIGTERM, httpd.shutdown)
        signal.signal(signal.SIGINT, httpd.shutdown)
        httpd.serve_forever()
    except Exception:
        httpd.shutdown()
        raise


def main():
    try:
        if demisto.command() == 'test-module':
            # validate that the port is integer
            int(demisto.getParam('longRunningPort'))

            demisto.results('ok')
            return

        if demisto.command() == 'proxy-filter-add-url':
            result = add_url_command(demisto.args())
            demisto.results(result)
            return

        if demisto.command() == 'proxy-filter-del-url':
            result = remove_url_command(demisto.args())
            demisto.results(result)
            return

        if demisto.command() == 'long-running-execution':
            port = int(demisto.getParam('longRunningPort'))
            run_long_running(port)

    except Exception as ex:
        return_error(f'Failed to run {demisto.command()}. Error: {str(ex)}', ex)


if __name__ in ("__builtin__", "builtins"):
    main()
