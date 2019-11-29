import signal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(demisto.getParam('longRunningPort'))


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


if demisto.command() == 'test-module':
    demisto.results('ok')
    sys.exit(0)

if demisto.command() == 'proxy-filter-add-url':
    ctx = demisto.getIntegrationContext()
    cat = demisto.getArg('category')
    urls = ctx.setdefault(cat, [])

    urls.append(demisto.getArg('url'))

    ctx[cat] = list(set(urls))
    demisto.setIntegrationContext(ctx)

    demisto.results('Done')
    sys.exit(0)

if demisto.command() == 'proxy-filter-del-url':
    ctx = demisto.getIntegrationContext()
    cat = demisto.getArg('category')
    urls = ctx.setdefault(cat, [])
    url = demisto.getArg('url')
    try:
        urls.remove(url)
    except ValueError:
        return_error(f'{url} not in block list for category {cat}')
        sys.exit(0)

    ctx[cat] = list(set(urls))
    demisto.setIntegrationContext(ctx)

    demisto.results('Done')
    sys.exit(0)

if demisto.command() == 'long-running-execution':
    try:
        httpd = ThreadingHTTPServer(('0.0.0.0', PORT), RequestHandler)
        signal.signal(signal.SIGTERM, httpd.shutdown)
        signal.signal(signal.SIGINT, httpd.shutdown)
        httpd.serve_forever()
    except Exception:
        httpd.shutdown()
