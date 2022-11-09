import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
banner = args.get('banner')
body_header = args.get('body_header')
body_text = '<br/>' + args.get('htmlBody', args.get('body')) + '<br/>'
custom_css = args.get('custom_css')

params = {'body': body_text,
          'header': body_header,
          'banner': banner,
          'custom_css': custom_css}

email_html = demisto.executeCommand(
    'fancy-email-make-email', params)[0]["Contents"]['html']
args['htmlBody'] = email_html


return_results(demisto.executeCommand('send-mail', args))
