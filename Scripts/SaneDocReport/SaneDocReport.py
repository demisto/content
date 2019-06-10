import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import base64
from sane_doc_reports.main import run

try:
    sane_json_b64 = demisto.args().get('sane_docx_report_base64', '').encode("utf-8")
    with open('sane.json', 'wb') as f:
        f.write(base64.b64decode(sane_json_b64))

    run('sane.json', 'out.docx')

    with open('out.docx', 'rb') as f:
        encoded = base64.b64encode(f.read()).decode("utf-8", "ignore")
        return_outputs(readable_output='Successfully generated docx',
                       outputs={}, raw_response={'data': encoded})
except Exception as e:
    return_error(f'[SaneDocReports Automation Error] - {str(e)}')
