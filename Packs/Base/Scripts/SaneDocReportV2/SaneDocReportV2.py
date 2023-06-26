import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback

from CommonServerUserPython import *
import os
import base64
from sane_doc_reports.main import run


OUTPUT_FILE_PATH = 'out.docx'
try:
    sane_json_b64 = demisto.args().get('sane_docx_report_base64', '').encode(
        'utf-8')
    orientation = demisto.args().get('orientation', 'portrait')
    paper_size = demisto.args().get('paperSize', 'A4')
    demistoLogo = demisto.args().get('demistoLogo', '')
    customerLogo = demisto.args().get('customerLogo', '')

    with open('sane.json', 'wb') as f:
        f.write(base64.b64decode(sane_json_b64))

    run('sane.json', OUTPUT_FILE_PATH, {
        'orientation': orientation,
        'paper_size': paper_size,
        'demistoLogo': demistoLogo,
        'customerLogo': customerLogo,
    })

    with open(OUTPUT_FILE_PATH, 'rb') as f:  # type: ignore
        encoded = base64.b64encode(f.read()).decode('utf-8', 'ignore')

    os.remove(OUTPUT_FILE_PATH)
    return_outputs(readable_output='Successfully generated docx',
                   outputs={}, raw_response={'data': encoded})
except Exception:
    tb = traceback.format_exc()
    wrap = "=====sane-doc-reports error====="
    err = f'{wrap}\n{tb}{wrap}\n'
    return_error(f'[SaneDocReports Automation Error] - {err}')
