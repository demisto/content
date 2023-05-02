import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import base64

def img2html(image):
    data_uri = base64.b64encode(open(image, 'rb').read()).decode('utf-8')
    html = '<img src="data:image/png;base64,{0}">'.format(data_uri)
    return html

def main():
    if not demisto.context().get('RDPImageEntryID'):
        return_error("Missing Image")
    RDPImage = demisto.context().get('RDPImageEntryID')
    result = demisto.getFilePath(RDPImage)
    if not result:
        return_error("Couldn't find entry id: {}".format(entry_id))
    file_path = result['path']
    img_html = img2html(file_path)
    demisto.results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': img_html
    })

if __name__ in ["__builtin__", "builtins", '__main__']:
    main()

register_module_line('DisplayRDPImage', 'end', __line__())
