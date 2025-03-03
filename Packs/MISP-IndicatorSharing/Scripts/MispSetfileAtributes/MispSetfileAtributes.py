import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
file_indicator_dict = demisto.args()['file_indicator']


misp_atribute = {}

for key in file_indicator_dict.keys():
    if key == 'associatedfilenames':
        if file_indicator_dict[key] != 'n/a':
            misp_atribute["filename"] = ','.join(file_indicator_dict[key])
    if key == 'md5':
        if file_indicator_dict[key] != 'n/a':
            misp_atribute["md5"] = file_indicator_dict[key]
    if key == 'path':
        if file_indicator_dict[key] != 'n/a':
            misp_atribute["path"] = file_indicator_dict[key]
    if key == 'sha1':
        if file_indicator_dict[key] != 'n/a':
            misp_atribute["sha1"] = file_indicator_dict[key]
    if key == 'sha256':
        if file_indicator_dict[key] != 'n/a':
            misp_atribute["sha256"] = file_indicator_dict[key]
    if key == 'size-in-bytes':
        if file_indicator_dict[key] != 'n/a':
            misp_atribute["size-in-bytes"] = file_indicator_dict[key]
    if key == 'ssdeep':
        if file_indicator_dict[key] != 'n/a':
            misp_atribute["ssdeep"] = file_indicator_dict[key]
    if key == 'mimetype':
        if file_indicator_dict[key] != 'n/a':
            misp_atribute["mimetype"] = file_indicator_dict[key]


if len(misp_atribute.keys()) > 0:
    results = CommandResults(
        outputs_prefix='fileindicator',
        outputs=misp_atribute,
        readable_output=tableToMarkdown('', misp_atribute, headers=misp_atribute.keys())
    )


return_results(results)
