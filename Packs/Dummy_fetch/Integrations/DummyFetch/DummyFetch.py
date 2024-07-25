import random
import string
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3
urllib3.disable_warnings()


''' CLIENT CLASS '''


def create_the_attachment():
    filename="large_file.pdf"
    size_in_mb=700
    target_size_bytes = size_in_mb * 1024 * 1024
    current_size = 0

    def get_random_text_block(size):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=size))

    header = (
        "%PDF-1.4\n"
        "1 0 obj\n"
        "<< /Type /Catalog /Pages 2 0 R >>\n"
        "endobj\n"
        "2 0 obj\n"
        "<< /Type /Pages /Count 1 /Kids [3 0 R] >>\n"
        "endobj\n"
        "3 0 obj\n"
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\n"
        "endobj\n"
    )

    start_xref = 113 + len(header)
    chunk_size = 1000
    content_stream = header

    content_stream += "4 0 obj\n<< /Length "
    content_stream += str(target_size_bytes)
    content_stream += " >>\nstream\n"

    while current_size < target_size_bytes:
        chunk = get_random_text_block(chunk_size)
        content_stream += chunk
        current_size += chunk_size

    content_stream += "\nendstream\nendobj\n"

    xref = (
        f"xref\n0 5\n0000000000 65535 f \n"
        f"0000000010 00000 n \n"
        f"0000000060 00000 n \n"
        f"0000000110 00000 n \n"
        f"{start_xref:010} 00000 n \n"
    )

    trailer = (
        "trailer\n<< /Size 5 /Root 1 0 R >>\n"
        "startxref\n"
        f"{start_xref}\n"
        "%%EOF"
    )

    content_stream += xref
    content_stream += trailer

    content_bytes = content_stream.encode('latin1')

    return fileResult(filename, content_bytes)


def create_incident_with_300_mb_command(last_run):
    incidents = []
    incident = {}
    incident['Name'] = "This is an incident for attachment larger then 300mb."
    incident['occurred'] = '2021-07-01T00:00:01Z'
    file_result = create_the_attachment()
    incident['rawJSON'] = json.dumps({})
    incident["attachment"] = [{
        "path": file_result["FileID"],
        "name": file_result["File"],
    }]
    demisto.setLastRun({"start_time": incident['occurred']})
    incidents.append(incident)
    return incidents

def download_file():
    file_result = create_the_attachment()
    return_results(file_result)

''' MAIN FUNCTION '''


def main() -> None:
    command = 'fetch-incidents'
    if command == "fetch-incidents":
        last_run = demisto.getLastRun()
        incidents = create_incident_with_300_mb_command(last_run)
        demisto.incidents(incidents)
    if command == 'download-file':
        return_results(download_file())
''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
