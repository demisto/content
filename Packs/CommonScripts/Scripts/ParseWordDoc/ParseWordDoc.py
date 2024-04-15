import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from docx import Document
from docx.opc.exceptions import PackageNotFoundError
from docx.opc.constants import RELATIONSHIP_TYPE as RT
import zipfile
from xml.etree.cElementTree import XML


def extract_urls_xml(file_path):
    urls = []
    document = zipfile.ZipFile(file_path)
    xml_content = document.read('word/document.xml')
    document.close()
    tree = XML(xml_content)

    for element in tree.iter():
        if hasattr(element, 'text') and element.text and 'HYPERLINK' in element.text:
            url = element.text.replace(' HYPERLINK "', '')[:-1]
            urls.append(url)
    return urls


def extract_urls_docx(document):
    urls = []
    rels = document.part.rels
    for rel in rels.values():
        if rel.reltype == RT.HYPERLINK:
            urls.append(rel._target)
    return urls


def parse_word_doc(entry_id):
    res = []
    errEntry = {
        "Type": entryTypes["error"],
        "ContentsFormat": formats["text"],
        "Contents": ""
    }

    try:
        cmd_res = demisto.getFilePath(entry_id)
        file_path = cmd_res.get('path')
        document = Document(file_path)
        file_data = '\n'.join([para.text for para in document.paragraphs])

        urls = extract_urls_xml(file_path) + extract_urls_docx(document)
        file_data = file_data + '\n\n\nExtracted links:\n* ' + '\n* '.join([url for url in urls])

        file_name = cmd_res.get('name')
        output_file_name = file_name[0:file_name.rfind('.')] + '.txt'
        res = fileResult(output_file_name, file_data.encode('utf8'))
    except PackageNotFoundError:
        errEntry["Contents"] = "Input file is not a valid docx/doc file."
        demisto.results(errEntry)
    except BaseException as e:
        errEntry["Contents"] = "Error occurred while parsing input file.\nException info: " + str(e)
        demisto.results(errEntry)

    demisto.results(res)


def main():
    entry_id = demisto.args()['entryID']
    parse_word_doc(entry_id)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
