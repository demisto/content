import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict, Any
import openpyxl
from docx import Document
from pptx import Presentation


def extract_hyperlinks_from_xlsx(file_path):
    wb = openpyxl.load_workbook(file_path)
    links = []
    for sheet in wb:
        for row in sheet.iter_rows():
            for cell in row:
                if cell.hyperlink:
                    links.append(cell.hyperlink.target)
    return links


def extract_hyperlinks_from_docx(file_path):
    doc = Document(file_path)
    links = []
    for para in doc.paragraphs:
        for hyper in para.hyperlinks:
            if hyper.address:
                links.append(hyper.address)
    return links


def extract_hyperlinks_from_pptx(file_path):
    prs = Presentation(file_path)
    links = []
    for slide in prs.slides:
        for shape in slide.shapes:
            if shape.has_text_frame:
                for paragraph in shape.text_frame.paragraphs:
                    for run in paragraph.runs:
                        if run.hyperlink and run.hyperlink.address:
                            links.append(run.hyperlink.address)
    return links


def extract_hyperlink_by_file_type(args: Dict[str, Any]) -> CommandResults:

    entry_id = args.get("entry_id")
    file_result = demisto.getFilePath(entry_id)
    if not file_result:
        return_error("Couldn't find entry id: {}".format(entry_id))
    file_path = file_result.get('path')

    result = []
    if file_path.endswith('.xlsx'):
        result = extract_hyperlinks_from_xlsx(file_path)
    elif file_path.endswith('.docx'):
        result = extract_hyperlinks_from_docx(file_path)
    elif file_path.endswith('.pptx'):
        result = extract_hyperlinks_from_pptx(file_path)
    else:
        return_error("Not supported file type. Supported types are: 'xlsx, docx, pptx'")
    if result:
        hr = f'# Extracted hyperlinks are:\n\n{",".join(result)}'
    else:
        hr = '**No hyperlinks.**'

    return CommandResults(
        outputs_prefix='ExtractHyperlinksFromOfficeFiles',
        outputs=result,
        readable_output=hr
    )


def main():
    try:
        return_results(extract_hyperlink_by_file_type(demisto.args()))
    except Exception as ex:
        return_error(f'Failed to execute ExtractHyperlinksFromOfficeFiles. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
