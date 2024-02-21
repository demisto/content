import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict, Any
import openpyxl
from docx import Document
from pptx import Presentation
import zipfile
import pandas as pd


def extract_hyperlinks_from_xlsx(file_path):

    with zipfile.ZipFile(file_path, "r") as zf:
        xmls = [zf.read(fn) for fn in zf.infolist()
                if fn.filename.startswith("xl/drawings/_rels/")]

    urls = set()

    for xml_data in xmls:
        df = pd.read_xml(xml_data)

        if "TargetMode" in df.columns:
            filtered_df = df.loc[df["TargetMode"].eq("External"), "Target"]
            urls |= set(filtered_df)

    wb = openpyxl.load_workbook(file_path)
    for sheet in wb:
        for row in sheet.iter_rows():
            for cell in row:
                if cell.hyperlink:
                    urls.add(cell.hyperlink.target)

    return urls


def extract_hyperlinks_from_docx(file_path):
    doc = Document(file_path)
    links = set()
    for para in doc.paragraphs:
        for hyper in para.hyperlinks:
            if hyper.address:
                links.add(hyper.address)
    return links


def extract_hyperlinks_from_pptx(file_path):
    prs = Presentation(file_path)
    links = set()
    for slide in prs.slides:
        for shape in slide.shapes:
            if shape.has_text_frame:
                for paragraph in shape.text_frame.paragraphs:
                    for run in paragraph.runs:
                        if run.hyperlink and run.hyperlink.address:
                            links.add(run.hyperlink.address)
            if shape.click_action and shape.click_action.hyperlink.address:
                links.add(shape.click_action.hyperlink.address)

    return links


def extract_hyperlink_by_file_type(file_path: str) -> CommandResults:

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


def main():     # pragma: no cover
    entry_id = demisto.args().get("entry_id")
    file_result = demisto.getFilePath(entry_id)
    if not file_result:
        return_error("Couldn't find entry id: {}".format(entry_id))
    file_path = file_result.get('path')

    try:
        return_results(extract_hyperlink_by_file_type(file_path))
    except Exception as ex:
        return_error(f'Failed to execute ExtractHyperlinksFromOfficeFiles. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
