import demistomock as demisto
from CommonServerPython import *
import subprocess
import traceback
from typing import List

TESSERACT_EXE = 'tesseract'


def list_languages() -> List[str]:
    lang_out = subprocess.check_output([TESSERACT_EXE, '--list-langs'], universal_newlines=True)
    if not lang_out:  # something went wrong
        raise ValueError('No output from --list-langs')
    lines = lang_out.splitlines()
    if len(lines) <= 1:
        raise ValueError('No output from --list-langs')
    return sorted(lines[1:])  # ignore first line


def extract_text(image_path: str, languages: List[str] = None) -> str:
    exe_params = [TESSERACT_EXE, image_path, 'stdout']
    if languages:
        exe_params.extend(['-l', '+'.join(languages)])
    res = subprocess.run(exe_params, capture_output=True, check=True, text=True)
    if res.stderr:
        demisto.debug('tesseract returned ok but stderr contains warnings: {}'.format(res.stderr))
    return res.stdout


def list_languages_command() -> dict:
    langs = list_languages()
    return {
        'Type': entryTypes['note'],
        'Contents': langs,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': "## Image OCR Supported Languages\n\n" + "\n".join(['* ' + s for s in langs]),
    }


def extract_text_command() -> dict:
    langs = argToList(demisto.getArg('langs')) or argToList(demisto.getParam('langs'))
    demisto.debug("Using langs settings: {}".format(langs))
    entry_id = demisto.args()['entryid']
    file_path = demisto.getFilePath(entry_id)
    if not file_path:
        return_error("Couldn't find entry id: {}".format(entry_id))
    demisto.debug('Extracting text from file: {}'.format(file_path))
    res = extract_text(file_path['path'], langs)
    file_entry = {'EntryID': entry_id, 'Text': res}
    return {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['text'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': "## Image OCR Extracted Text\n\n" + res,
        "EntryContext": {"File(val.EntryID == obj.EntryID)": file_entry},
    }


def test_module() -> None:
    try:
        supported_langs = list_languages()
        conf_langs = argToList(demisto.getParam('langs'))
        if conf_langs:
            for language in conf_langs:
                if language not in supported_langs:
                    demisto.results('Unsupported language configured: {}'.format(language))
        demisto.results('ok')
    except Exception as exception:
        demisto.results('Failed testing {}: {}'.format(TESSERACT_EXE, str(exception)))


def main():
    try:
        if demisto.command() == 'test-module':
            test_module()
        elif demisto.command() == 'image-ocr-list-languages':
            demisto.results(list_languages_command())
        elif demisto.command() == 'image-ocr-extract-text':
            demisto.results(extract_text_command())
        else:
            return_error('Unknown command: {}'.format(demisto.command()))
    except subprocess.CalledProcessError as cpe:
        return_error("Failed {} execution. Return status: {}.\nError:\n{}".format(cpe.cmd, cpe.returncode, cpe.stderr))
    except Exception as ex:
        return_error("Failed with error: {}\n\nTrace:\n{}".format(str(ex), traceback.format_exc()))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
