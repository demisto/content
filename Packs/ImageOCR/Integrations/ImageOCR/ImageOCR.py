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


def list_languages_command() -> CommandResults:
    langs = list_languages()
    return CommandResults(
        readable_output="## Image OCR Supported Languages\n\n" + "\n".join(['* ' + s for s in langs]),
        raw_response=langs
    )


def extract_text_command(args: dict, instance_languages: list) -> CommandResults:
    langs = argToList(args.get('langs')) or instance_languages
    demisto.debug("Using langs settings: {}".format(langs))

    entry_id = args.get('entryid')
    file_path = demisto.getFilePath(entry_id)
    if not file_path:
        raise DemistoException("Couldn't find entry id: {}".format(entry_id))

    demisto.debug('Extracting text from file: {}'.format(file_path))
    res = extract_text(file_path['path'], langs)
    file_entry = {'EntryID': entry_id, 'Text': res}

    return CommandResults(
        readable_output="## Image OCR Extracted Text\n\n" + res,
        outputs_prefix='File',
        outputs_key_field='EntryID',
        outputs=file_entry,
        raw_response=res
    )


def run_test_module(instance_languages: list) -> str:
    try:
        supported_langs = list_languages()
        if instance_languages:
            for language in instance_languages:
                if language not in supported_langs:
                    raise DemistoException('Unsupported language configured: {}'.format(language))
        return 'ok'
    except Exception as exception:
        raise Exception('Failed testing {}: {}'.format(TESSERACT_EXE, str(exception)))


def main() -> None:
    command = demisto.command()
    args = demisto.args()
    instance_languages = argToList(demisto.params().get('langs'))
    try:
        if command == 'test-module':
            return_results(run_test_module(instance_languages))
        elif command == 'image-ocr-list-languages':
            return_results(list_languages_command())
        elif command == 'image-ocr-extract-text':
            return_results(extract_text_command(args, instance_languages))
        else:
            raise NotImplementedError(f'Command {command} was not implemented.')
    except subprocess.CalledProcessError as cpe:
        return_error("Failed {} execution. Return status: {}.\nError:\n{}".format(cpe.cmd, cpe.returncode, cpe.stderr))
    except Exception as err:
        return_error("Failed with error: {}\n\nTrace:\n{}".format(str(err), traceback.format_exc()))


# python2 uses __builtin__ python3 uses builtins
if __name__ in ("__builtin__", "builtins", '__main__'):
    main()
