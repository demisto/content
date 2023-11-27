import demistomock as demisto
from CommonServerPython import *
import subprocess

TESSERACT_EXE = 'tesseract'


def list_languages() -> list[str]:
    lang_out = subprocess.check_output([TESSERACT_EXE, '--list-langs'], universal_newlines=True)
    if not lang_out:  # something went wrong
        raise ValueError('No output from --list-langs')
    lines = lang_out.splitlines()
    if len(lines) <= 1:
        raise ValueError('No output from --list-langs')
    return sorted(lines[1:])  # ignore first line


def extract_text(image_path: str, languages: list[str] = None) -> str:
    exe_params = [TESSERACT_EXE, image_path, 'stdout']
    if languages:
        exe_params.extend(['-l', '+'.join(languages)])
    res = subprocess.run(exe_params, capture_output=True, check=True, text=True)
    if res.stderr:
        demisto.debug(f'tesseract returned ok but stderr contains warnings: {res.stderr}')
    return res.stdout


def list_languages_command() -> CommandResults:
    langs = list_languages()
    return CommandResults(
        readable_output="## Image OCR Supported Languages\n\n" + "\n".join(['* ' + s for s in langs]),
        raw_response=langs
    )


def extract_text_command(args: dict, instance_languages: list) -> tuple[list, list]:
    langs = argToList(args.get('langs')) or instance_languages
    demisto.debug(f"Using langs settings: {langs}")
    results, errors = [], []

    entry_ids = argToList(args.get('entryid'))
    for entry_id in entry_ids:
        try:
            file_path = demisto.getFilePath(entry_id)
            if not file_path:
                raise DemistoException(f"Couldn't find entry id: {entry_id}")

            demisto.debug(f'Extracting text from file: {file_path}')
            res = extract_text(file_path['path'], langs)
            file_entry = {'EntryID': entry_id, 'Text': res}
            results.append(
                CommandResults(
                    readable_output=f"## Image OCR Extracted Text for Entry ID {entry_id}\n\n" + res,
                    outputs_prefix='File',
                    outputs_key_field='EntryID',
                    outputs=file_entry,
                    raw_response=res,
                )
            )
        except subprocess.CalledProcessError as cpe:
            errors.append(
                f"An error occurred while trying to process {entry_id=}: "
                f"Failed {cpe.cmd} execution. Return status: {cpe.returncode}.\n"
                f"Error:\n{cpe.stderr}"
            )
        except Exception as e:
            errors.append(f"An error occurred while trying to process {entry_id=}: {e}")

    return results, errors


def run_test_module(instance_languages: list) -> str:
    try:
        supported_langs = list_languages()
        if instance_languages:
            for language in instance_languages:
                if language not in supported_langs:
                    raise DemistoException(f'Unsupported language configured: {language}')
        return 'ok'
    except Exception as exception:
        raise Exception(f'Failed testing {TESSERACT_EXE}: {exception}')


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
            results, errors = extract_text_command(args, instance_languages)
            return_results(results)
            if errors:
                raise DemistoException("\n".join(errors))
        else:
            raise NotImplementedError(f'Command {command} was not implemented.')
    except Exception as err:
        return_error(f"Failed with error(s): {err}")


# python2 uses __builtin__ python3 uses builtins
if __name__ in ("__builtin__", "builtins", '__main__'):
    main()
