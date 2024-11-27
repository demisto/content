import demistomock as demisto
from CommonServerPython import *
import subprocess

TESSERACT_EXE = 'tesseract'
CORRUPTED_ERR = 'pix not read'
CORRUPTED_MSG = 'WARNING: failed to extract text - image is corrupted'


def list_languages() -> list[str]:
    lang_out = subprocess.check_output([TESSERACT_EXE, '--list-langs'], universal_newlines=True)
    if not lang_out:  # something went wrong
        raise ValueError('No output from --list-langs')
    lines = lang_out.splitlines()
    if len(lines) <= 1:
        raise ValueError('No output from --list-langs')
    return sorted(lines[1:])  # ignore first line


def extract_text(image_path: str, languages: list[str] = [], verbose: bool = False) -> str:
    exe_params = [TESSERACT_EXE, image_path, 'stdout']
    if verbose:
        exe_params.extend(["-v"])

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


def extract_text_command(args: dict, instance_languages: list, skip_corrupted: bool) -> tuple[list, list]:
    langs = argToList(args.get('langs')) or instance_languages
    verbose = argToBoolean(args.get('verbose', False))
    demisto.debug(f"Using langs settings: {langs}")
    results, errors = [], []

    entry_ids = argToList(args.get('entryid'))
    for entry_id in entry_ids:
        try:
            file_path = demisto.getFilePath(entry_id)
            if not file_path:
                raise DemistoException(f"Couldn't find entry id: {entry_id}")

            demisto.debug(f'Extracting text from file: {file_path}')
            res = extract_text(file_path['path'], langs, verbose)
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
            if CORRUPTED_ERR in cpe.stderr and skip_corrupted:
                file_entry = {"EntryID": entry_id, "Text": CORRUPTED_MSG}
                results.append(
                    CommandResults(
                        readable_output=f"## Could not process file with entry ID {entry_id} - image is corrupted",
                        outputs_prefix='File',
                        outputs_key_field='EntryID',
                        outputs=file_entry,
                        entry_type=EntryType.WARNING,
                    )
                )
            else:
                errors.append(
                    f"An error occurred while trying to process {entry_id=}: "
                    f"Failed {cpe.cmd} execution. Return status: {cpe.returncode}.\n"
                    f"Error:\n{cpe.stderr}\n"
                    f"Stdout:\n{cpe.stdout}"
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
    params = demisto.params()
    instance_languages = argToList(params.get('langs'))
    skip_corrupted = params.get('skip_corrupted')
    try:
        if command == 'test-module':
            return_results(run_test_module(instance_languages))
        elif command == 'image-ocr-list-languages':
            return_results(list_languages_command())
        elif command == 'image-ocr-extract-text':
            results, errors = extract_text_command(args, instance_languages, skip_corrupted)
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
