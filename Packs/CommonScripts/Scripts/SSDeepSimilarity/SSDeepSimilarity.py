import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback

import tempfile

HEADERS = "ssdeep,1.1--blocksize:hash:hash,filename\n"

''' COMMAND FUNCTION '''


def _handle_existing_outputs(anchor_hash: str, output_key: str, new_hashes_outputs: list):
    context = demisto.get(demisto.context(), f'{output_key}')
    if not context:
        context = []
    elif not isinstance(context, list):
        context = [context]
    context = list(filter(lambda item: item.get('SourceHash') == anchor_hash, context))

    if context:
        context = context[0].get('compared_hashes')

    new_hashes = [current_hash.get('hash') for current_hash in new_hashes_outputs]
    res = []

    for item in context:
        if item.get('hash') not in new_hashes:
            res.append(item)
    res += new_hashes_outputs
    return res


def _handle_inputs(args: dict):
    anchor_hash = args.get('ssdeep_hash')
    if not anchor_hash:
        raise ValueError('Please provide an hash to compare to.')
    hashes_to_compare = argToList(args.get('ssdeep_hashes_to_compare'))
    if not hashes_to_compare:
        raise ValueError('Please provide at least one hash to compare with.')

    output_key = args.get('output_key', 'SSDeepSimilarity')
    return anchor_hash, hashes_to_compare, output_key


def _format_results(results: list) -> List[dict]:
    """
    Args:
        results: a list of results with the following format:
        ['"<hash>","<anchor_hash>",<score>']

    Returns: a list of dictionaries containing the hash and score

    """
    formatted_res = []

    # Remove last empty value returned from the process
    if not results[-1]:
        results = results[:-1]

    for result in results:
        result = result.split(',')
        formatted_res.append({
            'hash': result[0].strip('"'),
            'similarityValue': int(result[2])
        })
    return formatted_res


def run_ssdeep_command(anchor_hash: str, hashes_to_compare: str):
    with tempfile.NamedTemporaryFile() as anchor_hashes_file:
        with tempfile.NamedTemporaryFile() as hashes_to_compare_file:
            anchor_hashes_file.write(bytes(anchor_hash, encoding='utf-8'))
            anchor_hashes_file.flush()
            hashes_to_compare_file.write(bytes(hashes_to_compare, encoding='utf-8'))
            hashes_to_compare_file.flush()
            stream = os.popen(f"ssdeep -k {anchor_hashes_file.name} {hashes_to_compare_file.name} -c -a")  # nosec
            return stream.read().split('\n')


def compare_ssdeep(anchor_hash: str, hashes_to_compare: list, output_key: str) -> CommandResults:
    hashes_list_to_file = HEADERS
    anchor_hash_to_file = f'{HEADERS}{anchor_hash},"{anchor_hash}"\n'

    for current_hash in hashes_to_compare:
        hashes_list_to_file += f'{current_hash},"{current_hash}"\n'
    res = run_ssdeep_command(anchor_hash_to_file, hashes_list_to_file)
    hashes_outputs = _format_results(res)
    hashes_outputs_merged = _handle_existing_outputs(anchor_hash, output_key, hashes_outputs)
    md = tableToMarkdown(anchor_hash, hashes_outputs)
    return CommandResults(
        outputs_prefix=output_key,
        readable_output=md,
        outputs_key_field='SourceHash',
        outputs={'SourceHash': anchor_hash, 'compared_hashes': hashes_outputs_merged}
    )


''' MAIN FUNCTION '''


def main():
    try:
        args = demisto.args()
        anchor_hash, hashes_to_compare, output_key = _handle_inputs(args)
        res = compare_ssdeep(anchor_hash, hashes_to_compare, output_key)
        return_results(res)

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to compare ssdeep hashes. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
