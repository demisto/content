import traceback
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import tempfile

HEADERS = "ssdeep,1.1--blocksize:hash:hash,filename\n"

''' COMMAND FUNCTION '''


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
    with tempfile.NamedTemporaryFile() as hash1:
        with tempfile.NamedTemporaryFile() as hash2:
            hash1.write(bytes(anchor_hash, encoding='utf-8'))
            hash1.flush()
            hash2.write(bytes(hashes_to_compare, encoding='utf-8'))
            hash2.flush()
            stream = os.popen(f"ssdeep -k {hash1.name} {hash2.name} -c -a")  # nosec
            return stream.read().split('\n')


def compare_ssdeep(anchor_hash: str, hashes_to_compare: list, output_key: str) -> CommandResults:
    hashes_list_to_file = HEADERS
    anchor_hash_to_file = f'{HEADERS}{anchor_hash},"{anchor_hash}"\n'

    for current_hash in hashes_to_compare:
        hashes_list_to_file += f'{current_hash},"{current_hash}"\n'

    res = run_ssdeep_command(anchor_hash_to_file, hashes_list_to_file)
    hashes_outputs = _format_results(res)

    md = tableToMarkdown(anchor_hash, hashes_outputs)
    return CommandResults(
        outputs_prefix=output_key,
        readable_output=md,
        outputs={'SourceHash': anchor_hash, 'compared_hashes': hashes_outputs}
    )


def _handle_inputs(args: dict):
    anchor_hash = args.get('ssdeep_hash')
    if not anchor_hash:
        raise ValueError('Please provide an hash to compare to.')
    hashes_to_compare = argToList(args.get('ssdeep_hashes_to_compare'))
    if not hashes_to_compare:
        raise ValueError('Please provide at least one hash to compare with.')

    output_key = args.get('output_key', 'SSDeepSimilarity')
    return anchor_hash, hashes_to_compare, output_key


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
