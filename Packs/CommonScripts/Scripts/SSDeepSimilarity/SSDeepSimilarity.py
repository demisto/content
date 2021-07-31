import traceback

import ssdeep

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' COMMAND FUNCTION '''


def compare_ssdeep(anchor_hash: str, hashes_to_compare: list, output_key: str) -> CommandResults:
    hashes_outputs = []
    for current_hash in hashes_to_compare:
        try:
            hashes_outputs.append({
                'hash': current_hash,
                'similarityValue': ssdeep.compare(anchor_hash, current_hash)
            })

        except ssdeep.InternalError as e:
            demisto.error(DemistoException(f'Could not compare hashes due to internal error: {str(e)}'))
            continue
        except TypeError as e:
            demisto.error(DemistoException(f'Hashes must be of type String, Unicode or Bytes: {str(e)}'))
            continue

    return CommandResults(
        outputs_prefix=output_key,
        outputs_key_field='hash',
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
        return_results(compare_ssdeep(anchor_hash, hashes_to_compare, output_key))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to compare ssdeep hashes. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
