from CommonServerPython import *

ALL_LABELS = "*"


def get_phishing_map_labels(comma_values):
    if comma_values == ALL_LABELS:
        return comma_values
    values = [x.strip() for x in comma_values.split(",")]
    labels_dict = {}
    for v in values:
        v = v.strip()
        if ":" in v:
            splited = v.split(":")
            labels_dict[splited[0].strip()] = splited[1].strip()
        else:
            labels_dict[v] = v
    return {k: v for k, v in labels_dict.items()}


def build_query_in_reepect_to_phishing_labels(args):
    mapping = args.get('phishingLabels', ALL_LABELS)
    tag_field = args['tagField']
    query = args.get('query', '')
    if mapping == ALL_LABELS:
        mapping_query = '{}:*'.format(tag_field)
    else:
        mapping_dict = get_phishing_map_labels(mapping)
        tags_union = ' '.join(['"{}"'.format(label) for label in mapping_dict])
        mapping_query = '{}:({})'.format(tag_field, tags_union)
    if query == '':
        modified_query = mapping_query
    else:
        modified_query = '({}) and ({})'.format(query, mapping_query)
    return modified_query


def main():
    try:
        result = {'extendedQuery': build_query_in_reepect_to_phishing_labels(demisto.args())}

        res = CommandResults(
            outputs_prefix='ExtendQueryBasedOnPhishingLabels',
            outputs_key_field='',
            outputs=result,
        )
        return_results(res)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ExtendQueryBasedOnPhishingLabels. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

