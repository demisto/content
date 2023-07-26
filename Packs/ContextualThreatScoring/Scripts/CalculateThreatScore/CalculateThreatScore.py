import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime, timezone
from dateutil import parser

''' GLOBAL CONSTANTS & VARIABLES'''

RELIABILITY_DICTIONARY = {
    'A+ - 3rd party enrichment': 10,
    'A - Completely reliable': 8,
    'B - Usually reliable': 8,
    'C - Fairly reliable': 6,
    'D - Not usually reliable': 4,
    'E - Unreliable': 2,
    'F - Reliability cannot be judged': 10
}

''' HELPER FUNCTIONS '''


# Helper function to fetch indicator details
def get_indicator(indicator, keys_to_remove):
    response = demisto.executeCommand("getIndicator", {'value': indicator})
    content = demisto.get(response[0], "Contents")
    if len(content) == 0:
        return_error('Error in getIndicator. Please check if this is a valid indicator in XSOAR database.')

    if keys_to_remove:
        [content[0].pop(key) for key in keys_to_remove if key in content[0]]

    indicator_content = []
    if 'CustomFields' in content[0]:
        custom_fields = content[0].pop('CustomFields')
        content[0].update(custom_fields)
        indicator_content.append(content[0])
    else:
        indicator_content = content

    if not indicator_content:
        return_error("Error in getIndicator. Please check if this is a valid indicator in XSOAR database.")

    return indicator_content[0]


# Helper function to fetch list details
def get_list_content(list_name: str):
    response = demisto.executeCommand("getList", {"listName": list_name})
    if True in [isError(entry) for entry in response]:
        return_error(demisto.get(response[0], "Contents"))
        
    response_content = demisto.get(response[0], "Contents")
    threat_score_factors = json.loads(response_content)
    if not threat_score_factors:
        return_error('Empty results returned from the threat score factors list.')

    return threat_score_factors


# Helper function to search related indicators
def search_related(indicator, entity_types):
    indicator_details = {}
    if entity_types:
        response = demisto.executeCommand("searchRelationships", {"filter": {"entities": [indicator], "size": 5}})

        if response['data']:
            for entity in response['data']:
                if (entity['entityBType']).lower() in entity_types:
                    indicator_details = get_indicator(entity['entityB'], ['comments', 'moduleToFeedMap'])
                    return indicator_details

    return None


def get_factor_value(key, alias, search_dict):
    if key in search_dict:
        factor_value = search_dict.get(key)

    elif alias and alias in search_dict:
        factor_value = search_dict.get(alias)

    else:
        factor_value = None

    return factor_value


'''
Functions to calculate value for the derived factors. This cannot be done dynamically at this point.
This is because each factor has its own custom calculation defined.
'''


# Calculate the age of the indicator
def calculate_age(first_seen):
    now = datetime.now(timezone.utc)
    time_difference = now - parser.parse(first_seen)
    age = time_difference.days

    return age


# Calculate a weighted version of dbot score to include all reliability and verdict values across reporting sources
def normalize_dbot_score(sources, module_feed_maps):
    w_dbot_score = 0.0
    weight = 0.0
    dbot_scores = []

    for module in module_feed_maps:
        if module in sources:
            reliability = module_feed_maps[module].get('reliability', '')
            score = module_feed_maps[module].get('score', 0)
            reliability = (RELIABILITY_DICTIONARY.get(reliability, 1))
            dbot_scores.append({
                'name': module,
                'reliability': reliability,
                'score': score
            })

    for source in dbot_scores:
        if source['score'] != 0:
            w_dbot_score += (source['reliability']**2) * source['score']
            weight += source['reliability']

    if weight:
        w_dbot_score = w_dbot_score / weight
        if w_dbot_score <= 25:
            w_dbot_score = (w_dbot_score * 100) / 25
            w_dbot_score = int(w_dbot_score)
        else:
            w_dbot_score = 100

    return w_dbot_score


# Calculate weighted score for continuous values
def calculate_cont(factor_scores, factor_value):
    factor_keys = {int(key): value for key, value in factor_scores.items()}
    sorted_keys = sorted(factor_keys.keys(), reverse=True)

    for key in sorted_keys:
        str_key = str(key)
        if int(factor_value) >= key:
            return factor_scores[str_key]


# Base script to calculate indicator scores
def base_script():
    threat_score = []
    long_output = []
    weights = []
    entity_types = set()

    indicator = demisto.args()['indicator']
    indicator_details = get_indicator(indicator, ['comments'])
    factors_map = get_list_content('threat_score_factors')

    for key, value in factors_map.items():
        if value.get("search_related"):
            entity_types.add(value["search_related"])

    related_indicator = search_related(indicator, entity_types)

    if 'firstSeen' in indicator_details:
        age = calculate_age(indicator_details.get('firstSeen'))
        age_value = calculate_cont(factors_map['age']['factor_scores'], age)
        weighted_score = age_value * factors_map['age']['weight']
        threat_score.append(weighted_score)
        long_output.append({
            'Factor': 'age',
            'Weight': factors_map['age']['weight'],
            'Value': age,
            'Weighted Score': weighted_score
        })

    # calculate weighted score for source wise distributed calculation of dbot_score
    if 'sourceBrands' in indicator_details and 'moduleToFeedMap' in indicator_details:
        w_dbot_score = normalize_dbot_score(indicator_details.get('sourceBrands'), indicator_details.get('moduleToFeedMap'))
        weighted_score = w_dbot_score * factors_map['weightedScore']['weight']
        threat_score.append(weighted_score)
        long_output.append({
            'Factor': 'weighted dBot score',
            'Weight': factors_map['weightedScore']['weight'],
            'Value': w_dbot_score,
            'Weighted Score': weighted_score
        })

    for k, v in factors_map.items():
        factor_value = None
        weights.append(v.get('weight'))
        if v.get('derived') is False:

            factor_value = get_factor_value(k, v.get('alias'), indicator_details)

            if not factor_value:
                if (
                    v.get('search_related')
                    and indicator_details['indicator_type'] != v.get('search_related')
                    and related_indicator
                ):
                    factor_value = get_factor_value(k, v.get('alias'), related_indicator)

            # get scores for the factor value. ex, if the indicator_type is ip, associated score could be 50
            factor_scores = v['factor_scores']

            # calculate score
            if v.get('type') == 'discrete':
                if factor_value is not None:
                    factor_score = factor_scores.get(factor_value.lower(), factor_scores.get('default', 0))
                else:
                    factor_score = factor_scores.get('default', 0)
                weighted_score = factor_score * v.get('weight')

            elif v.get('type') == 'continuous' and factor_scores:
                if factor_value is not None:
                    weighted_score = calculate_cont(factor_scores, factor_value) * v.get('weight')
                else:
                    weighted_score = 100 * v.get('weight')

            threat_score.append(weighted_score)

            long_output.append({
                'Factor': k,
                'Weight': v.get('weight'),
                'Value': factor_value,
                'Weighted Score': weighted_score
            })
    if len(threat_score) == 0:
        final_score = 0
    else:
        final_score = round(sum(threat_score) / sum(weights))

    detailedResults = demisto.args()['detailedResults']

    if detailedResults == 'true':
        raw_results = ({
            'indicator': indicator,
            'threatScore': final_score,
            'factors': long_output
        })

        headers = ['Factor', 'Weight', 'Value', 'Weighted Score']
        md_result = tableToMarkdown('Threat Score = ' + str(final_score), long_output, headers=headers, removeNull=True)

    else:
        raw_results = ({
            'indicator': indicator,
            'threatScore': final_score
        })

        md_result = 'Final threat score = ' + str(final_score)

    results = CommandResults(
        readable_output=md_result,
        outputs_prefix='threatScore',
        outputs_key_field='indicator',
        outputs=raw_results
    )

    return results


# Main function to initiate the program flow
def main():
    try:
        # Invoke base command script
        return_results(base_script())
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute script. Error: {str(ex)}')

''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
