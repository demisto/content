MAX_FETCH = 1000
LIMIT = MAX_FETCH + 1

MESSAGES = {
    "LIMIT_ERROR": "{} is an invalid value for limit. Limit must be between 1 and {}.",
    "NO_INDICATORS_FOUND": "No indicators were found for the given argument(s)."
}

fetch_indicator_params = [
    ({"first_fetch": "abc"}, '"abc" is not a valid date')
]

get_indicator_params = [
    ({"limit": "-1"}, MESSAGES['LIMIT_ERROR'].format("-1", MAX_FETCH)),
    ({"limit": LIMIT}, MESSAGES['LIMIT_ERROR'].format(LIMIT, MAX_FETCH)),
    ({"updated_since": "abc"}, '"abc" is not a valid date')
]
