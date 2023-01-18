import json


def print_keys():
    with open('response.json', 'r') as f:
        j = json.load(f)

    events = j.get('value')
    dictionary_check(events[0])


def dictionary_check(input, prefix=''):
    """
    First prints the final entry in the dictionary (most nested) and its key
    Then prints the keys leading into this
    * could be reversed to be more useful, I guess
    """
    for key, value in input.items():
        if isinstance(value, dict):
            print(prefix + key)
            dictionary_check(value, prefix + '\t')
        else:
            print(prefix + key)


def get_types(d):
    types = {}
    for key, value in d.items():
        if isinstance(value, dict):
            types[key] = get_types(value)
        else:
            types[key] = type(value)
    return types


def discoverType(value) -> str: 
    if isinstance(value, list):
        return 'array'
    elif isinstance(value, bool):
        return 'bool'
    elif isinstance(value, int):
        return 'int'
    return 'string'


def main():
    with open('/Users/okarkkatz/dev/demisto/content/Utils/Moddeling_rule_creator/event.json', 'r') as f:
        j = json.load(f)
    # print(get_types(j))
    # print_keys()

    data = 'properties.status'

    keys_split = data.split('.')
    temp = j
    for key in keys_split:
        temp = temp.get(key)
    discovered = discoverType(temp)
    if discovered == 'array':
        if temp:
            inner_array_type = discoverType(temp[0])
            return {
                "type": inner_array_type,
                "is_array": True
            }
    return {
        "type": discovered,
        "is_array": False
    }


if __name__ == '__main__':
    main()