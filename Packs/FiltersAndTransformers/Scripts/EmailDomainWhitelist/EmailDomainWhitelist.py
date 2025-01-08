import demistomock as demisto


def csv_string_to_list(v):
    if type(v) is str:  # requires python3
        return v.lower().replace(' ', '').replace('\n', '').split(',')
    v = [val.lower() for val in v]
    return v


def main():
    DOMAIN_LIST = csv_string_to_list(demisto.args()['domain_list'])
    EMAIL_ADDRESSES = csv_string_to_list(demisto.args()['value'])

    filtered_addresses = []

    for address in EMAIL_ADDRESSES:
        [user, domain] = address.split('@')

        if domain in DOMAIN_LIST:
            filtered_addresses.append(address)

    if len(filtered_addresses) != 0:
        demisto.results(filtered_addresses)
    else:
        demisto.results(None)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
