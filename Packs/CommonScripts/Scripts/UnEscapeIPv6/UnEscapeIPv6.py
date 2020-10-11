import demistomock as demisto


BEGINNING_CHARACTERS_LIST = ['(', '[', ' ', '-', '\'', '"', '.', ',', '`']
ENDING_CHARACTERS_LIST = [')', ']', ' ', '-', '\'', '"', '.', ',', '`']


def clearing_the_address_from_unrelated_characters(ipv6_address: str) -> str:
    """Returns the address without the unrelated characters

    :type ipv6_address: ``str``
    :param ipv6_address: The address with unrelated characters - (::1234)

    :return: The address without the unrelated characters - ::1234
    :rtype: ``str``
    """

    if ipv6_address[0] in BEGINNING_CHARACTERS_LIST:
        ipv6_address = ipv6_address[1:]

    if ipv6_address[-1] in ENDING_CHARACTERS_LIST:
        ipv6_address = ipv6_address[:-1]

    return ipv6_address


''' MAIN FUNCTION '''


def main():
    ipv6_address = demisto.args().get('input')
    ipv6_indicator = clearing_the_address_from_unrelated_characters(ipv6_address)

    demisto.results(ipv6_indicator)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
