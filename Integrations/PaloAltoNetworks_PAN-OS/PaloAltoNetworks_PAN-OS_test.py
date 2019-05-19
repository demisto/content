from 'PaloAltoNetworks_PAN-OS' import add_argument_list, add_argument, add_argument_yes_no, \
    add_argument_target, prettify_addresses_arr


def test_add_argument_list():
    list_argument = ["foo", "bar"]

    response_with_member = add_argument_list(list_argument, "test", True)
    expected_with_member = '<test><member><foo></member><member><bar></member></test>'
    assert response_with_member == expected_with_member

    response_with_member_field_name = add_argument_list(list_argument, "member", True)
    expected_with_member_field_name = '<member><foo></member><member><bar></member>'
    assert response_with_member_field_name == expected_with_member_field_name


def test_add_argument():
    argument = "foo"

    response_with_member = add_argument(argument, "test", True)
    expected_with_member = '<test><member><foo></member></test>'
    assert response_with_member == expected_with_member

    response_without_member = add_argument_list(argument, "test", False)
    expected_without_member = '<test><foo></test>'
    assert response_without_member == expected_without_member


def test_add_argument_yes_no():
    arg = 'No'
    field = 'test'
    option = True

    response_option_true = add_argument_yes_no(arg, field, option)
    expected_option_true = '<option><test><No></test></option>'
    assert response_option_true == expected_option_true

    option = False
    response_option_false = add_argument_yes_no(arg, field, option)
    expected_option_false = '<test><No></test>'
    assert response_option_false == expected_option_false


def test_add_argument_target():
    response = add_argument_target('foo', 'bar')
    expected = '<bar><devices><entry name=\"foo\"/></devices></bar>'
    assert response == expected


def test_prettify_addresses_arr():
    addresses_arr = [{'@name': 'my_name', 'fqdn': 'a.com'},
                     {'@name': 'my_name2', 'fqdn': 'b.com'}]
    response = prettify_addresses_arr(addresses_arr)
    expected = [{'Name': 'my_name', 'FQDN': 'a.com'},
                {'Name': 'my_name2', 'FQDN': 'b.com'}]
    assert response == expected
