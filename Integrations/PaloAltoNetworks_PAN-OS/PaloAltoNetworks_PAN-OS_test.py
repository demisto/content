from PaloAltoNetworks_PAN-OS import add_argument_list, add_argument


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
