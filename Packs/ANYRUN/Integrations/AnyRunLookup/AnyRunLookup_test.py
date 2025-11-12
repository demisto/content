from AnyRunLookup import get_authentication


def test_get_authentication_add_a_valid_prefix():
    params = {"credentials": {"password": "asdAD13SADm1"}}
    assert get_authentication(params) == "API-KEY asdAD13SADm1"
