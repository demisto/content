from AnyRunLookup import (
    test_module,
    get_authentication
)


def test_test_module_returns_error_if_credentials_are_not_valid():
    params = {'credentials': {'password': 'not_valid_password}'}}
    assert test_module(
        params) == '[AnyRun Exception] Status code: 401. Description: Authorization is required to access this resource.'


def test_get_authentication_add_a_valid_prefix():
    params = {'credentials': {'password': 'asdAD13SADm1}'}}
    assert get_authentication(params) == 'API-KEY asdAD13SADm1'
