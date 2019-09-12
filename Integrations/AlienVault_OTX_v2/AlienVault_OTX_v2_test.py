# Import std packages

# Import 3-rd party packages
import pytest

# Import local packages
from AlienVault_OTX_v2 import geo_by_ec, dbot_score, remove_none

# Geo point test
arg_names_geo = "lat, long, point_ec"
arg_values_geo = [
    (5.6666, -8.777, "5.6666,-8.777"),
    (-5.6666, -8.777, "-5.6666,-8.777"),
    (5.6666, 8.777, "5.6666,8.777")
]


@pytest.mark.parametrize(argnames=arg_names_geo, argvalues=arg_values_geo)
def test_geo_by_ec(lat: str, long: str, point_ec: str):
    assert geo_by_ec(lat, long) == point_ec, f"Geo point wrong convention lat: {lat}, long : {long}"


# DBot calculation Test
arg_names_dbot = "count, score"

arg_values_dbot = [
    ({}, 'unknown'),
    ({'count': -1}, 'unknown'),
    ({'count': 0}, 'good'),
    ({'count': 1}, 'suspicious'),
    ({'count': 2}, 'bad'),
    ({'count': 1000}, 'bad'),
]


@pytest.mark.parametrize(argnames=arg_names_dbot, argvalues=arg_values_dbot)
def test_dbot_score(count: dict, score: str):
    assert dbot_score(count) == score, f"Error calculate DBot Score {count}"


arg_names_to_remove = "to_remove, after_remove"
arg_values_to_remove = [
    ({'key': None}, {}),
    ({'key-1': {'key-2': None}}, {'key-1': {}}),
    ({'key-1': {'key-2': 'value-2'}}, {'key-1': {'key-2': 'value-2'}})
]


@pytest.mark.parametrize(argnames=arg_names_to_remove, argvalues=arg_values_to_remove)
def test_remove_none(to_remove: object, after_remove: object):
    assert remove_none(to_remove) == after_remove
