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
arg_names_dbot = "pulse, threshold, score"

arg_values_dbot = [
    ({}, 2, 0),
    ({'count': -1}, 2, 0),
    ({'count': 0}, 2, 1),
    ({'count': 1}, 2, 2),
    ({'count': 2}, 2, 3),
    ({'count': 1000}, 2, 3),
    ({'count': 10}, 20, 2),
    ({'count': 10}, 20, 2),
]


@pytest.mark.parametrize(argnames=arg_names_dbot, argvalues=arg_values_dbot)
def test_dbot_score(pulse: dict, threshold: int, score: int):
    assert dbot_score(pulse, threshold) == score, f"Error calculate DBot Score {pulse.get('count')}"


arg_names_to_remove = "to_remove, after_remove"
arg_values_to_remove = [
    ({'key': None}, {}),
    ({'key-1': {'key-2': None}}, {'key-1': {}}),
    ({'key-1': {'key-2': 'value-2'}}, {'key-1': {'key-2': 'value-2'}})
]


@pytest.mark.parametrize(argnames=arg_names_to_remove, argvalues=arg_values_to_remove)
def test_remove_none(to_remove: object, after_remove: object):
    assert remove_none(to_remove) == after_remove
