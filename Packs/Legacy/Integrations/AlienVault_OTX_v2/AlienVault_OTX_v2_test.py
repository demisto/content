# Import std packages

# Import 3-rd party packages
import pytest

# Import local packages
from AlienVault_OTX_v2 import calculate_dbot_score

# DBot calculation Test
arg_names_dbot = "pulse, score"

arg_values_dbot = [
    ({}, 0),
    ({'count': -1}, 0),
    ({'count': 0}, 0),
    ({'count': 1}, 2),
    ({'count': 2}, 3),
    ({'count': 1000}, 3),
    ({'count': 10}, 3),
    ({'count': 10}, 3),
]


@pytest.mark.parametrize(argnames=arg_names_dbot, argvalues=arg_values_dbot)
def test_dbot_score(pulse: dict, score: int):
    assert calculate_dbot_score(pulse) == score, f"Error calculate DBot Score {pulse.get('count')}"
