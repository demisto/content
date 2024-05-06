"""
Created on September 26, 2019

@author: Saadat Abid
"""


def test_get_dbot_score():
    from SlashNextPhishingIncidentResponse import get_dbot_score

    assert get_dbot_score(verdict='Benign') == 1
    assert get_dbot_score(verdict='Redirector') == 1

    assert get_dbot_score(verdict='Suspicious') == 2

    assert get_dbot_score(verdict='Malicious') == 3

    assert get_dbot_score(verdict='Unrated') == 0
