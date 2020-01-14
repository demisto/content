"""
Created on September 26, 2019

@author: Saadat Abid
"""


def test_get_dbot_score():
    from SlashNextPhishingIncidentResponse import get_dbot_score

    assert 1 == get_dbot_score(verdict='Benign')
    assert 1 == get_dbot_score(verdict='Redirector')

    assert 2 == get_dbot_score(verdict='Suspicious')

    assert 3 == get_dbot_score(verdict='Malicious')

    assert 0 == get_dbot_score(verdict='Unrated')
