""" Widget script for calculating "Who Broke Master" Stats

"""

import random
import traceback

import demistomock as demisto
from CommonServerPython import *

CONTENT_USERS = [
    "glicht", "anara123", "jochman", "Arsenikr", "yardensade", "aviadl", "yuvalbenshalom", "DeanArbel", "Bargenish",
    "JonathanMeler", "michalgold", "yaakovi", "Itay4", "guykeller", "liorblob", "gal-berger", "bakatzir", "ronykoz",
    "dantavori", "BenJoParadise", "hod-alpert", "amshamah419", "idovandijk", "mayagoldb", "IkaDemisto", "Shellyber",
    "adi88d", "avidan-H", "reutshal", "roysagi", "orlichter1", "teizenman", "David-BMS", "GalRabin", "guyfreund",
    "barchen1", "ChanochShayner", "esharf", "moishce", "orhovy", "ohaim1008", "EliorKedar", "darkushin",
    "altmannyarden", "abaumgarten", "JasBeilin", "DinaMeylakh", "daryakoval", "Noy-Maimon", "tallieber", "evisochek",
]
NASICH = 'idovandijk'

# COMMAND FUNCTION #


def create_bar_widget() -> BarColumnPieWidget:
    widget = BarColumnPieWidget()

    users = random.sample(CONTENT_USERS, 5)
    if NASICH in users:
        users.remove(NASICH)

    for user in users:
        widget.add_category(user, random.randrange(start=0, stop=3))

    widget.add_category(NASICH, random.randrange(start=12, stop=15))

    return widget


# MAIN FUNCTION #


def main():
    try:
        widget = create_bar_widget()
        return_results(widget)
    except Exception as exc:  # pylint: disable=W0703
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute WidgetAviadsFavoriteStats. Error: {str(exc)}')


# ENTRY POINT #


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
