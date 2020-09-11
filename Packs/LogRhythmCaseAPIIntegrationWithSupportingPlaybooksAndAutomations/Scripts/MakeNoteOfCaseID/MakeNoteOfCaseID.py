import demistomock as demisto
from CommonServerPython import *  # noqa: F401

# takes in a case ID and appends it to a string to a descriptive string
# then creates a note in the war room of the case Id
#
# @param case_id the unique case identifier used in LogRhythm


def main():
    # parse the case_id off of the xsoar arguments
    case_id = demisto.args()['case_id']

    # append the case id to a descriptive field
    contents = "LR Case ID: " + str(case_id)

    # format the contents string and return it to the war room.
    demisto.results({'Type': entryTypes['note'],
                     'Contents': contents,
                     'ContentsFormat': formats['text'],
                     'ReadableContentsFormat': formats['markdown'],
                     'EntryContext': context})


main()
