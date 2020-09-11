import demistomock as demisto
from CommonServerPython import *  # noqa: F401

# appedndToField takes in three arguments from the demisto platform
#
# @param field is the field that a given text is to be appended to
# @param field_contents is the contents of the specified field
# @param append_this is the text to be appended
#
# finally appendToField appends the given text to the initial contents
# of a field and then updates that field.


def main():
    # define an empty string for further usage
    current_text = ""

    # parse the applicable demisto arguments required for this automation
    # to append and update a given field
    add_text = str(demisto.args()['append_this'])
    field = demisto.args()['field']
    current_text = demisto.args()['field_contents']

    # begins processing the by adding a new line character to the initial
    # field contents
    current_text = current_text + "\n"

    # determine if is a set, if it is then replace ',' with new line characters
    # and append to the current text. otherwise append the given field to the
    # current text.
    if "[" in add_text:
        add_text_array = add_text[1:-1].split(',')
        for text in add_text_array:
            current_text = current_text + str(text) + "\n"
    else:
        current_text += add_text

    # update the field with the new values specified
    demisto.executeCommand('setIncident', {field: current_text})


# best practice in demisto is to specify a main function and call into it
main()
