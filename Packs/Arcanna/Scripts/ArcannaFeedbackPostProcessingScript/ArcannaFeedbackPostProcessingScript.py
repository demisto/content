import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

ARCANNA_AUTO_CLOSED_TICKET_PLAYBOOK_PLACEHOLDER = "Arcanna decision:"


def get_value_from_context(key):
    return demisto.get(demisto.context(), key)


def send_arcanna_feedback(close_notes, close_reason, closing_user, event_id, job_id):
    ret = demisto.executeCommand("arcanna-send-event-feedback", {
        "job_id": job_id,
        "event_id": event_id,
        "label": close_reason,
        "username": closing_user,
        "closing_notes": close_notes
    })
    return ret


def extract_feedback_information():
    feedback_field = get_value_from_context(key="Arcanna.FeedbackField")
    if type(feedback_field) == list:
        feedback_field = feedback_field[0]

    if feedback_field is None or feedback_field == "":
        raise Exception("Failed to get value for Arcanna closing field")

    # Get Values from incident
    feedback_field_value = demisto.incident().get(feedback_field, None)
    if feedback_field_value is None or feedback_field_value == "":
        # if closing field value is Empty try to get it from Args as a fallback
        feedback_field_value = demisto.args().get(feedback_field, None)

    return feedback_field, feedback_field_value


def add_closing_user_information(closing_user, owner, survey_user):
    if closing_user is None or closing_user == "":
        if survey_user is not None:
            closing_user = survey_user
        elif owner is not None:
            closing_user = owner
        else:
            closing_user = "dbot"
    return closing_user


def run_arcanna_send_feedback():
    try:
        event_id = get_value_from_context(key="Arcanna.Event.event_id")
        job_id = get_value_from_context(key="Arcanna.Event.job_id")
        incident_id = demisto.incident().get('id')
        if event_id is None:
            demisto.log("Trying to send feedback for an event which was not sent to Arcanna first.Skipping")
            return_results(f'Skipping event feedback with id={incident_id}')
            return

        args_closing_reason = demisto.args().get("closing_reason", None)
        if args_closing_reason is not None and args_closing_reason != "":
            user = demisto.args().get("closing_user", None)
            notes = demisto.args().get("closing_notes", None)
            ret = send_arcanna_feedback(notes, args_closing_reason, user, event_id, job_id)
            return_results(ret)
        else:
            demisto.executeCommand("arcanna-get-feedback-field", {})

            feedback_field, feedback_field_value = extract_feedback_information()

            close_reason = demisto.incident().get('closeReason', None)
            close_notes = demisto.incident().get('closeNotes')
            owner = demisto.incident().get('owner', None)
            closing_user = demisto.incident().get('closingUserId', None)
            # if feedback_field_value is not empty get that value, else use the default closeReason value
            if feedback_field_value is not None and feedback_field_value != "":
                close_reason = feedback_field_value

            survey_user = get_value_from_context(key="Closure_Reason_Survey.Answers.name")
            # Arcanna-Generic-Playbook usage.Prevent sending Arcanna Feedback if no analyst reviewed the incident
            if str(close_notes).startswith(ARCANNA_AUTO_CLOSED_TICKET_PLAYBOOK_PLACEHOLDER):
                return_results(
                    f'Skipping Sending Arcanna event feedback for incident_id={incident_id}.No Analyst Reviewed')
                return

            if close_reason is None or close_reason == "":
                raise Exception(
                    "Trying to use arcanna post processing script without providing value for the closing field")

            closing_user = add_closing_user_information(closing_user, owner, survey_user)

            ret = send_arcanna_feedback(close_notes, close_reason, closing_user, event_id, job_id)
            return_results(ret)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ArcannaFeedbackPostProcessingScript. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    run_arcanna_send_feedback()
