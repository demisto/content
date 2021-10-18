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
    if type(feedback_field) == list and len(feedback_field) > 0:
        feedback_field = feedback_field[0]

    if not feedback_field:
        raise Exception("Failed to get value for Arcanna closing field")

    # Get Values from incident
    feedback_field_value = demisto.incident().get(feedback_field, None)
    if not feedback_field_value:
        # if closing field value is Empty try to get it from Args as a fallback
        feedback_field_value = demisto.args().get(feedback_field, None)

    return feedback_field, feedback_field_value


def add_closing_user_information(closing_user, owner, survey_user):
    if not closing_user:
        if survey_user:
            closing_user = survey_user
        elif owner:
            closing_user = owner
        else:
            closing_user = "dbot"
    return closing_user


def run_arcanna_send_feedback():
    try:
        event_id = get_value_from_context(key="Arcanna.Event.event_id")
        job_id = get_value_from_context(key="Arcanna.Event.job_id")
        incident = demisto.incident()
        run_status = incident.get("runStatus")

        if run_status == "waiting":
            return_error("Trying to close and incident without completing task")

        incident_id = incident.get('id')
        if not event_id:
            demisto.debug("Trying to send feedback for an event which was not sent to Arcanna first.Skipping")
            return_results(f'Skipping event feedback with id={incident_id}')
            return

        args_closing_reason = demisto.args().get("closing_reason", None)
        if args_closing_reason:
            user = demisto.args().get("closing_user", None)
            notes = demisto.args().get("closing_notes", None)
            ret = send_arcanna_feedback(notes, args_closing_reason, user, event_id, job_id)
            return_results(ret)
        else:
            demisto.executeCommand("arcanna-get-feedback-field", {})

            feedback_field, feedback_field_value = extract_feedback_information()

            close_reason = incident.get('closeReason', None)
            close_notes = incident.get('closeNotes')
            owner = incident.get('owner', None)
            closing_user = incident.get('closingUserId', None)
            demisto.debug(f"Values supplied to command are{feedback_field} "
                          f"close_reason={close_reason} owner={owner} closing_user={closing_user} "
                          f"close_notes={close_notes}")

            # if feedback_field_value is not empty get that value, else use the default closeReason value
            if feedback_field_value:
                close_reason = feedback_field_value

            survey_user = get_value_from_context(key="Closure_Reason_Survey.Answers.name")
            # Arcanna-Generic-Playbook usage.Prevent sending Arcanna Feedback if no analyst reviewed the incident
            if str(close_notes).startswith(ARCANNA_AUTO_CLOSED_TICKET_PLAYBOOK_PLACEHOLDER):
                return_results(
                    f'Skipping Sending Arcanna event feedback for incident_id={incident_id}.No Analyst Reviewed')
                return

            if not closing_user and not close_notes and not close_reason:
                return_results(
                    f'Skipping Sending Arcanna event feedback for incident_id={incident_id}.No Analyst Reviewed')
                return

            if not close_reason:
                raise Exception(
                    "Trying to use Arcanna post-processing script without providing value for the closing field")

            closing_user = add_closing_user_information(closing_user, owner, survey_user)

            ret = send_arcanna_feedback(close_notes, close_reason, closing_user, event_id, job_id)
            return_results(ret)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ArcannaFeedbackPostProcessingScript. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    run_arcanna_send_feedback()
