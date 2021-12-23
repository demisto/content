import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback


PUB_SUB_TOPIC_ID = "share-topic"


def get_tir_id():
    return demisto.args()["object"]["id"]


def get_tir_data(tir_id):
    tir_data = execute_command("GetTIRDataForShare", {"tir_id": tir_id})
    if tir_data:
        if 'Failed to execute' in tir_data:
            raise DemistoException(f"GetTIRDataForShare with TIR ID: {tir_id} returned an error: {tir_data}. Won't share.")
        else:
            return tir_data
    else:
        raise DemistoException(f"GetTIRDataForShare with TIR ID: {tir_id} returned an empty data. Won't share")


def share_tir_with_sub_pub(tir_data):
    response = execute_command("gcp-pubsub-topic-publish-message",
                               {"topic_id": PUB_SUB_TOPIC_ID, "data": tir_data, "using": "GooglePubSub_tir_share_send"})
    if response:
        if 'Failed to execute' in response:
            raise DemistoException(f"gcp-pubsub-topic-publish-message was failed with error: {response}")
        else:
            return CommandResults(readable_output="Sharing the TIR is done.")
    else:
        raise DemistoException("execute command gcp-pubsub-topic-publish-message was failed, returned en empty response")


def main():
    try:
        tir_id = get_tir_id()
        tir_data = get_tir_data(tir_id)
        return_results(share_tir_with_sub_pub(tir_data))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ShareThreatIntelReportPubSub. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
