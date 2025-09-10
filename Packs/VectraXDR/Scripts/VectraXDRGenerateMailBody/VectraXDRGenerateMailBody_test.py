import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from VectraXDRGenerateMailBody import main  # Import the main function from the script file
from VectraXDRGenerateMailBody import generate_mail_body


def test_generate_mail_body():
    """
    Given:
    - A list of detection assessment responses.

    When:
    - Calling the 'generate_mail_body' function with the provided list.

    Then:
    - Assert that the function returns a CommandResults object.
    """
    # Test with a list of detection assessment responses
    body_content = {
        "12345-test_detection_name_1": {
            "0": "True Positive",
            "1": "",
            "name": "admin",
        },
    }

    output_context = {
        "VectraXDRMailBody": "Hi,\nPlease find below the detection assessment response for Vectra MDR escalation process.\n\n "
        "1.Detection ID: 12345\n    Detection Name: test_detection_name_1\n    "
        "- Assessment Reason: True Positive\n\n"
    }

    result = generate_mail_body(body_content)
    result_context = result.to_context()
    assert result.outputs_prefix == "VectraXDRMailBody"
    assert result_context.get("HumanReadable") == output_context["VectraXDRMailBody"]
    assert result_context.get("EntryContext") == output_context


def test_main(mocker):
    """
    Given:
    - A list of detection assessment responses.

    When:
    - Calling the 'main' function with the provided args.
    """
    detection_assessment_content = '{"12345-test_detection_name_1":{"0":"True Positive","1":"","name":"admin"}}'
    args = {"body_content": detection_assessment_content}
    mocker.patch.object(demisto, "args", return_value=args)

    main()
