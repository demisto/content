from DomainTools_Iris import format_investigate_output, format_enrich_output
from test_data import mock_response, expected


def write_test_data(file_path, string_to_write):
    """
        Use this function to save expected action output for asserting future edge cases.
        example:
        human_readable_output, context = format_enrich_output(mock_response.domaintools_response)
        # requires you to replace "\" with "\\" in file for assertions to pass
        write_test_data('new-test-data.txt', human_readable_output)

        Args:
            file_path: file to save test expected output.
            string_to_write: the results to save.
        """
    with open(file_path, "w") as file:
        file.write(string_to_write)


def test_format_investigate():
    human_readable_output, context = format_investigate_output(mock_response.domaintools_response)

    expected_investigate_domaintools_context = expected.domaintools_investigate_context
    domaintools_context = context.get("domaintools")
    assert domaintools_context.get("Name") == expected_investigate_domaintools_context.get("domaintools", {}).get("Name")


def test_format_enrich():
    human_readable_output, context = format_enrich_output(mock_response.domaintools_response)
    expected_enrich_domaintools_context = expected.domaintools_enrich_context
    domaintools_context = context.get("domaintools")
    assert domaintools_context.get("Name") == expected_enrich_domaintools_context.get("domaintools", {}).get("Name")
