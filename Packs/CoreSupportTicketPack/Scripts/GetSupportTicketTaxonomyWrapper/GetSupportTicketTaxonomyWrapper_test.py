import demistomock as demisto  # noqa: F401


def test_get_support_ticket_taxonomy_wrapper(mocker):
    """Test that the wrapper correctly delegates to GetSupportTicketTaxonomy."""
    expected_results = [
        {
            "Type": 1,
            "Contents": '[{"Agent": ["Communication", "Device Control"]}]',
            "ContentsFormat": "text",
        }
    ]
    mocker.patch.object(demisto, "executeCommand", return_value=expected_results)
    mocker.patch.object(demisto, "results")

    from GetSupportTicketTaxonomyWrapper import main

    main()

    demisto.executeCommand.assert_called_once_with("GetSupportTicketTaxonomy", {})
