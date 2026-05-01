import demistomock as demisto  # noqa: F401


def test_verify_support_ticket_permission_wrapper(mocker):
    """Test that the wrapper correctly delegates to VerifySupportTicketPermission."""
    expected_results = [
        {
            "Type": 1,
            "Contents": {
                "user_csp_permission": True,
                "tenant_entitlement_check": True,
                "has_permission": True,
            },
            "ContentsFormat": "json",
        }
    ]
    mocker.patch.object(demisto, "executeCommand", return_value=expected_results)
    mocker.patch.object(demisto, "results")

    from VerifySupportTicketPermissionWrapper import main

    main()

    demisto.executeCommand.assert_called_once_with("VerifySupportTicketPermission", {})
