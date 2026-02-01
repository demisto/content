from RubrikSuspiciousFileCount import main, demisto, ORANGE_HTML_STYLE, GREEN_HTML_STYLE, RED_HTML_STYLE, DIV_HTML_STYLE


def test_suspicious_file_count_none(mocker):
    """Test case when suspicious_file_count is None (no results found)"""
    # Mock the demisto.incident() function to return None for rubriksuspiciousfilecount
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {"rubriksuspiciousfilecount": None}})
    mock_results = mocker.patch.object(demisto, "results")

    main()

    # Verify the correct HTML is generated for None case
    expected_html = f"<div style={DIV_HTML_STYLE}><h1 style={ORANGE_HTML_STYLE}No Results Found</h1></div>"
    mock_results.assert_called_once()
    call_args = mock_results.call_args[0][0]
    assert call_args["Contents"] == expected_html
    assert call_args["ContentsFormat"] == "html"


def test_suspicious_file_count_zero(mocker):
    """Test case when suspicious_file_count is 0 (green display)"""
    # Mock the demisto.incident() function to return 0 for rubriksuspiciousfilecount
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {"rubriksuspiciousfilecount": 0}})
    mock_results = mocker.patch.object(demisto, "results")

    main()

    # Verify the correct HTML is generated for 0 case
    expected_html = f"<div style={DIV_HTML_STYLE}><h1 style={GREEN_HTML_STYLE}0</h1></div>"
    mock_results.assert_called_once()
    call_args = mock_results.call_args[0][0]
    assert call_args["Contents"] == expected_html
    assert call_args["ContentsFormat"] == "html"


def test_suspicious_file_count_positive(mocker):
    """Test case when suspicious_file_count is positive (red display)"""
    # Mock the demisto.incident() function to return 5 for rubriksuspiciousfilecount
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {"rubriksuspiciousfilecount": 500}})
    mock_results = mocker.patch.object(demisto, "results")

    main()

    # Verify the correct HTML is generated for positive case
    expected_html = f"<div style={DIV_HTML_STYLE}><h1 style={RED_HTML_STYLE}500</h1></div>"
    mock_results.assert_called_once()
    call_args = mock_results.call_args[0][0]
    assert call_args["Contents"] == expected_html
    assert call_args["ContentsFormat"] == "html"
