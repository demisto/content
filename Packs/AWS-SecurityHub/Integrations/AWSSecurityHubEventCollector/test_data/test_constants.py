"""
Test findings data for AWS SecurityHub Event Collector tests.
Shared across get_events and fetch_events test suites.
"""

# Sample findings data - reusable across different test scenarios
SAMPLE_FINDINGS = [
    {"Id": "finding-1", "CreatedAt": "2023-01-01T12:00:00.000Z", "Title": "Test Finding 1"},
    {"Id": "finding-2", "CreatedAt": "2023-01-01T12:01:00.000Z", "Title": "Test Finding 2"},
    {"Id": "finding-3", "CreatedAt": "2023-01-01T12:02:00.000Z", "Title": "Test Finding 3"},
    {"Id": "finding-4", "CreatedAt": "2023-01-01T12:03:00.000Z", "Title": "Test Finding 4"},
    {"Id": "finding-5", "CreatedAt": "2023-01-01T12:04:00.000Z", "Title": "Test Finding 5"},
]

# Findings designed to be filtered out by ignore lists
IGNORED_FINDINGS = [
    {"Id": "ignore-me", "CreatedAt": "2023-01-01T12:01:00.000Z", "Title": "Ignored Finding"},
    {"Id": "also-ignore", "CreatedAt": "2023-01-01T12:03:00.000Z", "Title": "Also Ignored"},
    {"Id": "ignore-1", "CreatedAt": "2023-01-01T12:00:00.000Z", "Title": "Ignored 1"},
    {"Id": "ignore-2", "CreatedAt": "2023-01-01T12:01:00.000Z", "Title": "Ignored 2"},
]

# Single duplicate finding for specific test scenarios
DUPLICATE_FINDING = {"Id": "duplicate-1", "CreatedAt": "2023-01-01T12:00:00.000Z", "Title": "Duplicate Finding"}
