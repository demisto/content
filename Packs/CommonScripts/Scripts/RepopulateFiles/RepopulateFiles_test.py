from RepopulateFiles import parse_attachment_entries


def test_parse_attachment_entries():
    entries = [
        {'ContentsFormat': 'text', 'Tags': None, 'Brand': 'Builtin', 'HumanReadable': None, 'ID': '588@11',
         'FileID': '', 'IgnoreAutoExtract': False, 'Evidence': False, 'EntryContext': None, 'Contents': '509',
         'File': '12', 'EvidenceID': '', 'FileMetadata': {'size': '42'}, 'ImportantEntryContext': None},
        {'ContentsFormat': 'text', 'Tags': None, 'Brand': 'Builtin', 'HumanReadable': None, 'ID': '638@11',
         'FileID': '', 'IgnoreAutoExtract': False, 'Evidence': False, 'EntryContext': None, 'Contents': '511',
         'File': '34', 'EvidenceID': '', 'FileMetadata': {'type': 'PDF'}, 'ImportantEntryContext': None}
    ]

    entry_context = parse_attachment_entries(entries)
    assert len(entry_context) == 2
    assert entry_context[0].get('Size') == '42'
    assert entry_context[1].get('Type') == 'PDF'
