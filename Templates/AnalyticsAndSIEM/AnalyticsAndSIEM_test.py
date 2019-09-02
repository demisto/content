class TestBuildContext:
    def test_build_context(self):
        from AnalyticsAndSIEM import build_context
        input_dict = {'eventId': 'ab123',
                      'description': 'Phishing email',
                      'createdAt': '2010-01-01T00:00:00Z',
                      'isActive': True,
                      'assignee': [{'name': 'DBot Demisto', 'id': '11'},
                                   {'name': 'Demisto DBot', 'id': '12'}]}

        output_dict = {'Assignee': [{'ID': '11', 'Name': 'DBot Demisto'},
                                    {'ID': '12', 'Name': 'Demisto DBot'}],
                       'Created': '2010-01-01T00:00:00Z',
                       'Description': 'Phishing email',
                       'ID': 'ab123',
                       'IsActive': True}
        res = build_context(input_dict)
        assert res == output_dict
