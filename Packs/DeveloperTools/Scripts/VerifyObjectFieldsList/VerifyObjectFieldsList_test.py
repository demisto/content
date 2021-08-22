from VerifyObjectFieldsList import check_fields
import pytest
CONTEXT1 = {'FirstField': {'SecondField': {'ThirdField': 1}}}
CONTEXT2 = {'FirstField': [{'SecondField': [{'ThirdField': 1, 'FourthField': 3}, {'ThirdField': 2, 'FourthField': 4}]}]}


@pytest.mark.parametrize('fields_to_search,context,expected_result', [
    ('FirstField.SecondField.ThirdField', CONTEXT1, (True, None)),
    ('FirstField.SecondField.FiveField', CONTEXT1, (False, 'FirstField.SecondField.FiveField')),
    ('FirstField.SecondField.ThirdField', CONTEXT2, (True, None)),
    ('FirstField.SecondField.FourthField', CONTEXT2, (True, None)),
    ('FirstField.FiveField', CONTEXT2, (False, 'FirstField.FiveField'))
])
def test_check_fields(fields_to_search, context, expected_result):
    fields = fields_to_search.split(',')
    assert check_fields(fields, context) == expected_result
