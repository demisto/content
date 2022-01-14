import pytest
from CommonServerPython import *
from QRadarCreateAQLQuery import *


class TestFieldsSection:
    def test_sanity(self):
        assert fields_section(['field'], ['value']) == "(field = 'value')"

    def test_with_space(self):
        assert fields_section(['field name'], ['value']) == "('field name' = 'value')"

    def test_multiple_fields(self):
        assert fields_section(['field1', 'field2'], ['value']) == "(field1 = 'value' OR field2 = 'value')"

    def test_multiple_values(self):
        assert fields_section(['field'], ['value1', 'value2']) == "(field = 'value1' OR field = 'value2')"

    def test_multiple_fields_and_values(self):
        assert fields_section(['field1', 'field2'], ['value1', 'value2']) \
            == "(field1 = 'value1' OR field1 = 'value2' OR field2 = 'value1' OR field2 = 'value2')"

    def test_not_equal(self):
        assert fields_section(['field'], ['value'], match_rule=MatchRule.NOT_EQUAL) == "(field != 'value')"

    def test_ilike(self):
        assert fields_section(['field'], ['value'], match_rule=MatchRule.ILIKE) == "(field ILIKE '%value%')"

    def test_not_not_ilike(self):
        assert fields_section(['field'], ['value'], match_rule=MatchRule.NOT_ILIKE) == "(field NOT ILIKE '%value%')"


def test_complete_query():
    assert complete_query('select_fields', 'combined_sections', 'time_frame') \
        == "select select_fields from events where combined_sections time_frame"


class TestPrepareArgs:
    def test_with_empty(self):
        assert prepare_args({'some emty ergument': ''}) == {}

    def test_with_base_args(self):
        test = 'test'
        original_args = {
            'base_values_to_search': test,
            'base_fields_to_search': test,
            'base_field_state': test,
            'base_field_match': test
        }
        expected_args = {
            'base_additional_values': test,
            'base_additional_fields': test,
            'base_additional_field_state': test,
            'base_additional_field_match': test
        }
        assert prepare_args(original_args) == expected_args

    def test_base_kyas_not_found(self):
        assert prepare_args({}) == {}


def test_original_key_name():
    assert original_key_name('non_existing_key') == 'non_existing_key'
    assert original_key_name('base_additional_values') == 'base_values_to_search'
    assert original_key_name('base_additional_fields') == 'base_fields_to_search'
    assert original_key_name('base_additional_field_state') == 'base_field_state'
    assert original_key_name('base_additional_field_match') == 'base_field_match'


class TestCreateSectionsStr:

    def test_failure_with_non_existing_base(self):
        with pytest.raises(DemistoException, match='base arguments not given correctly'):
            create_sections_str({})

    def test_go_over_all_3_arg_groups(self, mocker):
        mocker.patch('QRadarCreateAQLQuery.prepare_section', return_value={})
        fields_section_mocker = mocker.patch('QRadarCreateAQLQuery.fields_section', return_value='')
        create_sections_str({})
        assert fields_section_mocker.call_count == 3

    def test_operator_concat(self, mocker):
        mocker.patch('QRadarCreateAQLQuery.prepare_section', return_value={})
        mocker.patch('QRadarCreateAQLQuery.fields_section', return_value='test')
        assert create_sections_str({}) == 'test AND test AND test'


class TestPrepareSection:

    def test_without_the_section_args(self):
        with pytest.raises(SectionNotFound, match='section name'):
            prepare_section({}, 'section name')

    def test_singel_value_and_field(self):
        input_args = {
            '_additional_values': 'test_val',
            '_additional_fields': 'test_field',
            '_additional_field_state': 'include',
            '_additional_field_match': 'exact'
        }
        output_args = prepare_section(input_args, '')
        assert output_args['values_list'] == ['test_val']
        assert output_args['fields_list'] == ['test_field']

    def test_values_list(self):
        input_args = {
            '_additional_values': 'test_val1,test_val2',
            '_additional_fields': 'test_field1,test_field2',
            '_additional_field_state': 'include',
            '_additional_field_match': 'exact'
        }
        output_args = prepare_section(input_args, '')
        assert output_args['values_list'] == ['test_val1', 'test_val2']
        assert output_args['fields_list'] == ['test_field1', 'test_field2']

    class TestWithoutFields:
        def test_with_exact_field_match(self):
            args = {
                '_additional_values': 'test',
                '_additional_field_state': 'include',
                '_additional_field_match': 'exact'
            }
            with pytest.raises(KeyError, match='_additional_fields'):
                prepare_section(args, '')

        def test_with_partial_field_match(self):
            input_args = {
                '_additional_values': 'test_val1,test_val2',
                '_additional_field_state': 'include',
                '_additional_field_match': 'partial'
            }
            output_args = prepare_section(input_args, '')
            assert output_args['fields_list'] == ['UTF8(payload)']

    class TestMachRules:

        def setup(self):
            self._args = {
                '_additional_values': 'test_val',
                '_additional_fields': 'test_field'
            }

        def test_match_rule_equal(self):
            self._args.update({
                '_additional_field_state': 'include',
                '_additional_field_match': 'exact'
            })
            assert prepare_section(self._args, '')['match_rule'] == MatchRule.EQUAL

        def test_match_rule_not_equal(self):
            self._args.update({
                '_additional_field_state': 'exclude',
                '_additional_field_match': 'exact'
            })
            assert prepare_section(self._args, '')['match_rule'] == MatchRule.NOT_EQUAL

        def test_match_rule_ilike(self):
            self._args.update({
                '_additional_field_state': 'include',
                '_additional_field_match': 'partial'
            })
            assert prepare_section(self._args, '')['match_rule'] == MatchRule.ILIKE

        def test_match_rule_not_ilike(self):
            self._args.update({
                '_additional_field_state': 'exclude',
                '_additional_field_match': 'partial'
            })
            assert prepare_section(self._args, '')['match_rule'] == MatchRule.NOT_ILIKE


class TestKeyErrors:
    @staticmethod
    def mocks(args, mocker):
        mocker.patch.object(demisto, 'args', return_value=args)
        return mocker.patch('QRadarCreateAQLQuery.return_error')

    def test_with_required_key(self, mocker):
        mock_return_error = self.mocks({}, mocker)
        main()
        mock_return_error.assert_called_once_with('Missing time_frame.')

    def test_with_base_key(self, mocker):
        args = {
            'time_frame': 'test',
            'select_fields': "test",
            'base_values_to_search': 'test',
            'base_field_state': 'exclude',
            'base_field_match': 'exact'
        }
        mock_return_error = self.mocks(args, mocker)
        main()
        mock_return_error.assert_called_once_with('Missing base_fields_to_search.')

    def test_with_other_key(self, mocker):
        args = {
            'time_frame': 'test',
            'select_fields': "test",
            'base_values_to_search': 'test',
            'base_field_state': 'exclude',
            'base_field_match': 'partial',
            'first_additional_values': 'test',
            'first_additional_field_state': 'exclude',
            'first_additional_field_match': 'exact'

        }
        mock_return_error = self.mocks(args, mocker)
        main()
        mock_return_error.assert_called_once_with('Missing first_additional_fields.')


def test_main_general_exception(mocker):
    error = Exception('test')

    def raising():
        raise error
    mocker.patch.object(demisto, 'args', new=raising)
    mock_return_error = mocker.patch('QRadarCreateAQLQuery.return_error')
    main()
    mock_return_error.assert_called_once_with('test', error)
