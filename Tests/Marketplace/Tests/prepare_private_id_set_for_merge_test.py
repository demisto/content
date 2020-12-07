from Tests.Marketplace.prepare_private_id_set_for_merge import merge_private_id_set_with_new_pack
from Tests.scripts.infrastructure_tests import test_collect_tests_and_content_packs as test_utils

NEW_PACK_NAME = 'Workday'
PRIVATE_ID_PATH = 'Tests/scripts/infrastructure_tests/tests_data/mock_id_set.json'


def test_merge_private_id_set_with_new_pack(repo):
    script_name = 'script_a'
    fake_script = test_utils.TestUtils.create_script(name=script_name)
    fake_id_set = test_utils.TestUtils.create_id_set(
        with_scripts=fake_script['id_set']
    )
    private_id_set = merge_private_id_set_with_new_pack(PRIVATE_ID_PATH, NEW_PACK_NAME)
    assert private_id_set == 1


# CLASSIFIER_WITH_VALID_INCIDENT_FIELD = {"mapping": {"0": {"internalMapping": {"Incident Field": "incident field"}}}}
#
#     ID_SET_WITH_INCIDENT_FIELD = {"IncidentFields": [{"name": {"name": "Incident Field"}}],
#                                   "IndicatorFields": [{"name": {"name": "Incident Field"}}]}
#
#     ID_SET_WITHOUT_INCIDENT_FIELD = {"IncidentFields": [{"name": {"name": "name"}}],
#                                      "IndicatorFields": [{"name": {"name": "name"}}]}
#
#     IS_INCIDENT_FIELD_EXIST = [
#         (CLASSIFIER_WITH_VALID_INCIDENT_FIELD, ID_SET_WITH_INCIDENT_FIELD, True),
#         (CLASSIFIER_WITH_VALID_INCIDENT_FIELD, ID_SET_WITHOUT_INCIDENT_FIELD, False)
#     ]
#
#     @pytest.mark.parametrize("classifier_json, id_set_json, expected_result", IS_INCIDENT_FIELD_EXIST)
#     def test_is_incident_field_exist(self, repo, classifier_json, id_set_json, expected_result):
#         """
#         Given
#         - A mapper with incident fields
#         - An id_set file.
#         When
#         - validating mapper
#         Then
#         - validating that incident fields exist in id_set.
#         """
#         repo.id_set.write_json(id_set_json)
#         structure = mock_structure("", classifier_json)
#         validator = ClassifierValidator(structure)
#         assert validator.is_incident_field_exist(id_set_json) == expected_result
