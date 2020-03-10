from GetLicenseID import get_license_id
import demistomock as demisto


def test_human_readable(mocker):
    mocker.patch.object(demisto, 'getLicenseID', return_value='test_license_id')
    human_readable_results = get_license_id()[0]
    assert human_readable_results == '### Demisto License ID\n|License ID|\n|---|\n| test_license_id |\n'
