from freezegun import freeze_time
from pytest_mock import MockerFixture

@freeze_time('01-01-2024')
def test_main(mocker: MockerFixture):
    from AwsGenerateExternalID import main

    mock_return_results = mocker.patch('AwsGenerateExternalID.return_results')

    main()

    assert mock_return_results.call_args_list[0].args[0].readable_output == (
        '### External ID generated: *b192f209-d066-5169-a2fe-23fb02a1c851*')
