from datetime import datetime, timedelta
import json


class MockGithub:
    class MockNamedUser:
        pass

    def get_user(self, login: str):
        file_path = ''
        if login == 'FakeUser':
            file_path = './testdata/user_with_valid_email.json'
        elif login == 'FakeUser1':
            file_path = './testdata/user_no_email_with_valid_name.json'
        elif login == 'FakeUser2':
            file_path = './testdata/user_no_email_with_invalid_name.json'
        else:
            valid_values = {'FakeUser', 'FakeUser1', 'FakeUser2'}
            msg = f'There is no test data json file associated with login "{login}", valid values are {valid_values}'
            raise ValueError(msg)

        mocked_user = MockGithub()
        with open(file_path, 'r') as df:
            data_obj = json.load(df)
            for key, val in data_obj.items():
                setattr(mocked_user, key, val)
        return mocked_user


class TestUsernameToEmail:
    def test_user_with_valid_email(self):
        '''
        Scenario: Try getting the email address of a github user

        Given
        - Using the pygithub client

        When
        - The github user has a panw email as part of their public user data

        Then
        - Ensure the panw email from the user's public data is returned
        '''
        from nudge_external_prs import username_to_email
        gh = MockGithub()
        email = username_to_email(gh, 'FakeUser')  # type: ignore
        assert email == 'osmith@paloaltonetworks.com'

    def test_user_no_email_with_valid_name(self):
        '''
        Scenario: Try getting the email address of a github user

        Given
        - Using the pygithub client

        When
        - The github user's public data does not include a panw email
        - The user's public data includes a two-part name

        Then
        - Ensure the constructed panw email from the user's name matches expectations
        '''
        from nudge_external_prs import username_to_email
        gh = MockGithub()
        email = username_to_email(gh, 'FakeUser1')  # type: ignore
        assert email == 'OSmith@paloaltonetworks.com'

    def test_user_no_email_with_invalid_name(self):
        '''
        Scenario: Try getting the email address of a github user

        Given
        - Using the pygithub client

        When
        - The github user's public data does not include a panw email
        - The user's public data includes a one-part name (and is therefore probably just a nickname)

        Then
        - Ensure the empty string is returned
        '''
        from nudge_external_prs import username_to_email
        gh = MockGithub()
        email = username_to_email(gh, 'FakeUser2')  # type: ignore
        assert email == ''


class MockTimelineEvent:
    def __init__(self, dt: datetime):
        self.__setattr__('created_at', dt)


class TestDetermineSlackMsg:
    def test_oldest_slack_message(self):
        '''
        Scenario: Determine which message will be sent to requested reviewers (over slack)

        Given
        - The last commit event of the PR

        When
        - The last commit event was created 15 days ago

        Then
        - Ensure the "SUGGEST_CLOSE_MSG" is chosen
        '''
        from nudge_external_prs import determine_slack_msg, SUGGEST_CLOSE_MSG
        created_at = datetime.utcnow() - timedelta(15)
        mock_commit_event = MockTimelineEvent(created_at)
        selected_msg = determine_slack_msg(mock_commit_event)  # type: ignore
        assert selected_msg == SUGGEST_CLOSE_MSG

    def test_older_slack_message(self):
        '''
        Scenario: Determine which message will be sent to requested reviewers (over slack)

        Given
        - The last commit event of the PR

        When
        - The last commit event was created 10 days ago

        Then
        - Ensure the "LOTR_NUDGE_MSG" is chosen
        '''
        from nudge_external_prs import determine_slack_msg, LOTR_NUDGE_MSG
        created_at = datetime.utcnow() - timedelta(10)
        mock_commit_event = MockTimelineEvent(created_at)
        selected_msg = determine_slack_msg(mock_commit_event)  # type: ignore
        assert selected_msg == LOTR_NUDGE_MSG

    def test_old_slack_message(self):
        '''
        Scenario: Determine which message will be sent to requested reviewers (over slack)

        Given
        - The last commit event of the PR

        When
        - The last commit event was created 5 days ago

        Then
        - Ensure the "NEEDS_REVIEW_MSG" is chosen
        '''
        from nudge_external_prs import determine_slack_msg, NEEDS_REVIEW_MSG
        created_at = datetime.utcnow() - timedelta(5)
        mock_commit_event = MockTimelineEvent(created_at)
        selected_msg = determine_slack_msg(mock_commit_event)  # type: ignore
        assert selected_msg == NEEDS_REVIEW_MSG
