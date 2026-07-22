from Malwr import MalwrAPI
from requests_mock import Mocker
import tempfile
import pytest


TEST_HTML = """
<form action="/action_page.php">
  <label for="math_captcha_question">Math Captcha Question:</label>
  <input type="text" id="math_captcha_question" name="math_captcha_question" value="what is the answer?"><br><br>
  <label for="csrfmiddlewaretoken">CSRF Middleware Token:</label>
  <input type="text" id="csrfmiddlewaretoken" name="csrfmiddlewaretoken" value="some_token"><br><br>
  <p id="somemath">
  10 + 14 = 24
  2 * 7 = 14
  2 - 7 = -5
  </p>
</form>
"""


def test_find_submission_links_links_in_response(mocker):
    """Test MalwrAPI static method find_submission_links

    Given:
        - MalwrAPI client
        - Response from submitting a sample

    When:
        - The response contains submissions links

    Then:
        - Ensure submission links are returned by the method
    """
    malwr = MalwrAPI(url='https://fake.com', username='y', password='z')
    malwr.logged = True
    resp_text = 'blah/analysis/abcd1234efgh/\nxabvafg/analysis/11234557788943/blah/blah'
    with Mocker(session=malwr.session) as session_mock:
        session_mock.get(url='https://fake.com/submission/', request_headers=malwr.HEADERS, text=TEST_HTML)
        resp = session_mock.post(
            url='https://fake.com/submission/', request_headers=malwr.HEADERS,
            text=resp_text
        )
        find_submission_links_og = MalwrAPI.find_submission_links
        find_submission_links_mock = mocker.MagicMock(name='find_submission_links')

        def side_effect(req):
            return find_submission_links_og(req)

        find_submission_links_mock.side_effect = side_effect
        MalwrAPI.find_submission_links = find_submission_links_mock
        with tempfile.NamedTemporaryFile() as temp:
            temp.write(b'blah blah blah')
            temp.flush()
            result, _ = malwr.submit_sample(temp.name)
        assert result.get('analysis_link', '') == '/analysis/abcd1234efgh/'
        find_submission_links_mock.assert_called_once()
        mocked_call_arg_text = find_submission_links_mock.call_args.args[0].text
        mocked_session_post_response_text = resp._responses[0].get_response(session_mock.last_request).text
        assert mocked_call_arg_text == mocked_session_post_response_text


testdata = [
    ('file like this waiting for processing, submission aborted.', 'File already submitted, check its status.'),
    ('blah blah blah blah blah blah blah blah blah blah blah bl.', 'Error with the file.'),
]


@pytest.mark.parametrize("post_resp_text,expected_result", testdata)
def test_find_submission_links_links_not_in_response(mocker, post_resp_text, expected_result):
    """Test MalwrAPI static method find_submission_links

    Given:
        - MalwrAPI client
        - Response from submitting a sample

    When:
        - The response does not contain submissions links

    Then:
        - Ensure submission links are not returned by the method
    """
    malwr = MalwrAPI(url='https://fake.com', username='y', password='z')
    malwr.logged = True
    with Mocker(session=malwr.session) as session_mock:
        session_mock.get(url='https://fake.com/submission/', request_headers=malwr.HEADERS, text=TEST_HTML)
        session_mock.post(
            url='https://fake.com/submission/', request_headers=malwr.HEADERS,
            text=post_resp_text
        )
        find_submission_links_og = MalwrAPI.find_submission_links
        find_submission_links_mock = mocker.MagicMock(name='find_submission_links')

        def side_effect(req):
            return find_submission_links_og(req)

        find_submission_links_mock.side_effect = side_effect
        MalwrAPI.find_submission_links = find_submission_links_mock
        with tempfile.NamedTemporaryFile() as temp:
            temp.write(b'blah blah blah')
            temp.flush()
            result, _ = malwr.submit_sample(temp.name)
        find_submission_links_mock.assert_called_once()
        assert result == expected_result
