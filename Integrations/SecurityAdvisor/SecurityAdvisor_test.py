import SecurityAdvisor
import unittest
from mock import patch, Mock

URL_SUFFIX = 'apis/coachuser/'
RESPONSE_JSON = {
    "SecurityAdvisor.CoachUser": {
        "coaching_date": "2019-10-04T21:04:19.480425",
        "coaching_status": "Pending",
        "coaching_score": "",
        "user": "track@securityadvisor.io",
        "context": "phishing",
        "message": "Coaching Sent"
    }
}


class SecurityAdvisorTest(unittest.TestCase):

    @patch('SecurityAdvisor.requests.request')
    def test_http_request(self, mock_post):
        """tests send message function
        Args:
            requests_mock ([requests_mock]): [http request mock]
        """
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.json.return_value = RESPONSE_JSON
        response = SecurityAdvisor.http_request('POST', URL_SUFFIX)
        assert response == RESPONSE_JSON

    @patch('SecurityAdvisor.requests.request')
    def test_send_message(self, mock_post):
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.json.return_value = RESPONSE_JSON
        response = SecurityAdvisor.send_message(
            'track@securityadvisor.io', 'phishing')
        assert response == RESPONSE_JSON


if __name__ == '__main__':
    unittest.main()
