import unittest
from unittest.mock import patch

from CommonServerPython import DemistoException
from WorkdaySignonEventGenerator import (
    random_datetime_in_range,
    random_string,
    xml_generator,
    mock_workday_endpoint,
    module_of_testing,
    main,
)

from WorkdaySignonEventGenerator import APP as app


class TestWorkdaySignonEventGenerator(unittest.TestCase):
    def test_random_datetime_in_range(self) -> None:
        """
        Given:
            - A start datetime '2023-08-21T11:46:02Z' and an end datetime '2023-08-21T11:47:02Z'

        When:
            - Generating a random datetime in the given range

        Then:
            - Ensure that the random datetime generated falls within the specified range
        """
        random_date = random_datetime_in_range(
            "2023-08-21T11:46:02Z", "2023-08-21T11:47:02Z"
        )
        assert "2023-08-21T11:46:02Z" <= random_date <= "2023-08-21T11:47:02Z"

    def test_random_string(self) -> None:
        """
        Given:
            - No initial conditions

        When:
            - Generating a random string of default length 10

        Then:
            - Ensure that the length of the generated string is 10
        """
        assert len(random_string()) == 10

    def test_random_guid(self) -> None:
        """
        Given:
            - No initial conditions

        When:
            - Generating a random GUID-like string of default length 6

        Then:
            - Ensure that the length of the generated string is 6
        """
        assert len(random_string(length=6)) == 6

    def test_xml_generator(self) -> None:
        """
        Given:
            - A start datetime '2023-08-21T11:46:02Z', an end datetime '2023-08-21T11:47:02Z', and a count 1

        When:
            - Generating an XML response containing Workday sign-on events

        Then:
            - Ensure that the XML response contains exactly one Workday sign-on event
        """
        xml_response = xml_generator("2023-08-21T11:46:02Z", "2023-08-21T11:47:02Z", 1)
        assert xml_response.count("<wd:Workday_Account_Signon>") == 1


class TestMockWorkdayEndpoint(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    @patch("WorkdaySignonEventGenerator.Response")
    def test_mock_workday_endpoint(self, MockResponse):
        mock_post_data = """<bsvc:From_DateTime>2023-08-21T11:46:02Z</bsvc:From_DateTime>
            <bsvc:To_DateTime>2023-08-21T11:47:02Z</bsvc:To_DateTime>
            <bsvc:Count>2</bsvc:Count>"""
        with self.app as c, c.post("/", data=mock_post_data):
            mock_workday_endpoint()

        MockResponse.assert_called()


class TestModuleOfTesting(unittest.TestCase):
    @patch("WorkdaySignonEventGenerator.demisto.results")
    @patch("WorkdaySignonEventGenerator.return_error")
    @patch("WorkdaySignonEventGenerator.xml_generator")
    def test_module_of_testing(self, MockXmlGenerator, MockReturnError, MockResults):
        MockXmlGenerator.return_value = "<xml>some response</xml>"

        # Test for valid input
        module_of_testing(True, 5000)
        MockResults.assert_called_with("ok")

        # Test for invalid input
        try:
            module_of_testing(False, None)
        except DemistoException as e:
            assert (
                str(e)
                == "Please make sure the long running port is filled and the long running checkbox is marked."
            )
        else:
            raise AssertionError("Expected DemistoException but did not get one")


class TestMainTestingFunction(unittest.TestCase):
    @patch("WorkdaySignonEventGenerator.demisto")
    def test_main_function_test_module(self, MockDemisto):
        MockDemisto.params.return_value = {
            "longRunningPort": "5000",
            "longRunning": True,
        }
        MockDemisto.command.return_value = "test-module"

        with patch(
            "WorkdaySignonEventGenerator.module_of_testing"
        ) as MockModuleTesting:
            main()
            MockModuleTesting.assert_called_with(
                longrunning_port=5000, is_longrunning=True
            )


if __name__ == "__main__":
    unittest.main()
