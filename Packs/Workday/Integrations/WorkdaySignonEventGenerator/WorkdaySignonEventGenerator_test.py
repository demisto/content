import unittest
from WorkdaySignonEventGenerator import (
    random_datetime_in_range,
    random_string,
    xml_generator,
)


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
        self.assertTrue("2023-08-21T11:46:02Z" <= random_date <= "2023-08-21T11:47:02Z")

    def test_random_string(self) -> None:
        """
        Given:
            - No initial conditions

        When:
            - Generating a random string of default length 10

        Then:
            - Ensure that the length of the generated string is 10
        """
        self.assertEqual(len(random_string()), 10)

    def test_random_guid(self) -> None:
        """
        Given:
            - No initial conditions

        When:
            - Generating a random GUID-like string of default length 6

        Then:
            - Ensure that the length of the generated string is 6
        """
        self.assertEqual(len(random_string(length=6)), 6)

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
        self.assertEqual(xml_response.count("<wd:Workday_Account_Signon>"), 1)


if __name__ == "__main__":
    unittest.main()
