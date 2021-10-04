"""
Tests module for ThreatExchangeV2 integration logic
"""
from typing import Tuple, List, Dict, Optional

from ThreatExchangeV2 import ThreatExchangeV2Status, calculate_dbot_score, calculate_engines,\
    get_reputation_data_statuses, convert_string_to_epoch_time, flatten_outputs_paging
import pytest
from CommonServerPython import Common

MALICIOUS_THRESHOLD = 50
SUSPICIOUS_THRESHOLD = 1
NON_MALICIOUS_THRESHOLD = 50
STATUS = 'status'


class TestsThreatExchangeV2:

    # Inputs for test_dbot_score_calculation:
    # ----------------------------------------

    malicious_test_input = [{STATUS: ThreatExchangeV2Status.MALICIOUS},
                            {STATUS: ThreatExchangeV2Status.MALICIOUS},
                            {STATUS: ThreatExchangeV2Status.MALICIOUS},
                            {STATUS: ThreatExchangeV2Status.UNKNOWN}
                            ]  # Malicious statuses > 50%
    malicious_test_err_msg = 'Malicious statuses > 50% - DBot Score should be 3'

    malicious_suspicious_test_input = [{STATUS: ThreatExchangeV2Status.MALICIOUS},
                                       {STATUS: ThreatExchangeV2Status.UNKNOWN},
                                       {STATUS: ThreatExchangeV2Status.NON_MALICIOUS},
                                       {STATUS: ThreatExchangeV2Status.MALICIOUS}
                                       ]  # Malicious statuses <= 50%
    malicious_suspicious_test_err_msg = 'Malicious statuses >0 and <= 50% - DBot Score should be 2'

    suspicious_test_input = [{STATUS: ThreatExchangeV2Status.SUSPICIOUS},
                             {STATUS: ThreatExchangeV2Status.SUSPICIOUS},
                             {STATUS: ThreatExchangeV2Status.UNKNOWN},
                             {STATUS: ThreatExchangeV2Status.NON_MALICIOUS}
                             ]  # No malicious statuses, Suspicious statuses > 1
    suspicious_test_err_msg = 'No malicious statuses, Suspicious statuses > 1 - DBot Score should be 2'

    not_suspicious_test_input = [{STATUS: ThreatExchangeV2Status.SUSPICIOUS},
                                 {STATUS: ThreatExchangeV2Status.NON_MALICIOUS},
                                 {STATUS: ThreatExchangeV2Status.UNKNOWN},
                                 {STATUS: ThreatExchangeV2Status.NON_MALICIOUS}
                                 ]  # No malicious statuses, Suspicious statuses <= 1, non_malicious statuses <= 50%
    not_suspicious_test_err_msg = 'No malicious statuses, Suspicious statuses <= 1, non_malicious statuses <= 50% - ' \
                                  'DBot Score should be 0'

    non_malicious_test_input = [{STATUS: ThreatExchangeV2Status.NON_MALICIOUS},
                                {STATUS: ThreatExchangeV2Status.NON_MALICIOUS},
                                {STATUS: ThreatExchangeV2Status.UNKNOWN},
                                {STATUS: ThreatExchangeV2Status.NON_MALICIOUS}
                                ]  # No malicious or suspicious statuses, non_malicious statuses > 50%
    non_malicious_test_err_msg = 'No malicious or suspicious statuses, non_malicious statuses > 50% - ' \
                                 'DBot Score should be 1'

    unknown_test_input = [{STATUS: ThreatExchangeV2Status.UNKNOWN},
                          {STATUS: ThreatExchangeV2Status.UNKNOWN},
                          {STATUS: ThreatExchangeV2Status.NON_MALICIOUS},
                          {STATUS: ThreatExchangeV2Status.NON_MALICIOUS}
                          ]  # No malicious or suspicious statuses, non_malicious statuses <= 50%
    unknown_test_err_msg = 'No malicious or suspicious statuses, non_malicious statuses <= 50% - DBot Score should be 0'

    # Inputs for test_calculate_engines:
    # ----------------------------------

    four_engines_three_positive_test_input = [{STATUS: ThreatExchangeV2Status.MALICIOUS},
                                              {STATUS: ThreatExchangeV2Status.MALICIOUS},
                                              {STATUS: ThreatExchangeV2Status.MALICIOUS},
                                              {STATUS: ThreatExchangeV2Status.UNKNOWN}
                                              ]
    four_engines_three_positive_test_err_msg = 'Number of engines should be 4, number of positive (Malicious)' \
                                               ' detections should be 3'

    four_engines_two_positive_test_input = [{STATUS: ThreatExchangeV2Status.MALICIOUS},
                                            {STATUS: ThreatExchangeV2Status.UNKNOWN},
                                            {STATUS: ThreatExchangeV2Status.NON_MALICIOUS},
                                            {STATUS: ThreatExchangeV2Status.MALICIOUS}
                                            ]
    four_engines_two_positive_test_err_msg = 'Number of engines should be 4, number of positive (Malicious)' \
                                             ' detections should be 2'

    four_engines_no_positive_test_input = [{STATUS: ThreatExchangeV2Status.SUSPICIOUS},
                                           {STATUS: ThreatExchangeV2Status.SUSPICIOUS},
                                           {STATUS: ThreatExchangeV2Status.UNKNOWN},
                                           {STATUS: ThreatExchangeV2Status.NON_MALICIOUS}
                                           ]
    four_engines_no_positive_test_err_msg = 'Number of engines should be 4, number of positive (Malicious) ' \
                                            'detections should be 0'

    # Inputs for test_flatten_outputs_paging:
    # --------------------------------------

    full_raw_response = {'data': [],
                         'paging': {'cursors': {
                             'before': 'AcEkOnHaV894JkYgDuZAZBpF4LPkXqSVJjZCxNU0Dy0k7N5SrZA3hQcL8ZAhTSMsAt6bGrjoZD',
                             'after': 'AcGLELPh2NYeHoZCBAtQc25pelwm2SC1TMyNwQZANrocSZCHpZCFeFkLxGf5d7gNmHGFMdkZD'}}
                         }

    full_expected_output = {'data': [],
                            'paging': {
                                'before': 'AcEkOnHaV894JkYgDuZAZBpF4LPkXqSVJjZCxNU0Dy0k7N5SrZA3hQcL8ZAhTSMsAt6bGrjoZD',
                                'after': 'AcGLELPh2NYeHoZCBAtQc25pelwm2SC1TMyNwQZANrocSZCHpZCFeFkLxGf5d7gNmHGFMdkZD'}
                            }
    raw_response_without_before_after = {'data': [],
                                         'paging': {
                                             'cursors': {}}
                                         }
    expected_output_without_before_after = {'data': [],
                                            'paging': {
                                                'before': None,
                                                'after': None}
                                            }

    raw_response_without_cursors = {'data': [],
                                    'paging': {}
                                    }
    expected_output_without_cursors = {'data': [],
                                       'paging': {
                                           'before': None,
                                           'after': None}
                                       }

    # Tests:
    # ------

    def test_get_reputation_data_statuses(self):
        """
            Given:
                - A list which represents a returned data of a certain reputation command.
            When:
                - Running get reputation data statuses function.
            Then:
                - Verify command output is as expected.
        """
        data = [{STATUS: ThreatExchangeV2Status.MALICIOUS},
                {STATUS: ThreatExchangeV2Status.SUSPICIOUS},
                {STATUS: ThreatExchangeV2Status.NON_MALICIOUS},
                {STATUS: ThreatExchangeV2Status.UNKNOWN},
                {}
                ]
        expected_output = [ThreatExchangeV2Status.MALICIOUS, ThreatExchangeV2Status.SUSPICIOUS,
                           ThreatExchangeV2Status.NON_MALICIOUS, ThreatExchangeV2Status.UNKNOWN]
        assert get_reputation_data_statuses(reputation_data=data) == expected_output

    @pytest.mark.parametrize('reputation_data_input, expected_output, error_msg', [
        (malicious_test_input, Common.DBotScore.BAD, malicious_test_err_msg),
        (malicious_suspicious_test_input, Common.DBotScore.SUSPICIOUS, malicious_suspicious_test_err_msg),
        (suspicious_test_input, Common.DBotScore.SUSPICIOUS, suspicious_test_err_msg),
        (not_suspicious_test_input, Common.DBotScore.NONE, not_suspicious_test_err_msg),
        (non_malicious_test_input, Common.DBotScore.GOOD, non_malicious_test_err_msg),
        (unknown_test_input, Common.DBotScore.NONE, unknown_test_err_msg),
        ([], Common.DBotScore.NONE, 'Reputation data has no reported statuses - DBot Score should be 0')
    ])
    def test_dbot_score_calculation(self, reputation_data_input: List[Dict],
                                    expected_output: Common.DBotScore,
                                    error_msg: str):
        """
            Given:
                1. A list representing a returned data of a certain reputation command, in which the percentage of
                reported malicious statuses exceeds 50%.

                2. A list representing a returned data of a certain reputation command, in which the percentage of
                reported malicious statuses is less than 50% but exists.

                3. A list representing a returned data of a certain reputation command, in which there are no
                malicious statuses, but there is more than one suspicious reported status.

                4. A list representing a returned data of a certain reputation command, where there are no malicious
                statuses, there is at most one suspicious status and less than 50% non-malicious statuses.

                5. A list representing a returned data of a certain reputation command, in which there are no
                malicious or suspicious statuses, but there are more than 50% non-malicious reported status.

                6. A list representing a returned data of a certain reputation command, where there are no malicious
                and suspicious statuses and there are less than 50% non-malicious statuses.

                7. A list representing a returned data of a certain reputation command, with no reported statuses.

            When:
                Running calculate dbot score function.
            Then:
                1. Verify command output is a Malicious Dbot score (= 3).

                2. Verify command output is a Suspicious Dbot score (= 2).

                3. Verify command output is a Suspicious Dbot score (= 2).

                4. Verify command output is a Unknown Dbot score (= 0).

                5. Verify command output is a Good Dbot score (= 1).

                6. Verify command output is a Unknown Dbot score (= 0).

                7. Verify command output is a Unknown Dbot score (= 0).
        """
        params = {'malicious_threshold': MALICIOUS_THRESHOLD,
                  'suspicious_threshold': SUSPICIOUS_THRESHOLD,
                  'non_malicious_threshold': NON_MALICIOUS_THRESHOLD}
        assert calculate_dbot_score(reputation_data=reputation_data_input, params=params) == expected_output, error_msg

    @pytest.mark.parametrize('reputation_data_input, expected_output, error_msg', [
        (four_engines_three_positive_test_input, (4, 3), four_engines_three_positive_test_err_msg),
        (four_engines_two_positive_test_input, (4, 2), four_engines_two_positive_test_err_msg),
        (four_engines_no_positive_test_input, (4, 0), four_engines_no_positive_test_err_msg),
        ([], (0, 0), 'Reputation data is empty - Number of engines and positive detections should be 0')
    ])
    def test_calculate_engines(self, reputation_data_input: List[Dict],
                               expected_output: Tuple[int, int],
                               error_msg: str):
        """
            Given:
                 1. A list representing data returned from a reputation command on a particular indicator,
                  which contains results from 4 engines, of which 3 reported that the indicator was malicious.

                 2. A list representing data returned from a reputation command on a particular indicator,
                  which contains results from 4 engines, of which 2 reported that the indicator was malicious.

                3. A list representing data returned from a reputation command on a particular indicator,
                  which contains results from 4 engines, none of which reported that the indicator was malicious.

                4. An empty list representing data returned from a reputation command on a particular indicator,
                - no data returned.

            When:
                - Running calculate engines function.
            Then:
                - Verify command output is as expected:
                Number of engines is as the number of the data list entries, and number of positive detections is as the
                number of Malicious reported statuses in the list.
        """
        assert calculate_engines(reputation_data=reputation_data_input) == expected_output, error_msg

    @pytest.mark.parametrize('raw_response_input, expected_output', [
        (full_raw_response, full_expected_output),
        (raw_response_without_before_after, expected_output_without_before_after),
        (raw_response_without_cursors, expected_output_without_cursors)
    ])
    def test_flatten_outputs_paging(self, raw_response_input: Dict, expected_output: Dict):
        """
            Given:
                1. A dict which represents a returned raw response of a certain API call, a full raw response contains a
                data list, and a paging list.

                2. A dict which represents a returned raw response of a certain API call, the raw response contains a
                data list, and a paging list without 'before' and 'after' values.

                3. A dict which represents a returned raw response of a certain API call, the raw response contains a
                data list, and a paging list without 'cursors' value.
            When:
                - Running flatten outputs paging function.
            Then:
                - Verify command output is as expected:
                a dict contains data section and a flat paging section - i.e paging list which contains before' and
                 'after' keys and values without the 'cursors' key.
        """
        assert flatten_outputs_paging(raw_response=raw_response_input) == expected_output

    @pytest.mark.parametrize('date_input, expected_output', [
        ('2021-05-01T12:00:00', 1619870400),
        (None, None)
    ])
    def test_convert_string_to_epoch_time(self, date_input: Optional[str], expected_output: Optional[int]):
        """
            Given:
                1. A string representing a date in iso 8601 format.
                2. None
            When:
                - Running convert string to epoch time function.
            Then:
                - Verify command output is as expected:
                1. Given date in epoch time format.
                2. None
        """
        assert convert_string_to_epoch_time(date_input) == expected_output
