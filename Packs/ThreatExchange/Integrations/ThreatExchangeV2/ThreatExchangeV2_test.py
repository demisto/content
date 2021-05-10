"""
Tests module for ThreatExchangeV2 integration logic
"""
from typing import Tuple, List, Dict

from ThreatExchangeV2 import ThreatExchangeV2Status, calculate_dbot_score, calculate_engines,\
    get_reputation_data_statuses
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
    not_suspicious_test_err_msg = 'No malicious statuses, Suspicious statuses <= 1, non_malicious statuses <= 50% -' \
                                  ' DBot Score should be 0'

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

    # Tests:
    # ------

    def test_get_reputation_data_statuses(self):
        """
            Given:
                - A list which represents a returned data of a certain reputation command
            When:
                - Running get reputation data statuses function
            Then:
                - Verify command output is as expected
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
        ([], Common.DBotScore.NONE, 'Reputation data is empty - DBot Score should be 0')
    ])
    def test_dbot_score_calculation(self, reputation_data_input: List[Dict],
                                    expected_output: Common.DBotScore,
                                    error_msg: str):
        """
            Given:
                - A list which represents a returned data of a certain reputation command
            When:
                - Running calculate dbot score function
            Then:
                - Verify command output is as expected
                - Verify dbot score is calculate according to the following logic:
                    MALICIOUS > malicious threshold (50%) = Malicious
                    MALICIOUS <= malicious threshold (50%) = Suspicious
                    SUSPICIOUS > suspicious threshold (1) = Suspicious
                    NON_MALICIOUS > non malicious threshold (50%) = Good
                    else Unknown
        """
        params = {'malicious_threshold': MALICIOUS_THRESHOLD,
                  'suspicious_threshold': SUSPICIOUS_THRESHOLD,
                  'non_malicious_threshold': NON_MALICIOUS_THRESHOLD}
        assert calculate_dbot_score(reputation_data=reputation_data_input, params=params) == expected_output, error_msg

    @pytest.mark.parametrize('reputation_data_input, expected_output, error_msg', [
        (malicious_test_input, (4, 3), four_engines_three_positive_test_err_msg),
        (malicious_suspicious_test_input, (4, 2), four_engines_two_positive_test_err_msg),
        (suspicious_test_input, (4, 0), four_engines_no_positive_test_err_msg),
        ([], (0, 0), 'Reputation data is empty - Number of engines and positive detections should be 0')
    ])
    def test_calculate_engines(self, reputation_data_input: List[Dict],
                               expected_output: Tuple[int, int],
                               error_msg: str):
        """
            Given:
                 - A list which represents a returned data of a certain reputation command
            When:
                - Running calculate engines function
            Then:
                - Verify command output is as expected
        """
        assert calculate_engines(reputation_data=reputation_data_input) == expected_output, error_msg
