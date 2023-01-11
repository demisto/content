import demistomock as demisto
from CommonServerPython import *

import math
from typing import Dict, Any


def round_up(n):
    if n is None:
        return None
    int_input = int(n * 100000)
    if (int_input % 10000) == 00:
        return int_input / 100000.0
    else:
        return math.floor((int_input / 10000) + 1) / 10.0


def main():
    args = demisto.args()
    version = args.get('version', '3.1')
    vector_string = f"CVSS:{version}/"

    values_map_options: Dict[str, Dict[str, Dict[str, Any]]] = {
        "3.0": {
            "AV": {
                "X": None,
                "N": 0.85,
                "A": 0.62,
                "L": 0.55,
                "P": 0.2,
            },
            "AC": {
                "X": None,
                "L": 0.77,
                "H": 0.44
            },
            "PR": {
                "X": None,
                "N": 0.85,
                "L": {
                    "C": 0.68,
                    "U": 0.62
                },
                "H": {
                    "C": 0.5,
                    "U": 0.27
                }
            },
            "UI": {
                "X": None,
                "N": 0.85,
                "R": 0.62
            },
            "CIA": {
                "X": None,
                "N": 0,
                "H": 0.56,
                "L": 0.22,
            },
            "E": {
                "X": 1,
                "H": 1,
                "F": 0.97,
                "P": 0.94,
                "U": 0.91
            },
            "RL": {
                "X": 1,
                "U": 1,
                "W": 0.97,
                "T": 0.96,
                "O": 0.95
            },
            "RC": {
                "X": 1,
                "C": 1,
                "R": 0.96,
                "U": 0.92
            },
            "CIAR": {
                "X": 1,
                "H": 1.5,
                "M": 1,
                "L": 0.5
            }
        },
        "3.1": {
            "AV": {
                "X": None,
                "N": 0.85,
                "A": 0.62,
                "L": 0.55,
                "P": 0.2,
            },
            "AC": {
                "X": None,
                "L": 0.77,
                "H": 0.44
            },
            "PR": {
                "X": None,
                "N": 0.85,
                "L": {
                    "C": 0.68,
                    "U": 0.62
                },
                "H": {
                    "C": 0.5,
                    "U": 0.27
                }
            },
            "UI": {
                "X": None,
                "N": 0.85,
                "R": 0.56
            },
            "CIA": {
                "X": None,
                "N": 0,
                "H": 0.56,
                "L": 0.22,
            },
            "E": {
                "X": 1,
                "H": 1,
                "F": 0.97,
                "P": 0.94,
                "U": 0.91
            },
            "RL": {
                "X": 1,
                "U": 1,
                "W": 0.97,
                "T": 0.96,
                "O": 0.95
            },
            "RC": {
                "X": 1,
                "C": 1,
                "R": 0.96,
                "U": 0.92
            },
            "CIAR": {
                "X": 1,
                "H": 1.5,
                "M": 1,
                "L": 0.5
            }
        }
    }
    version = args.get('version')
    values_map = values_map_options[version]

    value_list = list()
    for k, v in args.items():
        if v != "X" and k != "version":
            value_list.append(f"{k}:{v}")
    vector_string += "/".join(value_list)

    ###########################################
    # Get all required values for calculations
    ###########################################
    confidentiality = values_map['CIA'][args.get('C')]
    modified_confidentiality = args.get('MC', "X")
    modified_confidentiality = confidentiality if\
        modified_confidentiality == "X" else values_map['CIA'][modified_confidentiality]
    integrity = values_map['CIA'][args.get('I')]
    modified_integrity = args.get('MI', "X")
    modified_integrity = integrity if modified_integrity == "X" else values_map['CIA'][modified_integrity]
    availability = values_map['CIA'][args.get('A')]
    modified_availability = args.get('MA', "X")
    modified_availability = availability if modified_availability == "X"\
        else values_map['CIA'][modified_availability]
    exploit_code_maturity = values_map["E"].get(args.get('E'), "X")
    scope_changed = True if args.get('S') == "C" else False
    modified_scope_changed = True if args.get('MS') == "C" else False
    atack_vector = values_map['AV'].get(args.get('AV'), 0)

    modified_attack_vector = args.get('MAV', "X")
    modified_attack_vector = atack_vector if modified_attack_vector == "X"\
        else values_map['AV'].get(modified_attack_vector, 0)
    attack_complexity = values_map['AC'][args.get('AC')]
    modified_attack_complexity = args.get('MAC', "X")
    modified_attack_complexity = attack_complexity if modified_attack_complexity == "X"\
        else values_map['AC'][modified_attack_complexity]

    privileges_required = values_map['PR'][args.get('PR')]
    if type(privileges_required) == dict:
        privileges_required = privileges_required.get("C") if scope_changed or modified_scope_changed\
            else privileges_required["U"]
    modified_privileges_required = args.get('MPR', "X")
    if modified_privileges_required == "X":
        modified_privileges_required = privileges_required
    elif type(modified_privileges_required) == dict:
        modified_privileges_required = modified_privileges_required["C"] if scope_changed or\
            modified_scope_changed else modified_privileges_required["U"]
    else:
        modified_privileges_required = values_map['PR'][modified_privileges_required]
    user_interaction = values_map['UI'][args.get('UI')]
    modified_user_interaction = args.get('MUI', "X")
    modified_user_interaction = user_interaction if modified_user_interaction == "X"\
        else values_map['UI'][modified_user_interaction]
    remediation_level = values_map['RL'][args.get('RL', "X")]
    report_confidence = values_map['RC'][args.get('RC', "X")]
    confidentiality_requirement = values_map['CIAR'][args.get('CR', "X")]
    integrity_requirement = values_map['CIAR'][args.get('IR', "X")]
    availability_requirement = values_map['CIAR'][args.get('AR', "X")]

    ###########################################
    # Base Metric Equation calculations
    ###########################################

    # Impact Sub-Score
    iss = 0
    if version in ['3.0', '3.1']:
        iss = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))

    # Impact
    impact = 0.0
    if version in ['3.0', '3.1']:
        if not scope_changed:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    # Exploitability
    exploitability = 0.0
    if version in ['3.0', '3.1']:
        exploitability = 8.22 * atack_vector * attack_complexity * privileges_required * user_interaction

    # Base Score
    base_score = 0.0
    if version in ['3.0', '3.1']:
        base_score = 0
        if impact > 0:
            multiplier = 1.0
            if scope_changed:
                multiplier = 1.08
            calculated_value = multiplier * (impact + exploitability)
            base_score = calculated_value if calculated_value < 10.0 else 10.0
            base_score = round_up(base_score)

    ###########################################
    # Temporal Metric calculations
    ###########################################
    temporal_score_roundup = 0.0
    if version in ['3.0', '3.1']:
        temporal_score_roundup = base_score * exploit_code_maturity * remediation_level * report_confidence

    # Environmental Metrics
    modified_impact_sub_score = 0.0
    modified_impact = 0.0
    modified_exploitability = 0.0
    if version in ['3.0', '3.1']:
        calculatedmodified_impact_sub_score = (
            1 - (
                (1 - confidentiality_requirement * modified_confidentiality)
                * (1 - integrity_requirement * modified_integrity)
                * (1 - availability_requirement * modified_availability)
            )
        )
        modified_impact_sub_score = calculatedmodified_impact_sub_score if calculatedmodified_impact_sub_score < 0.915\
            else 0.915

    if version in ['3.0', '3.1']:
        if modified_scope_changed:
            if version == '3.0':
                modified_impact = 7.52 * (modified_impact_sub_score - 0.029) - 3.25 *\
                    (modified_impact_sub_score * 0.9731 - 0.02) ** 15
            elif version == '3.1':
                modified_impact = 7.52 * (modified_impact_sub_score - 0.029) - 3.25 *\
                    (modified_impact_sub_score * 0.9731 - 0.02) ** 13
        else:
            modified_impact = 6.42 * modified_impact_sub_score
        modified_exploitability = 8.22 * modified_attack_vector *\
            modified_attack_complexity * modified_privileges_required * modified_user_interaction

    # Environmental Score
    environmental_score = 0.0
    if version in ['3.0', '3.1']:
        environmental_score = 0
        if modified_impact > 0:
            exponential = 1.0
            if modified_scope_changed:
                exponential = 1.08
            calculated_value = exponential * (modified_impact + modified_exploitability)
            calculated_value = calculated_value if calculated_value < 10 else 10
            calculated_value = round_up(calculated_value)
            environmental_score = calculated_value * exploit_code_maturity * remediation_level * report_confidence
            environmental_score = round_up(environmental_score)

    # Round values
    iss = round_up(iss)
    impact = round_up(impact)
    exploitability = round_up(exploitability)
    base_score = round_up(base_score)
    temporal_score_roundup = round_up(temporal_score_roundup)
    modified_impact_sub_score = round_up(modified_impact_sub_score)
    modified_impact = round_up(modified_impact)
    modified_exploitability = round_up(modified_exploitability)
    environmental_score = round_up(environmental_score)

    entry = {
        "VectorString": vector_string,
        "Version": version,
        "ImpactSubScore": iss,
        "Impact": impact,
        "Exploitability": exploitability,
        "BaseScore": base_score,
        "TemporalScore": temporal_score_roundup,
        "ModifiedImpactSubScore": modified_impact_sub_score,
        "ModifiedImpact": modified_impact,
        "ModifiedExploitability": modified_exploitability,
        "EnvironmentalScore": environmental_score
    }

    hrentry = {k: v for k, v in entry.items() if v}
    markdown = tableToMarkdown('CVSS Score:', hrentry)

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='',
        outputs_key_field='',
        outputs={
            'CVSS(val.VectorString === obj.VectorString && val.Version === obj.Version)': entry
        }
    )
    return results


if __name__ in ['__main__', 'builtin', 'builtins']:
    res = main()
    return_results(res)
