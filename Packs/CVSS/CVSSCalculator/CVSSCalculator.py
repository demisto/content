import math


def round_up(n):
    if n is None:
        return None
    int_input = int(n * 100000)
    if (int_input % 10000) == 00:
        return int_input / 100000.0
    else:
        return math.floor((int_input / 10000) + 1) / 10.0

args = demisto.args()
version = args.get('version', '3.1')
vectorString = f"CVSS:{version}/"

valuesMapOptions = {
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
valuesMap = valuesMapOptions.get(version)

valueList = list()
for k, v in args.items():
    if v != "X" and k != "version":
        valueList.append(f"{k}:{v}")
vectorString += "/".join(valueList)


###########################################
# Get all required values for calculations
###########################################
C = valuesMap["CIA"].get(args.get('C'))
MC = args.get('MC', "X")
if MC == "X":
    MC = C
else:
    MC = valuesMap['CIA'].get(MC)
I = valuesMap['CIA'].get(args.get('I'))
MI = args.get('MI', "X")
if MI == "X":
    MI = I
else:
    MI = valuesMap['CIA'].get(MI)
A = valuesMap["CIA"].get(args.get('A'))
MA = args.get('MA', "X")
if MA == "X":
    MA = A
else:
    MA = valuesMap['CIA'].get(MA)
E = valuesMap["E"].get(args.get('E'), "X")
scopeChanged = True if args.get('S') == "C" else False
modifiedScopeChanged = True if args.get('MS') == "C" else False
AV = valuesMap['AV'].get(args.get('AV'))
MAV = args.get('MAV', "X")
if MAV == "X":
    MAV = AV
else:
    MAV = valuesMap['AV'].get(MAV)
AC = valuesMap['AC'].get(args.get('AC'))
MAC = args.get('MAC', "X")
if MAC == "X":
    MAC = AC
else:
    MAC = valuesMap['AC'].get(MAC)
PR = valuesMap['PR'].get(args.get('PR'))
if type(PR) == dict:
    PR = PR.get("C") if scopeChanged or modifiedScopeChanged else PR.get("U")
MPR = args.get('MPR', "X")
if MPR == "X":
    MPR = PR
elif type(MPR) == dict:
    MPR = MPR.get("C") if scopeChanged or modifiedScopeChanged else MPR.get("U")
else:
    MPR = valuesMap['PR'].get(MPR)
UI = valuesMap['UI'].get(args.get('UI'))
MUI = args.get('MUI', "X")
if MUI == "X":
    MUI = UI
else:
    MUI = valuesMap['UI'].get(MUI)
RL = valuesMap['RL'].get(args.get('RL', "X"))
RC = valuesMap['RC'].get(args.get('RC', "X"))
CR = valuesMap['CIAR'].get(args.get('CR', "X"))
IR = valuesMap['CIAR'].get(args.get('IR', "X"))
AR = valuesMap['CIAR'].get(args.get('AR', "X"))


###########################################
# Base Metric Equation calculations
###########################################

# Impact Sub-Score
iss = None
if version in ['3.0', '3.1']:
    iss = 1 - ((1 - C) * (1 - I) * (1 - A))


# Impact
impact = None
if version in ['3.0', '3.1']:
    if not scopeChanged:
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss -0.029) - 3.25 * (iss - 0.02) ** 15


# Exploitability
exploitability = None
if version in ['3.0', '3.1']:
    exploitability = 8.22 * AV * AC * PR * UI


# Base Score
baseScore = None
if version in ['3.0', '3.1']:
    baseScore = 0
    if impact > 0:
        multiplier = 1
        if scopeChanged:
            multiplier = 1.08
        calculatedValue = multiplier * (impact + exploitability)
        baseScore =  calculatedValue if calculatedValue < 10 else 10
        baseScore = round_up(baseScore)


###########################################
# Temporal Metric calculations
###########################################
temporalScoreRoundup = None
if version in ['3.0', '3.1']:
    temporalScoreRoundup = baseScore * E * RL * RC


# Environmental Metrics
MISS = None
modifiedImpact = None
modifiedExploitability = None
if version in ['3.0', '3.1']:
    calculatedMISS = (1 - (( 1 - CR * MC) * (1 - IR * MI) * (1 - AR * MA)))
    MISS = calculatedMISS if calculatedMISS < 0.915 else 0.915

if version in ['3.0', '3.1']:
    if modifiedScopeChanged:
        if version == '3.0':
            modifiedImpact = 7.52 * (MISS - 0.029) - 3.25 * (MISS * 0.9731 - 0.02) ** 15
        elif version == '3.1':
            modifiedImpact = 7.52 * (MISS - 0.029) - 3.25 * (MISS * 0.9731 - 0.02) ** 13
    else:
        modifiedImpact = 6.42 * MISS
    modifiedExploitability = 8.22 * MAV * MAC * MPR * MUI


# Environmental Score
environmentalScore = None
if version in ['3.0', '3.1']:
    environmentalScore = 0
    if modifiedImpact > 0:
        exponential = 1
        if modifiedScopeChanged:
            exponential = 1.08
        calculatedValue = exponential * (modifiedImpact + modifiedExploitability)
        calculatedValue = calculatedValue if calculatedValue < 10 else 10
        calculatedValue = round_up(calculatedValue)
        environmentalScore = calculatedValue * E * RL * RC
        environmentalScore = round_up(environmentalScore)


# Round values
iss = round_up(iss)
impact = round_up(impact)
exploitability = round_up(exploitability)
baseScore = round_up(baseScore)
temporalScoreRoundup = round_up(temporalScoreRoundup)
MISS = round_up(MISS)
modifiedImpact = round_up(modifiedImpact)
modifiedExploitability = round_up(modifiedExploitability)
environmentalScore = round_up(environmentalScore)

entry = {
    "VectorString": vectorString,
    "Version": version,
    "ImpactSubScore": iss,
    "Impact": impact,
    "Exploitability": exploitability,
    "BaseScore": baseScore,
    "TemporalScore": temporalScoreRoundup,
    "ModifiedImpactSubScore": MISS,
    "ModifiedImpact": modifiedImpact,
    "ModifiedExploitability": modifiedExploitability,
    "EnvironmentalScore": environmentalScore
}

hrentry = {k: v for k,v in entry.items() if v}
md = tableToMarkdown('CVSS Score:', hrentry)

ec = {
    "CVSS(val.VectorString == obj.VectorString && val.Version == obj.Version)": entry
}

demisto.results({
    'Type': entryTypes['note'],
    'Contents': entry,
    'ContentsFormat': formats['json'],
    'HumanReadable': md,
    'ReadableContentsFormat': formats['markdown'],
    'EntryContext': ec
})
