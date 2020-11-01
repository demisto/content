const SEVERITY_VALUES = {
  "unknown": 0,
  "informational": 0.5,
  "low": 1,
  "medium": 2,
  "high": 3,
  "critical": 4,
  "0": 0,
  "0.5": 0.5,
  "1": 1,
  "2": 2,
  "3": 3,
  "4": 4
};

const severity_str = `${args.severity}`.toLowerCase();
const severity = SEVERITY_VALUES[severity_str];
const current_incident_severity = incidents[0].severity;

if (severity > current_incident_severity) {
    executeCommand('setIncident', { severity } );
    return `Severity increased to ${severity}`;
}

return "Severity not increased";
