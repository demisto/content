import datetime as datetime
import json
import pprint
from typing import List, Dict, Any
# import demistomock as demisto

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
SECURTIYSCORECARD_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

def events_to_import(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
	"""
	Helper function to filter events that need to be imported
	It filters the events based on the `created_at` timestamp

	:type ``events``: ``List[Dict[str, Any]]``
	
	:return
		Events to import

	:rtype
		``List[Dict[str, Any]]``
	"""

	today = datetime.datetime.today().date()

	incidents_to_import: List[Dict[str, Any]] = []

	pprint.pprint(alerts)
	for alert in alerts:
        	# remove unnecessary properties
		# del alert["alert_settings"]
		# del alert["my_scorecard"]
		# del alert["portfolios"]
		# del alert["username"]

		alert_time = datetime.datetime.strptime(alert.get("created_at"), SECURTIYSCORECARD_DATE_FORMAT)
		alert_date = alert_time.date()

		alert_id = alert.get("id")
		
		print("today: {0}, alert_date: {1}, should import alert '{2}'? (today == alert_date): {3}".format(today, alert_date, alert_id, (alert_date == today)))

		if alert_date == today:
			incident = {}
			incident["name"] = alert.get("change_type")
			incident["occurred"] = alert_time.strftime(DATE_FORMAT)
			incident["rawJSON"] = json.dumps(alert)
			incidents_to_import.append(incident)
		
	return incidents_to_import
    
with open("./alert_test_data.json", "r") as f:
	d = json.load(f)

incidents = events_to_import(d.get("entries"))
print("{0} Incidents will be imported".format(str(len(incidents))))
pprint.pprint(incidents)