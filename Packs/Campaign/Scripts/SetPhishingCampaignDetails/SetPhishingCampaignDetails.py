import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import dateparser

EMAIL_CAMPAIGN_KEY = 'EmailCampaign'


class SetPhishingCampaignDetails:

    def __init__(self, _demisto=demisto, execute_command=execute_command):
        self.incident_context = _demisto.context()
        self.dt = _demisto.dt
        self.execute_command = execute_command

    def get_current_incident_campaign_data(self) -> dict:
        # Getting the context of the current incident under the campaign key.
        # An example for context is available in 'context_example' file
        current_incident_campaign_data = self.incident_context.get(EMAIL_CAMPAIGN_KEY, {})
        return current_incident_campaign_data

    def get_campaign_context_from_incident(self, incident_id: str) -> dict:
        # Getting the campaign current context under the campaign key.
        incident_context = self.execute_command('getContext', {'id': incident_id})

        # If campaign context key is not found in the context, dt should return None.
        campaign_context = self.dt(incident_context, f'context.{EMAIL_CAMPAIGN_KEY}')
        return campaign_context if campaign_context else {}

    def get_similarities_from_incident(self, incident_id: str) -> dict:
        incident_data = self.get_campaign_context_from_incident(incident_id)
        return {incident["id"]: incident["similarity"] for incident in incident_data.get('incidents', [])}

    def is_incident_new_in_campaign(self, incident_id: str, campaign_data: dict) -> bool:
        incidents = campaign_data.get('incidents', [])
        incidents_ids = [incident["id"] for incident in incidents]
        return incident_id not in incidents_ids

    def add_current_incident_to_campaign(self, current_incident_data: dict, campaign_data: dict) -> None:
        # Add the incident entry to the existing incidents.
        current_incidents_in_campaign = campaign_data.get('incidents', [])
        # Current incident is always the first in the incident list in its campaign data.
        incident_campaign_data = current_incident_data['incidents'][0]
        current_incidents_in_campaign.append(incident_campaign_data)
        campaign_data['incidents'] = current_incidents_in_campaign
        campaign_data["involvedIncidentsCount"] = int(campaign_data["involvedIncidentsCount"]) + 1

    def _get_most_updated_incident_id(self, campaign_incidents: list) -> str:
        # Assuming campaign_incidents contains at least the new incident.
        last_occurred = dateparser.parse(campaign_incidents[0]["occurred"])
        assert last_occurred is not None
        last_id = campaign_incidents[0]["id"]
        for incident in campaign_incidents:
            occurred = dateparser.parse(incident["occurred"])
            assert occurred is not None, f'failed parsing {incident["occurred"]}'
            if last_occurred < occurred:
                last_occurred = occurred
                last_id = incident["id"]
        return last_id

    def update_similarity_to_last_incident(self, campaign_incidents: list) -> None:
        most_current_incident_id = self._get_most_updated_incident_id(campaign_incidents)
        demisto.debug(f"Newest incident in campaign: {most_current_incident_id}.")

        similarities_according_to_last_updated = self.get_similarities_from_incident(most_current_incident_id)
        for incident in campaign_incidents:
            # Assuming most recent sees all incidents that was created before it.
            if incident['id'] in similarities_according_to_last_updated:
                incident['similarity'] = similarities_according_to_last_updated[incident['id']]

    def merge_contexts(self, current_incident_data: dict, campaign_data: dict) -> dict:
        """
        This will update the existing incident's campaign data with the rest of the campaign data,
        according to the following logic:
        If we have a new campaign, copy the all current incident's campaign context to campaign.
        If we have an existing campaign - if the current incident is new, add the new incident to the campaign.
            Also, update other campaign incident's similarity to match the new one.
        """
        if not campaign_data:
            demisto.debug("Creating new Campaign with the current incident data.")
            return current_incident_data

        if self.is_incident_new_in_campaign(demisto.incident()["id"], campaign_data):
            demisto.debug("Adding current incident as new incident to Campaign.")

            self.add_current_incident_to_campaign(current_incident_data, campaign_data)
            self.update_similarity_to_last_incident(current_incident_data.get('incidents', []))
            return campaign_data

        else:
            demisto.debug("Current incident already exists in Campaign.")

            return campaign_data

    def copy_campaign_data_to_incident(self, incident_id: str, merged_campaign: dict, append: bool):

        args = {'key': EMAIL_CAMPAIGN_KEY, 'value': merged_campaign, 'append': append}

        demisto.debug(f'Executing set command on incident {incident_id} with {args=}')
        demisto.executeCommand("executeCommandAt",
                               {'command': 'Set', 'incidents': incident_id, 'arguments': args})

    def run(self, campaign_incident_id: str, append: bool):
        if not campaign_incident_id:
            raise ValueError("Please provide Campaign incident id.")

        current_incident_campaign_data = self.get_current_incident_campaign_data()
        campaign_data = self.get_campaign_context_from_incident(campaign_incident_id)
        merged_campaign = self.merge_contexts(current_incident_campaign_data, campaign_data)
        self.copy_campaign_data_to_incident(campaign_incident_id, merged_campaign, append)


def main():
    try:
        args = demisto.args()
        incident_id = args.get('id')

        append = argToBoolean(args['append'])

        set_phishing_campaign_details = SetPhishingCampaignDetails()
        set_phishing_campaign_details.run(incident_id, append)
        CommandResults(readable_output='Added incident successfully to Campaign.')

    except Exception as e:
        return_error(f'Failed to set campaign details.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
