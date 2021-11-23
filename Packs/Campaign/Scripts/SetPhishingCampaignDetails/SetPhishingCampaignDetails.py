import traceback

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

EMAIL_CAMPAIGN_KEY = 'EmailCampaign'

class SetPhishingCampaignDetails:

    def __init__(self, _demisto = demisto, execute_command = execute_command):
        self.incident_context = _demisto.context()
        self.dt = _demisto.dt
        self.execute_command = execute_command

    def get_current_incident_campaing_data(self):
        # Getting the context of the current incident under the campaign key.
        # An example for context is available in 'context_example' file
        current_incident_campaing_data = self.incident_context.get(EMAIL_CAMPAIGN_KEY, {})
        return current_incident_campaing_data

    def get_campaign_context(self,campaign_id):
        # Getting the campaign current context under the campaign key.
        incident_context = self.execute_command('getContext', {'id': campaign_id})
        if is_error(incident_context):
            demisto.debug(f"Could not get context for campaign incident {id}")
            return {}

        # If campaign context key is not found in the context, dt should return None.
        campaign_context = self.dt(incident_context, f'Contents.context.{EMAIL_CAMPAIGN_KEY}')
        return campaign_context if campaign_context else {}

    def is_incident_new_in_campaign(self, incident_id, campaign_data):
        incidents = campaign_data.get('incidents', [])
        incidents_ids = [incident["id"] for incident in incidents]
        return incident_id not in incidents_ids


    def add_current_incident_to_campaign(self, current_incident_data: dict, campaign_data: dict) -> dict:
        # Add the incident entry to the existing incidents.
        current_incidents_in_campaign = campaign_data.get('incidents', [])

        # Current incident is always the first in the incident list in its campaign data.
        incident_campaign_data = current_incident_data['incidents'][0]
        current_incidents_in_campaign.append(incident_campaign_data)

        current_similar_incidents = set(current_incident_data['incidents'])

        # update all other incident's similarity to be according to new incident
        for existing_incident_according_to_new_incident in current_similar_incidents:
            existing_id = existing_incident_according_to_new_incident["id"]
            # Todo
            # new_data_of_existing_incident =
            #
            # existing_incident["similarity"] =


    def merge_contexts(self, current_incident_data: dict, campaign_data:dict) -> dict:
        """
        This will update the existing incident's campaign data with the rest of the campaign data,
        according to the following logic:
        If we have a new campaign, copy the all current incident's campaign context to campaign.
        If we have an existing campaign - if the current incident is new, add the new incident to the campaign.
            Also, update other campaign incident's similarity to match the new one.
        """
        if not campaign_data:
            return current_incident_data

        if self.is_incident_new_in_campaign(demisto.incident()["id"], campaign_data):
            return self.add_current_incident_to_campaign(current_incident_data, campaign_data)

        else:
            return campaign_data


    def copy_campaign_data_to_incident(self, incident_id: int, campaign_data: dict, append: bool):

        args = {'key': EMAIL_CAMPAIGN_KEY, 'value': merged_campaign, 'append': append}

        res = self.execute_command(
            'executeCommandAt',
            {
                'incidents': incident_id,
                'command': 'Set',
                'arguments': args,
            }
        )
        if is_error(res):
            return_error(f"error in setting merged campaign data to incident id {incident_id}. Error: {res}")

        return res

    def run(self, campaign_incident_id, append):
        current_incident_campaign_data = self.get_current_incident_campaing_data()
        campaign_data = self.get_campaign_context(campaign_incident_id)

        merged_campaign = self.merge_contexts(current_incident_campaign_data, campaign_data)
        res = self.copy_campaign_data_to_incident(campaign_incident_id, merged_campaign, append)
        if res:
            demisto.results(res)

def main():
    try:
        args = demisto.args()
        incident_id = args.get('id')
        if not incident_id:
            raise Exception("Please provide incident id.")
        append = argToBoolean(args['append'])

        set_phishing_campaign_details = SetPhishingCampaignDetails()
        set_phishing_campaign_details.run(incident_id, append)

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to set campaign details.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
