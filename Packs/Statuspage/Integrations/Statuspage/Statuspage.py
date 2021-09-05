import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def add_components_for_page_access_user_request(self, page_id, page_access_user_id, component_ids):
        data = {"component_ids": component_ids}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PATCH', f'pages/{page_id}/page_access_users/{page_access_user_id}/components', json_data=data, headers=headers)

        return response

    def add_components_for_page_access_user_request(self, page_id, page_access_user_id, component_ids):
        data = {"component_ids": component_ids}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PUT', f'pages/{page_id}/page_access_users/{page_access_user_id}/components', json_data=data, headers=headers)

        return response

    def replace_components_for_page_access_user_request(self, page_id, page_access_user_id, component_ids):
        data = {"component_ids": component_ids}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'POST', f'pages/{page_id}/page_access_users/{page_access_user_id}/components', json_data=data, headers=headers)

        return response

    def remove_components_for_page_access_user_request(self, page_id, page_access_user_id, component_ids):
        data = {"component_ids": component_ids}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'DELETE', f'pages/{page_id}/page_access_users/{page_access_user_id}/components', json_data=data, headers=headers)

        return response

    def get_components_for_page_access_user_request(self, page_id, page_access_user_id):
        headers = self._headers

        response = self._http_request(
            'GET', f'pages/{page_id}/page_access_users/{page_access_user_id}/components', headers=headers)

        return response

    def remove_component_for_page_access_user_request(self, page_id, page_access_user_id, component_id):
        headers = self._headers

        response = self._http_request(
            'DELETE', f'pages/{page_id}/page_access_users/{page_access_user_id}/components/{component_id}', headers=headers)

        return response

    def add_metrics_for_page_access_user_request(self, page_id, page_access_user_id, metric_ids):
        data = {"metric_ids": metric_ids}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PATCH', f'pages/{page_id}/page_access_users/{page_access_user_id}/metrics', json_data=data, headers=headers)

        return response

    def add_metrics_for_page_access_user_request(self, page_id, page_access_user_id, metric_ids):
        data = {"metric_ids": metric_ids}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PUT', f'pages/{page_id}/page_access_users/{page_access_user_id}/metrics', json_data=data, headers=headers)

        return response

    def replace_metrics_for_page_access_user_request(self, page_id, page_access_user_id, metric_ids):
        data = {"metric_ids": metric_ids}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'POST', f'pages/{page_id}/page_access_users/{page_access_user_id}/metrics', json_data=data, headers=headers)

        return response

    def delete_metrics_for_page_access_user_request(self, page_id, page_access_user_id, metric_ids):
        data = {"metric_ids": metric_ids}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'DELETE', f'pages/{page_id}/page_access_users/{page_access_user_id}/metrics', json_data=data, headers=headers)

        return response

    def get_metrics_for_page_access_user_request(self, page_id, page_access_user_id):
        headers = self._headers

        response = self._http_request(
            'GET', f'pages/{page_id}/page_access_users/{page_access_user_id}/metrics', headers=headers)

        return response

    def delete_metric_for_page_access_user_request(self, page_id, page_access_user_id, metric_id):
        headers = self._headers

        response = self._http_request(
            'DELETE', f'pages/{page_id}/page_access_users/{page_access_user_id}/metrics/{metric_id}', headers=headers)

        return response

    def update_page_access_user_request(self, page_id, page_access_user_id):
        headers = self._headers

        response = self._http_request(
            'PATCH', f'pages/{page_id}/page_access_users/{page_access_user_id}', headers=headers)

        return response

    def update_page_access_user_request(self, page_id, page_access_user_id):
        headers = self._headers

        response = self._http_request(
            'PUT', f'pages/{page_id}/page_access_users/{page_access_user_id}', headers=headers)

        return response

    def delete_page_access_user_request(self, page_id, page_access_user_id):
        headers = self._headers

        response = self._http_request(
            'DELETE', f'pages/{page_id}/page_access_users/{page_access_user_id}', headers=headers)

        return response

    def get_page_access_user_request(self, page_id, page_access_user_id):
        headers = self._headers

        response = self._http_request(
            'GET', f'pages/{page_id}/page_access_users/{page_access_user_id}', headers=headers)

        return response

    def add_a_page_access_user_request(self, page_id, external_login, email, page_access_group_ids, subscribe_to_components):
        data = {"page_access_user": {"email": email, "external_login": external_login,
                                     "page_access_group_ids": page_access_group_ids, "subscribe_to_components": subscribe_to_components}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', f'pages/{page_id}/page_access_users', json_data=data, headers=headers)

        return response

    def get_a_list_of_page_access_users_request(self, page_id, email, page, per_page):
        params = assign_params(email=email, page=page, per_page=per_page)
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/page_access_users', params=params, headers=headers)

        return response

    def add_components_to_page_access_group_request(self, page_id, page_access_group_id, component_ids):
        data = {"component_ids": component_ids}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PATCH', f'pages/{page_id}/page_access_groups/{page_access_group_id}/components', json_data=data, headers=headers)

        return response

    def add_components_to_page_access_group_request(self, page_id, page_access_group_id, component_ids):
        data = {"component_ids": component_ids}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PUT', f'pages/{page_id}/page_access_groups/{page_access_group_id}/components', json_data=data, headers=headers)

        return response

    def replace_components_for_a_page_access_group_request(self, page_id, page_access_group_id, component_ids):
        data = {"component_ids": component_ids}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'POST', f'pages/{page_id}/page_access_groups/{page_access_group_id}/components', json_data=data, headers=headers)

        return response

    def delete_components_for_a_page_access_group_request(self, page_id, page_access_group_id, component_ids):
        data = {"component_ids": component_ids}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'DELETE', f'pages/{page_id}/page_access_groups/{page_access_group_id}/components', json_data=data, headers=headers)

        return response

    def list_components_for_a_page_access_group_request(self, page_id, page_access_group_id):
        headers = self._headers

        response = self._http_request(
            'GET', f'pages/{page_id}/page_access_groups/{page_access_group_id}/components', headers=headers)

        return response

    def remove_a_component_from_a_page_access_group_request(self, page_id, page_access_group_id, component_id):
        headers = self._headers

        response = self._http_request(
            'DELETE', f'pages/{page_id}/page_access_groups/{page_access_group_id}/components/{component_id}', headers=headers)

        return response

    def get_a_page_access_group_request(self, page_id, page_access_group_id):
        headers = self._headers

        response = self._http_request(
            'GET', f'pages/{page_id}/page_access_groups/{page_access_group_id}', headers=headers)

        return response

    def update_a_page_access_group_request(self, page_id, page_access_group_id, name, external_identifier, component_ids, metric_ids, page_access_user_ids):
        data = {"page_access_group": {"component_ids": component_ids, "external_identifier": external_identifier,
                                      "metric_ids": metric_ids, "name": name, "page_access_user_ids": page_access_user_ids}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PATCH', f'pages/{page_id}/page_access_groups/{page_access_group_id}', json_data=data, headers=headers)

        return response

    def update_a_page_access_group_request(self, page_id, page_access_group_id, name, external_identifier, component_ids, metric_ids, page_access_user_ids):
        data = {"page_access_group": {"component_ids": component_ids, "external_identifier": external_identifier,
                                      "metric_ids": metric_ids, "name": name, "page_access_user_ids": page_access_user_ids}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PUT', f'pages/{page_id}/page_access_groups/{page_access_group_id}', json_data=data, headers=headers)

        return response

    def remove_a_page_access_group_request(self, page_id, page_access_group_id):
        headers = self._headers

        response = self._http_request(
            'DELETE', f'pages/{page_id}/page_access_groups/{page_access_group_id}', headers=headers)

        return response

    def get_a_list_of_page_access_groups_request(self, page_id):
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/page_access_groups', headers=headers)

        return response

    def create_a_page_access_group_request(self, page_id, name, external_identifier, component_ids, metric_ids, page_access_user_ids):
        data = {"page_access_group": {"component_ids": component_ids, "external_identifier": external_identifier,
                                      "metric_ids": metric_ids, "name": name, "page_access_user_ids": page_access_user_ids}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', f'pages/{page_id}/page_access_groups', json_data=data, headers=headers)

        return response

    def unsubscribe_a_subscriber_request(self, page_id, subscriber_id, skip_unsubscription_notification):
        params = assign_params(skip_unsubscription_notification=skip_unsubscription_notification)
        headers = self._headers

        response = self._http_request(
            'DELETE', f'pages/{page_id}/subscribers/{subscriber_id}', params=params, headers=headers)

        return response

    def update_a_subscriber_request(self, page_id, subscriber_id, component_ids):
        data = {"component_ids": component_ids}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PATCH', f'pages/{page_id}/subscribers/{subscriber_id}', json_data=data, headers=headers)

        return response

    def get_a_subscriber_request(self, page_id, subscriber_id):
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/subscribers/{subscriber_id}', headers=headers)

        return response

    def resend_confirmation_to_a_subscriber_request(self, page_id, subscriber_id):
        headers = self._headers

        response = self._http_request(
            'POST', f'pages/{page_id}/subscribers/{subscriber_id}/resend_confirmation', headers=headers)

        return response

    def create_a_subscriber_request(self, page_id, email, endpoint, phone_country, phone_number, skip_confirmation_notification, page_access_user, component_ids):
        data = {"subscriber": {"component_ids": component_ids, "email": email, "endpoint": endpoint, "page_access_user": page_access_user,
                               "phone_country": phone_country, "phone_number": phone_number, "skip_confirmation_notification": skip_confirmation_notification}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', f'pages/{page_id}/subscribers', json_data=data, headers=headers)

        return response

    def get_a_list_of_subscribers_request(self, page_id, q, type_, state, limit, page, sort_field, sort_direction):
        params = assign_params(q=q, type=type_, state=state, limit=limit, page=page,
                               sort_field=sort_field, sort_direction=sort_direction)
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/subscribers', params=params, headers=headers)

        return response

    def resend_confirmations_to_a_list_of_subscribers_request(self, page_id, subscribers):
        data = {"subscribers": subscribers}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'POST', f'pages/{page_id}/subscribers/resend_confirmation', json_data=data, headers=headers)

        return response

    def unsubscribe_a_list_of_subscribers_request(self, page_id, subscribers, type_, state, skip_unsubscription_notification):
        data = {"skip_unsubscription_notification": skip_unsubscription_notification,
                "state": state, "subscribers": subscribers, "type": type}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'POST', f'pages/{page_id}/subscribers/unsubscribe', json_data=data, headers=headers)

        return response

    def reactivate_a_list_of_subscribers_request(self, page_id, subscribers, type_):
        data = {"subscribers": subscribers, "type": type}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'POST', f'pages/{page_id}/subscribers/reactivate', json_data=data, headers=headers)

        return response

    def get_a_histogram_of_subscribers_by_type_and_then_state_request(self, page_id):
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/subscribers/histogram_by_state', headers=headers)

        return response

    def get_a_count_of_subscribers_by_type_request(self, page_id, type_, state):
        params = assign_params(type=type_, state=state)
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/subscribers/count', params=params, headers=headers)

        return response

    def get_a_list_of_unsubscribed_subscribers_request(self, page_id):
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/subscribers/unsubscribed', headers=headers)

        return response

    def create_a_template_request(self, page_id, name, title, body, group_id, update_status, should_tweet, should_send_notifications, component_ids):
        data = {"template": {"body": body, "component_ids": component_ids, "group_id": group_id, "name": name,
                             "should_send_notifications": should_send_notifications, "should_tweet": should_tweet, "title": title, "update_status": update_status}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', f'pages/{page_id}/incident_templates', json_data=data, headers=headers)

        return response

    def get_a_list_of_templates_request(self, page_id, page, per_page):
        params = assign_params(page=page, per_page=per_page)
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/incident_templates', params=params, headers=headers)

        return response

    def update_a_previous_incident_update_request(self, page_id, incident_id, incident_update_id, wants_twitter_update, body, display_at, deliver_notifications):
        data = {"incident_update": {"body": body, "deliver_notifications": deliver_notifications,
                                    "display_at": display_at, "wants_twitter_update": wants_twitter_update}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PATCH', f'pages/{page_id}/incidents/{incident_id}/incident_updates/{incident_update_id}', json_data=data, headers=headers)

        return response

    def update_a_previous_incident_update_request(self, page_id, incident_id, incident_update_id, wants_twitter_update, body, display_at, deliver_notifications):
        data = {"incident_update": {"body": body, "deliver_notifications": deliver_notifications,
                                    "display_at": display_at, "wants_twitter_update": wants_twitter_update}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PUT', f'pages/{page_id}/incidents/{incident_id}/incident_updates/{incident_update_id}', json_data=data, headers=headers)

        return response

    def unsubscribe_an_incident_subscriber_request(self, page_id, incident_id, subscriber_id):
        headers = self._headers

        response = self._http_request(
            'DELETE', f'pages/{page_id}/incidents/{incident_id}/subscribers/{subscriber_id}', headers=headers)

        return response

    def get_an_incident_subscriber_request(self, page_id, incident_id, subscriber_id):
        headers = self._headers

        response = self._http_request(
            'GET', f'pages/{page_id}/incidents/{incident_id}/subscribers/{subscriber_id}', headers=headers)

        return response

    def resend_confirmation_to_an_incident_subscriber_request(self, page_id, incident_id, subscriber_id):
        headers = self._headers

        response = self._http_request(
            'POST', f'pages/{page_id}/incidents/{incident_id}/subscribers/{subscriber_id}/resend_confirmation', headers=headers)

        return response

    def create_an_incident_subscriber_request(self, page_id, incident_id, email, phone_country, phone_number, skip_confirmation_notification):
        data = {"subscriber": {"email": email, "phone_country": phone_country,
                               "phone_number": phone_number, "skip_confirmation_notification": skip_confirmation_notification}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'POST', f'pages/{page_id}/incidents/{incident_id}/subscribers', json_data=data, headers=headers)

        return response

    def get_a_list_of_incident_subscribers_request(self, page_id, incident_id):
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/incidents/{incident_id}/subscribers', headers=headers)

        return response

    def get_postmortem_request(self, page_id, incident_id):
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/incidents/{incident_id}/postmortem', headers=headers)

        return response

    def create_postmortem_request(self, page_id, incident_id, body_draft):
        data = {"postmortem": {"body_draft": body_draft}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PUT', f'pages/{page_id}/incidents/{incident_id}/postmortem', json_data=data, headers=headers)

        return response

    def delete_postmortem_request(self, page_id, incident_id):
        headers = self._headers

        response = self._http_request('DELETE', f'pages/{page_id}/incidents/{incident_id}/postmortem', headers=headers)

        return response

    def publish_postmortem_request(self, page_id, incident_id, notify_twitter, notify_subscribers, custom_tweet):
        data = {"postmortem": {"custom_tweet": custom_tweet,
                               "notify_subscribers": notify_subscribers, "notify_twitter": notify_twitter}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PUT', f'pages/{page_id}/incidents/{incident_id}/postmortem/publish', json_data=data, headers=headers)

        return response

    def revert_postmortem_request(self, page_id, incident_id):
        headers = self._headers

        response = self._http_request(
            'PUT', f'pages/{page_id}/incidents/{incident_id}/postmortem/revert', headers=headers)

        return response

    def delete_an_incident_request(self, page_id, incident_id):
        headers = self._headers

        response = self._http_request('DELETE', f'pages/{page_id}/incidents/{incident_id}', headers=headers)

        return response

    def update_an_incident_request(self, page_id, incident_id, name, status, impact_override, scheduled_for, scheduled_until, scheduled_remind_prior, scheduled_auto_in_progress, scheduled_auto_completed, deliver_notifications, auto_transition_deliver_notifications_at_end, auto_transition_deliver_notifications_at_start, auto_transition_to_maintenance_state, auto_transition_to_operational_state, auto_tweet_at_beginning, auto_tweet_on_completion, auto_tweet_on_creation, auto_tweet_one_hour_before, backfill_date, backfilled, body, fl9frwst8231, component_ids, scheduled_auto_transition):
        data = {"incident": {"auto_transition_deliver_notifications_at_end": auto_transition_deliver_notifications_at_end, "auto_transition_deliver_notifications_at_start": auto_transition_deliver_notifications_at_start, "auto_transition_to_maintenance_state": auto_transition_to_maintenance_state, "auto_transition_to_operational_state": auto_transition_to_operational_state, "auto_tweet_at_beginning": auto_tweet_at_beginning, "auto_tweet_on_completion": auto_tweet_on_completion, "auto_tweet_on_creation": auto_tweet_on_creation, "auto_tweet_one_hour_before": auto_tweet_one_hour_before,
                             "backfill_date": backfill_date, "backfilled": backfilled, "body": body, "component_ids": component_ids, "components": {"fl9frwst8231": fl9frwst8231}, "deliver_notifications": deliver_notifications, "impact_override": impact_override, "metadata": {}, "name": name, "scheduled_auto_completed": scheduled_auto_completed, "scheduled_auto_in_progress": scheduled_auto_in_progress, "scheduled_auto_transition": scheduled_auto_transition, "scheduled_for": scheduled_for, "scheduled_remind_prior": scheduled_remind_prior, "scheduled_until": scheduled_until, "status": status}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PATCH', f'pages/{page_id}/incidents/{incident_id}', json_data=data, headers=headers)

        return response

    def update_an_incident_request(self, page_id, incident_id, name, status, impact_override, scheduled_for, scheduled_until, scheduled_remind_prior, scheduled_auto_in_progress, scheduled_auto_completed, deliver_notifications, auto_transition_deliver_notifications_at_end, auto_transition_deliver_notifications_at_start, auto_transition_to_maintenance_state, auto_transition_to_operational_state, auto_tweet_at_beginning, auto_tweet_on_completion, auto_tweet_on_creation, auto_tweet_one_hour_before, backfill_date, backfilled, body, fl9frwst8231, component_ids, scheduled_auto_transition):
        data = {"incident": {"auto_transition_deliver_notifications_at_end": auto_transition_deliver_notifications_at_end, "auto_transition_deliver_notifications_at_start": auto_transition_deliver_notifications_at_start, "auto_transition_to_maintenance_state": auto_transition_to_maintenance_state, "auto_transition_to_operational_state": auto_transition_to_operational_state, "auto_tweet_at_beginning": auto_tweet_at_beginning, "auto_tweet_on_completion": auto_tweet_on_completion, "auto_tweet_on_creation": auto_tweet_on_creation, "auto_tweet_one_hour_before": auto_tweet_one_hour_before,
                             "backfill_date": backfill_date, "backfilled": backfilled, "body": body, "component_ids": component_ids, "components": {"fl9frwst8231": fl9frwst8231}, "deliver_notifications": deliver_notifications, "impact_override": impact_override, "metadata": {}, "name": name, "scheduled_auto_completed": scheduled_auto_completed, "scheduled_auto_in_progress": scheduled_auto_in_progress, "scheduled_auto_transition": scheduled_auto_transition, "scheduled_for": scheduled_for, "scheduled_remind_prior": scheduled_remind_prior, "scheduled_until": scheduled_until, "status": status}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PUT', f'pages/{page_id}/incidents/{incident_id}', json_data=data, headers=headers)

        return response

    def get_an_incident_request(self, page_id, incident_id):
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/incidents/{incident_id}', headers=headers)

        return response

    def create_an_incident_request(self, page_id, name, status, impact_override, scheduled_for, scheduled_until, scheduled_remind_prior, scheduled_auto_in_progress, scheduled_auto_completed, deliver_notifications, auto_transition_deliver_notifications_at_end, auto_transition_deliver_notifications_at_start, auto_transition_to_maintenance_state, auto_transition_to_operational_state, auto_tweet_at_beginning, auto_tweet_on_completion, auto_tweet_on_creation, auto_tweet_one_hour_before, backfill_date, backfilled, body, d1p30m113pht, component_ids, scheduled_auto_transition):
        data = {"incident": {"auto_transition_deliver_notifications_at_end": auto_transition_deliver_notifications_at_end, "auto_transition_deliver_notifications_at_start": auto_transition_deliver_notifications_at_start, "auto_transition_to_maintenance_state": auto_transition_to_maintenance_state, "auto_transition_to_operational_state": auto_transition_to_operational_state, "auto_tweet_at_beginning": auto_tweet_at_beginning, "auto_tweet_on_completion": auto_tweet_on_completion, "auto_tweet_on_creation": auto_tweet_on_creation, "auto_tweet_one_hour_before": auto_tweet_one_hour_before,
                             "backfill_date": backfill_date, "backfilled": backfilled, "body": body, "component_ids": component_ids, "components": {"d1p30m113pht": d1p30m113pht}, "deliver_notifications": deliver_notifications, "impact_override": impact_override, "metadata": {}, "name": name, "scheduled_auto_completed": scheduled_auto_completed, "scheduled_auto_in_progress": scheduled_auto_in_progress, "scheduled_auto_transition": scheduled_auto_transition, "scheduled_for": scheduled_for, "scheduled_remind_prior": scheduled_remind_prior, "scheduled_until": scheduled_until, "status": status}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', f'pages/{page_id}/incidents', json_data=data, headers=headers)

        return response

    def get_a_list_of_incidents_request(self, page_id, q, limit, page):
        params = assign_params(q=q, limit=limit, page=page)
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/incidents', params=params, headers=headers)

        return response

    def get_a_list_of_active_maintenances_request(self, page_id, page, per_page):
        params = assign_params(page=page, per_page=per_page)
        headers = self._headers

        response = self._http_request(
            'GET', f'pages/{page_id}/incidents/active_maintenance', params=params, headers=headers)

        return response

    def get_a_list_of_upcoming_incidents_request(self, page_id, page, per_page):
        params = assign_params(page=page, per_page=per_page)
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/incidents/upcoming', params=params, headers=headers)

        return response

    def get_a_list_of_scheduled_incidents_request(self, page_id, page, per_page):
        params = assign_params(page=page, per_page=per_page)
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/incidents/scheduled', params=params, headers=headers)

        return response

    def get_a_list_of_unresolved_incidents_request(self, page_id, page, per_page):
        params = assign_params(page=page, per_page=per_page)
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/incidents/unresolved', params=params, headers=headers)

        return response

    def remove_page_access_users_from_component_request(self, page_id, component_id):
        headers = self._headers

        response = self._http_request(
            'DELETE', f'pages/{page_id}/components/{component_id}/page_access_users', headers=headers)

        return response

    def add_page_access_users_to_a_component_request(self, page_id, component_id):
        headers = self._headers
        headers['Content-Type'] = 'application/x-www-form-urlencoded'

        response = self._http_request(
            'POST', f'pages/{page_id}/components/{component_id}/page_access_users', headers=headers)

        return response

    def remove_page_access_groups_from_a_component_request(self, page_id, component_id):
        headers = self._headers

        response = self._http_request(
            'DELETE', f'pages/{page_id}/components/{component_id}/page_access_groups', headers=headers)

        return response

    def add_page_access_groups_to_a_component_request(self, page_id, component_id):
        headers = self._headers

        response = self._http_request(
            'POST', f'pages/{page_id}/components/{component_id}/page_access_groups', headers=headers)

        return response

    def update_a_component_request(self, page_id, component_id, description, status, name, only_show_if_degraded, group_id, showcase, start_date):
        data = {"component": {"description": description, "group_id": group_id, "name": name,
                              "only_show_if_degraded": only_show_if_degraded, "showcase": showcase, "start_date": start_date, "status": status}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PATCH', f'pages/{page_id}/components/{component_id}', json_data=data, headers=headers)

        return response

    def update_a_component_request(self, page_id, component_id, description, status, name, only_show_if_degraded, group_id, showcase, start_date):
        data = {"component": {"description": description, "group_id": group_id, "name": name,
                              "only_show_if_degraded": only_show_if_degraded, "showcase": showcase, "start_date": start_date, "status": status}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PUT', f'pages/{page_id}/components/{component_id}', json_data=data, headers=headers)

        return response

    def delete_a_component_request(self, page_id, component_id):
        headers = self._headers

        response = self._http_request('DELETE', f'pages/{page_id}/components/{component_id}', headers=headers)

        return response

    def get_a_component_request(self, page_id, component_id):
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/components/{component_id}', headers=headers)

        return response

    def get_uptime_data_for_a_component_request(self, page_id, component_id, start, end):
        params = assign_params(start=start, end=end)
        headers = self._headers

        response = self._http_request(
            'GET', f'pages/{page_id}/components/{component_id}/uptime', params=params, headers=headers)

        return response

    def create_a_component_request(self, page_id, description, status, name, only_show_if_degraded, group_id, showcase, start_date):
        data = {"component": {"description": description, "group_id": group_id, "name": name,
                              "only_show_if_degraded": only_show_if_degraded, "showcase": showcase, "start_date": start_date, "status": status}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', f'pages/{page_id}/components', json_data=data, headers=headers)

        return response

    def get_a_list_of_components_request(self, page_id, page, per_page):
        params = assign_params(page=page, per_page=per_page)
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/components', params=params, headers=headers)

        return response

    def update_a_component_group_request(self, page_id, id_, description, components, name):
        data = {"component_group": {"components": components, "name": name}, "description": description}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PATCH', f'pages/{page_id_}/component-groups/{id_}', json_data=data, headers=headers)

        return response

    def update_a_component_group_request(self, page_id, id_, description, components, name):
        data = {"component_group": {"components": components, "name": name}, "description": description}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PUT', f'pages/{page_id_}/component-groups/{id_}', json_data=data, headers=headers)

        return response

    def delete_a_component_group_request(self, page_id, id_):
        headers = self._headers

        response = self._http_request('DELETE', f'pages/{page_id_}/component-groups/{id_}', headers=headers)

        return response

    def get_a_component_group_request(self, page_id, id_):
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id_}/component-groups/{id_}', headers=headers)

        return response

    def get_uptime_data_for_a_component_group_request(self, page_id, id_, start, end):
        params = assign_params(start=start, end=end)
        headers = self._headers

        response = self._http_request(
            'GET', f'pages/{page_id_}/component-groups/{id_}/uptime', params=params, headers=headers)

        return response

    def create_a_component_group_request(self, page_id, description, components, name):
        data = {"component_group": {"components": components, "name": name}, "description": description}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', f'pages/{page_id}/component-groups', json_data=data, headers=headers)

        return response

    def get_a_list_of_component_groups_request(self, page_id):
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/component-groups', headers=headers)

        return response

    def reset_data_for_a_metric_request(self, page_id, metric_id):
        headers = self._headers

        response = self._http_request('DELETE', f'pages/{page_id}/metrics/{metric_id}/data', headers=headers)

        return response

    def add_data_to_a_metric_request(self, page_id, metric_id, timestamp, value):
        data = {"data": {"timestamp": timestamp, "value": value}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'POST', f'pages/{page_id}/metrics/{metric_id}/data', json_data=data, headers=headers)

        return response

    def update_a_metric_request(self, page_id, metric_id, name, metric_identifier):
        data = {"metric": {"metric_identifier": metric_identifier, "name": name}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('PATCH', f'pages/{page_id}/metrics/{metric_id}', json_data=data, headers=headers)

        return response

    def update_a_metric_request(self, page_id, metric_id, name, metric_identifier):
        data = {"metric": {"metric_identifier": metric_identifier, "name": name}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('PUT', f'pages/{page_id}/metrics/{metric_id}', json_data=data, headers=headers)

        return response

    def delete_a_metric_request(self, page_id, metric_id):
        headers = self._headers

        response = self._http_request('DELETE', f'pages/{page_id}/metrics/{metric_id}', headers=headers)

        return response

    def get_a_metric_request(self, page_id, metric_id):
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/metrics/{metric_id}', headers=headers)

        return response

    def get_a_list_of_metrics_request(self, page_id):
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/metrics', headers=headers)

        return response

    def add_data_points_to_metrics_request(self, page_id, timestamp, value):
        data = {"data": {"metric_id": [{"timestamp": timestamp, "value": value}]}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', f'pages/{page_id}/metrics/data', json_data=data, headers=headers)

        return response

    def list_metrics_for_a_metric_provider_request(self, page_id, metrics_provider_id):
        headers = self._headers

        response = self._http_request(
            'GET', f'pages/{page_id}/metrics_providers/{metrics_provider_id}/metrics', headers=headers)

        return response

    def create_a_metric_for_a_metric_provider_request(self, page_id, metrics_provider_id, name, metric_identifier, transform, suffix, y_axis_min, y_axis_max, y_axis_hidden, display, decimal_places, tooltip_description):
        data = {"metric": {"decimal_places": decimal_places, "display": display, "metric_identifier": metric_identifier, "name": name, "suffix": suffix,
                           "tooltip_description": tooltip_description, "transform": transform, "y_axis_hidden": y_axis_hidden, "y_axis_max": y_axis_max, "y_axis_min": y_axis_min}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'POST', f'pages/{page_id}/metrics_providers/{metrics_provider_id}/metrics', json_data=data, headers=headers)

        return response

    def get_a_metric_provider_request(self, page_id, metrics_provider_id):
        headers = self._headers

        response = self._http_request(
            'GET', f'pages/{page_id}/metrics_providers/{metrics_provider_id}', headers=headers)

        return response

    def update_a_metric_provider_request(self, page_id, metrics_provider_id, type_, metric_base_uri):
        data = {"metrics_provider": {"metric_base_uri": metric_base_uri, "type": type}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PATCH', f'pages/{page_id}/metrics_providers/{metrics_provider_id}', json_data=data, headers=headers)

        return response

    def update_a_metric_provider_request(self, page_id, metrics_provider_id, type_, metric_base_uri):
        data = {"metrics_provider": {"metric_base_uri": metric_base_uri, "type": type}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PUT', f'pages/{page_id}/metrics_providers/{metrics_provider_id}', json_data=data, headers=headers)

        return response

    def delete_a_metric_provider_request(self, page_id, metrics_provider_id):
        headers = self._headers

        response = self._http_request(
            'DELETE', f'pages/{page_id}/metrics_providers/{metrics_provider_id}', headers=headers)

        return response

    def get_a_list_of_metric_providers_request(self, page_id):
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/metrics_providers', headers=headers)

        return response

    def create_a_metric_provider_request(self, page_id, email, password, api_key, api_token, application_key, type_, metric_base_uri):
        data = {"metrics_provider": {"api_key": api_key, "api_token": api_token, "application_key": application_key,
                                     "email": email, "metric_base_uri": metric_base_uri, "password": password, "type": type}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', f'pages/{page_id}/metrics_providers', json_data=data, headers=headers)

        return response

    def get_status_embed_config_settings_request(self, page_id):
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}/status_embed_config', headers=headers)

        return response

    def update_status_embed_config_settings_request(self, page_id, position, incident_background_color, incident_text_color, maintenance_background_color, maintenance_text_color):
        data = {"status_embed_config": {"incident_background_color": incident_background_color, "incident_text_color": incident_text_color,
                                        "maintenance_background_color": maintenance_background_color, "maintenance_text_color": maintenance_text_color, "position": position}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('PATCH', f'pages/{page_id}/status_embed_config', json_data=data, headers=headers)

        return response

    def update_status_embed_config_settings_request(self, page_id, position, incident_background_color, incident_text_color, maintenance_background_color, maintenance_text_color):
        data = {"status_embed_config": {"incident_background_color": incident_background_color, "incident_text_color": incident_text_color,
                                        "maintenance_background_color": maintenance_background_color, "maintenance_text_color": maintenance_text_color, "position": position}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('PUT', f'pages/{page_id}/status_embed_config', json_data=data, headers=headers)

        return response

    def update_a_page_request(self, page_id, name, domain, subdomain, url, branding, css_body_background_color, css_font_color, css_light_font_color, css_greens, css_yellows, css_oranges, css_reds, css_blues, css_border_color, css_graph_color, css_link_color, css_no_data, hidden_from_search, viewers_must_be_team_members, allow_page_subscribers, allow_incident_subscribers, allow_email_subscribers, allow_sms_subscribers, allow_rss_atom_feeds, allow_webhook_subscribers, notifications_from_email, time_zone, notifications_email_footer):
        data = {"page": {"allow_email_subscribers": allow_email_subscribers, "allow_incident_subscribers": allow_incident_subscribers, "allow_page_subscribers": allow_page_subscribers, "allow_rss_atom_feeds": allow_rss_atom_feeds, "allow_sms_subscribers": allow_sms_subscribers, "allow_webhook_subscribers": allow_webhook_subscribers, "branding": branding, "css_blues": css_blues, "css_body_background_color": css_body_background_color, "css_border_color": css_border_color, "css_font_color": css_font_color, "css_graph_color": css_graph_color,
                         "css_greens": css_greens, "css_light_font_color": css_light_font_color, "css_link_color": css_link_color, "css_no_data": css_no_data, "css_oranges": css_oranges, "css_reds": css_reds, "css_yellows": css_yellows, "domain": domain, "hidden_from_search": hidden_from_search, "name": name, "notifications_email_footer": notifications_email_footer, "notifications_from_email": notifications_from_email, "subdomain": subdomain, "time_zone": time_zone, "url": url, "viewers_must_be_team_members": viewers_must_be_team_members}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('PATCH', f'pages/{page_id}', json_data=data, headers=headers)

        return response

    def update_a_page_request(self, page_id, name, domain, subdomain, url, branding, css_body_background_color, css_font_color, css_light_font_color, css_greens, css_yellows, css_oranges, css_reds, css_blues, css_border_color, css_graph_color, css_link_color, css_no_data, hidden_from_search, viewers_must_be_team_members, allow_page_subscribers, allow_incident_subscribers, allow_email_subscribers, allow_sms_subscribers, allow_rss_atom_feeds, allow_webhook_subscribers, notifications_from_email, time_zone, notifications_email_footer):
        data = {"page": {"allow_email_subscribers": allow_email_subscribers, "allow_incident_subscribers": allow_incident_subscribers, "allow_page_subscribers": allow_page_subscribers, "allow_rss_atom_feeds": allow_rss_atom_feeds, "allow_sms_subscribers": allow_sms_subscribers, "allow_webhook_subscribers": allow_webhook_subscribers, "branding": branding, "css_blues": css_blues, "css_body_background_color": css_body_background_color, "css_border_color": css_border_color, "css_font_color": css_font_color, "css_graph_color": css_graph_color,
                         "css_greens": css_greens, "css_light_font_color": css_light_font_color, "css_link_color": css_link_color, "css_no_data": css_no_data, "css_oranges": css_oranges, "css_reds": css_reds, "css_yellows": css_yellows, "domain": domain, "hidden_from_search": hidden_from_search, "name": name, "notifications_email_footer": notifications_email_footer, "notifications_from_email": notifications_from_email, "subdomain": subdomain, "time_zone": time_zone, "url": url, "viewers_must_be_team_members": viewers_must_be_team_members}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('PUT', f'pages/{page_id}', json_data=data, headers=headers)

        return response

    def get_a_page_request(self, page_id):
        headers = self._headers

        response = self._http_request('GET', f'pages/{page_id}', headers=headers)

        return response

    def get_a_list_of_pages_request(self):
        headers = self._headers

        response = self._http_request('GET', 'pages', headers=headers)

        return response

    def create_a_user_request(self, organization_id, email, password, first_name, last_name):
        data = {"user": {"email": email, "first_name": first_name, "last_name": last_name, "password": password}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', f'organizations/{organization_id}/users', json_data=data, headers=headers)

        return response

    def get_a_list_of_users_request(self, organization_id):
        headers = self._headers

        response = self._http_request('GET', f'organizations/{organization_id}/users', headers=headers)

        return response

    def delete_a_user_request(self, organization_id, user_id):
        headers = self._headers

        response = self._http_request('DELETE', f'organizations/{organization_id}/users/{user_id}', headers=headers)

        return response


def add_components_for_page_access_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_user_id = args.get('page_access_user_id')
    component_ids = args.get('component_ids')

    response = client.add_components_for_page_access_user_request(page_id, page_access_user_id, component_ids)
    command_results = CommandResults(
        outputs_prefix='Statuspage.AddComponentsForPageAccessUser',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def replace_components_for_page_access_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_user_id = args.get('page_access_user_id')
    component_ids = args.get('component_ids')

    response = client.replace_components_for_page_access_user_request(page_id, page_access_user_id, component_ids)
    command_results = CommandResults(
        outputs_prefix='Statuspage.ReplaceComponentsForPageAccessUser',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def remove_components_for_page_access_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_user_id = args.get('page_access_user_id')
    component_ids = args.get('component_ids')

    response = client.remove_components_for_page_access_user_request(page_id, page_access_user_id, component_ids)
    command_results = CommandResults(
        outputs_prefix='Statuspage.RemoveComponentsForPageAccessUser',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_components_for_page_access_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_user_id = args.get('page_access_user_id')

    response = client.get_components_for_page_access_user_request(page_id, page_access_user_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetComponentsForPageAccessUser',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def remove_component_for_page_access_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_user_id = args.get('page_access_user_id')
    component_id = args.get('component_id')

    response = client.remove_component_for_page_access_user_request(page_id, page_access_user_id, component_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.RemoveComponentForPageAccessUser',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def add_metrics_for_page_access_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_user_id = args.get('page_access_user_id')
    metric_ids = args.get('metric_ids')

    response = client.add_metrics_for_page_access_user_request(page_id, page_access_user_id, metric_ids)
    command_results = CommandResults(
        outputs_prefix='Statuspage.AddMetricsForPageAccessUser',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def replace_metrics_for_page_access_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_user_id = args.get('page_access_user_id')
    metric_ids = args.get('metric_ids')

    response = client.replace_metrics_for_page_access_user_request(page_id, page_access_user_id, metric_ids)
    command_results = CommandResults(
        outputs_prefix='Statuspage.ReplaceMetricsForPageAccessUser',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_metrics_for_page_access_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_user_id = args.get('page_access_user_id')
    metric_ids = args.get('metric_ids')

    response = client.delete_metrics_for_page_access_user_request(page_id, page_access_user_id, metric_ids)
    command_results = CommandResults(
        outputs_prefix='Statuspage.DeleteMetricsForPageAccessUser',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_metrics_for_page_access_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_user_id = args.get('page_access_user_id')

    response = client.get_metrics_for_page_access_user_request(page_id, page_access_user_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetMetricsForPageAccessUser',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_metric_for_page_access_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_user_id = args.get('page_access_user_id')
    metric_id = args.get('metric_id')

    response = client.delete_metric_for_page_access_user_request(page_id, page_access_user_id, metric_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.DeleteMetricForPageAccessUser',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_page_access_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_user_id = args.get('page_access_user_id')

    response = client.update_page_access_user_request(page_id, page_access_user_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.UpdatePageAccessUser',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_page_access_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_user_id = args.get('page_access_user_id')

    response = client.delete_page_access_user_request(page_id, page_access_user_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.DeletePageAccessUser',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_page_access_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_user_id = args.get('page_access_user_id')

    response = client.get_page_access_user_request(page_id, page_access_user_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetPageAccessUser',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def add_a_page_access_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    external_login = args.get('external_login')
    email = args.get('email')
    page_access_group_ids = args.get('page_access_group_ids')
    subscribe_to_components = args.get('subscribe_to_components')

    response = client.add_a_page_access_user_request(
        page_id, external_login, email, page_access_group_ids, subscribe_to_components)
    command_results = CommandResults(
        outputs_prefix='Statuspage.AddAPageAccessUser',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_page_access_users_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    email = args.get('email')
    page = args.get('page')
    per_page = args.get('per_page')

    response = client.get_a_list_of_page_access_users_request(page_id, email, page, per_page)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAListOfPageAccessUsers',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def add_components_to_page_access_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_group_id = args.get('page_access_group_id')
    component_ids = args.get('component_ids')

    response = client.add_components_to_page_access_group_request(page_id, page_access_group_id, component_ids)
    command_results = CommandResults(
        outputs_prefix='Statuspage.AddComponentsToPageAccessGroup',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def replace_components_for_a_page_access_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_group_id = args.get('page_access_group_id')
    component_ids = args.get('component_ids')

    response = client.replace_components_for_a_page_access_group_request(page_id, page_access_group_id, component_ids)
    command_results = CommandResults(
        outputs_prefix='Statuspage.ReplaceComponentsForAPageAccessGroup',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_components_for_a_page_access_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_group_id = args.get('page_access_group_id')
    component_ids = args.get('component_ids')

    response = client.delete_components_for_a_page_access_group_request(page_id, page_access_group_id, component_ids)
    command_results = CommandResults(
        outputs_prefix='Statuspage.DeleteComponentsForAPageAccessGroup',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def list_components_for_a_page_access_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_group_id = args.get('page_access_group_id')

    response = client.list_components_for_a_page_access_group_request(page_id, page_access_group_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.ListComponentsForAPageAccessGroup',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def remove_a_component_from_a_page_access_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_group_id = args.get('page_access_group_id')
    component_id = args.get('component_id')

    response = client.remove_a_component_from_a_page_access_group_request(page_id, page_access_group_id, component_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.RemoveAComponentFromAPageAccessGroup',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_page_access_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_group_id = args.get('page_access_group_id')

    response = client.get_a_page_access_group_request(page_id, page_access_group_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAPageAccessGroup',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_a_page_access_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_group_id = args.get('page_access_group_id')
    name = args.get('name')
    external_identifier = args.get('external_identifier')
    component_ids = args.get('component_ids')
    metric_ids = args.get('metric_ids')
    page_access_user_ids = args.get('page_access_user_ids')

    response = client.update_a_page_access_group_request(
        page_id, page_access_group_id, name, external_identifier, component_ids, metric_ids, page_access_user_ids)
    command_results = CommandResults(
        outputs_prefix='Statuspage.UpdateAPageAccessGroup',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def remove_a_page_access_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page_access_group_id = args.get('page_access_group_id')

    response = client.remove_a_page_access_group_request(page_id, page_access_group_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.RemoveAPageAccessGroup',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_page_access_groups_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')

    response = client.get_a_list_of_page_access_groups_request(page_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAListOfPageAccessGroups',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_a_page_access_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    name = args.get('name')
    external_identifier = args.get('external_identifier')
    component_ids = args.get('component_ids')
    metric_ids = args.get('metric_ids')
    page_access_user_ids = args.get('page_access_user_ids')

    response = client.create_a_page_access_group_request(
        page_id, name, external_identifier, component_ids, metric_ids, page_access_user_ids)
    command_results = CommandResults(
        outputs_prefix='Statuspage.CreateAPageAccessGroup',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def unsubscribe_a_subscriber_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    subscriber_id = args.get('subscriber_id')
    skip_unsubscription_notification = args.get('skip_unsubscription_notification')

    response = client.unsubscribe_a_subscriber_request(page_id, subscriber_id, skip_unsubscription_notification)
    command_results = CommandResults(
        outputs_prefix='Statuspage.UnsubscribeASubscriber',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_a_subscriber_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    subscriber_id = args.get('subscriber_id')
    component_ids = args.get('component_ids')

    response = client.update_a_subscriber_request(page_id, subscriber_id, component_ids)
    command_results = CommandResults(
        outputs_prefix='Statuspage.UpdateASubscriber',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_subscriber_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    subscriber_id = args.get('subscriber_id')

    response = client.get_a_subscriber_request(page_id, subscriber_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetASubscriber',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def resend_confirmation_to_a_subscriber_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    subscriber_id = args.get('subscriber_id')

    response = client.resend_confirmation_to_a_subscriber_request(page_id, subscriber_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.ResendConfirmationToASubscriber',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_a_subscriber_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    email = args.get('email')
    endpoint = args.get('endpoint')
    phone_country = args.get('phone_country')
    phone_number = args.get('phone_number')
    skip_confirmation_notification = args.get('skip_confirmation_notification')
    page_access_user = args.get('page_access_user')
    component_ids = args.get('component_ids')

    response = client.create_a_subscriber_request(
        page_id, email, endpoint, phone_country, phone_number, skip_confirmation_notification, page_access_user, component_ids)
    command_results = CommandResults(
        outputs_prefix='Statuspage.CreateASubscriber',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_subscribers_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    q = args.get('q')
    type_ = args.get('type')
    state = args.get('state')
    limit = args.get('limit')
    page = args.get('page')
    sort_field = args.get('sort_field')
    sort_direction = args.get('sort_direction')

    response = client.get_a_list_of_subscribers_request(
        page_id, q, type_, state, limit, page, sort_field, sort_direction)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAListOfSubscribers',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def resend_confirmations_to_a_list_of_subscribers_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    subscribers = args.get('subscribers')

    response = client.resend_confirmations_to_a_list_of_subscribers_request(page_id, subscribers)
    command_results = CommandResults(
        outputs_prefix='Statuspage.ResendConfirmationsToAListOfSubscribers',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def unsubscribe_a_list_of_subscribers_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    subscribers = args.get('subscribers')
    type_ = args.get('type')
    state = args.get('state')
    skip_unsubscription_notification = args.get('skip_unsubscription_notification')

    response = client.unsubscribe_a_list_of_subscribers_request(
        page_id, subscribers, type_, state, skip_unsubscription_notification)
    command_results = CommandResults(
        outputs_prefix='Statuspage.UnsubscribeAListOfSubscribers',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def reactivate_a_list_of_subscribers_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    subscribers = args.get('subscribers')
    type_ = args.get('type')

    response = client.reactivate_a_list_of_subscribers_request(page_id, subscribers, type_)
    command_results = CommandResults(
        outputs_prefix='Statuspage.ReactivateAListOfSubscribers',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_histogram_of_subscribers_by_type_and_then_state_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')

    response = client.get_a_histogram_of_subscribers_by_type_and_then_state_request(page_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAHistogramOfSubscribersByTypeAndThenState',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_count_of_subscribers_by_type_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    type_ = args.get('type')
    state = args.get('state')

    response = client.get_a_count_of_subscribers_by_type_request(page_id, type_, state)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetACountOfSubscribersByType',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_unsubscribed_subscribers_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')

    response = client.get_a_list_of_unsubscribed_subscribers_request(page_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAListOfUnsubscribedSubscribers',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_a_template_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    name = args.get('name')
    title = args.get('title')
    body = args.get('body')
    group_id = args.get('group_id')
    update_status = args.get('update_status')
    should_tweet = args.get('should_tweet')
    should_send_notifications = args.get('should_send_notifications')
    component_ids = args.get('component_ids')

    response = client.create_a_template_request(
        page_id, name, title, body, group_id, update_status, should_tweet, should_send_notifications, component_ids)
    command_results = CommandResults(
        outputs_prefix='Statuspage.CreateATemplate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_templates_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page = args.get('page')
    per_page = args.get('per_page')

    response = client.get_a_list_of_templates_request(page_id, page, per_page)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAListOfTemplates',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_a_previous_incident_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    incident_id = args.get('incident_id')
    incident_update_id = args.get('incident_update_id')
    wants_twitter_update = args.get('wants_twitter_update')
    body = args.get('body')
    display_at = args.get('display_at')
    deliver_notifications = args.get('deliver_notifications')

    response = client.update_a_previous_incident_update_request(
        page_id, incident_id, incident_update_id, wants_twitter_update, body, display_at, deliver_notifications)
    command_results = CommandResults(
        outputs_prefix='Statuspage.UpdateAPreviousIncidentUpdate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def unsubscribe_an_incident_subscriber_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    incident_id = args.get('incident_id')
    subscriber_id = args.get('subscriber_id')

    response = client.unsubscribe_an_incident_subscriber_request(page_id, incident_id, subscriber_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.UnsubscribeAnIncidentSubscriber',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_an_incident_subscriber_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    incident_id = args.get('incident_id')
    subscriber_id = args.get('subscriber_id')

    response = client.get_an_incident_subscriber_request(page_id, incident_id, subscriber_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAnIncidentSubscriber',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def resend_confirmation_to_an_incident_subscriber_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    incident_id = args.get('incident_id')
    subscriber_id = args.get('subscriber_id')

    response = client.resend_confirmation_to_an_incident_subscriber_request(page_id, incident_id, subscriber_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.ResendConfirmationToAnIncidentSubscriber',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_an_incident_subscriber_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    incident_id = args.get('incident_id')
    email = args.get('email')
    phone_country = args.get('phone_country')
    phone_number = args.get('phone_number')
    skip_confirmation_notification = args.get('skip_confirmation_notification')

    response = client.create_an_incident_subscriber_request(
        page_id, incident_id, email, phone_country, phone_number, skip_confirmation_notification)
    command_results = CommandResults(
        outputs_prefix='Statuspage.CreateAnIncidentSubscriber',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_incident_subscribers_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    incident_id = args.get('incident_id')

    response = client.get_a_list_of_incident_subscribers_request(page_id, incident_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAListOfIncidentSubscribers',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_postmortem_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    incident_id = args.get('incident_id')

    response = client.get_postmortem_request(page_id, incident_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetPostmortem',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_postmortem_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    incident_id = args.get('incident_id')
    body_draft = args.get('body_draft')

    response = client.create_postmortem_request(page_id, incident_id, body_draft)
    command_results = CommandResults(
        outputs_prefix='Statuspage.CreatePostmortem',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_postmortem_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    incident_id = args.get('incident_id')

    response = client.delete_postmortem_request(page_id, incident_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.DeletePostmortem',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def publish_postmortem_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    incident_id = args.get('incident_id')
    notify_twitter = args.get('notify_twitter')
    notify_subscribers = args.get('notify_subscribers')
    custom_tweet = args.get('custom_tweet')

    response = client.publish_postmortem_request(page_id, incident_id, notify_twitter, notify_subscribers, custom_tweet)
    command_results = CommandResults(
        outputs_prefix='Statuspage.PublishPostmortem',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def revert_postmortem_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    incident_id = args.get('incident_id')

    response = client.revert_postmortem_request(page_id, incident_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.RevertPostmortem',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_an_incident_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    incident_id = args.get('incident_id')

    response = client.delete_an_incident_request(page_id, incident_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.DeleteAnIncident',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_an_incident_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    incident_id = args.get('incident_id')
    name = args.get('name')
    status = args.get('status')
    impact_override = args.get('impact_override')
    scheduled_for = args.get('scheduled_for')
    scheduled_until = args.get('scheduled_until')
    scheduled_remind_prior = args.get('scheduled_remind_prior')
    scheduled_auto_in_progress = args.get('scheduled_auto_in_progress')
    scheduled_auto_completed = args.get('scheduled_auto_completed')
    deliver_notifications = args.get('deliver_notifications')
    auto_transition_deliver_notifications_at_end = args.get('auto_transition_deliver_notifications_at_end')
    auto_transition_deliver_notifications_at_start = args.get('auto_transition_deliver_notifications_at_start')
    auto_transition_to_maintenance_state = args.get('auto_transition_to_maintenance_state')
    auto_transition_to_operational_state = args.get('auto_transition_to_operational_state')
    auto_tweet_at_beginning = args.get('auto_tweet_at_beginning')
    auto_tweet_on_completion = args.get('auto_tweet_on_completion')
    auto_tweet_on_creation = args.get('auto_tweet_on_creation')
    auto_tweet_one_hour_before = args.get('auto_tweet_one_hour_before')
    backfill_date = args.get('backfill_date')
    backfilled = args.get('backfilled')
    body = args.get('body')
    fl9frwst8231 = args.get('fl9frwst8231')
    component_ids = args.get('component_ids')
    scheduled_auto_transition = args.get('scheduled_auto_transition')

    response = client.update_an_incident_request(page_id, incident_id, name, status, impact_override, scheduled_for, scheduled_until, scheduled_remind_prior, scheduled_auto_in_progress, scheduled_auto_completed, deliver_notifications, auto_transition_deliver_notifications_at_end, auto_transition_deliver_notifications_at_start,
                                                 auto_transition_to_maintenance_state, auto_transition_to_operational_state, auto_tweet_at_beginning, auto_tweet_on_completion, auto_tweet_on_creation, auto_tweet_one_hour_before, backfill_date, backfilled, body, fl9frwst8231, component_ids, scheduled_auto_transition)
    command_results = CommandResults(
        outputs_prefix='Statuspage.UpdateAnIncident',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_an_incident_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    incident_id = args.get('incident_id')

    response = client.get_an_incident_request(page_id, incident_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAnIncident',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_an_incident_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    name = args.get('name')
    status = args.get('status')
    impact_override = args.get('impact_override')
    scheduled_for = args.get('scheduled_for')
    scheduled_until = args.get('scheduled_until')
    scheduled_remind_prior = args.get('scheduled_remind_prior')
    scheduled_auto_in_progress = args.get('scheduled_auto_in_progress')
    scheduled_auto_completed = args.get('scheduled_auto_completed')
    deliver_notifications = args.get('deliver_notifications')
    auto_transition_deliver_notifications_at_end = args.get('auto_transition_deliver_notifications_at_end')
    auto_transition_deliver_notifications_at_start = args.get('auto_transition_deliver_notifications_at_start')
    auto_transition_to_maintenance_state = args.get('auto_transition_to_maintenance_state')
    auto_transition_to_operational_state = args.get('auto_transition_to_operational_state')
    auto_tweet_at_beginning = args.get('auto_tweet_at_beginning')
    auto_tweet_on_completion = args.get('auto_tweet_on_completion')
    auto_tweet_on_creation = args.get('auto_tweet_on_creation')
    auto_tweet_one_hour_before = args.get('auto_tweet_one_hour_before')
    backfill_date = args.get('backfill_date')
    backfilled = args.get('backfilled')
    body = args.get('body')
    d1p30m113pht = args.get('d1p30m113pht')
    component_ids = args.get('component_ids')
    scheduled_auto_transition = args.get('scheduled_auto_transition')

    response = client.create_an_incident_request(page_id, name, status, impact_override, scheduled_for, scheduled_until, scheduled_remind_prior, scheduled_auto_in_progress, scheduled_auto_completed, deliver_notifications, auto_transition_deliver_notifications_at_end, auto_transition_deliver_notifications_at_start,
                                                 auto_transition_to_maintenance_state, auto_transition_to_operational_state, auto_tweet_at_beginning, auto_tweet_on_completion, auto_tweet_on_creation, auto_tweet_one_hour_before, backfill_date, backfilled, body, d1p30m113pht, component_ids, scheduled_auto_transition)
    command_results = CommandResults(
        outputs_prefix='Statuspage.CreateAnIncident',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_incidents_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    q = args.get('q')
    limit = args.get('limit')
    page = args.get('page')

    response = client.get_a_list_of_incidents_request(page_id, q, limit, page)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAListOfIncidents',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_active_maintenances_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page = args.get('page')
    per_page = args.get('per_page')

    response = client.get_a_list_of_active_maintenances_request(page_id, page, per_page)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAListOfActiveMaintenances',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_upcoming_incidents_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page = args.get('page')
    per_page = args.get('per_page')

    response = client.get_a_list_of_upcoming_incidents_request(page_id, page, per_page)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAListOfUpcomingIncidents',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_scheduled_incidents_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page = args.get('page')
    per_page = args.get('per_page')

    response = client.get_a_list_of_scheduled_incidents_request(page_id, page, per_page)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAListOfScheduledIncidents',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_unresolved_incidents_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page = args.get('page')
    per_page = args.get('per_page')

    response = client.get_a_list_of_unresolved_incidents_request(page_id, page, per_page)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAListOfUnresolvedIncidents',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def remove_page_access_users_from_component_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    component_id = args.get('component_id')

    response = client.remove_page_access_users_from_component_request(page_id, component_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.RemovePageAccessUsersFromComponent',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def add_page_access_users_to_a_component_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    component_id = args.get('component_id')

    response = client.add_page_access_users_to_a_component_request(page_id, component_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.AddPageAccessUsersToAComponent',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def remove_page_access_groups_from_a_component_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    component_id = args.get('component_id')

    response = client.remove_page_access_groups_from_a_component_request(page_id, component_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.RemovePageAccessGroupsFromAComponent',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def add_page_access_groups_to_a_component_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    component_id = args.get('component_id')

    response = client.add_page_access_groups_to_a_component_request(page_id, component_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.AddPageAccessGroupsToAComponent',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_a_component_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    component_id = args.get('component_id')
    description = args.get('description')
    status = args.get('status')
    name = args.get('name')
    only_show_if_degraded = args.get('only_show_if_degraded')
    group_id = args.get('group_id')
    showcase = args.get('showcase')
    start_date = args.get('start_date')

    response = client.update_a_component_request(
        page_id, component_id, description, status, name, only_show_if_degraded, group_id, showcase, start_date)
    command_results = CommandResults(
        outputs_prefix='Statuspage.UpdateAComponent',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_a_component_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    component_id = args.get('component_id')

    response = client.delete_a_component_request(page_id, component_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.DeleteAComponent',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_component_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    component_id = args.get('component_id')

    response = client.get_a_component_request(page_id, component_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAComponent',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_uptime_data_for_a_component_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    component_id = args.get('component_id')
    start = args.get('start')
    end = args.get('end')

    response = client.get_uptime_data_for_a_component_request(page_id, component_id, start, end)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetUptimeDataForAComponent',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_a_component_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    description = args.get('description')
    status = args.get('status')
    name = args.get('name')
    only_show_if_degraded = args.get('only_show_if_degraded')
    group_id = args.get('group_id')
    showcase = args.get('showcase')
    start_date = args.get('start_date')

    response = client.create_a_component_request(
        page_id, description, status, name, only_show_if_degraded, group_id, showcase, start_date)
    command_results = CommandResults(
        outputs_prefix='Statuspage.CreateAComponent',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_components_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    page = args.get('page')
    per_page = args.get('per_page')

    response = client.get_a_list_of_components_request(page_id, page, per_page)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAListOfComponents',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_a_component_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    id_ = args.get('id')
    description = args.get('description')
    components = args.get('components')
    name = args.get('name')

    response = client.update_a_component_group_request(page_id, id_, description, components, name)
    command_results = CommandResults(
        outputs_prefix='Statuspage.UpdateAComponentGroup',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_a_component_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    id_ = args.get('id')

    response = client.delete_a_component_group_request(page_id, id_)
    command_results = CommandResults(
        outputs_prefix='Statuspage.DeleteAComponentGroup',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_component_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    id_ = args.get('id')

    response = client.get_a_component_group_request(page_id, id_)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAComponentGroup',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_uptime_data_for_a_component_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    id_ = args.get('id')
    start = args.get('start')
    end = args.get('end')

    response = client.get_uptime_data_for_a_component_group_request(page_id, id_, start, end)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetUptimeDataForAComponentGroup',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_a_component_group_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    description = args.get('description')
    components = args.get('components')
    name = args.get('name')

    response = client.create_a_component_group_request(page_id, description, components, name)
    command_results = CommandResults(
        outputs_prefix='Statuspage.CreateAComponentGroup',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_component_groups_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')

    response = client.get_a_list_of_component_groups_request(page_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAListOfComponentGroups',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def reset_data_for_a_metric_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    metric_id = args.get('metric_id')

    response = client.reset_data_for_a_metric_request(page_id, metric_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.ResetDataForAMetric',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def add_data_to_a_metric_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    metric_id = args.get('metric_id')
    timestamp = args.get('timestamp')
    value = args.get('value')

    response = client.add_data_to_a_metric_request(page_id, metric_id, timestamp, value)
    command_results = CommandResults(
        outputs_prefix='Statuspage.AddDataToAMetric',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_a_metric_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    metric_id = args.get('metric_id')
    name = args.get('name')
    metric_identifier = args.get('metric_identifier')

    response = client.update_a_metric_request(page_id, metric_id, name, metric_identifier)
    command_results = CommandResults(
        outputs_prefix='Statuspage.UpdateAMetric',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_a_metric_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    metric_id = args.get('metric_id')

    response = client.delete_a_metric_request(page_id, metric_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.DeleteAMetric',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_metric_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    metric_id = args.get('metric_id')

    response = client.get_a_metric_request(page_id, metric_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAMetric',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_metrics_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')

    response = client.get_a_list_of_metrics_request(page_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAListOfMetrics',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def add_data_points_to_metrics_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    timestamp = args.get('timestamp')
    value = args.get('value')

    response = client.add_data_points_to_metrics_request(page_id, timestamp, value)
    command_results = CommandResults(
        outputs_prefix='Statuspage.AddDataPointsToMetrics',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def list_metrics_for_a_metric_provider_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    metrics_provider_id = args.get('metrics_provider_id')

    response = client.list_metrics_for_a_metric_provider_request(page_id, metrics_provider_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.ListMetricsForAMetricProvider',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_a_metric_for_a_metric_provider_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    metrics_provider_id = args.get('metrics_provider_id')
    name = args.get('name')
    metric_identifier = args.get('metric_identifier')
    transform = args.get('transform')
    suffix = args.get('suffix')
    y_axis_min = args.get('y_axis_min')
    y_axis_max = args.get('y_axis_max')
    y_axis_hidden = args.get('y_axis_hidden')
    display = args.get('display')
    decimal_places = args.get('decimal_places')
    tooltip_description = args.get('tooltip_description')

    response = client.create_a_metric_for_a_metric_provider_request(
        page_id, metrics_provider_id, name, metric_identifier, transform, suffix, y_axis_min, y_axis_max, y_axis_hidden, display, decimal_places, tooltip_description)
    command_results = CommandResults(
        outputs_prefix='Statuspage.CreateAMetricForAMetricProvider',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_metric_provider_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    metrics_provider_id = args.get('metrics_provider_id')

    response = client.get_a_metric_provider_request(page_id, metrics_provider_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAMetricProvider',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_a_metric_provider_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    metrics_provider_id = args.get('metrics_provider_id')
    type_ = args.get('type')
    metric_base_uri = args.get('metric_base_uri')

    response = client.update_a_metric_provider_request(page_id, metrics_provider_id, type_, metric_base_uri)
    command_results = CommandResults(
        outputs_prefix='Statuspage.UpdateAMetricProvider',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_a_metric_provider_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    metrics_provider_id = args.get('metrics_provider_id')

    response = client.delete_a_metric_provider_request(page_id, metrics_provider_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.DeleteAMetricProvider',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_metric_providers_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')

    response = client.get_a_list_of_metric_providers_request(page_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAListOfMetricProviders',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_a_metric_provider_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    email = args.get('email')
    password = args.get('password')
    api_key = args.get('api_key')
    api_token = args.get('api_token')
    application_key = args.get('application_key')
    type_ = args.get('type')
    metric_base_uri = args.get('metric_base_uri')

    response = client.create_a_metric_provider_request(
        page_id, email, password, api_key, api_token, application_key, type_, metric_base_uri)
    command_results = CommandResults(
        outputs_prefix='Statuspage.CreateAMetricProvider',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_status_embed_config_settings_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')

    response = client.get_status_embed_config_settings_request(page_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetStatusEmbedConfigSettings',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_status_embed_config_settings_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    position = args.get('position')
    incident_background_color = args.get('incident_background_color')
    incident_text_color = args.get('incident_text_color')
    maintenance_background_color = args.get('maintenance_background_color')
    maintenance_text_color = args.get('maintenance_text_color')

    response = client.update_status_embed_config_settings_request(
        page_id, position, incident_background_color, incident_text_color, maintenance_background_color, maintenance_text_color)
    command_results = CommandResults(
        outputs_prefix='Statuspage.UpdateStatusEmbedConfigSettings',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_a_page_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')
    name = args.get('name')
    domain = args.get('domain')
    subdomain = args.get('subdomain')
    url = args.get('url')
    branding = args.get('branding')
    css_body_background_color = args.get('css_body_background_color')
    css_font_color = args.get('css_font_color')
    css_light_font_color = args.get('css_light_font_color')
    css_greens = args.get('css_greens')
    css_yellows = args.get('css_yellows')
    css_oranges = args.get('css_oranges')
    css_reds = args.get('css_reds')
    css_blues = args.get('css_blues')
    css_border_color = args.get('css_border_color')
    css_graph_color = args.get('css_graph_color')
    css_link_color = args.get('css_link_color')
    css_no_data = args.get('css_no_data')
    hidden_from_search = args.get('hidden_from_search')
    viewers_must_be_team_members = args.get('viewers_must_be_team_members')
    allow_page_subscribers = args.get('allow_page_subscribers')
    allow_incident_subscribers = args.get('allow_incident_subscribers')
    allow_email_subscribers = args.get('allow_email_subscribers')
    allow_sms_subscribers = args.get('allow_sms_subscribers')
    allow_rss_atom_feeds = args.get('allow_rss_atom_feeds')
    allow_webhook_subscribers = args.get('allow_webhook_subscribers')
    notifications_from_email = args.get('notifications_from_email')
    time_zone = args.get('time_zone')
    notifications_email_footer = args.get('notifications_email_footer')

    response = client.update_a_page_request(page_id, name, domain, subdomain, url, branding, css_body_background_color, css_font_color, css_light_font_color, css_greens, css_yellows, css_oranges, css_reds, css_blues, css_border_color, css_graph_color, css_link_color, css_no_data,
                                            hidden_from_search, viewers_must_be_team_members, allow_page_subscribers, allow_incident_subscribers, allow_email_subscribers, allow_sms_subscribers, allow_rss_atom_feeds, allow_webhook_subscribers, notifications_from_email, time_zone, notifications_email_footer)
    command_results = CommandResults(
        outputs_prefix='Statuspage.UpdateAPage',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_page_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page_id = args.get('page_id')

    response = client.get_a_page_request(page_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAPage',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_pages_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    response = client.get_a_list_of_pages_request()
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAListOfPages',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_a_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_id = args.get('organization_id')
    email = args.get('email')
    password = args.get('password')
    first_name = args.get('first_name')
    last_name = args.get('last_name')

    response = client.create_a_user_request(organization_id, email, password, first_name, last_name)
    command_results = CommandResults(
        outputs_prefix='Statuspage.CreateAUser',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_users_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_id = args.get('organization_id')

    response = client.get_a_list_of_users_request(organization_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.GetAListOfUsers',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_a_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_id = args.get('organization_id')
    user_id = args.get('user_id')

    response = client.delete_a_user_request(organization_id, user_id)
    command_results = CommandResults(
        outputs_prefix='Statuspage.DeleteAUser',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client: Client) -> None:
    # Test functions here
    return_results('ok')


def main() -> None:

    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    headers = {}
    headers['Authorization'] = params['api_key']

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=None)

        commands = {
            'statuspage-add-components-for-page-access-user': add_components_for_page_access_user_command,
            'statuspage-replace-components-for-page-access-user': replace_components_for_page_access_user_command,
            'statuspage-remove-components-for-page-access-user': remove_components_for_page_access_user_command,
            'statuspage-get-components-for-page-access-user': get_components_for_page_access_user_command,
            'statuspage-remove-component-for-page-access-user': remove_component_for_page_access_user_command,
            'statuspage-add-metrics-for-page-access-user': add_metrics_for_page_access_user_command,
            'statuspage-replace-metrics-for-page-access-user': replace_metrics_for_page_access_user_command,
            'statuspage-delete-metrics-for-page-access-user': delete_metrics_for_page_access_user_command,
            'statuspage-get-metrics-for-page-access-user': get_metrics_for_page_access_user_command,
            'statuspage-delete-metric-for-page-access-user': delete_metric_for_page_access_user_command,
            'statuspage-update-page-access-user': update_page_access_user_command,
            'statuspage-delete-page-access-user': delete_page_access_user_command,
            'statuspage-get-page-access-user': get_page_access_user_command,
            'statuspage-add-a-page-access-user': add_a_page_access_user_command,
            'statuspage-get-a-list-of-page-access-users': get_a_list_of_page_access_users_command,
            'statuspage-add-components-to-page-access-group': add_components_to_page_access_group_command,
            'statuspage-replace-components-for-a-page-access-group': replace_components_for_a_page_access_group_command,
            'statuspage-delete-components-for-a-page-access-group': delete_components_for_a_page_access_group_command,
            'statuspage-list-components-for-a-page-access-group': list_components_for_a_page_access_group_command,
            'statuspage-remove-a-component-from-a-page-access-group': remove_a_component_from_a_page_access_group_command,
            'statuspage-get-a-page-access-group': get_a_page_access_group_command,
            'statuspage-update-a-page-access-group': update_a_page_access_group_command,
            'statuspage-remove-a-page-access-group': remove_a_page_access_group_command,
            'statuspage-get-a-list-of-page-access-groups': get_a_list_of_page_access_groups_command,
            'statuspage-create-a-page-access-group': create_a_page_access_group_command,
            'statuspage-unsubscribe-a-subscriber': unsubscribe_a_subscriber_command,
            'statuspage-update-a-subscriber': update_a_subscriber_command,
            'statuspage-get-a-subscriber': get_a_subscriber_command,
            'statuspage-resend-confirmation-to-a-subscriber': resend_confirmation_to_a_subscriber_command,
            'statuspage-create-a-subscriber': create_a_subscriber_command,
            'statuspage-get-a-list-of-subscribers': get_a_list_of_subscribers_command,
            'statuspage-resend-confirmations-to-a-list-of-subscribers': resend_confirmations_to_a_list_of_subscribers_command,
            'statuspage-unsubscribe-a-list-of-subscribers': unsubscribe_a_list_of_subscribers_command,
            'statuspage-reactivate-a-list-of-subscribers': reactivate_a_list_of_subscribers_command,
            'statuspage-get-a-histogram-of-subscribers-by-type-and-then-state': get_a_histogram_of_subscribers_by_type_and_then_state_command,
            'statuspage-get-a-count-of-subscribers-by-type': get_a_count_of_subscribers_by_type_command,
            'statuspage-get-a-list-of-unsubscribed-subscribers': get_a_list_of_unsubscribed_subscribers_command,
            'statuspage-create-a-template': create_a_template_command,
            'statuspage-get-a-list-of-templates': get_a_list_of_templates_command,
            'statuspage-update-a-previous-incident-update': update_a_previous_incident_update_command,
            'statuspage-unsubscribe-an-incident-subscriber': unsubscribe_an_incident_subscriber_command,
            'statuspage-get-an-incident-subscriber': get_an_incident_subscriber_command,
            'statuspage-resend-confirmation-to-an-incident-subscriber': resend_confirmation_to_an_incident_subscriber_command,
            'statuspage-create-an-incident-subscriber': create_an_incident_subscriber_command,
            'statuspage-get-a-list-of-incident-subscribers': get_a_list_of_incident_subscribers_command,
            'statuspage-get-postmortem': get_postmortem_command,
            'statuspage-create-postmortem': create_postmortem_command,
            'statuspage-delete-postmortem': delete_postmortem_command,
            'statuspage-publish-postmortem': publish_postmortem_command,
            'statuspage-revert-postmortem': revert_postmortem_command,
            'statuspage-delete-an-incident': delete_an_incident_command,
            'statuspage-update-an-incident': update_an_incident_command,
            'statuspage-get-an-incident': get_an_incident_command,
            'statuspage-create-an-incident': create_an_incident_command,
            'statuspage-get-a-list-of-incidents': get_a_list_of_incidents_command,
            'statuspage-get-a-list-of-active-maintenances': get_a_list_of_active_maintenances_command,
            'statuspage-get-a-list-of-upcoming-incidents': get_a_list_of_upcoming_incidents_command,
            'statuspage-get-a-list-of-scheduled-incidents': get_a_list_of_scheduled_incidents_command,
            'statuspage-get-a-list-of-unresolved-incidents': get_a_list_of_unresolved_incidents_command,
            'statuspage-remove-page-access-users-from-component': remove_page_access_users_from_component_command,
            'statuspage-add-page-access-users-to-a-component': add_page_access_users_to_a_component_command,
            'statuspage-remove-page-access-groups-from-a-component': remove_page_access_groups_from_a_component_command,
            'statuspage-add-page-access-groups-to-a-component': add_page_access_groups_to_a_component_command,
            'statuspage-update-a-component': update_a_component_command,
            'statuspage-delete-a-component': delete_a_component_command,
            'statuspage-get-a-component': get_a_component_command,
            'statuspage-get-uptime-data-for-a-component': get_uptime_data_for_a_component_command,
            'statuspage-create-a-component': create_a_component_command,
            'statuspage-get-a-list-of-components': get_a_list_of_components_command,
            'statuspage-update-a-component-group': update_a_component_group_command,
            'statuspage-delete-a-component-group': delete_a_component_group_command,
            'statuspage-get-a-component-group': get_a_component_group_command,
            'statuspage-get-uptime-data-for-a-component-group': get_uptime_data_for_a_component_group_command,
            'statuspage-create-a-component-group': create_a_component_group_command,
            'statuspage-get-a-list-of-component-groups': get_a_list_of_component_groups_command,
            'statuspage-reset-data-for-a-metric': reset_data_for_a_metric_command,
            'statuspage-add-data-to-a-metric': add_data_to_a_metric_command,
            'statuspage-update-a-metric': update_a_metric_command,
            'statuspage-delete-a-metric': delete_a_metric_command,
            'statuspage-get-a-metric': get_a_metric_command,
            'statuspage-get-a-list-of-metrics': get_a_list_of_metrics_command,
            'statuspage-add-data-points-to-metrics': add_data_points_to_metrics_command,
            'statuspage-list-metrics-for-a-metric-provider': list_metrics_for_a_metric_provider_command,
            'statuspage-create-a-metric-for-a-metric-provider': create_a_metric_for_a_metric_provider_command,
            'statuspage-get-a-metric-provider': get_a_metric_provider_command,
            'statuspage-update-a-metric-provider': update_a_metric_provider_command,
            'statuspage-delete-a-metric-provider': delete_a_metric_provider_command,
            'statuspage-get-a-list-of-metric-providers': get_a_list_of_metric_providers_command,
            'statuspage-create-a-metric-provider': create_a_metric_provider_command,
            'statuspage-get-status-embed-config-settings': get_status_embed_config_settings_command,
            'statuspage-update-status-embed-config-settings': update_status_embed_config_settings_command,
            'statuspage-update-a-page': update_a_page_command,
            'statuspage-get-a-page': get_a_page_command,
            'statuspage-get-a-list-of-pages': get_a_list_of_pages_command,
            'statuspage-create-a-user': create_a_user_command,
            'statuspage-get-a-list-of-users': get_a_list_of_users_command,
            'statuspage-delete-a-user': delete_a_user_command,
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
