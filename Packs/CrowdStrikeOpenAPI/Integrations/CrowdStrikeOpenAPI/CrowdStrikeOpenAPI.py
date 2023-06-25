import demistomock as demisto
from CommonServerPython import *
import urllib3

# flake8: noqa: E501

class Client:
    def __init__(self, params: Dict):
        self.cs_client = CrowdStrikeClient(params)

    def add_role_request(self, domain_mssprolerequestv1_resources):
        data = assign_params(resources=domain_mssprolerequestv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'mssp/entities/mssp-roles/v1', json_data=data, headers=headers)

        return response

    def add_user_group_members_request(self, domain_usergroupmembersrequestv1_resources):
        data = assign_params(resources=domain_usergroupmembersrequestv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'mssp/entities/user-group-members/v1', json_data=data, headers=headers)

        return response

    def addcid_group_members_request(self, domain_cidgroupmembersrequestv1_resources):
        data = assign_params(resources=domain_cidgroupmembersrequestv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'mssp/entities/cid-group-members/v1', json_data=data, headers=headers)

        return response

    def aggregate_allow_list_request(self, msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing, msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type):
        data = assign_params(date_ranges=msa_aggregatequeryrequest_date_ranges, field=msa_aggregatequeryrequest_field, filter=msa_aggregatequeryrequest_filter, interval=msa_aggregatequeryrequest_interval, min_doc_count=msa_aggregatequeryrequest_min_doc_count, missing=msa_aggregatequeryrequest_missing,
                             name=msa_aggregatequeryrequest_name, q=msa_aggregatequeryrequest_q, ranges=msa_aggregatequeryrequest_ranges, size=msa_aggregatequeryrequest_size, sort=msa_aggregatequeryrequest_sort, sub_aggregates=msa_aggregatequeryrequest_sub_aggregates, time_zone=msa_aggregatequeryrequest_time_zone, type=msa_aggregatequeryrequest_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'falcon-complete-dashboards/aggregates/allowlist/GET/v1', json_data=data, headers=headers)

        return response

    def aggregate_block_list_request(self, msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing, msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type):
        data = assign_params(date_ranges=msa_aggregatequeryrequest_date_ranges, field=msa_aggregatequeryrequest_field, filter=msa_aggregatequeryrequest_filter, interval=msa_aggregatequeryrequest_interval, min_doc_count=msa_aggregatequeryrequest_min_doc_count, missing=msa_aggregatequeryrequest_missing,
                             name=msa_aggregatequeryrequest_name, q=msa_aggregatequeryrequest_q, ranges=msa_aggregatequeryrequest_ranges, size=msa_aggregatequeryrequest_size, sort=msa_aggregatequeryrequest_sort, sub_aggregates=msa_aggregatequeryrequest_sub_aggregates, time_zone=msa_aggregatequeryrequest_time_zone, type=msa_aggregatequeryrequest_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'falcon-complete-dashboards/aggregates/blocklist/GET/v1', json_data=data, headers=headers)

        return response

    def aggregate_detections_request(self, msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing, msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type):
        data = assign_params(date_ranges=msa_aggregatequeryrequest_date_ranges, field=msa_aggregatequeryrequest_field, filter=msa_aggregatequeryrequest_filter, interval=msa_aggregatequeryrequest_interval, min_doc_count=msa_aggregatequeryrequest_min_doc_count, missing=msa_aggregatequeryrequest_missing,
                             name=msa_aggregatequeryrequest_name, q=msa_aggregatequeryrequest_q, ranges=msa_aggregatequeryrequest_ranges, size=msa_aggregatequeryrequest_size, sort=msa_aggregatequeryrequest_sort, sub_aggregates=msa_aggregatequeryrequest_sub_aggregates, time_zone=msa_aggregatequeryrequest_time_zone, type=msa_aggregatequeryrequest_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'falcon-complete-dashboards/aggregates/detects/GET/v1', json_data=data, headers=headers)

        return response

    def aggregate_device_count_collection_request(self, msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing, msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type):
        data = assign_params(date_ranges=msa_aggregatequeryrequest_date_ranges, field=msa_aggregatequeryrequest_field, filter=msa_aggregatequeryrequest_filter, interval=msa_aggregatequeryrequest_interval, min_doc_count=msa_aggregatequeryrequest_min_doc_count, missing=msa_aggregatequeryrequest_missing,
                             name=msa_aggregatequeryrequest_name, q=msa_aggregatequeryrequest_q, ranges=msa_aggregatequeryrequest_ranges, size=msa_aggregatequeryrequest_size, sort=msa_aggregatequeryrequest_sort, sub_aggregates=msa_aggregatequeryrequest_sub_aggregates, time_zone=msa_aggregatequeryrequest_time_zone, type=msa_aggregatequeryrequest_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'falcon-complete-dashboards/aggregates/devicecount-collections/GET/v1', json_data=data, headers=headers)

        return response

    def aggregate_escalations_request(self, msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing, msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type):
        data = assign_params(date_ranges=msa_aggregatequeryrequest_date_ranges, field=msa_aggregatequeryrequest_field, filter=msa_aggregatequeryrequest_filter, interval=msa_aggregatequeryrequest_interval, min_doc_count=msa_aggregatequeryrequest_min_doc_count, missing=msa_aggregatequeryrequest_missing,
                             name=msa_aggregatequeryrequest_name, q=msa_aggregatequeryrequest_q, ranges=msa_aggregatequeryrequest_ranges, size=msa_aggregatequeryrequest_size, sort=msa_aggregatequeryrequest_sort, sub_aggregates=msa_aggregatequeryrequest_sub_aggregates, time_zone=msa_aggregatequeryrequest_time_zone, type=msa_aggregatequeryrequest_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'falcon-complete-dashboards/aggregates/escalations/GET/v1', json_data=data, headers=headers)

        return response

    def aggregate_notificationsv1_request(self, msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing, msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type):
        data = assign_params(date_ranges=msa_aggregatequeryrequest_date_ranges, field=msa_aggregatequeryrequest_field, filter=msa_aggregatequeryrequest_filter, interval=msa_aggregatequeryrequest_interval, min_doc_count=msa_aggregatequeryrequest_min_doc_count, missing=msa_aggregatequeryrequest_missing,
                             name=msa_aggregatequeryrequest_name, q=msa_aggregatequeryrequest_q, ranges=msa_aggregatequeryrequest_ranges, size=msa_aggregatequeryrequest_size, sort=msa_aggregatequeryrequest_sort, sub_aggregates=msa_aggregatequeryrequest_sub_aggregates, time_zone=msa_aggregatequeryrequest_time_zone, type=msa_aggregatequeryrequest_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'recon/aggregates/notifications/GET/v1', json_data=data, headers=headers)

        return response

    def aggregate_remediations_request(self, msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing, msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type):
        data = assign_params(date_ranges=msa_aggregatequeryrequest_date_ranges, field=msa_aggregatequeryrequest_field, filter=msa_aggregatequeryrequest_filter, interval=msa_aggregatequeryrequest_interval, min_doc_count=msa_aggregatequeryrequest_min_doc_count, missing=msa_aggregatequeryrequest_missing,
                             name=msa_aggregatequeryrequest_name, q=msa_aggregatequeryrequest_q, ranges=msa_aggregatequeryrequest_ranges, size=msa_aggregatequeryrequest_size, sort=msa_aggregatequeryrequest_sort, sub_aggregates=msa_aggregatequeryrequest_sub_aggregates, time_zone=msa_aggregatequeryrequest_time_zone, type=msa_aggregatequeryrequest_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'falcon-complete-dashboards/aggregates/remediations/GET/v1', json_data=data, headers=headers)

        return response

    def aggregateevents_request(self, fwmgr_msa_aggregatequeryrequest_date_ranges, fwmgr_msa_aggregatequeryrequest_field, fwmgr_msa_aggregatequeryrequest_filter, fwmgr_msa_aggregatequeryrequest_interval, fwmgr_msa_aggregatequeryrequest_min_doc_count, fwmgr_msa_aggregatequeryrequest_missing, fwmgr_msa_aggregatequeryrequest_name, fwmgr_msa_aggregatequeryrequest_q, fwmgr_msa_aggregatequeryrequest_ranges, fwmgr_msa_aggregatequeryrequest_size, fwmgr_msa_aggregatequeryrequest_sort, fwmgr_msa_aggregatequeryrequest_sub_aggregates, fwmgr_msa_aggregatequeryrequest_time_zone, fwmgr_msa_aggregatequeryrequest_type):
        data = assign_params(date_ranges=fwmgr_msa_aggregatequeryrequest_date_ranges, field=fwmgr_msa_aggregatequeryrequest_field, filter=fwmgr_msa_aggregatequeryrequest_filter, interval=fwmgr_msa_aggregatequeryrequest_interval, min_doc_count=fwmgr_msa_aggregatequeryrequest_min_doc_count, missing=fwmgr_msa_aggregatequeryrequest_missing, name=fwmgr_msa_aggregatequeryrequest_name,
                             q=fwmgr_msa_aggregatequeryrequest_q, ranges=fwmgr_msa_aggregatequeryrequest_ranges, size=fwmgr_msa_aggregatequeryrequest_size, sort=fwmgr_msa_aggregatequeryrequest_sort, sub_aggregates=fwmgr_msa_aggregatequeryrequest_sub_aggregates, time_zone=fwmgr_msa_aggregatequeryrequest_time_zone, type=fwmgr_msa_aggregatequeryrequest_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'fwmgr/aggregates/events/GET/v1', json_data=data, headers=headers)

        return response

    def aggregatefc_incidents_request(self, msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing, msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type):
        data = assign_params(date_ranges=msa_aggregatequeryrequest_date_ranges, field=msa_aggregatequeryrequest_field, filter=msa_aggregatequeryrequest_filter, interval=msa_aggregatequeryrequest_interval, min_doc_count=msa_aggregatequeryrequest_min_doc_count, missing=msa_aggregatequeryrequest_missing,
                             name=msa_aggregatequeryrequest_name, q=msa_aggregatequeryrequest_q, ranges=msa_aggregatequeryrequest_ranges, size=msa_aggregatequeryrequest_size, sort=msa_aggregatequeryrequest_sort, sub_aggregates=msa_aggregatequeryrequest_sub_aggregates, time_zone=msa_aggregatequeryrequest_time_zone, type=msa_aggregatequeryrequest_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'falcon-complete-dashboards/aggregates/incidents/GET/v1', json_data=data, headers=headers)

        return response

    def aggregatepolicyrules_request(self, fwmgr_msa_aggregatequeryrequest_date_ranges, fwmgr_msa_aggregatequeryrequest_field, fwmgr_msa_aggregatequeryrequest_filter, fwmgr_msa_aggregatequeryrequest_interval, fwmgr_msa_aggregatequeryrequest_min_doc_count, fwmgr_msa_aggregatequeryrequest_missing, fwmgr_msa_aggregatequeryrequest_name, fwmgr_msa_aggregatequeryrequest_q, fwmgr_msa_aggregatequeryrequest_ranges, fwmgr_msa_aggregatequeryrequest_size, fwmgr_msa_aggregatequeryrequest_sort, fwmgr_msa_aggregatequeryrequest_sub_aggregates, fwmgr_msa_aggregatequeryrequest_time_zone, fwmgr_msa_aggregatequeryrequest_type):
        data = assign_params(date_ranges=fwmgr_msa_aggregatequeryrequest_date_ranges, field=fwmgr_msa_aggregatequeryrequest_field, filter=fwmgr_msa_aggregatequeryrequest_filter, interval=fwmgr_msa_aggregatequeryrequest_interval, min_doc_count=fwmgr_msa_aggregatequeryrequest_min_doc_count, missing=fwmgr_msa_aggregatequeryrequest_missing, name=fwmgr_msa_aggregatequeryrequest_name,
                             q=fwmgr_msa_aggregatequeryrequest_q, ranges=fwmgr_msa_aggregatequeryrequest_ranges, size=fwmgr_msa_aggregatequeryrequest_size, sort=fwmgr_msa_aggregatequeryrequest_sort, sub_aggregates=fwmgr_msa_aggregatequeryrequest_sub_aggregates, time_zone=fwmgr_msa_aggregatequeryrequest_time_zone, type=fwmgr_msa_aggregatequeryrequest_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'fwmgr/aggregates/policy-rules/GET/v1', json_data=data, headers=headers)

        return response

    def aggregaterulegroups_request(self, fwmgr_msa_aggregatequeryrequest_date_ranges, fwmgr_msa_aggregatequeryrequest_field, fwmgr_msa_aggregatequeryrequest_filter, fwmgr_msa_aggregatequeryrequest_interval, fwmgr_msa_aggregatequeryrequest_min_doc_count, fwmgr_msa_aggregatequeryrequest_missing, fwmgr_msa_aggregatequeryrequest_name, fwmgr_msa_aggregatequeryrequest_q, fwmgr_msa_aggregatequeryrequest_ranges, fwmgr_msa_aggregatequeryrequest_size, fwmgr_msa_aggregatequeryrequest_sort, fwmgr_msa_aggregatequeryrequest_sub_aggregates, fwmgr_msa_aggregatequeryrequest_time_zone, fwmgr_msa_aggregatequeryrequest_type):
        data = assign_params(date_ranges=fwmgr_msa_aggregatequeryrequest_date_ranges, field=fwmgr_msa_aggregatequeryrequest_field, filter=fwmgr_msa_aggregatequeryrequest_filter, interval=fwmgr_msa_aggregatequeryrequest_interval, min_doc_count=fwmgr_msa_aggregatequeryrequest_min_doc_count, missing=fwmgr_msa_aggregatequeryrequest_missing, name=fwmgr_msa_aggregatequeryrequest_name,
                             q=fwmgr_msa_aggregatequeryrequest_q, ranges=fwmgr_msa_aggregatequeryrequest_ranges, size=fwmgr_msa_aggregatequeryrequest_size, sort=fwmgr_msa_aggregatequeryrequest_sort, sub_aggregates=fwmgr_msa_aggregatequeryrequest_sub_aggregates, time_zone=fwmgr_msa_aggregatequeryrequest_time_zone, type=fwmgr_msa_aggregatequeryrequest_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'fwmgr/aggregates/rule-groups/GET/v1', json_data=data, headers=headers)

        return response

    def aggregaterules_request(self, fwmgr_msa_aggregatequeryrequest_date_ranges, fwmgr_msa_aggregatequeryrequest_field, fwmgr_msa_aggregatequeryrequest_filter, fwmgr_msa_aggregatequeryrequest_interval, fwmgr_msa_aggregatequeryrequest_min_doc_count, fwmgr_msa_aggregatequeryrequest_missing, fwmgr_msa_aggregatequeryrequest_name, fwmgr_msa_aggregatequeryrequest_q, fwmgr_msa_aggregatequeryrequest_ranges, fwmgr_msa_aggregatequeryrequest_size, fwmgr_msa_aggregatequeryrequest_sort, fwmgr_msa_aggregatequeryrequest_sub_aggregates, fwmgr_msa_aggregatequeryrequest_time_zone, fwmgr_msa_aggregatequeryrequest_type):
        data = assign_params(date_ranges=fwmgr_msa_aggregatequeryrequest_date_ranges, field=fwmgr_msa_aggregatequeryrequest_field, filter=fwmgr_msa_aggregatequeryrequest_filter, interval=fwmgr_msa_aggregatequeryrequest_interval, min_doc_count=fwmgr_msa_aggregatequeryrequest_min_doc_count, missing=fwmgr_msa_aggregatequeryrequest_missing, name=fwmgr_msa_aggregatequeryrequest_name,
                             q=fwmgr_msa_aggregatequeryrequest_q, ranges=fwmgr_msa_aggregatequeryrequest_ranges, size=fwmgr_msa_aggregatequeryrequest_size, sort=fwmgr_msa_aggregatequeryrequest_sort, sub_aggregates=fwmgr_msa_aggregatequeryrequest_sub_aggregates, time_zone=fwmgr_msa_aggregatequeryrequest_time_zone, type=fwmgr_msa_aggregatequeryrequest_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'fwmgr/aggregates/rules/GET/v1', json_data=data, headers=headers)

        return response

    def aggregates_detections_global_counts_request(self, filter_):
        params = assign_params(filter=filter_)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'overwatch-dashboards/aggregates/detections-global-counts/v1', params=params, headers=headers)

        return response

    def aggregates_events_request(self, msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing, msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type):
        data = assign_params(date_ranges=msa_aggregatequeryrequest_date_ranges, field=msa_aggregatequeryrequest_field, filter=msa_aggregatequeryrequest_filter, interval=msa_aggregatequeryrequest_interval, min_doc_count=msa_aggregatequeryrequest_min_doc_count, missing=msa_aggregatequeryrequest_missing,
                             name=msa_aggregatequeryrequest_name, q=msa_aggregatequeryrequest_q, ranges=msa_aggregatequeryrequest_ranges, size=msa_aggregatequeryrequest_size, sort=msa_aggregatequeryrequest_sort, sub_aggregates=msa_aggregatequeryrequest_sub_aggregates, time_zone=msa_aggregatequeryrequest_time_zone, type=msa_aggregatequeryrequest_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'overwatch-dashboards/aggregates/events/GET/v1', json_data=data, headers=headers)

        return response

    def aggregates_events_collections_request(self, msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing, msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type):
        data = assign_params(date_ranges=msa_aggregatequeryrequest_date_ranges, field=msa_aggregatequeryrequest_field, filter=msa_aggregatequeryrequest_filter, interval=msa_aggregatequeryrequest_interval, min_doc_count=msa_aggregatequeryrequest_min_doc_count, missing=msa_aggregatequeryrequest_missing,
                             name=msa_aggregatequeryrequest_name, q=msa_aggregatequeryrequest_q, ranges=msa_aggregatequeryrequest_ranges, size=msa_aggregatequeryrequest_size, sort=msa_aggregatequeryrequest_sort, sub_aggregates=msa_aggregatequeryrequest_sub_aggregates, time_zone=msa_aggregatequeryrequest_time_zone, type=msa_aggregatequeryrequest_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'overwatch-dashboards/aggregates/events-collections/GET/v1', json_data=data, headers=headers)

        return response

    def aggregates_incidents_global_counts_request(self, filter_):
        params = assign_params(filter=filter_)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'overwatch-dashboards/aggregates/incidents-global-counts/v1', params=params, headers=headers)

        return response

    def aggregatesow_events_global_counts_request(self, filter_):
        params = assign_params(filter=filter_)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'overwatch-dashboards/aggregates/ow-events-global-counts/v1', params=params, headers=headers)

        return response

    def apipreemptproxypostgraphql_request(self, ):

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'identity-protection/combined/graphql/v1', headers=headers)

        return response

    def auditeventsquery_request(self, offset, limit, sort, filter_):
        params = assign_params(offset=offset, limit=limit, sort=sort, filter=filter_)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'installation-tokens/queries/audit-events/v1', params=params, headers=headers)

        return response

    def auditeventsread_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'installation-tokens/entities/audit-events/v1', params=params, headers=headers)

        return response

    def batch_active_responder_cmd_request(self, timeout, timeout_duration, domain_batchexecutecommandrequest_base_command, domain_batchexecutecommandrequest_batch_id, domain_batchexecutecommandrequest_command_string, domain_batchexecutecommandrequest_optional_hosts, domain_batchexecutecommandrequest_persist_all):
        params = assign_params(timeout=timeout, timeout_duration=timeout_duration)
        data = assign_params(base_command=domain_batchexecutecommandrequest_base_command, batch_id=domain_batchexecutecommandrequest_batch_id,
                             command_string=domain_batchexecutecommandrequest_command_string, optional_hosts=domain_batchexecutecommandrequest_optional_hosts, persist_all=domain_batchexecutecommandrequest_persist_all)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'real-time-response/combined/batch-active-responder-command/v1', params=params, json_data=data, headers=headers)

        return response

    def batch_admin_cmd_request(self, timeout, timeout_duration, domain_batchexecutecommandrequest_base_command, domain_batchexecutecommandrequest_batch_id, domain_batchexecutecommandrequest_command_string, domain_batchexecutecommandrequest_optional_hosts, domain_batchexecutecommandrequest_persist_all):
        params = assign_params(timeout=timeout, timeout_duration=timeout_duration)
        data = assign_params(base_command=domain_batchexecutecommandrequest_base_command, batch_id=domain_batchexecutecommandrequest_batch_id,
                             command_string=domain_batchexecutecommandrequest_command_string, optional_hosts=domain_batchexecutecommandrequest_optional_hosts, persist_all=domain_batchexecutecommandrequest_persist_all)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'real-time-response/combined/batch-admin-command/v1', params=params, json_data=data, headers=headers)

        return response

    def batch_cmd_request(self, timeout, timeout_duration, domain_batchexecutecommandrequest_base_command, domain_batchexecutecommandrequest_batch_id, domain_batchexecutecommandrequest_command_string, domain_batchexecutecommandrequest_optional_hosts, domain_batchexecutecommandrequest_persist_all):
        params = assign_params(timeout=timeout, timeout_duration=timeout_duration)
        data = assign_params(base_command=domain_batchexecutecommandrequest_base_command, batch_id=domain_batchexecutecommandrequest_batch_id,
                             command_string=domain_batchexecutecommandrequest_command_string, optional_hosts=domain_batchexecutecommandrequest_optional_hosts, persist_all=domain_batchexecutecommandrequest_persist_all)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'real-time-response/combined/batch-command/v1', params=params, json_data=data, headers=headers)

        return response

    def batch_get_cmd_request(self, timeout, timeout_duration, domain_batchgetcommandrequest_batch_id, domain_batchgetcommandrequest_file_path, domain_batchgetcommandrequest_optional_hosts):
        params = assign_params(timeout=timeout, timeout_duration=timeout_duration)
        data = assign_params(batch_id=domain_batchgetcommandrequest_batch_id,
                             file_path=domain_batchgetcommandrequest_file_path, optional_hosts=domain_batchgetcommandrequest_optional_hosts)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'real-time-response/combined/batch-get-command/v1', params=params, json_data=data, headers=headers)

        return response

    def batch_get_cmd_status_request(self, timeout, timeout_duration, batch_get_cmd_req_id):
        params = assign_params(timeout=timeout, timeout_duration=timeout_duration, batch_get_cmd_req_id=batch_get_cmd_req_id)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'real-time-response/combined/batch-get-command/v1', params=params, headers=headers)

        return response

    def batch_init_sessions_request(self, timeout, timeout_duration, domain_batchinitsessionrequest_existing_batch_id, domain_batchinitsessionrequest_host_ids, domain_batchinitsessionrequest_queue_offline):
        params = assign_params(timeout=timeout, timeout_duration=timeout_duration)
        data = assign_params(existing_batch_id=domain_batchinitsessionrequest_existing_batch_id,
                             host_ids=domain_batchinitsessionrequest_host_ids, queue_offline=domain_batchinitsessionrequest_queue_offline)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'real-time-response/combined/batch-init-session/v1', params=params, json_data=data, headers=headers)

        return response

    def batch_refresh_sessions_request(self, timeout, timeout_duration, domain_batchrefreshsessionrequest_batch_id, domain_batchrefreshsessionrequest_hosts_to_remove):
        params = assign_params(timeout=timeout, timeout_duration=timeout_duration)
        data = assign_params(batch_id=domain_batchrefreshsessionrequest_batch_id,
                             hosts_to_remove=domain_batchrefreshsessionrequest_hosts_to_remove)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'real-time-response/combined/batch-refresh-session/v1', params=params, json_data=data, headers=headers)

        return response

    def create_actionsv1_request(self, domain_registeractionsrequest_actions, domain_registeractionsrequest_rule_id):
        data = assign_params(actions=domain_registeractionsrequest_actions, rule_id=domain_registeractionsrequest_rule_id)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'recon/entities/actions/v1', json_data=data, headers=headers)

        return response

    def create_device_control_policies_request(self, requests_createdevicecontrolpoliciesv1_resources):
        data = assign_params(resources=requests_createdevicecontrolpoliciesv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'policy/entities/device-control/v1', json_data=data, headers=headers)

        return response

    def create_firewall_policies_request(self, requests_createfirewallpoliciesv1_resources, clone_id):
        params = assign_params(clone_id=clone_id)
        data = assign_params(resources=requests_createfirewallpoliciesv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'policy/entities/firewall/v1',
                                               params=params, json_data=data, headers=headers)

        return response

    def create_host_groups_request(self, requests_creategroupsv1_resources):
        data = assign_params(resources=requests_creategroupsv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'devices/entities/host-groups/v1', json_data=data, headers=headers)

        return response

    def create_or_updateaws_settings_request(self, models_modifyawscustomersettingsv1_resources):
        data = assign_params(resources=models_modifyawscustomersettingsv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'cloud-connect-aws/entities/settings/v1', json_data=data, headers=headers)

        return response

    def create_prevention_policies_request(self, requests_createpreventionpoliciesv1_resources):
        data = assign_params(resources=requests_createpreventionpoliciesv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'policy/entities/prevention/v1', json_data=data, headers=headers)

        return response

    def create_rulesv1_request(self, sadomain_createrulerequestv1_filter, sadomain_createrulerequestv1_name, sadomain_createrulerequestv1_permissions, sadomain_createrulerequestv1_priority, sadomain_createrulerequestv1_topic):
        data = assign_params(filter=sadomain_createrulerequestv1_filter, name=sadomain_createrulerequestv1_name,
                             permissions=sadomain_createrulerequestv1_permissions, priority=sadomain_createrulerequestv1_priority, topic=sadomain_createrulerequestv1_topic)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'recon/entities/rules/v1', json_data=data, headers=headers)

        return response

    def create_sensor_update_policies_request(self, requests_createsensorupdatepoliciesv1_resources):
        data = assign_params(resources=requests_createsensorupdatepoliciesv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'policy/entities/sensor-update/v1', json_data=data, headers=headers)

        return response

    def create_sensor_update_policiesv2_request(self, requests_createsensorupdatepoliciesv2_resources):
        data = assign_params(resources=requests_createsensorupdatepoliciesv2_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'policy/entities/sensor-update/v2', json_data=data, headers=headers)

        return response

    def create_user_request(self, domain_usercreaterequest_firstname, domain_usercreaterequest_lastname, domain_usercreaterequest_password, domain_usercreaterequest_uid):
        data = assign_params(firstName=domain_usercreaterequest_firstname, lastName=domain_usercreaterequest_lastname,
                             password=domain_usercreaterequest_password, uid=domain_usercreaterequest_uid)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'users/entities/users/v1', json_data=data, headers=headers)

        return response

    def create_user_groups_request(self, domain_usergroupsrequestv1_resources):
        data = assign_params(resources=domain_usergroupsrequestv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'mssp/entities/user-groups/v1', json_data=data, headers=headers)

        return response

    def createaws_account_request(self, k8sreg_createawsaccreq_resources):
        data = assign_params(resources=k8sreg_createawsaccreq_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'kubernetes-protection/entities/accounts/aws/v1', json_data=data, headers=headers)

        return response

    def createcid_groups_request(self, domain_cidgroupsrequestv1_resources):
        data = assign_params(resources=domain_cidgroupsrequestv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'mssp/entities/cid-groups/v1', json_data=data, headers=headers)

        return response

    def createcspm_aws_account_request(self, registration_awsaccountcreaterequestextv2_resources):
        data = assign_params(resources=registration_awsaccountcreaterequestextv2_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'cloud-connect-cspm-aws/entities/account/v1', json_data=data, headers=headers)

        return response

    def createcspmgcp_account_request(self, registration_gcpaccountcreaterequestextv1_resources):
        data = assign_params(resources=registration_gcpaccountcreaterequestextv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'cloud-connect-gcp/entities/account/v1', json_data=data, headers=headers)

        return response

    def createioc_request(self, api_iocviewrecord_batch_id, api_iocviewrecord_created_by, api_iocviewrecord_created_timestamp, api_iocviewrecord_description, api_iocviewrecord_expiration_days, api_iocviewrecord_expiration_timestamp, api_iocviewrecord_modified_by, api_iocviewrecord_modified_timestamp, api_iocviewrecord_policy, api_iocviewrecord_share_level, api_iocviewrecord_source, api_iocviewrecord_type, api_iocviewrecord_value):
        data = assign_params(batch_id=api_iocviewrecord_batch_id, created_by=api_iocviewrecord_created_by, created_timestamp=api_iocviewrecord_created_timestamp, description=api_iocviewrecord_description, expiration_days=api_iocviewrecord_expiration_days, expiration_timestamp=api_iocviewrecord_expiration_timestamp,
                             modified_by=api_iocviewrecord_modified_by, modified_timestamp=api_iocviewrecord_modified_timestamp, policy=api_iocviewrecord_policy, share_level=api_iocviewrecord_share_level, source=api_iocviewrecord_source, type=api_iocviewrecord_type, value=api_iocviewrecord_value)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'indicators/entities/iocs/v1', json_data=data, headers=headers)

        return response

    def createml_exclusionsv1_request(self, requests_mlexclusioncreatereqv1_comment, requests_mlexclusioncreatereqv1_excluded_from, requests_mlexclusioncreatereqv1_groups, requests_mlexclusioncreatereqv1_value):
        data = assign_params(comment=requests_mlexclusioncreatereqv1_comment, excluded_from=requests_mlexclusioncreatereqv1_excluded_from,
                             groups=requests_mlexclusioncreatereqv1_groups, value=requests_mlexclusioncreatereqv1_value)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'policy/entities/ml-exclusions/v1', json_data=data, headers=headers)

        return response

    def creatert_response_policies_request(self, requests_creatertresponsepoliciesv1_resources):
        data = assign_params(resources=requests_creatertresponsepoliciesv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'policy/entities/response/v1', json_data=data, headers=headers)

        return response

    def createrule_request(self, api_rulecreatev1_comment, api_rulecreatev1_description, api_rulecreatev1_disposition_id, api_rulecreatev1_field_values, api_rulecreatev1_name, api_rulecreatev1_pattern_severity, api_rulecreatev1_rulegroup_id, api_rulecreatev1_ruletype_id):
        data = assign_params(comment=api_rulecreatev1_comment, description=api_rulecreatev1_description, disposition_id=api_rulecreatev1_disposition_id, field_values=api_rulecreatev1_field_values,
                             name=api_rulecreatev1_name, pattern_severity=api_rulecreatev1_pattern_severity, rulegroup_id=api_rulecreatev1_rulegroup_id, ruletype_id=api_rulecreatev1_ruletype_id)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'ioarules/entities/rules/v1', json_data=data, headers=headers)

        return response

    def createrulegroup_request(self, clone_id, li_ary, comment, fwmgr_api_rulegroupcreaterequestv1_description, fwmgr_api_rulegroupcreaterequestv1_enabled, fwmgr_api_rulegroupcreaterequestv1_name, fwmgr_api_rulegroupcreaterequestv1_rules):
        params = assign_params(clone_id=clone_id, li_ary=li_ary, comment=comment)
        data = assign_params(description=fwmgr_api_rulegroupcreaterequestv1_description, enabled=fwmgr_api_rulegroupcreaterequestv1_enabled,
                             name=fwmgr_api_rulegroupcreaterequestv1_name, rules=fwmgr_api_rulegroupcreaterequestv1_rules)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'fwmgr/entities/rule-groups/v1',
                                               params=params, json_data=data, headers=headers)

        return response

    def createrulegroup_mixin0_request(self, api_rulegroupcreaterequestv1_comment, api_rulegroupcreaterequestv1_description, api_rulegroupcreaterequestv1_name, api_rulegroupcreaterequestv1_platform):
        data = assign_params(comment=api_rulegroupcreaterequestv1_comment, description=api_rulegroupcreaterequestv1_description,
                             name=api_rulegroupcreaterequestv1_name, platform=api_rulegroupcreaterequestv1_platform)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'ioarules/entities/rule-groups/v1', json_data=data, headers=headers)

        return response

    def createsv_exclusionsv1_request(self, requests_svexclusioncreatereqv1_comment, requests_svexclusioncreatereqv1_groups, requests_svexclusioncreatereqv1_value):
        data = assign_params(comment=requests_svexclusioncreatereqv1_comment,
                             groups=requests_svexclusioncreatereqv1_groups, value=requests_svexclusioncreatereqv1_value)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'policy/entities/sv-exclusions/v1', json_data=data, headers=headers)

        return response

    def crowd_score_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'incidents/combined/crowdscores/v1', params=params, headers=headers)

        return response

    def customersettingsread_request(self):

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'installation-tokens/entities/customer-settings/v1', headers=headers)

        return response

    def delete_actionv1_request(self, id_):
        params = assign_params(id=id_)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'recon/entities/actions/v1', params=params, headers=headers)

        return response

    def delete_device_control_policies_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'policy/entities/device-control/v1', params=params, headers=headers)

        return response

    def delete_firewall_policies_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'policy/entities/firewall/v1', params=params, headers=headers)

        return response

    def delete_host_groups_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'devices/entities/host-groups/v1', params=params, headers=headers)

        return response

    def delete_notificationsv1_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'recon/entities/notifications/v1', params=params, headers=headers)

        return response

    def delete_prevention_policies_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'policy/entities/prevention/v1', params=params, headers=headers)

        return response

    def delete_report_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'falconx/entities/reports/v1', params=params, headers=headers)

        return response

    def delete_rulesv1_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'recon/entities/rules/v1', params=params, headers=headers)

        return response

    def delete_samplev2_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'samples/entities/samples/v2', params=params, headers=headers)

        return response

    def delete_samplev3_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'samples/entities/samples/v3', params=params, headers=headers)

        return response

    def delete_sensor_update_policies_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'policy/entities/sensor-update/v1', params=params, headers=headers)

        return response

    def delete_sensor_visibility_exclusionsv1_request(self, ids, comment):
        params = assign_params(ids=ids, comment=comment)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'policy/entities/sv-exclusions/v1', params=params, headers=headers)

        return response

    def delete_user_request(self, user_uuid):
        params = assign_params(user_uuid=user_uuid)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'users/entities/users/v1', params=params, headers=headers)

        return response

    def delete_user_group_members_request(self, domain_usergroupmembersrequestv1_resources):
        data = assign_params(resources=domain_usergroupmembersrequestv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'mssp/entities/user-group-members/v1', json_data=data, headers=headers)

        return response

    def delete_user_groups_request(self, user_group_ids):
        params = assign_params(user_group_ids=user_group_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'mssp/entities/user-groups/v1', params=params, headers=headers)

        return response

    def deleteaws_accounts_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'cloud-connect-aws/entities/accounts/v1', params=params, headers=headers)

        return response

    def deleteaws_accounts_mixin0_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'delete', 'kubernetes-protection/entities/accounts/aws/v1', params=params, headers=headers)

        return response

    def deletecid_group_members_request(self, domain_cidgroupmembersrequestv1_resources):
        data = assign_params(resources=domain_cidgroupmembersrequestv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'mssp/entities/cid-group-members/v1', json_data=data, headers=headers)

        return response

    def deletecid_groups_request(self, cid_group_ids):
        params = assign_params(cid_group_ids=cid_group_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'mssp/entities/cid-groups/v1', params=params, headers=headers)

        return response

    def deletecspm_aws_account_request(self, ids, organization_ids):
        params = assign_params(ids=ids, organization_ids=organization_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'delete', 'cloud-connect-cspm-aws/entities/account/v1', params=params, headers=headers)

        return response

    def deletecspm_azure_account_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'delete', 'cloud-connect-cspm-azure/entities/account/v1', params=params, headers=headers)

        return response

    def deleted_roles_request(self, domain_mssprolerequestv1_resources):
        data = assign_params(resources=domain_mssprolerequestv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'mssp/entities/mssp-roles/v1', json_data=data, headers=headers)

        return response

    def deleteioa_exclusionsv1_request(self, ids, comment):
        params = assign_params(ids=ids, comment=comment)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'policy/entities/ioa-exclusions/v1', params=params, headers=headers)

        return response

    def deleteioc_request(self, type_, value):
        params = assign_params(type=type_, value=value)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'indicators/entities/iocs/v1', params=params, headers=headers)

        return response

    def deleteml_exclusionsv1_request(self, ids, comment):
        params = assign_params(ids=ids, comment=comment)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'policy/entities/ml-exclusions/v1', params=params, headers=headers)

        return response

    def deletert_response_policies_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'policy/entities/response/v1', params=params, headers=headers)

        return response

    def deleterulegroups_request(self, ids, comment):
        params = assign_params(ids=ids, comment=comment)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'fwmgr/entities/rule-groups/v1', params=params, headers=headers)

        return response

    def deleterulegroups_mixin0_request(self, comment, ids):
        params = assign_params(comment=comment, ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'ioarules/entities/rule-groups/v1', params=params, headers=headers)

        return response

    def deleterules_request(self, rule_group_id, comment, ids):
        params = assign_params(rule_group_id=rule_group_id, comment=comment, ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'ioarules/entities/rules/v1', params=params, headers=headers)

        return response

    def devices_count_request(self, type_, value):
        params = assign_params(type=type_, value=value)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'indicators/aggregates/devices-count/v1', params=params, headers=headers)

        return response

    def devices_ran_on_request(self, type_, value, limit, offset):
        params = assign_params(type=type_, value=value, limit=limit, offset=offset)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'indicators/queries/devices/v1', params=params, headers=headers)

        return response

    def download_sensor_installer_by_id_request(self, id_):
        params = assign_params(id=id_)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'sensors/entities/download-installer/v1', params=params, headers=headers,
                                               resp_type='response')

        return response

    def entitiesprocesses_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'processes/entities/processes/v1', params=params, headers=headers)

        return response

    def get_actionsv1_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'recon/entities/actions/v1', params=params, headers=headers)

        return response

    def get_aggregate_detects_request(self, msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing, msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type):
        data = assign_params(date_ranges=msa_aggregatequeryrequest_date_ranges, field=msa_aggregatequeryrequest_field, filter=msa_aggregatequeryrequest_filter, interval=msa_aggregatequeryrequest_interval, min_doc_count=msa_aggregatequeryrequest_min_doc_count, missing=msa_aggregatequeryrequest_missing,
                             name=msa_aggregatequeryrequest_name, q=msa_aggregatequeryrequest_q, ranges=msa_aggregatequeryrequest_ranges, size=msa_aggregatequeryrequest_size, sort=msa_aggregatequeryrequest_sort, sub_aggregates=msa_aggregatequeryrequest_sub_aggregates, time_zone=msa_aggregatequeryrequest_time_zone, type=msa_aggregatequeryrequest_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'detects/aggregates/detects/GET/v1', json_data=data, headers=headers)

        return response

    def get_artifacts_request(self, id_, name):
        params = assign_params(id=id_, name=name)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'falconx/entities/artifacts/v1', params=params, headers=headers)

        return response

    def get_assessmentv1_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'zero-trust-assessment/entities/assessments/v1', params=params, headers=headers)

        return response

    def get_available_role_ids_request(self):

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'user-roles/queries/user-role-ids-by-cid/v1', headers=headers)

        return response

    def get_behaviors_request(self, msa_idsrequest_ids):
        data = assign_params(ids=msa_idsrequest_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'incidents/entities/behaviors/GET/v1', json_data=data, headers=headers)

        return response

    def get_children_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'mssp/entities/children/v1', params=params, headers=headers)

        return response

    def get_cloudconnectazure_entities_account_v1_request(self, ids, scan_type):
        params = assign_params(ids=ids, scan_type=scan_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'cloud-connect-azure/entities/account/v1', params=params, headers=headers)

        return response

    def get_cloudconnectazure_entities_userscriptsdownload_v1_request(self):

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'cloud-connect-azure/entities/user-scripts-download/v1', headers=headers)

        return response

    def get_cloudconnectcspmazure_entities_account_v1_request(self, ids, scan_type, status, limit, offset):
        params = assign_params(ids=ids, scan_type=scan_type, status=status, limit=limit, offset=offset)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'cloud-connect-cspm-azure/entities/account/v1', params=params, headers=headers)

        return response

    def get_cloudconnectcspmazure_entities_userscriptsdownload_v1_request(self, tenant_id):
        params = assign_params(tenant_id=tenant_id)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'cloud-connect-cspm-azure/entities/user-scripts-download/v1', params=params, headers=headers)

        return response

    def get_clusters_request(self, cluster_names, account_ids, locations, cluster_service, limit, offset):
        params = assign_params(cluster_names=cluster_names, account_ids=account_ids, locations=locations,
                               cluster_service=cluster_service, limit=limit, offset=offset)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'kubernetes-protection/entities/kubernetes/clusters/v1', params=params, headers=headers)

        return response

    def get_combined_sensor_installers_by_query_request(self, offset, limit, sort, filter_):
        params = assign_params(offset=offset, limit=limit, sort=sort, filter=filter_)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'sensors/combined/installers/v1', params=params, headers=headers)

        return response

    def get_detect_summaries_request(self, msa_idsrequest_ids):
        data = assign_params(ids=msa_idsrequest_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'detects/entities/summaries/GET/v1', json_data=data, headers=headers)

        return response

    def get_device_control_policies_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/entities/device-control/v1', params=params, headers=headers)

        return response

    def get_device_count_collection_queries_by_filter_request(self, limit, sort, filter_, offset):
        params = assign_params(limit=limit, sort=sort, filter=filter_, offset=offset)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'falcon-complete-dashboards/queries/devicecount-collections/v1', params=params, headers=headers)

        return response

    def get_device_details_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'devices/entities/devices/v2', params=params, headers=headers)

        return response

    def get_device_login_history_request(self, ids):
        data = assign_params(ids=ids)

        headers = self.cs_client._headers
        response = self.cs_client.http_request('post', 'devices/combined/devices/login-history/v1', json_data=data,
                                               headers=headers)

        return response

    def get_device_network_history_request(self, ids):
        data = assign_params(ids=ids)

        headers = self.cs_client._headers
        response = self.cs_client.http_request('post', 'devices/combined/devices/network-address-history/v1',
                                               json_data=data, headers=headers)

        return response

    def get_firewall_policies_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/entities/firewall/v1', params=params, headers=headers)

        return response

    def get_helm_values_yaml_request(self, cluster_name):
        params = assign_params(cluster_name=cluster_name)

        headers = self.cs_client._headers
        headers['Accept'] = 'application/yaml'

        response = self.cs_client.http_request(
            'get', 'kubernetes-protection/entities/integration/agent/v1', params=params, headers=headers)

        return response

    def get_host_groups_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'devices/entities/host-groups/v1', params=params, headers=headers)

        return response

    def get_incidents_request(self, msa_idsrequest_ids):
        data = assign_params(ids=msa_idsrequest_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'incidents/entities/incidents/GET/v1', json_data=data, headers=headers)

        return response

    def get_intel_actor_entities_request(self, ids, fields):
        params = assign_params(ids=ids, fields=fields)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'intel/entities/actors/v1', params=params, headers=headers)

        return response

    def get_intel_indicator_entities_request(self, msa_idsrequest_ids):
        data = assign_params(ids=msa_idsrequest_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'intel/entities/indicators/GET/v1', json_data=data, headers=headers)

        return response

    def get_intel_report_entities_request(self, ids, fields):
        params = assign_params(ids=ids, fields=fields)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'intel/entities/reports/v1', params=params, headers=headers)

        return response

    def get_intel_reportpdf_request(self, id_):
        params = assign_params(id=id_)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'intel/entities/report-files/v1', params=params, headers=headers)

        return response

    def get_intel_rule_entities_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'intel/entities/rules/v1', params=params, headers=headers)

        return response

    def get_intel_rule_file_request(self, id_, format):
        params = assign_params(id=id_, format=format)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'intel/entities/rules-files/v1', params=params, headers=headers)

        return response

    def get_latest_intel_rule_file_request(self, type_, format):
        params = assign_params(type=type_, format=format)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'intel/entities/rules-latest-files/v1', params=params, headers=headers)

        return response

    def get_locations_request(self, clouds):
        params = assign_params(clouds=clouds)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'kubernetes-protection/entities/cloud-locations/v1', params=params, headers=headers)

        return response

    def get_mal_query_downloadv1_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'malquery/entities/download-files/v1', params=params, headers=headers)

        return response

    def get_mal_query_entities_samples_fetchv1_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'malquery/entities/samples-fetch/v1', params=params, headers=headers)

        return response

    def get_mal_query_metadatav1_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'malquery/entities/metadata/v1', params=params, headers=headers)

        return response

    def get_mal_query_quotasv1_request(self):

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'malquery/aggregates/quotas/v1', headers=headers)

        return response

    def get_mal_query_requestv1_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'malquery/entities/requests/v1', params=params, headers=headers)

        return response

    def get_notifications_detailed_translatedv1_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'recon/entities/notifications-detailed-translated/v1', params=params, headers=headers)

        return response

    def get_notifications_detailedv1_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'recon/entities/notifications-detailed/v1', params=params, headers=headers)

        return response

    def get_notifications_translatedv1_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'recon/entities/notifications-translated/v1', params=params, headers=headers)

        return response

    def get_notificationsv1_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'recon/entities/notifications/v1', params=params, headers=headers)

        return response

    def get_prevention_policies_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/entities/prevention/v1', params=params, headers=headers)

        return response

    def get_reports_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'falconx/entities/reports/v1', params=params, headers=headers)

        return response

    def get_roles_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'user-roles/entities/user-roles/v1', params=params, headers=headers)

        return response

    def get_roles_byid_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'mssp/entities/mssp-roles/v1', params=params, headers=headers)

        return response

    def get_rulesv1_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'recon/entities/rules/v1', params=params, headers=headers)

        return response

    def get_samplev2_request(self, ids, password_protected):
        params = assign_params(ids=ids, password_protected=password_protected)

        headers = self.cs_client._headers
        headers['Accept'] = 'application/octet-stream'

        response = self.cs_client.http_request('get', 'samples/entities/samples/v2', params=params, headers=headers)

        return response

    def get_samplev3_request(self, ids, password_protected):
        params = assign_params(ids=ids, password_protected=password_protected)

        headers = self.cs_client._headers
        headers['Accept'] = 'application/octet-stream'

        response = self.cs_client.http_request('get', 'samples/entities/samples/v3', params=params, headers=headers)

        return response

    def get_scans_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'scanner/entities/scans/v1', params=params, headers=headers)

        return response

    def get_scans_aggregates_request(self, msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing, msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type):
        data = assign_params(date_ranges=msa_aggregatequeryrequest_date_ranges, field=msa_aggregatequeryrequest_field, filter=msa_aggregatequeryrequest_filter, interval=msa_aggregatequeryrequest_interval, min_doc_count=msa_aggregatequeryrequest_min_doc_count, missing=msa_aggregatequeryrequest_missing,
                             name=msa_aggregatequeryrequest_name, q=msa_aggregatequeryrequest_q, ranges=msa_aggregatequeryrequest_ranges, size=msa_aggregatequeryrequest_size, sort=msa_aggregatequeryrequest_sort, sub_aggregates=msa_aggregatequeryrequest_sub_aggregates, time_zone=msa_aggregatequeryrequest_time_zone, type=msa_aggregatequeryrequest_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'scanner/aggregates/scans/GET/v1', json_data=data, headers=headers)

        return response

    def get_sensor_installers_by_query_request(self, offset, limit, sort, filter_):
        params = assign_params(offset=offset, limit=limit, sort=sort, filter=filter_)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'sensors/queries/installers/v1', params=params, headers=headers)

        return response

    def get_sensor_installers_entities_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'sensors/entities/installers/v1', params=params, headers=headers)

        return response

    def get_sensor_installersccid_by_query_request(self):

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'sensors/queries/installers/ccid/v1', headers=headers)

        return response

    def get_sensor_update_policies_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/entities/sensor-update/v1', params=params, headers=headers)

        return response

    def get_sensor_update_policiesv2_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/entities/sensor-update/v2', params=params, headers=headers)

        return response

    def get_sensor_visibility_exclusionsv1_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/entities/sv-exclusions/v1', params=params, headers=headers)

        return response

    def get_submissions_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'falconx/entities/submissions/v1', params=params, headers=headers)

        return response

    def get_summary_reports_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'falconx/entities/report-summaries/v1', params=params, headers=headers)

        return response

    def get_user_group_members_byid_request(self, user_group_ids):
        params = assign_params(user_group_ids=user_group_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'mssp/entities/user-group-members/v1', params=params, headers=headers)

        return response

    def get_user_groups_byid_request(self, user_group_ids):
        params = assign_params(user_group_ids=user_group_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'mssp/entities/user-groups/v1', params=params, headers=headers)

        return response

    def get_user_role_ids_request(self, user_uuid):
        params = assign_params(user_uuid=user_uuid)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'user-roles/queries/user-role-ids-by-user-uuid/v1', params=params, headers=headers)

        return response

    def get_vulnerabilities_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'spotlight/entities/vulnerabilities/v2', params=params, headers=headers)

        return response

    def getaws_accounts_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'cloud-connect-aws/entities/accounts/v1', params=params, headers=headers)

        return response

    def getaws_accounts_mixin0_request(self, ids, status, limit, offset):
        params = assign_params(ids=ids, status=status, limit=limit, offset=offset)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'kubernetes-protection/entities/accounts/aws/v1', params=params, headers=headers)

        return response

    def getaws_settings_request(self):

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'cloud-connect-aws/combined/settings/v1', headers=headers)

        return response

    def getcid_group_by_id_request(self, cid_group_ids):
        params = assign_params(cid_group_ids=cid_group_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'mssp/entities/cid-groups/v1', params=params, headers=headers)

        return response

    def getcid_group_members_by_request(self, cid_group_ids):
        params = assign_params(cid_group_ids=cid_group_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'mssp/entities/cid-group-members/v1', params=params, headers=headers)

        return response

    def getcspm_aws_account_request(self, scan_type, ids, organization_ids, status, limit, offset, group_by):
        params = assign_params(scan_type=scan_type, ids=ids, organization_ids=organization_ids,
                               status=status, limit=limit, offset=offset, group_by=group_by)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'cloud-connect-cspm-aws/entities/account/v1', params=params, headers=headers)

        return response

    def getcspm_aws_account_scripts_attachment_request(self):

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'cloud-connect-cspm-aws/entities/user-scripts-download/v1', headers=headers)

        return response

    def getcspm_aws_console_setupur_ls_request(self):

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'cloud-connect-cspm-aws/entities/console-setup-urls/v1', headers=headers)

        return response

    def getcspm_azure_user_scripts_request(self):

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'cloud-connect-azure/entities/user-scripts/v1', headers=headers)

        return response

    def getcspm_policy_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'settings/entities/policy-details/v1', params=params, headers=headers)

        return response

    def getcspm_policy_settings_request(self, service, policy_id, cloud_platform):
        params = assign_params(service=service, policy_id=policy_id, cloud_platform=cloud_platform)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'settings/entities/policy/v1', params=params, headers=headers)

        return response

    def getcspm_scan_schedule_request(self, cloud_platform):
        params = assign_params(cloud_platform=cloud_platform)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'settings/scan-schedule/v1', params=params, headers=headers)

        return response

    def getcspmcgp_account_request(self, scan_type, ids):
        params = assign_params(scan_type=scan_type, ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'cloud-connect-gcp/entities/account/v1', params=params, headers=headers)

        return response

    def getcspmgcp_user_scripts_request(self):

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'cloud-connect-gcp/entities/user-scripts/v1', headers=headers)

        return response

    def getcspmgcp_user_scripts_attachment_request(self):

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'cloud-connect-gcp/entities/user-scripts-download/v1', headers=headers)

        return response

    def getevents_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'fwmgr/entities/events/v1', params=params, headers=headers)

        return response

    def getfirewallfields_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'fwmgr/entities/firewall-fields/v1', params=params, headers=headers)

        return response

    def getioa_events_request(self, policy_id, cloud_provider, account_id, azure_tenant_id, user_ids, offset, limit):
        params = assign_params(policy_id=policy_id, cloud_provider=cloud_provider, account_id=account_id,
                               azure_tenant_id=azure_tenant_id, user_ids=user_ids, offset=offset, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'ioa/entities/events/v1', params=params, headers=headers)

        return response

    def getioa_exclusionsv1_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/entities/ioa-exclusions/v1', params=params, headers=headers)

        return response

    def getioa_users_request(self, policy_id, cloud_provider, account_id, azure_tenant_id):
        params = assign_params(policy_id=policy_id, cloud_provider=cloud_provider,
                               account_id=account_id, azure_tenant_id=azure_tenant_id)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'ioa/entities/users/v1', params=params, headers=headers)

        return response

    def getioc_request(self, type_, value):
        params = assign_params(type=type_, value=value)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'indicators/entities/iocs/v1', params=params, headers=headers)

        return response

    def getml_exclusionsv1_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/entities/ml-exclusions/v1', params=params, headers=headers)

        return response

    def getpatterns_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'ioarules/entities/pattern-severities/v1', params=params, headers=headers)

        return response

    def getplatforms_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'fwmgr/entities/platforms/v1', params=params, headers=headers)

        return response

    def getplatforms_mixin0_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'ioarules/entities/platforms/v1', params=params, headers=headers)

        return response

    def getpolicycontainers_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'fwmgr/entities/policies/v1', params=params, headers=headers)

        return response

    def getrt_response_policies_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/entities/response/v1', params=params, headers=headers)

        return response

    def getrulegroups_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'fwmgr/entities/rule-groups/v1', params=params, headers=headers)

        return response

    def getrulegroups_mixin0_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'ioarules/entities/rule-groups/v1', params=params, headers=headers)

        return response

    def getrules_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'fwmgr/entities/rules/v1', params=params, headers=headers)

        return response

    def getrules_mixin0_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'ioarules/entities/rules/v1', params=params, headers=headers)

        return response

    def getrulesget_request(self, api_rulesgetrequestv1_ids):
        data = assign_params(ids=api_rulesgetrequestv1_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'ioarules/entities/rules/GET/v1', json_data=data, headers=headers)

        return response

    def getruletypes_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'ioarules/entities/rule-types/v1', params=params, headers=headers)

        return response

    def grant_user_role_ids_request(self, user_uuid, domain_roleids_roleids):
        params = assign_params(user_uuid=user_uuid)
        data = assign_params(roleIds=domain_roleids_roleids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'user-roles/entities/user-roles/v1',
                                               params=params, json_data=data, headers=headers)

        return response

    def indicatorcombinedv1_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'iocs/combined/indicator/v1', params=params, headers=headers)

        return response

    def indicatorcreatev1_request(self, retrodetects, ignore_warnings, api_indicatorcreatereqsv1_comment, api_indicatorcreatereqsv1_indicators):
        params = assign_params(retrodetects=retrodetects, ignore_warnings=ignore_warnings)
        data = assign_params(comment=api_indicatorcreatereqsv1_comment, indicators=api_indicatorcreatereqsv1_indicators)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'iocs/entities/indicators/v1',
                                               params=params, json_data=data, headers=headers)

        return response

    def indicatordeletev1_request(self, filter_, ids, comment):
        params = assign_params(filter=filter_, ids=ids, comment=comment)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'iocs/entities/indicators/v1', params=params, headers=headers)

        return response

    def indicatorgetv1_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'iocs/entities/indicators/v1', params=params, headers=headers)

        return response

    def indicatorsearchv1_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'iocs/queries/indicators/v1', params=params, headers=headers)

        return response

    def indicatorupdatev1_request(self, retrodetects, ignore_warnings, api_indicatorupdatereqsv1_bulk_update, api_indicatorupdatereqsv1_comment, api_indicatorupdatereqsv1_indicators):
        params = assign_params(retrodetects=retrodetects, ignore_warnings=ignore_warnings)
        data = assign_params(bulk_update=api_indicatorupdatereqsv1_bulk_update,
                             comment=api_indicatorupdatereqsv1_comment, indicators=api_indicatorupdatereqsv1_indicators)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'iocs/entities/indicators/v1',
                                               params=params, json_data=data, headers=headers)

        return response

    def list_available_streamso_auth2_request(self, appId, format):
        params = assign_params(appId=appId, format=format)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'sensors/entities/datafeed/v2', params=params, headers=headers)

        return response

    def oauth2_access_token_request(self, client_id, client_secret, member_cid):
        data = assign_params(client_id=client_id, client_secret=client_secret, member_cid=member_cid)

        headers = self.cs_client._headers
        headers['Content-Type'] = 'application/x-www-form-urlencoded'

        response = self.cs_client.http_request('post', 'oauth2/token', json_data=data, headers=headers)

        return response

    def oauth2_revoke_token_request(self, token):
        data = assign_params(token=token)

        headers = self.cs_client._headers
        headers['Content-Type'] = 'application/x-www-form-urlencoded'

        response = self.cs_client.http_request('post', 'oauth2/revoke', json_data=data, headers=headers)

        return response

    def patch_cloudconnectazure_entities_clientid_v1_request(self, id_):
        params = assign_params(id=id_)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'patch', 'cloud-connect-azure/entities/client-id/v1', params=params, headers=headers)

        return response

    def patch_cloudconnectcspmazure_entities_clientid_v1_request(self, id_, tenant_id):
        params = assign_params(id=id_, tenant_id=tenant_id)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'patch', 'cloud-connect-cspm-azure/entities/client-id/v1', params=params, headers=headers)

        return response

    def patchcspm_aws_account_request(self, registration_awsaccountpatchrequest_resources):
        data = assign_params(resources=registration_awsaccountpatchrequest_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'patch', 'cloud-connect-cspm-aws/entities/account/v1', json_data=data, headers=headers)

        return response

    def perform_actionv2_request(self, action_name, msa_entityactionrequestv2_action__meters, msa_entityactionrequestv2_ids):
        params = assign_params(action_name=action_name)
        data = assign_params(action__meters=msa_entityactionrequestv2_action__meters, ids=msa_entityactionrequestv2_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'devices/entities/devices-actions/v2',
                                               params=params, json_data=data, headers=headers)

        return response

    def perform_device_control_policies_action_request(self, action_name, msa_entityactionrequestv2_action__meters, msa_entityactionrequestv2_ids):
        params = assign_params(action_name=action_name)
        data = assign_params(action__meters=msa_entityactionrequestv2_action__meters, ids=msa_entityactionrequestv2_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'policy/entities/device-control-actions/v1',
                                               params=params, json_data=data, headers=headers)

        return response

    def perform_firewall_policies_action_request(self, action_name, msa_entityactionrequestv2_action__meters, msa_entityactionrequestv2_ids):
        params = assign_params(action_name=action_name)
        data = assign_params(action__meters=msa_entityactionrequestv2_action__meters, ids=msa_entityactionrequestv2_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'policy/entities/firewall-actions/v1',
                                               params=params, json_data=data, headers=headers)

        return response

    def perform_group_action_request(self, action_name, msa_entityactionrequestv2_action__meters, msa_entityactionrequestv2_ids):
        params = assign_params(action_name=action_name)
        data = assign_params(action__meters=msa_entityactionrequestv2_action__meters, ids=msa_entityactionrequestv2_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'devices/entities/host-group-actions/v1',
                                               params=params, json_data=data, headers=headers)

        return response

    def perform_incident_action_request(self, msa_entityactionrequestv2_action__meters, msa_entityactionrequestv2_ids):
        data = assign_params(action__meters=msa_entityactionrequestv2_action__meters, ids=msa_entityactionrequestv2_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'incidents/entities/incident-actions/v1', json_data=data, headers=headers)

        return response

    def perform_prevention_policies_action_request(self, action_name, msa_entityactionrequestv2_action__meters, msa_entityactionrequestv2_ids):
        params = assign_params(action_name=action_name)
        data = assign_params(action__meters=msa_entityactionrequestv2_action__meters, ids=msa_entityactionrequestv2_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'policy/entities/prevention-actions/v1',
                                               params=params, json_data=data, headers=headers)

        return response

    def perform_sensor_update_policies_action_request(self, action_name, msa_entityactionrequestv2_action__meters, msa_entityactionrequestv2_ids):
        params = assign_params(action_name=action_name)
        data = assign_params(action__meters=msa_entityactionrequestv2_action__meters, ids=msa_entityactionrequestv2_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'policy/entities/sensor-update-actions/v1',
                                               params=params, json_data=data, headers=headers)

        return response

    def performrt_response_policies_action_request(self, action_name, msa_entityactionrequestv2_action__meters, msa_entityactionrequestv2_ids):
        params = assign_params(action_name=action_name)
        data = assign_params(action__meters=msa_entityactionrequestv2_action__meters, ids=msa_entityactionrequestv2_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'policy/entities/response-actions/v1',
                                               params=params, json_data=data, headers=headers)

        return response

    def post_cloudconnectazure_entities_account_v1_request(self, registration_azureaccountcreaterequestexternalv1_resources):
        data = assign_params(resources=registration_azureaccountcreaterequestexternalv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'cloud-connect-azure/entities/account/v1', json_data=data, headers=headers)

        return response

    def post_cloudconnectcspmazure_entities_account_v1_request(self, registration_azureaccountcreaterequestexternalv1_resources):
        data = assign_params(resources=registration_azureaccountcreaterequestexternalv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'cloud-connect-cspm-azure/entities/account/v1', json_data=data, headers=headers)

        return response

    def post_mal_query_entities_samples_multidownloadv1_request(self, malquery_multidownloadrequestv1_samples):
        data = assign_params(samples=malquery_multidownloadrequestv1_samples)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'malquery/entities/samples-multidownload/v1', json_data=data, headers=headers)

        return response

    def post_mal_query_exact_searchv1_request(self, malquery_externalexactsearchparametersv1_options, malquery_externalexactsearchparametersv1_patterns):
        data = assign_params(options=malquery_externalexactsearchparametersv1_options,
                             patterns=malquery_externalexactsearchparametersv1_patterns)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'malquery/queries/exact-search/v1', json_data=data, headers=headers)

        return response

    def post_mal_query_fuzzy_searchv1_request(self, malquery_fuzzysearchparametersv1_options, malquery_fuzzysearchparametersv1_patterns):
        data = assign_params(options=malquery_fuzzysearchparametersv1_options, patterns=malquery_fuzzysearchparametersv1_patterns)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'malquery/combined/fuzzy-search/v1', json_data=data, headers=headers)

        return response

    def post_mal_query_huntv1_request(self, malquery_externalhuntparametersv1_options, malquery_externalhuntparametersv1_yara_rule):
        data = assign_params(options=malquery_externalhuntparametersv1_options,
                             yara_rule=malquery_externalhuntparametersv1_yara_rule)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'malquery/queries/hunt/v1', json_data=data, headers=headers)

        return response

    def preview_rulev1_request(self, domain_rulepreviewrequest_filter, domain_rulepreviewrequest_topic):
        data = assign_params(filter=domain_rulepreviewrequest_filter, topic=domain_rulepreviewrequest_topic)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'recon/aggregates/rules-preview/GET/v1', json_data=data, headers=headers)

        return response

    def processes_ran_on_request(self, type_, value, device_id, limit, offset):
        params = assign_params(type=type_, value=value, device_id=device_id, limit=limit, offset=offset)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'indicators/queries/processes/v1', params=params, headers=headers)

        return response

    def provisionaws_accounts_request(self, mode, models_createawsaccountsv1_resources):
        params = assign_params(mode=mode)
        data = assign_params(resources=models_createawsaccountsv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'cloud-connect-aws/entities/accounts/v1',
                                               params=params, json_data=data, headers=headers)

        return response

    def query_actionsv1_request(self, offset, limit, sort, filter_, q):
        params = assign_params(offset=offset, limit=limit, sort=sort, filter=filter_, q=q)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'recon/queries/actions/v1', params=params, headers=headers)

        return response

    def query_allow_list_filter_request(self, limit, sort, filter_, offset):
        params = assign_params(limit=limit, sort=sort, filter=filter_, offset=offset)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'falcon-complete-dashboards/queries/allowlist/v1', params=params, headers=headers)

        return response

    def query_behaviors_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'incidents/queries/behaviors/v1', params=params, headers=headers)

        return response

    def query_block_list_filter_request(self, limit, sort, filter_, offset):
        params = assign_params(limit=limit, sort=sort, filter=filter_, offset=offset)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'falcon-complete-dashboards/queries/blocklist/v1', params=params, headers=headers)

        return response

    def query_children_request(self, sort, offset, limit):
        params = assign_params(sort=sort, offset=offset, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'mssp/queries/children/v1', params=params, headers=headers)

        return response

    def query_combined_device_control_policies_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/combined/device-control/v1', params=params, headers=headers)

        return response

    def query_combined_device_control_policy_members_request(self, id_, filter_, offset, limit, sort):
        params = assign_params(id=id_, filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/combined/device-control-members/v1', params=params, headers=headers)

        return response

    def query_combined_firewall_policies_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/combined/firewall/v1', params=params, headers=headers)

        return response

    def query_combined_firewall_policy_members_request(self, id_, filter_, offset, limit, sort):
        params = assign_params(id=id_, filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/combined/firewall-members/v1', params=params, headers=headers)

        return response

    def query_combined_group_members_request(self, id_, filter_, offset, limit, sort):
        params = assign_params(id=id_, filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'devices/combined/host-group-members/v1', params=params, headers=headers)

        return response

    def query_combined_host_groups_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'devices/combined/host-groups/v1', params=params, headers=headers)

        return response

    def query_combined_prevention_policies_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/combined/prevention/v1', params=params, headers=headers)

        return response

    def query_combined_prevention_policy_members_request(self, id_, filter_, offset, limit, sort):
        params = assign_params(id=id_, filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/combined/prevention-members/v1', params=params, headers=headers)

        return response

    def query_combined_sensor_update_builds_request(self, platform):
        params = assign_params(platform=platform)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/combined/sensor-update-builds/v1', params=params, headers=headers)

        return response

    def query_combined_sensor_update_policies_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/combined/sensor-update/v1', params=params, headers=headers)

        return response

    def query_combined_sensor_update_policiesv2_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/combined/sensor-update/v2', params=params, headers=headers)

        return response

    def query_combined_sensor_update_policy_members_request(self, id_, filter_, offset, limit, sort):
        params = assign_params(id=id_, filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/combined/sensor-update-members/v1', params=params, headers=headers)

        return response

    def query_combinedrt_response_policies_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/combined/response/v1', params=params, headers=headers)

        return response

    def query_combinedrt_response_policy_members_request(self, id_, filter_, offset, limit, sort):
        params = assign_params(id=id_, filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/combined/response-members/v1', params=params, headers=headers)

        return response

    def query_detection_ids_by_filter_request(self, limit, sort, filter_, offset):
        params = assign_params(limit=limit, sort=sort, filter=filter_, offset=offset)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'falcon-complete-dashboards/queries/detects/v1', params=params, headers=headers)

        return response

    def query_detects_request(self, offset, limit, sort, filter_, q):
        params = assign_params(offset=offset, limit=limit, sort=sort, filter=filter_, q=q)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'detects/queries/detects/v1', params=params, headers=headers)

        return response

    def query_device_control_policies_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/queries/device-control/v1', params=params, headers=headers)

        return response

    def query_device_control_policy_members_request(self, id_, filter_, offset, limit, sort):
        params = assign_params(id=id_, filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/queries/device-control-members/v1', params=params, headers=headers)

        return response

    def query_devices_by_filter_request(self, offset, limit, sort, filter_):
        params = assign_params(offset=offset, limit=limit, sort=sort, filter=filter_)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'devices/queries/devices/v1', params=params, headers=headers)

        return response

    def query_devices_by_filter_scroll_request(self, offset, limit, sort, filter_):
        params = assign_params(offset=offset, limit=limit, sort=sort, filter=filter_)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'devices/queries/devices-scroll/v1', params=params, headers=headers)

        return response

    def query_escalations_filter_request(self, limit, sort, filter_, offset):
        params = assign_params(limit=limit, sort=sort, filter=filter_, offset=offset)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'falcon-complete-dashboards/queries/escalations/v1', params=params, headers=headers)

        return response

    def query_firewall_policies_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/queries/firewall/v1', params=params, headers=headers)

        return response

    def query_firewall_policy_members_request(self, id_, filter_, offset, limit, sort):
        params = assign_params(id=id_, filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/queries/firewall-members/v1', params=params, headers=headers)

        return response

    def query_group_members_request(self, id_, filter_, offset, limit, sort):
        params = assign_params(id=id_, filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'devices/queries/host-group-members/v1', params=params, headers=headers)

        return response

    def query_hidden_devices_request(self, offset, limit, sort, filter_):
        params = assign_params(offset=offset, limit=limit, sort=sort, filter=filter_)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'devices/queries/devices-hidden/v1', params=params, headers=headers)

        return response

    def query_host_groups_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'devices/queries/host-groups/v1', params=params, headers=headers)

        return response

    def query_incident_ids_by_filter_request(self, limit, sort, filter_, offset):
        params = assign_params(limit=limit, sort=sort, filter=filter_, offset=offset)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'falcon-complete-dashboards/queries/incidents/v1', params=params, headers=headers)

        return response

    def query_incidents_request(self, sort, filter_, offset, limit):
        params = assign_params(sort=sort, filter=filter_, offset=offset, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'incidents/queries/incidents/v1', params=params, headers=headers)

        return response

    def query_intel_actor_entities_request(self, offset, limit, sort, filter_, q, fields):
        params = assign_params(offset=offset, limit=limit, sort=sort, filter=filter_, q=q, fields=fields)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'intel/combined/actors/v1', params=params, headers=headers)

        return response

    def query_intel_actor_ids_request(self, offset, limit, sort, filter_, q):
        params = assign_params(offset=offset, limit=limit, sort=sort, filter=filter_, q=q)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'intel/queries/actors/v1', params=params, headers=headers)

        return response

    def query_intel_indicator_entities_request(self, offset, limit, sort, filter_, q, include_deleted):
        params = assign_params(offset=offset, limit=limit, sort=sort, filter=filter_, q=q, include_deleted=include_deleted)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'intel/combined/indicators/v1', params=params, headers=headers)

        return response

    def query_intel_indicator_ids_request(self, offset, limit, sort, filter_, q, include_deleted):
        params = assign_params(offset=offset, limit=limit, sort=sort, filter=filter_, q=q, include_deleted=include_deleted)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'intel/queries/indicators/v1', params=params, headers=headers)

        return response

    def query_intel_report_entities_request(self, offset, limit, sort, filter_, q, fields):
        params = assign_params(offset=offset, limit=limit, sort=sort, filter=filter_, q=q, fields=fields)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'intel/combined/reports/v1', params=params, headers=headers)

        return response

    def query_intel_report_ids_request(self, offset, limit, sort, filter_, q):
        params = assign_params(offset=offset, limit=limit, sort=sort, filter=filter_, q=q)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'intel/queries/reports/v1', params=params, headers=headers)

        return response

    def query_intel_rule_ids_request(self, offset, limit, sort, name, type_, description, tags, min_created_date, max_created_date, q):
        params = assign_params(offset=offset, limit=limit, sort=sort, name=name, type=type_, description=description,
                               tags=tags, min_created_date=min_created_date, max_created_date=max_created_date, q=q)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'intel/queries/rules/v1', params=params, headers=headers)

        return response

    def query_notificationsv1_request(self, offset, limit, sort, filter_, q):
        params = assign_params(offset=offset, limit=limit, sort=sort, filter=filter_, q=q)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'recon/queries/notifications/v1', params=params, headers=headers)

        return response

    def query_prevention_policies_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/queries/prevention/v1', params=params, headers=headers)

        return response

    def query_prevention_policy_members_request(self, id_, filter_, offset, limit, sort):
        params = assign_params(id=id_, filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/queries/prevention-members/v1', params=params, headers=headers)

        return response

    def query_remediations_filter_request(self, limit, sort, filter_, offset):
        params = assign_params(limit=limit, sort=sort, filter=filter_, offset=offset)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'falcon-complete-dashboards/queries/remediations/v1', params=params, headers=headers)

        return response

    def query_reports_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'falconx/queries/reports/v1', params=params, headers=headers)

        return response

    def query_roles_request(self, user_group_id, cid_group_id, role_id, sort, offset, limit):
        params = assign_params(user_group_id=user_group_id, cid_group_id=cid_group_id,
                               role_id=role_id, sort=sort, offset=offset, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'mssp/queries/mssp-roles/v1', params=params, headers=headers)

        return response

    def query_rulesv1_request(self, offset, limit, sort, filter_, q):
        params = assign_params(offset=offset, limit=limit, sort=sort, filter=filter_, q=q)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'recon/queries/rules/v1', params=params, headers=headers)

        return response

    def query_samplev1_request(self, samplestore_querysamplesrequest_sha256s):
        data = assign_params(sha256s=samplestore_querysamplesrequest_sha256s)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'samples/queries/samples/GET/v1', json_data=data, headers=headers)

        return response

    def query_sensor_update_policies_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/queries/sensor-update/v1', params=params, headers=headers)

        return response

    def query_sensor_update_policy_members_request(self, id_, filter_, offset, limit, sort):
        params = assign_params(id=id_, filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/queries/sensor-update-members/v1', params=params, headers=headers)

        return response

    def query_sensor_visibility_exclusionsv1_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/queries/sv-exclusions/v1', params=params, headers=headers)

        return response

    def query_submissions_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'falconx/queries/submissions/v1', params=params, headers=headers)

        return response

    def query_submissions_mixin0_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'scanner/queries/scans/v1', params=params, headers=headers)

        return response

    def query_user_group_members_request(self, user_uuid, sort, offset, limit):
        params = assign_params(user_uuid=user_uuid, sort=sort, offset=offset, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'mssp/queries/user-group-members/v1', params=params, headers=headers)

        return response

    def query_user_groups_request(self, name, sort, offset, limit):
        params = assign_params(name=name, sort=sort, offset=offset, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'mssp/queries/user-groups/v1', params=params, headers=headers)

        return response

    def query_vulnerabilities_request(self, after, limit, sort, filter_):
        params = assign_params(after=after, limit=limit, sort=sort, filter=filter_)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'spotlight/queries/vulnerabilities/v1', params=params, headers=headers)

        return response

    def queryaws_accounts_request(self, limit, offset, sort, filter_):
        params = assign_params(limit=limit, offset=offset, sort=sort, filter=filter_)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'cloud-connect-aws/combined/accounts/v1', params=params, headers=headers)

        return response

    def queryaws_accounts_fori_ds_request(self, limit, offset, sort, filter_):
        params = assign_params(limit=limit, offset=offset, sort=sort, filter=filter_)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'cloud-connect-aws/queries/accounts/v1', params=params, headers=headers)

        return response

    def querycid_group_members_request(self, cid, sort, offset, limit):
        params = assign_params(cid=cid, sort=sort, offset=offset, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'mssp/queries/cid-group-members/v1', params=params, headers=headers)

        return response

    def querycid_groups_request(self, name, sort, offset, limit):
        params = assign_params(name=name, sort=sort, offset=offset, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'mssp/queries/cid-groups/v1', params=params, headers=headers)

        return response

    def queryevents_request(self, sort, filter_, q, offset, after, limit):
        params = assign_params(sort=sort, filter=filter_, q=q, offset=offset, after=after, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'fwmgr/queries/events/v1', params=params, headers=headers)

        return response

    def queryfirewallfields_request(self, platform_id, offset, limit):
        params = assign_params(platform_id=platform_id, offset=offset, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'fwmgr/queries/firewall-fields/v1', params=params, headers=headers)

        return response

    def queryio_cs_request(self, types, values, from_expiration_timestamp, to_expiration_timestamp, policies, sources, share_levels, created_by, deleted_by, include_deleted):
        params = assign_params(types=types, values=values, from_expiration_timestamp=from_expiration_timestamp, to_expiration_timestamp=to_expiration_timestamp,
                               policies=policies, sources=sources, share_levels=share_levels, created_by=created_by, deleted_by=deleted_by, include_deleted=include_deleted)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'indicators/queries/iocs/v1', params=params, headers=headers)

        return response

    def queryioa_exclusionsv1_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/queries/ioa-exclusions/v1', params=params, headers=headers)

        return response

    def queryml_exclusionsv1_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/queries/ml-exclusions/v1', params=params, headers=headers)

        return response

    def querypatterns_request(self, offset, limit):
        params = assign_params(offset=offset, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'ioarules/queries/pattern-severities/v1', params=params, headers=headers)

        return response

    def queryplatforms_request(self, offset, limit):
        params = assign_params(offset=offset, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'fwmgr/queries/platforms/v1', params=params, headers=headers)

        return response

    def queryplatforms_mixin0_request(self, offset, limit):
        params = assign_params(offset=offset, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'ioarules/queries/platforms/v1', params=params, headers=headers)

        return response

    def querypolicyrules_request(self, id_, sort, filter_, q, offset, limit):
        params = assign_params(id=id_, sort=sort, filter=filter_, q=q, offset=offset, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'fwmgr/queries/policy-rules/v1', params=params, headers=headers)

        return response

    def queryrt_response_policies_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/queries/response/v1', params=params, headers=headers)

        return response

    def queryrt_response_policy_members_request(self, id_, filter_, offset, limit, sort):
        params = assign_params(id=id_, filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'policy/queries/response-members/v1', params=params, headers=headers)

        return response

    def queryrulegroups_request(self, sort, filter_, q, offset, after, limit):
        params = assign_params(sort=sort, filter=filter_, q=q, offset=offset, after=after, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'fwmgr/queries/rule-groups/v1', params=params, headers=headers)

        return response

    def queryrulegroups_mixin0_request(self, sort, filter_, q, offset, limit):
        params = assign_params(sort=sort, filter=filter_, q=q, offset=offset, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'ioarules/queries/rule-groups/v1', params=params, headers=headers)

        return response

    def queryrulegroupsfull_request(self, sort, filter_, q, offset, limit):
        params = assign_params(sort=sort, filter=filter_, q=q, offset=offset, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'ioarules/queries/rule-groups-full/v1', params=params, headers=headers)

        return response

    def queryrules_request(self, sort, filter_, q, offset, after, limit):
        params = assign_params(sort=sort, filter=filter_, q=q, offset=offset, after=after, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'fwmgr/queries/rules/v1', params=params, headers=headers)

        return response

    def queryrules_mixin0_request(self, sort, filter_, q, offset, limit):
        params = assign_params(sort=sort, filter=filter_, q=q, offset=offset, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'ioarules/queries/rules/v1', params=params, headers=headers)

        return response

    def queryruletypes_request(self, offset, limit):
        params = assign_params(offset=offset, limit=limit)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'ioarules/queries/rule-types/v1', params=params, headers=headers)

        return response

    def refresh_active_stream_session_request(self, action_name, appId, partition):
        params = assign_params(action_name=action_name, appId=appId)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', f'sensors/entities/datafeed-actions/v1/{partition}', params=params, headers=headers)

        return response

    def regenerateapi_key_request(self):

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'kubernetes-protection/entities/integration/api-key/v1', headers=headers)

        return response

    def retrieve_emails_bycid_request(self):

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'users/queries/emails-by-cid/v1', headers=headers)

        return response

    def retrieve_user_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'users/entities/users/v1', params=params, headers=headers)

        return response

    def retrieve_useruui_ds_bycid_request(self):

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'users/queries/user-uuids-by-cid/v1', headers=headers)

        return response

    def retrieve_useruuid_request(self, uid):
        params = assign_params(uid=uid)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'users/queries/user-uuids-by-email/v1', params=params, headers=headers)

        return response

    def reveal_uninstall_token_request(self, requests_revealuninstalltokenv1_audit_message, requests_revealuninstalltokenv1_device_id):
        data = assign_params(audit_message=requests_revealuninstalltokenv1_audit_message,
                             device_id=requests_revealuninstalltokenv1_device_id)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'policy/combined/reveal-uninstall-token/v1', json_data=data, headers=headers)

        return response

    def revoke_user_role_ids_request(self, user_uuid, ids):
        params = assign_params(user_uuid=user_uuid, ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'user-roles/entities/user-roles/v1', params=params, headers=headers)

        return response

    def rtr_aggregate_sessions_request(self, msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing, msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type):
        data = assign_params(date_ranges=msa_aggregatequeryrequest_date_ranges, field=msa_aggregatequeryrequest_field, filter=msa_aggregatequeryrequest_filter, interval=msa_aggregatequeryrequest_interval, min_doc_count=msa_aggregatequeryrequest_min_doc_count, missing=msa_aggregatequeryrequest_missing,
                             name=msa_aggregatequeryrequest_name, q=msa_aggregatequeryrequest_q, ranges=msa_aggregatequeryrequest_ranges, size=msa_aggregatequeryrequest_size, sort=msa_aggregatequeryrequest_sort, sub_aggregates=msa_aggregatequeryrequest_sub_aggregates, time_zone=msa_aggregatequeryrequest_time_zone, type=msa_aggregatequeryrequest_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'real-time-response/aggregates/sessions/GET/v1', json_data=data, headers=headers)

        return response

    def rtr_check_active_responder_command_status_request(self, cloud_request_id, sequence_id):
        params = assign_params(cloud_request_id=cloud_request_id, sequence_id=sequence_id)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'real-time-response/entities/active-responder-command/v1', params=params, headers=headers)

        return response

    def rtr_check_admin_command_status_request(self, cloud_request_id, sequence_id):
        params = assign_params(cloud_request_id=cloud_request_id, sequence_id=sequence_id)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'real-time-response/entities/admin-command/v1', params=params, headers=headers)

        return response

    def rtr_check_command_status_request(self, cloud_request_id, sequence_id):
        params = assign_params(cloud_request_id=cloud_request_id, sequence_id=sequence_id)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'real-time-response/entities/command/v1', params=params, headers=headers)

        return response

    def rtr_create_put_files_request(self, file, description, name, comments_for_audit_log):
        data = assign_params(file=file, description=description, name=name, comments_for_audit_log=comments_for_audit_log)

        headers = self.cs_client._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self.cs_client.http_request(
            'post', 'real-time-response/entities/put-files/v1', json_data=data, headers=headers)

        return response

    def rtr_create_scripts_request(self, file, description, name, comments_for_audit_log, permission_type, content, platform):
        data = assign_params(file=file, description=description, name=name, comments_for_audit_log=comments_for_audit_log,
                             permission_type=permission_type, content=content, platform=platform)

        headers = self.cs_client._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self.cs_client.http_request('post', 'real-time-response/entities/scripts/v1', json_data=data, headers=headers)

        return response

    def rtr_delete_file_request(self, ids, session_id):
        params = assign_params(ids=ids, session_id=session_id)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'real-time-response/entities/file/v1', params=params, headers=headers)

        return response

    def rtr_delete_put_files_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'delete', 'real-time-response/entities/put-files/v1', params=params, headers=headers)

        return response

    def rtr_delete_queued_session_request(self, session_id, cloud_request_id):
        params = assign_params(session_id=session_id, cloud_request_id=cloud_request_id)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'delete', 'real-time-response/entities/queued-sessions/command/v1', params=params, headers=headers)

        return response

    def rtr_delete_scripts_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'real-time-response/entities/scripts/v1', params=params, headers=headers)

        return response

    def rtr_delete_session_request(self, session_id):
        params = assign_params(session_id=session_id)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'delete', 'real-time-response/entities/sessions/v1', params=params, headers=headers)

        return response

    def rtr_execute_active_responder_command_request(self, domain_commandexecuterequest_base_command, domain_commandexecuterequest_command_string, domain_commandexecuterequest_device_id, domain_commandexecuterequest_id, domain_commandexecuterequest_persist, domain_commandexecuterequest_session_id):
        data = assign_params(base_command=domain_commandexecuterequest_base_command, command_string=domain_commandexecuterequest_command_string, device_id=domain_commandexecuterequest_device_id,
                             id=domain_commandexecuterequest_id, persist=domain_commandexecuterequest_persist, session_id=domain_commandexecuterequest_session_id)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'real-time-response/entities/active-responder-command/v1', json_data=data, headers=headers)

        return response

    def rtr_execute_admin_command_request(self, domain_commandexecuterequest_base_command, domain_commandexecuterequest_command_string, domain_commandexecuterequest_device_id, domain_commandexecuterequest_id, domain_commandexecuterequest_persist, domain_commandexecuterequest_session_id):
        data = assign_params(base_command=domain_commandexecuterequest_base_command, command_string=domain_commandexecuterequest_command_string, device_id=domain_commandexecuterequest_device_id,
                             id=domain_commandexecuterequest_id, persist=domain_commandexecuterequest_persist, session_id=domain_commandexecuterequest_session_id)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'real-time-response/entities/admin-command/v1', json_data=data, headers=headers)

        return response

    def rtr_execute_command_request(self, domain_commandexecuterequest_base_command, domain_commandexecuterequest_command_string, domain_commandexecuterequest_device_id, domain_commandexecuterequest_id, domain_commandexecuterequest_persist, domain_commandexecuterequest_session_id):
        data = assign_params(base_command=domain_commandexecuterequest_base_command, command_string=domain_commandexecuterequest_command_string, device_id=domain_commandexecuterequest_device_id,
                             id=domain_commandexecuterequest_id, persist=domain_commandexecuterequest_persist, session_id=domain_commandexecuterequest_session_id)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'real-time-response/entities/command/v1', json_data=data, headers=headers)

        return response

    def rtr_get_extracted_file_contents_request(self, session_id, sha256, filename):
        params = assign_params(session_id=session_id, sha256=sha256, filename=filename)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'get', 'real-time-response/entities/extracted-file-contents/v1', params=params, headers=headers)

        return response

    def rtr_get_put_files_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'real-time-response/entities/put-files/v1', params=params, headers=headers)

        return response

    def rtr_get_scripts_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'real-time-response/entities/scripts/v1', params=params, headers=headers)

        return response

    def rtr_init_session_request(self, domain_initrequest_device_id, domain_initrequest_origin, domain_initrequest_queue_offline):
        data = assign_params(device_id=domain_initrequest_device_id, origin=domain_initrequest_origin,
                             queue_offline=domain_initrequest_queue_offline)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'real-time-response/entities/sessions/v1', json_data=data, headers=headers)

        return response

    def rtr_list_all_sessions_request(self, offset, limit, sort, filter_):
        params = assign_params(offset=offset, limit=limit, sort=sort, filter=filter_)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'real-time-response/queries/sessions/v1', params=params, headers=headers)

        return response

    def rtr_list_files_request(self, session_id):
        params = assign_params(session_id=session_id)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'real-time-response/entities/file/v1', params=params, headers=headers)

        return response

    def rtr_list_put_files_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'real-time-response/queries/put-files/v1', params=params, headers=headers)

        return response

    def rtr_list_queued_sessions_request(self, msa_idsrequest_ids):
        data = assign_params(ids=msa_idsrequest_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'real-time-response/entities/queued-sessions/GET/v1', json_data=data, headers=headers)

        return response

    def rtr_list_scripts_request(self, filter_, offset, limit, sort):
        params = assign_params(filter=filter_, offset=offset, limit=limit, sort=sort)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'real-time-response/queries/scripts/v1', params=params, headers=headers)

        return response

    def rtr_list_sessions_request(self, msa_idsrequest_ids):
        data = assign_params(ids=msa_idsrequest_ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'real-time-response/entities/sessions/GET/v1', json_data=data, headers=headers)

        return response

    def rtr_pulse_session_request(self, domain_initrequest_device_id, domain_initrequest_origin, domain_initrequest_queue_offline):
        data = assign_params(device_id=domain_initrequest_device_id, origin=domain_initrequest_origin,
                             queue_offline=domain_initrequest_queue_offline)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'real-time-response/entities/refresh-session/v1', json_data=data, headers=headers)

        return response

    def rtr_update_scripts_request(self, id_, file, description, name, comments_for_audit_log, permission_type, content, platform):
        data = assign_params(id=id_, file=file, description=description, name=name,
                             comments_for_audit_log=comments_for_audit_log, permission_type=permission_type, content=content, platform=platform)

        headers = self.cs_client._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self.cs_client.http_request('patch', 'real-time-response/entities/scripts/v1', json_data=data, headers=headers)

        return response

    def scan_samples_request(self, mlscanner_samplesscanparameters_samples):
        data = assign_params(samples=mlscanner_samplesscanparameters_samples)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'scanner/entities/scans/v1', json_data=data, headers=headers)

        return response

    def set_device_control_policies_precedence_request(self, requests_setpolicyprecedencereqv1_ids, requests_setpolicyprecedencereqv1_platform_name):
        data = assign_params(ids=requests_setpolicyprecedencereqv1_ids,
                             platform_name=requests_setpolicyprecedencereqv1_platform_name)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'policy/entities/device-control-precedence/v1', json_data=data, headers=headers)

        return response

    def set_firewall_policies_precedence_request(self, requests_setpolicyprecedencereqv1_ids, requests_setpolicyprecedencereqv1_platform_name):
        data = assign_params(ids=requests_setpolicyprecedencereqv1_ids,
                             platform_name=requests_setpolicyprecedencereqv1_platform_name)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'policy/entities/firewall-precedence/v1', json_data=data, headers=headers)

        return response

    def set_prevention_policies_precedence_request(self, requests_setpolicyprecedencereqv1_ids, requests_setpolicyprecedencereqv1_platform_name):
        data = assign_params(ids=requests_setpolicyprecedencereqv1_ids,
                             platform_name=requests_setpolicyprecedencereqv1_platform_name)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'policy/entities/prevention-precedence/v1', json_data=data, headers=headers)

        return response

    def set_sensor_update_policies_precedence_request(self, requests_setpolicyprecedencereqv1_ids, requests_setpolicyprecedencereqv1_platform_name):
        data = assign_params(ids=requests_setpolicyprecedencereqv1_ids,
                             platform_name=requests_setpolicyprecedencereqv1_platform_name)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'policy/entities/sensor-update-precedence/v1', json_data=data, headers=headers)

        return response

    def setrt_response_policies_precedence_request(self, requests_setpolicyprecedencereqv1_ids, requests_setpolicyprecedencereqv1_platform_name):
        data = assign_params(ids=requests_setpolicyprecedencereqv1_ids,
                             platform_name=requests_setpolicyprecedencereqv1_platform_name)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'policy/entities/response-precedence/v1', json_data=data, headers=headers)

        return response

    def submit_request(self, falconx_submissionparametersv1_sandbox, falconx_submissionparametersv1_user_tags):
        data = assign_params(sandbox=falconx_submissionparametersv1_sandbox, user_tags=falconx_submissionparametersv1_user_tags)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'falconx/entities/submissions/v1', json_data=data, headers=headers)

        return response

    def tokenscreate_request(self, api_tokencreaterequestv1_expires_timestamp, api_tokencreaterequestv1_label, api_tokencreaterequestv1_type):
        data = assign_params(expires_timestamp=api_tokencreaterequestv1_expires_timestamp,
                             label=api_tokencreaterequestv1_label, type=api_tokencreaterequestv1_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'installation-tokens/entities/tokens/v1', json_data=data, headers=headers)

        return response

    def tokensdelete_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('delete', 'installation-tokens/entities/tokens/v1', params=params, headers=headers)

        return response

    def tokensquery_request(self, offset, limit, sort, filter_):
        params = assign_params(offset=offset, limit=limit, sort=sort, filter=filter_)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'installation-tokens/queries/tokens/v1', params=params, headers=headers)

        return response

    def tokensread_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('get', 'installation-tokens/entities/tokens/v1', params=params, headers=headers)

        return response

    def tokensupdate_request(self, ids, api_tokenpatchrequestv1_expires_timestamp, api_tokenpatchrequestv1_label, api_tokenpatchrequestv1_revoked):
        params = assign_params(ids=ids)
        data = assign_params(expires_timestamp=api_tokenpatchrequestv1_expires_timestamp,
                             label=api_tokenpatchrequestv1_label, revoked=api_tokenpatchrequestv1_revoked)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'installation-tokens/entities/tokens/v1',
                                               params=params, json_data=data, headers=headers)

        return response

    def trigger_scan_request(self, scan_type):
        params = assign_params(scan_type=scan_type)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'kubernetes-protection/entities/scan/trigger/v1', params=params, headers=headers)

        return response

    def update_actionv1_request(self, domain_updateactionrequest_frequency, domain_updateactionrequest_id, domain_updateactionrequest_recipients, domain_updateactionrequest_status):
        data = assign_params(frequency=domain_updateactionrequest_frequency, id=domain_updateactionrequest_id,
                             recipients=domain_updateactionrequest_recipients, status=domain_updateactionrequest_status)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'recon/entities/actions/v1', json_data=data, headers=headers)

        return response

    def update_detects_by_idsv2_request(self, domain_detectsentitiespatchrequest_assigned_to_uuid, domain_detectsentitiespatchrequest_comment, domain_detectsentitiespatchrequest_ids, domain_detectsentitiespatchrequest_show_in_ui, domain_detectsentitiespatchrequest_status):
        data = assign_params(assigned_to_uuid=domain_detectsentitiespatchrequest_assigned_to_uuid, comment=domain_detectsentitiespatchrequest_comment,
                             ids=domain_detectsentitiespatchrequest_ids, show_in_ui=domain_detectsentitiespatchrequest_show_in_ui, status=domain_detectsentitiespatchrequest_status)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'detects/entities/detects/v2', json_data=data, headers=headers)

        return response

    def update_device_control_policies_request(self, requests_updatedevicecontrolpoliciesv1_resources):
        data = assign_params(resources=requests_updatedevicecontrolpoliciesv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'policy/entities/device-control/v1', json_data=data, headers=headers)

        return response

    def update_device_tags_request(self, domain_updatedevicetagsrequestv1_action, domain_updatedevicetagsrequestv1_device_ids, domain_updatedevicetagsrequestv1_tags):
        data = assign_params(action=domain_updatedevicetagsrequestv1_action,
                             device_ids=domain_updatedevicetagsrequestv1_device_ids, tags=domain_updatedevicetagsrequestv1_tags)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'devices/entities/devices/tags/v1', json_data=data, headers=headers)

        return response

    def update_firewall_policies_request(self, requests_updatefirewallpoliciesv1_resources):
        data = assign_params(resources=requests_updatefirewallpoliciesv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'policy/entities/firewall/v1', json_data=data, headers=headers)

        return response

    def update_host_groups_request(self, requests_updategroupsv1_resources):
        data = assign_params(resources=requests_updategroupsv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'devices/entities/host-groups/v1', json_data=data, headers=headers)

        return response

    def update_notificationsv1_request(self, domain_updatenotificationrequestv1_assigned_to_uuid, domain_updatenotificationrequestv1_id, domain_updatenotificationrequestv1_status):
        data = assign_params(assigned_to_uuid=domain_updatenotificationrequestv1_assigned_to_uuid,
                             id=domain_updatenotificationrequestv1_id, status=domain_updatenotificationrequestv1_status)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'recon/entities/notifications/v1', json_data=data, headers=headers)

        return response

    def update_prevention_policies_request(self, requests_updatepreventionpoliciesv1_resources):
        data = assign_params(resources=requests_updatepreventionpoliciesv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'policy/entities/prevention/v1', json_data=data, headers=headers)

        return response

    def update_rulesv1_request(self, domain_updaterulerequestv1_filter, domain_updaterulerequestv1_id, domain_updaterulerequestv1_name, domain_updaterulerequestv1_permissions, domain_updaterulerequestv1_priority):
        data = assign_params(filter=domain_updaterulerequestv1_filter, id=domain_updaterulerequestv1_id, name=domain_updaterulerequestv1_name,
                             permissions=domain_updaterulerequestv1_permissions, priority=domain_updaterulerequestv1_priority)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'recon/entities/rules/v1', json_data=data, headers=headers)

        return response

    def update_sensor_update_policies_request(self, requests_updatesensorupdatepoliciesv1_resources):
        data = assign_params(resources=requests_updatesensorupdatepoliciesv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'policy/entities/sensor-update/v1', json_data=data, headers=headers)

        return response

    def update_sensor_update_policiesv2_request(self, requests_updatesensorupdatepoliciesv2_resources):
        data = assign_params(resources=requests_updatesensorupdatepoliciesv2_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'policy/entities/sensor-update/v2', json_data=data, headers=headers)

        return response

    def update_sensor_visibility_exclusionsv1_request(self, requests_svexclusionupdatereqv1_comment, requests_svexclusionupdatereqv1_groups, requests_svexclusionupdatereqv1_id, requests_svexclusionupdatereqv1_value):
        data = assign_params(comment=requests_svexclusionupdatereqv1_comment, groups=requests_svexclusionupdatereqv1_groups,
                             id=requests_svexclusionupdatereqv1_id, value=requests_svexclusionupdatereqv1_value)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'policy/entities/sv-exclusions/v1', json_data=data, headers=headers)

        return response

    def update_user_request(self, user_uuid, domain_updateuserfields_firstname, domain_updateuserfields_lastname):
        params = assign_params(user_uuid=user_uuid)
        data = assign_params(firstName=domain_updateuserfields_firstname, lastName=domain_updateuserfields_lastname)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'users/entities/users/v1', params=params, json_data=data, headers=headers)

        return response

    def update_user_groups_request(self, domain_usergroupsrequestv1_resources):
        data = assign_params(resources=domain_usergroupsrequestv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'mssp/entities/user-groups/v1', json_data=data, headers=headers)

        return response

    def updateaws_account_request(self, ids, region):
        params = assign_params(ids=ids, region=region)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'patch', 'kubernetes-protection/entities/accounts/aws/v1', params=params, headers=headers)

        return response

    def updateaws_accounts_request(self, models_updateawsaccountsv1_resources):
        data = assign_params(resources=models_updateawsaccountsv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'cloud-connect-aws/entities/accounts/v1', json_data=data, headers=headers)

        return response

    def updatecid_groups_request(self, domain_cidgroupsrequestv1_resources):
        data = assign_params(resources=domain_cidgroupsrequestv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'mssp/entities/cid-groups/v1', json_data=data, headers=headers)

        return response

    def updatecspm_azure_tenant_default_subscriptionid_request(self, tenant_id, subscription_id):
        params = assign_params(tenant_id=tenant_id, subscription_id=subscription_id)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'patch', 'cloud-connect-cspm-azure/entities/default-subscription-id/v1', params=params, headers=headers)

        return response

    def updatecspm_policy_settings_request(self, registration_policyrequestextv1_resources):
        data = assign_params(resources=registration_policyrequestextv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'settings/entities/policy/v1', json_data=data, headers=headers)

        return response

    def updatecspm_scan_schedule_request(self, registration_scanscheduleupdaterequestv1_resources):
        data = assign_params(resources=registration_scanscheduleupdaterequestv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'settings/scan-schedule/v1', json_data=data, headers=headers)

        return response

    def updateioa_exclusionsv1_request(self, requests_ioaexclusionupdatereqv1_cl_regex, requests_ioaexclusionupdatereqv1_comment, requests_ioaexclusionupdatereqv1_description, requests_ioaexclusionupdatereqv1_detection_json, requests_ioaexclusionupdatereqv1_groups, requests_ioaexclusionupdatereqv1_id, requests_ioaexclusionupdatereqv1_ifn_regex, requests_ioaexclusionupdatereqv1_name, requests_ioaexclusionupdatereqv1_pattern_id, requests_ioaexclusionupdatereqv1_pattern_name):
        data = assign_params(cl_regex=requests_ioaexclusionupdatereqv1_cl_regex, comment=requests_ioaexclusionupdatereqv1_comment, description=requests_ioaexclusionupdatereqv1_description, detection_json=requests_ioaexclusionupdatereqv1_detection_json, groups=requests_ioaexclusionupdatereqv1_groups,
                             id=requests_ioaexclusionupdatereqv1_id, ifn_regex=requests_ioaexclusionupdatereqv1_ifn_regex, name=requests_ioaexclusionupdatereqv1_name, pattern_id=requests_ioaexclusionupdatereqv1_pattern_id, pattern_name=requests_ioaexclusionupdatereqv1_pattern_name)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'policy/entities/ioa-exclusions/v1', json_data=data, headers=headers)

        return response

    def updateioc_request(self, api_iocviewrecord_batch_id, api_iocviewrecord_created_by, api_iocviewrecord_created_timestamp, api_iocviewrecord_description, api_iocviewrecord_expiration_days, api_iocviewrecord_expiration_timestamp, api_iocviewrecord_modified_by, api_iocviewrecord_modified_timestamp, api_iocviewrecord_policy, api_iocviewrecord_share_level, api_iocviewrecord_source, api_iocviewrecord_type, api_iocviewrecord_value, type_, value):
        params = assign_params(type=type_, value=value)
        data = assign_params(batch_id=api_iocviewrecord_batch_id, created_by=api_iocviewrecord_created_by, created_timestamp=api_iocviewrecord_created_timestamp, description=api_iocviewrecord_description, expiration_days=api_iocviewrecord_expiration_days, expiration_timestamp=api_iocviewrecord_expiration_timestamp,
                             modified_by=api_iocviewrecord_modified_by, modified_timestamp=api_iocviewrecord_modified_timestamp, policy=api_iocviewrecord_policy, share_level=api_iocviewrecord_share_level, source=api_iocviewrecord_source, type=api_iocviewrecord_type, value=api_iocviewrecord_value)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'indicators/entities/iocs/v1',
                                               params=params, json_data=data, headers=headers)

        return response

    def updateml_exclusionsv1_request(self, requests_svexclusionupdatereqv1_comment, requests_svexclusionupdatereqv1_groups, requests_svexclusionupdatereqv1_id, requests_svexclusionupdatereqv1_value):
        data = assign_params(comment=requests_svexclusionupdatereqv1_comment, groups=requests_svexclusionupdatereqv1_groups,
                             id=requests_svexclusionupdatereqv1_id, value=requests_svexclusionupdatereqv1_value)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'policy/entities/ml-exclusions/v1', json_data=data, headers=headers)

        return response

    def updatepolicycontainer_request(self, fwmgr_api_policycontainerupsertrequestv1_default_inbound, fwmgr_api_policycontainerupsertrequestv1_default_outbound, fwmgr_api_policycontainerupsertrequestv1_enforce, fwmgr_api_policycontainerupsertrequestv1_is_default_policy, fwmgr_api_policycontainerupsertrequestv1_platform_id, fwmgr_api_policycontainerupsertrequestv1_policy_id, fwmgr_api_policycontainerupsertrequestv1_rule_group_ids, fwmgr_api_policycontainerupsertrequestv1_test_mode, fwmgr_api_policycontainerupsertrequestv1_tracking):
        data = assign_params(default_inbound=fwmgr_api_policycontainerupsertrequestv1_default_inbound, default_outbound=fwmgr_api_policycontainerupsertrequestv1_default_outbound, enforce=fwmgr_api_policycontainerupsertrequestv1_enforce, is_default_policy=fwmgr_api_policycontainerupsertrequestv1_is_default_policy,
                             platform_id=fwmgr_api_policycontainerupsertrequestv1_platform_id, policy_id=fwmgr_api_policycontainerupsertrequestv1_policy_id, rule_group_ids=fwmgr_api_policycontainerupsertrequestv1_rule_group_ids, test_mode=fwmgr_api_policycontainerupsertrequestv1_test_mode, tracking=fwmgr_api_policycontainerupsertrequestv1_tracking)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('put', 'fwmgr/entities/policies/v1', json_data=data, headers=headers)

        return response

    def updatert_response_policies_request(self, requests_updatertresponsepoliciesv1_resources):
        data = assign_params(resources=requests_updatertresponsepoliciesv1_resources)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'policy/entities/response/v1', json_data=data, headers=headers)

        return response

    def updaterulegroup_request(self, comment, fwmgr_api_rulegroupmodifyrequestv1_diff_operations, fwmgr_api_rulegroupmodifyrequestv1_diff_type, fwmgr_api_rulegroupmodifyrequestv1_id, fwmgr_api_rulegroupmodifyrequestv1_rule_ids, fwmgr_api_rulegroupmodifyrequestv1_rule_versions, fwmgr_api_rulegroupmodifyrequestv1_tracking):
        params = assign_params(comment=comment)
        data = assign_params(diff_operations=fwmgr_api_rulegroupmodifyrequestv1_diff_operations, diff_type=fwmgr_api_rulegroupmodifyrequestv1_diff_type, id=fwmgr_api_rulegroupmodifyrequestv1_id,
                             rule_ids=fwmgr_api_rulegroupmodifyrequestv1_rule_ids, rule_versions=fwmgr_api_rulegroupmodifyrequestv1_rule_versions, tracking=fwmgr_api_rulegroupmodifyrequestv1_tracking)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'fwmgr/entities/rule-groups/v1',
                                               params=params, json_data=data, headers=headers)

        return response

    def updaterulegroup_mixin0_request(self, api_rulegroupmodifyrequestv1_comment, api_rulegroupmodifyrequestv1_description, api_rulegroupmodifyrequestv1_enabled, api_rulegroupmodifyrequestv1_id, api_rulegroupmodifyrequestv1_name, api_rulegroupmodifyrequestv1_rulegroup_version):
        data = assign_params(comment=api_rulegroupmodifyrequestv1_comment, description=api_rulegroupmodifyrequestv1_description, enabled=api_rulegroupmodifyrequestv1_enabled,
                             id=api_rulegroupmodifyrequestv1_id, name=api_rulegroupmodifyrequestv1_name, rulegroup_version=api_rulegroupmodifyrequestv1_rulegroup_version)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'ioarules/entities/rule-groups/v1', json_data=data, headers=headers)

        return response

    def updaterules_request(self, api_ruleupdatesrequestv1_comment, api_ruleupdatesrequestv1_rule_updates, api_ruleupdatesrequestv1_rulegroup_id, api_ruleupdatesrequestv1_rulegroup_version):
        data = assign_params(comment=api_ruleupdatesrequestv1_comment, rule_updates=api_ruleupdatesrequestv1_rule_updates,
                             rulegroup_id=api_ruleupdatesrequestv1_rulegroup_id, rulegroup_version=api_ruleupdatesrequestv1_rulegroup_version)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('patch', 'ioarules/entities/rules/v1', json_data=data, headers=headers)

        return response

    def upload_samplev2_request(self, body, upfile, file_name, comment, is_confidential):
        params = assign_params(file_name=file_name, comment=comment, is_confidential=is_confidential)
        data = assign_params(body=body, upfile=upfile)

        headers = self.cs_client._headers
        headers['Content-Type'] = 'application/octet-stream'

        response = self.cs_client.http_request('post', 'samples/entities/samples/v2',
                                               params=params, json_data=data, headers=headers)

        return response

    def upload_samplev3_request(self, body, upfile, file_name, comment, is_confidential):
        params = assign_params(file_name=file_name, comment=comment, is_confidential=is_confidential)
        data = assign_params(body=body, upfile=upfile)

        headers = self.cs_client._headers
        headers['Content-Type'] = 'application/octet-stream'

        response = self.cs_client.http_request('post', 'samples/entities/samples/v3',
                                               params=params, json_data=data, headers=headers)

        return response

    def validate_request(self, api_validationrequestv1_fields):
        data = assign_params(fields=api_validationrequestv1_fields)

        headers = self.cs_client._headers

        response = self.cs_client.http_request('post', 'ioarules/entities/rules/validate/v1', json_data=data, headers=headers)

        return response

    def verifyaws_account_access_request(self, ids):
        params = assign_params(ids=ids)

        headers = self.cs_client._headers

        response = self.cs_client.http_request(
            'post', 'cloud-connect-aws/entities/verify-account-access/v1', params=params, headers=headers)

        return response


def add_role_command(client, args):
    domain_mssprolerequestv1_resources = argToList(args.get('domain_mssprolerequestv1_resources', []))

    response = client.add_role_request(domain_mssprolerequestv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainMSSPRoleResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def add_user_group_members_command(client, args):
    domain_usergroupmembersrequestv1_resources = argToList(args.get('domain_usergroupmembersrequestv1_resources', []))

    response = client.add_user_group_members_request(domain_usergroupmembersrequestv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainUserGroupMembersResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def addcid_group_members_command(client, args):
    domain_cidgroupmembersrequestv1_resources = argToList(args.get('domain_cidgroupmembersrequestv1_resources', []))

    response = client.addcid_group_members_request(domain_cidgroupmembersrequestv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainCIDGroupMembersResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def aggregate_allow_list_command(client, args):
    msa_aggregatequeryrequest_date_ranges = argToList(args.get('msa_aggregatequeryrequest_date_ranges', []))
    msa_aggregatequeryrequest_field = str(args.get('msa_aggregatequeryrequest_field', ''))
    msa_aggregatequeryrequest_filter = str(args.get('msa_aggregatequeryrequest_filter', ''))
    msa_aggregatequeryrequest_interval = str(args.get('msa_aggregatequeryrequest_interval', ''))
    msa_aggregatequeryrequest_min_doc_count = args.get('msa_aggregatequeryrequest_min_doc_count', None)
    msa_aggregatequeryrequest_missing = str(args.get('msa_aggregatequeryrequest_missing', ''))
    msa_aggregatequeryrequest_name = str(args.get('msa_aggregatequeryrequest_name', ''))
    msa_aggregatequeryrequest_q = str(args.get('msa_aggregatequeryrequest_q', ''))
    msa_aggregatequeryrequest_ranges = argToList(args.get('msa_aggregatequeryrequest_ranges', []))
    msa_aggregatequeryrequest_size = args.get('msa_aggregatequeryrequest_size', None)
    msa_aggregatequeryrequest_sort = str(args.get('msa_aggregatequeryrequest_sort', ''))
    msa_aggregatequeryrequest_sub_aggregates = argToList(args.get('msa_aggregatequeryrequest_sub_aggregates', []))
    msa_aggregatequeryrequest_time_zone = str(args.get('msa_aggregatequeryrequest_time_zone', ''))
    msa_aggregatequeryrequest_type = str(args.get('msa_aggregatequeryrequest_type', ''))

    response = client.aggregate_allow_list_request(msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing,
                                                   msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaAggregatesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def aggregate_block_list_command(client, args):
    msa_aggregatequeryrequest_date_ranges = argToList(args.get('msa_aggregatequeryrequest_date_ranges', []))
    msa_aggregatequeryrequest_field = str(args.get('msa_aggregatequeryrequest_field', ''))
    msa_aggregatequeryrequest_filter = str(args.get('msa_aggregatequeryrequest_filter', ''))
    msa_aggregatequeryrequest_interval = str(args.get('msa_aggregatequeryrequest_interval', ''))
    msa_aggregatequeryrequest_min_doc_count = args.get('msa_aggregatequeryrequest_min_doc_count', None)
    msa_aggregatequeryrequest_missing = str(args.get('msa_aggregatequeryrequest_missing', ''))
    msa_aggregatequeryrequest_name = str(args.get('msa_aggregatequeryrequest_name', ''))
    msa_aggregatequeryrequest_q = str(args.get('msa_aggregatequeryrequest_q', ''))
    msa_aggregatequeryrequest_ranges = argToList(args.get('msa_aggregatequeryrequest_ranges', []))
    msa_aggregatequeryrequest_size = args.get('msa_aggregatequeryrequest_size', None)
    msa_aggregatequeryrequest_sort = str(args.get('msa_aggregatequeryrequest_sort', ''))
    msa_aggregatequeryrequest_sub_aggregates = argToList(args.get('msa_aggregatequeryrequest_sub_aggregates', []))
    msa_aggregatequeryrequest_time_zone = str(args.get('msa_aggregatequeryrequest_time_zone', ''))
    msa_aggregatequeryrequest_type = str(args.get('msa_aggregatequeryrequest_type', ''))

    response = client.aggregate_block_list_request(msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing,
                                                   msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaAggregatesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def aggregate_detections_command(client, args):
    msa_aggregatequeryrequest_date_ranges = argToList(args.get('msa_aggregatequeryrequest_date_ranges', []))
    msa_aggregatequeryrequest_field = str(args.get('msa_aggregatequeryrequest_field', ''))
    msa_aggregatequeryrequest_filter = str(args.get('msa_aggregatequeryrequest_filter', ''))
    msa_aggregatequeryrequest_interval = str(args.get('msa_aggregatequeryrequest_interval', ''))
    msa_aggregatequeryrequest_min_doc_count = args.get('msa_aggregatequeryrequest_min_doc_count', None)
    msa_aggregatequeryrequest_missing = str(args.get('msa_aggregatequeryrequest_missing', ''))
    msa_aggregatequeryrequest_name = str(args.get('msa_aggregatequeryrequest_name', ''))
    msa_aggregatequeryrequest_q = str(args.get('msa_aggregatequeryrequest_q', ''))
    msa_aggregatequeryrequest_ranges = argToList(args.get('msa_aggregatequeryrequest_ranges', []))
    msa_aggregatequeryrequest_size = args.get('msa_aggregatequeryrequest_size', None)
    msa_aggregatequeryrequest_sort = str(args.get('msa_aggregatequeryrequest_sort', ''))
    msa_aggregatequeryrequest_sub_aggregates = argToList(args.get('msa_aggregatequeryrequest_sub_aggregates', []))
    msa_aggregatequeryrequest_time_zone = str(args.get('msa_aggregatequeryrequest_time_zone', ''))
    msa_aggregatequeryrequest_type = str(args.get('msa_aggregatequeryrequest_type', ''))

    response = client.aggregate_detections_request(msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing,
                                                   msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaAggregatesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def aggregate_device_count_collection_command(client, args):
    msa_aggregatequeryrequest_date_ranges = argToList(args.get('msa_aggregatequeryrequest_date_ranges', []))
    msa_aggregatequeryrequest_field = str(args.get('msa_aggregatequeryrequest_field', ''))
    msa_aggregatequeryrequest_filter = str(args.get('msa_aggregatequeryrequest_filter', ''))
    msa_aggregatequeryrequest_interval = str(args.get('msa_aggregatequeryrequest_interval', ''))
    msa_aggregatequeryrequest_min_doc_count = args.get('msa_aggregatequeryrequest_min_doc_count', None)
    msa_aggregatequeryrequest_missing = str(args.get('msa_aggregatequeryrequest_missing', ''))
    msa_aggregatequeryrequest_name = str(args.get('msa_aggregatequeryrequest_name', ''))
    msa_aggregatequeryrequest_q = str(args.get('msa_aggregatequeryrequest_q', ''))
    msa_aggregatequeryrequest_ranges = argToList(args.get('msa_aggregatequeryrequest_ranges', []))
    msa_aggregatequeryrequest_size = args.get('msa_aggregatequeryrequest_size', None)
    msa_aggregatequeryrequest_sort = str(args.get('msa_aggregatequeryrequest_sort', ''))
    msa_aggregatequeryrequest_sub_aggregates = argToList(args.get('msa_aggregatequeryrequest_sub_aggregates', []))
    msa_aggregatequeryrequest_time_zone = str(args.get('msa_aggregatequeryrequest_time_zone', ''))
    msa_aggregatequeryrequest_type = str(args.get('msa_aggregatequeryrequest_type', ''))

    response = client.aggregate_device_count_collection_request(msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing,
                                                                msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaAggregatesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def aggregate_escalations_command(client, args):
    msa_aggregatequeryrequest_date_ranges = argToList(args.get('msa_aggregatequeryrequest_date_ranges', []))
    msa_aggregatequeryrequest_field = str(args.get('msa_aggregatequeryrequest_field', ''))
    msa_aggregatequeryrequest_filter = str(args.get('msa_aggregatequeryrequest_filter', ''))
    msa_aggregatequeryrequest_interval = str(args.get('msa_aggregatequeryrequest_interval', ''))
    msa_aggregatequeryrequest_min_doc_count = args.get('msa_aggregatequeryrequest_min_doc_count', None)
    msa_aggregatequeryrequest_missing = str(args.get('msa_aggregatequeryrequest_missing', ''))
    msa_aggregatequeryrequest_name = str(args.get('msa_aggregatequeryrequest_name', ''))
    msa_aggregatequeryrequest_q = str(args.get('msa_aggregatequeryrequest_q', ''))
    msa_aggregatequeryrequest_ranges = argToList(args.get('msa_aggregatequeryrequest_ranges', []))
    msa_aggregatequeryrequest_size = args.get('msa_aggregatequeryrequest_size', None)
    msa_aggregatequeryrequest_sort = str(args.get('msa_aggregatequeryrequest_sort', ''))
    msa_aggregatequeryrequest_sub_aggregates = argToList(args.get('msa_aggregatequeryrequest_sub_aggregates', []))
    msa_aggregatequeryrequest_time_zone = str(args.get('msa_aggregatequeryrequest_time_zone', ''))
    msa_aggregatequeryrequest_type = str(args.get('msa_aggregatequeryrequest_type', ''))

    response = client.aggregate_escalations_request(msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing,
                                                    msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaAggregatesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def aggregate_notificationsv1_command(client, args):
    msa_aggregatequeryrequest_date_ranges = argToList(args.get('msa_aggregatequeryrequest_date_ranges', []))
    msa_aggregatequeryrequest_field = str(args.get('msa_aggregatequeryrequest_field', ''))
    msa_aggregatequeryrequest_filter = str(args.get('msa_aggregatequeryrequest_filter', ''))
    msa_aggregatequeryrequest_interval = str(args.get('msa_aggregatequeryrequest_interval', ''))
    msa_aggregatequeryrequest_min_doc_count = args.get('msa_aggregatequeryrequest_min_doc_count', None)
    msa_aggregatequeryrequest_missing = str(args.get('msa_aggregatequeryrequest_missing', ''))
    msa_aggregatequeryrequest_name = str(args.get('msa_aggregatequeryrequest_name', ''))
    msa_aggregatequeryrequest_q = str(args.get('msa_aggregatequeryrequest_q', ''))
    msa_aggregatequeryrequest_ranges = argToList(args.get('msa_aggregatequeryrequest_ranges', []))
    msa_aggregatequeryrequest_size = args.get('msa_aggregatequeryrequest_size', None)
    msa_aggregatequeryrequest_sort = str(args.get('msa_aggregatequeryrequest_sort', ''))
    msa_aggregatequeryrequest_sub_aggregates = argToList(args.get('msa_aggregatequeryrequest_sub_aggregates', []))
    msa_aggregatequeryrequest_time_zone = str(args.get('msa_aggregatequeryrequest_time_zone', ''))
    msa_aggregatequeryrequest_type = str(args.get('msa_aggregatequeryrequest_type', ''))

    response = client.aggregate_notificationsv1_request(msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing,
                                                        msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainAggregatesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def aggregate_remediations_command(client, args):
    msa_aggregatequeryrequest_date_ranges = argToList(args.get('msa_aggregatequeryrequest_date_ranges', []))
    msa_aggregatequeryrequest_field = str(args.get('msa_aggregatequeryrequest_field', ''))
    msa_aggregatequeryrequest_filter = str(args.get('msa_aggregatequeryrequest_filter', ''))
    msa_aggregatequeryrequest_interval = str(args.get('msa_aggregatequeryrequest_interval', ''))
    msa_aggregatequeryrequest_min_doc_count = args.get('msa_aggregatequeryrequest_min_doc_count', None)
    msa_aggregatequeryrequest_missing = str(args.get('msa_aggregatequeryrequest_missing', ''))
    msa_aggregatequeryrequest_name = str(args.get('msa_aggregatequeryrequest_name', ''))
    msa_aggregatequeryrequest_q = str(args.get('msa_aggregatequeryrequest_q', ''))
    msa_aggregatequeryrequest_ranges = argToList(args.get('msa_aggregatequeryrequest_ranges', []))
    msa_aggregatequeryrequest_size = args.get('msa_aggregatequeryrequest_size', None)
    msa_aggregatequeryrequest_sort = str(args.get('msa_aggregatequeryrequest_sort', ''))
    msa_aggregatequeryrequest_sub_aggregates = argToList(args.get('msa_aggregatequeryrequest_sub_aggregates', []))
    msa_aggregatequeryrequest_time_zone = str(args.get('msa_aggregatequeryrequest_time_zone', ''))
    msa_aggregatequeryrequest_type = str(args.get('msa_aggregatequeryrequest_type', ''))

    response = client.aggregate_remediations_request(msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing,
                                                     msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaAggregatesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def aggregateevents_command(client, args):
    fwmgr_msa_aggregatequeryrequest_date_ranges = argToList(args.get('fwmgr_msa_aggregatequeryrequest_date_ranges', []))
    fwmgr_msa_aggregatequeryrequest_field = str(args.get('fwmgr_msa_aggregatequeryrequest_field', ''))
    fwmgr_msa_aggregatequeryrequest_filter = str(args.get('fwmgr_msa_aggregatequeryrequest_filter', ''))
    fwmgr_msa_aggregatequeryrequest_interval = str(args.get('fwmgr_msa_aggregatequeryrequest_interval', ''))
    fwmgr_msa_aggregatequeryrequest_min_doc_count = args.get('fwmgr_msa_aggregatequeryrequest_min_doc_count', None)
    fwmgr_msa_aggregatequeryrequest_missing = str(args.get('fwmgr_msa_aggregatequeryrequest_missing', ''))
    fwmgr_msa_aggregatequeryrequest_name = str(args.get('fwmgr_msa_aggregatequeryrequest_name', ''))
    fwmgr_msa_aggregatequeryrequest_q = str(args.get('fwmgr_msa_aggregatequeryrequest_q', ''))
    fwmgr_msa_aggregatequeryrequest_ranges = argToList(args.get('fwmgr_msa_aggregatequeryrequest_ranges', []))
    fwmgr_msa_aggregatequeryrequest_size = args.get('fwmgr_msa_aggregatequeryrequest_size', None)
    fwmgr_msa_aggregatequeryrequest_sort = str(args.get('fwmgr_msa_aggregatequeryrequest_sort', ''))
    fwmgr_msa_aggregatequeryrequest_sub_aggregates = argToList(args.get('fwmgr_msa_aggregatequeryrequest_sub_aggregates', []))
    fwmgr_msa_aggregatequeryrequest_time_zone = str(args.get('fwmgr_msa_aggregatequeryrequest_time_zone', ''))
    fwmgr_msa_aggregatequeryrequest_type = str(args.get('fwmgr_msa_aggregatequeryrequest_type', ''))

    response = client.aggregateevents_request(fwmgr_msa_aggregatequeryrequest_date_ranges, fwmgr_msa_aggregatequeryrequest_field, fwmgr_msa_aggregatequeryrequest_filter, fwmgr_msa_aggregatequeryrequest_interval, fwmgr_msa_aggregatequeryrequest_min_doc_count, fwmgr_msa_aggregatequeryrequest_missing,
                                              fwmgr_msa_aggregatequeryrequest_name, fwmgr_msa_aggregatequeryrequest_q, fwmgr_msa_aggregatequeryrequest_ranges, fwmgr_msa_aggregatequeryrequest_size, fwmgr_msa_aggregatequeryrequest_sort, fwmgr_msa_aggregatequeryrequest_sub_aggregates, fwmgr_msa_aggregatequeryrequest_time_zone, fwmgr_msa_aggregatequeryrequest_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrapiAggregatesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def aggregatefc_incidents_command(client, args):
    msa_aggregatequeryrequest_date_ranges = argToList(args.get('msa_aggregatequeryrequest_date_ranges', []))
    msa_aggregatequeryrequest_field = str(args.get('msa_aggregatequeryrequest_field', ''))
    msa_aggregatequeryrequest_filter = str(args.get('msa_aggregatequeryrequest_filter', ''))
    msa_aggregatequeryrequest_interval = str(args.get('msa_aggregatequeryrequest_interval', ''))
    msa_aggregatequeryrequest_min_doc_count = args.get('msa_aggregatequeryrequest_min_doc_count', None)
    msa_aggregatequeryrequest_missing = str(args.get('msa_aggregatequeryrequest_missing', ''))
    msa_aggregatequeryrequest_name = str(args.get('msa_aggregatequeryrequest_name', ''))
    msa_aggregatequeryrequest_q = str(args.get('msa_aggregatequeryrequest_q', ''))
    msa_aggregatequeryrequest_ranges = argToList(args.get('msa_aggregatequeryrequest_ranges', []))
    msa_aggregatequeryrequest_size = args.get('msa_aggregatequeryrequest_size', None)
    msa_aggregatequeryrequest_sort = str(args.get('msa_aggregatequeryrequest_sort', ''))
    msa_aggregatequeryrequest_sub_aggregates = argToList(args.get('msa_aggregatequeryrequest_sub_aggregates', []))
    msa_aggregatequeryrequest_time_zone = str(args.get('msa_aggregatequeryrequest_time_zone', ''))
    msa_aggregatequeryrequest_type = str(args.get('msa_aggregatequeryrequest_type', ''))

    response = client.aggregatefc_incidents_request(msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing,
                                                    msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaAggregatesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def aggregatepolicyrules_command(client, args):
    fwmgr_msa_aggregatequeryrequest_date_ranges = argToList(args.get('fwmgr_msa_aggregatequeryrequest_date_ranges', []))
    fwmgr_msa_aggregatequeryrequest_field = str(args.get('fwmgr_msa_aggregatequeryrequest_field', ''))
    fwmgr_msa_aggregatequeryrequest_filter = str(args.get('fwmgr_msa_aggregatequeryrequest_filter', ''))
    fwmgr_msa_aggregatequeryrequest_interval = str(args.get('fwmgr_msa_aggregatequeryrequest_interval', ''))
    fwmgr_msa_aggregatequeryrequest_min_doc_count = args.get('fwmgr_msa_aggregatequeryrequest_min_doc_count', None)
    fwmgr_msa_aggregatequeryrequest_missing = str(args.get('fwmgr_msa_aggregatequeryrequest_missing', ''))
    fwmgr_msa_aggregatequeryrequest_name = str(args.get('fwmgr_msa_aggregatequeryrequest_name', ''))
    fwmgr_msa_aggregatequeryrequest_q = str(args.get('fwmgr_msa_aggregatequeryrequest_q', ''))
    fwmgr_msa_aggregatequeryrequest_ranges = argToList(args.get('fwmgr_msa_aggregatequeryrequest_ranges', []))
    fwmgr_msa_aggregatequeryrequest_size = args.get('fwmgr_msa_aggregatequeryrequest_size', None)
    fwmgr_msa_aggregatequeryrequest_sort = str(args.get('fwmgr_msa_aggregatequeryrequest_sort', ''))
    fwmgr_msa_aggregatequeryrequest_sub_aggregates = argToList(args.get('fwmgr_msa_aggregatequeryrequest_sub_aggregates', []))
    fwmgr_msa_aggregatequeryrequest_time_zone = str(args.get('fwmgr_msa_aggregatequeryrequest_time_zone', ''))
    fwmgr_msa_aggregatequeryrequest_type = str(args.get('fwmgr_msa_aggregatequeryrequest_type', ''))

    response = client.aggregatepolicyrules_request(fwmgr_msa_aggregatequeryrequest_date_ranges, fwmgr_msa_aggregatequeryrequest_field, fwmgr_msa_aggregatequeryrequest_filter, fwmgr_msa_aggregatequeryrequest_interval, fwmgr_msa_aggregatequeryrequest_min_doc_count, fwmgr_msa_aggregatequeryrequest_missing,
                                                   fwmgr_msa_aggregatequeryrequest_name, fwmgr_msa_aggregatequeryrequest_q, fwmgr_msa_aggregatequeryrequest_ranges, fwmgr_msa_aggregatequeryrequest_size, fwmgr_msa_aggregatequeryrequest_sort, fwmgr_msa_aggregatequeryrequest_sub_aggregates, fwmgr_msa_aggregatequeryrequest_time_zone, fwmgr_msa_aggregatequeryrequest_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrapiAggregatesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def aggregaterulegroups_command(client, args):
    fwmgr_msa_aggregatequeryrequest_date_ranges = argToList(args.get('fwmgr_msa_aggregatequeryrequest_date_ranges', []))
    fwmgr_msa_aggregatequeryrequest_field = str(args.get('fwmgr_msa_aggregatequeryrequest_field', ''))
    fwmgr_msa_aggregatequeryrequest_filter = str(args.get('fwmgr_msa_aggregatequeryrequest_filter', ''))
    fwmgr_msa_aggregatequeryrequest_interval = str(args.get('fwmgr_msa_aggregatequeryrequest_interval', ''))
    fwmgr_msa_aggregatequeryrequest_min_doc_count = args.get('fwmgr_msa_aggregatequeryrequest_min_doc_count', None)
    fwmgr_msa_aggregatequeryrequest_missing = str(args.get('fwmgr_msa_aggregatequeryrequest_missing', ''))
    fwmgr_msa_aggregatequeryrequest_name = str(args.get('fwmgr_msa_aggregatequeryrequest_name', ''))
    fwmgr_msa_aggregatequeryrequest_q = str(args.get('fwmgr_msa_aggregatequeryrequest_q', ''))
    fwmgr_msa_aggregatequeryrequest_ranges = argToList(args.get('fwmgr_msa_aggregatequeryrequest_ranges', []))
    fwmgr_msa_aggregatequeryrequest_size = args.get('fwmgr_msa_aggregatequeryrequest_size', None)
    fwmgr_msa_aggregatequeryrequest_sort = str(args.get('fwmgr_msa_aggregatequeryrequest_sort', ''))
    fwmgr_msa_aggregatequeryrequest_sub_aggregates = argToList(args.get('fwmgr_msa_aggregatequeryrequest_sub_aggregates', []))
    fwmgr_msa_aggregatequeryrequest_time_zone = str(args.get('fwmgr_msa_aggregatequeryrequest_time_zone', ''))
    fwmgr_msa_aggregatequeryrequest_type = str(args.get('fwmgr_msa_aggregatequeryrequest_type', ''))

    response = client.aggregaterulegroups_request(fwmgr_msa_aggregatequeryrequest_date_ranges, fwmgr_msa_aggregatequeryrequest_field, fwmgr_msa_aggregatequeryrequest_filter, fwmgr_msa_aggregatequeryrequest_interval, fwmgr_msa_aggregatequeryrequest_min_doc_count, fwmgr_msa_aggregatequeryrequest_missing,
                                                  fwmgr_msa_aggregatequeryrequest_name, fwmgr_msa_aggregatequeryrequest_q, fwmgr_msa_aggregatequeryrequest_ranges, fwmgr_msa_aggregatequeryrequest_size, fwmgr_msa_aggregatequeryrequest_sort, fwmgr_msa_aggregatequeryrequest_sub_aggregates, fwmgr_msa_aggregatequeryrequest_time_zone, fwmgr_msa_aggregatequeryrequest_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrapiAggregatesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def aggregaterules_command(client, args):
    fwmgr_msa_aggregatequeryrequest_date_ranges = argToList(args.get('fwmgr_msa_aggregatequeryrequest_date_ranges', []))
    fwmgr_msa_aggregatequeryrequest_field = str(args.get('fwmgr_msa_aggregatequeryrequest_field', ''))
    fwmgr_msa_aggregatequeryrequest_filter = str(args.get('fwmgr_msa_aggregatequeryrequest_filter', ''))
    fwmgr_msa_aggregatequeryrequest_interval = str(args.get('fwmgr_msa_aggregatequeryrequest_interval', ''))
    fwmgr_msa_aggregatequeryrequest_min_doc_count = args.get('fwmgr_msa_aggregatequeryrequest_min_doc_count', None)
    fwmgr_msa_aggregatequeryrequest_missing = str(args.get('fwmgr_msa_aggregatequeryrequest_missing', ''))
    fwmgr_msa_aggregatequeryrequest_name = str(args.get('fwmgr_msa_aggregatequeryrequest_name', ''))
    fwmgr_msa_aggregatequeryrequest_q = str(args.get('fwmgr_msa_aggregatequeryrequest_q', ''))
    fwmgr_msa_aggregatequeryrequest_ranges = argToList(args.get('fwmgr_msa_aggregatequeryrequest_ranges', []))
    fwmgr_msa_aggregatequeryrequest_size = args.get('fwmgr_msa_aggregatequeryrequest_size', None)
    fwmgr_msa_aggregatequeryrequest_sort = str(args.get('fwmgr_msa_aggregatequeryrequest_sort', ''))
    fwmgr_msa_aggregatequeryrequest_sub_aggregates = argToList(args.get('fwmgr_msa_aggregatequeryrequest_sub_aggregates', []))
    fwmgr_msa_aggregatequeryrequest_time_zone = str(args.get('fwmgr_msa_aggregatequeryrequest_time_zone', ''))
    fwmgr_msa_aggregatequeryrequest_type = str(args.get('fwmgr_msa_aggregatequeryrequest_type', ''))

    response = client.aggregaterules_request(fwmgr_msa_aggregatequeryrequest_date_ranges, fwmgr_msa_aggregatequeryrequest_field, fwmgr_msa_aggregatequeryrequest_filter, fwmgr_msa_aggregatequeryrequest_interval, fwmgr_msa_aggregatequeryrequest_min_doc_count, fwmgr_msa_aggregatequeryrequest_missing,
                                             fwmgr_msa_aggregatequeryrequest_name, fwmgr_msa_aggregatequeryrequest_q, fwmgr_msa_aggregatequeryrequest_ranges, fwmgr_msa_aggregatequeryrequest_size, fwmgr_msa_aggregatequeryrequest_sort, fwmgr_msa_aggregatequeryrequest_sub_aggregates, fwmgr_msa_aggregatequeryrequest_time_zone, fwmgr_msa_aggregatequeryrequest_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrapiAggregatesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def aggregates_detections_global_counts_command(client, args):
    filter_ = str(args.get('filter_', ''))

    response = client.aggregates_detections_global_counts_request(filter_)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaFacetsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def aggregates_events_command(client, args):
    msa_aggregatequeryrequest_date_ranges = argToList(args.get('msa_aggregatequeryrequest_date_ranges', []))
    msa_aggregatequeryrequest_field = str(args.get('msa_aggregatequeryrequest_field', ''))
    msa_aggregatequeryrequest_filter = str(args.get('msa_aggregatequeryrequest_filter', ''))
    msa_aggregatequeryrequest_interval = str(args.get('msa_aggregatequeryrequest_interval', ''))
    msa_aggregatequeryrequest_min_doc_count = args.get('msa_aggregatequeryrequest_min_doc_count', None)
    msa_aggregatequeryrequest_missing = str(args.get('msa_aggregatequeryrequest_missing', ''))
    msa_aggregatequeryrequest_name = str(args.get('msa_aggregatequeryrequest_name', ''))
    msa_aggregatequeryrequest_q = str(args.get('msa_aggregatequeryrequest_q', ''))
    msa_aggregatequeryrequest_ranges = argToList(args.get('msa_aggregatequeryrequest_ranges', []))
    msa_aggregatequeryrequest_size = args.get('msa_aggregatequeryrequest_size', None)
    msa_aggregatequeryrequest_sort = str(args.get('msa_aggregatequeryrequest_sort', ''))
    msa_aggregatequeryrequest_sub_aggregates = argToList(args.get('msa_aggregatequeryrequest_sub_aggregates', []))
    msa_aggregatequeryrequest_time_zone = str(args.get('msa_aggregatequeryrequest_time_zone', ''))
    msa_aggregatequeryrequest_type = str(args.get('msa_aggregatequeryrequest_type', ''))

    response = client.aggregates_events_request(msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing,
                                                msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaAggregatesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def aggregates_events_collections_command(client, args):
    msa_aggregatequeryrequest_date_ranges = argToList(args.get('msa_aggregatequeryrequest_date_ranges', []))
    msa_aggregatequeryrequest_field = str(args.get('msa_aggregatequeryrequest_field', ''))
    msa_aggregatequeryrequest_filter = str(args.get('msa_aggregatequeryrequest_filter', ''))
    msa_aggregatequeryrequest_interval = str(args.get('msa_aggregatequeryrequest_interval', ''))
    msa_aggregatequeryrequest_min_doc_count = args.get('msa_aggregatequeryrequest_min_doc_count', None)
    msa_aggregatequeryrequest_missing = str(args.get('msa_aggregatequeryrequest_missing', ''))
    msa_aggregatequeryrequest_name = str(args.get('msa_aggregatequeryrequest_name', ''))
    msa_aggregatequeryrequest_q = str(args.get('msa_aggregatequeryrequest_q', ''))
    msa_aggregatequeryrequest_ranges = argToList(args.get('msa_aggregatequeryrequest_ranges', []))
    msa_aggregatequeryrequest_size = args.get('msa_aggregatequeryrequest_size', None)
    msa_aggregatequeryrequest_sort = str(args.get('msa_aggregatequeryrequest_sort', ''))
    msa_aggregatequeryrequest_sub_aggregates = argToList(args.get('msa_aggregatequeryrequest_sub_aggregates', []))
    msa_aggregatequeryrequest_time_zone = str(args.get('msa_aggregatequeryrequest_time_zone', ''))
    msa_aggregatequeryrequest_type = str(args.get('msa_aggregatequeryrequest_type', ''))

    response = client.aggregates_events_collections_request(msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing,
                                                            msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaAggregatesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def aggregates_incidents_global_counts_command(client, args):
    filter_ = str(args.get('filter_', ''))

    response = client.aggregates_incidents_global_counts_request(filter_)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaFacetsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def aggregatesow_events_global_counts_command(client, args):
    filter_ = str(args.get('filter_', ''))

    response = client.aggregatesow_events_global_counts_request(filter_)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaFacetsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def apipreemptproxypostgraphql_command(client, args):

    response = client.apipreemptproxypostgraphql_request()
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def auditeventsquery_command(client, args):
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))

    response = client.auditeventsquery_request(offset, limit, sort, filter_)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def auditeventsread_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.auditeventsread_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiauditEventDetailsResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def batch_active_responder_cmd_command(client, args):
    timeout = int(args.get('timeout', 30))
    timeout_duration = str(args.get('timeout_duration', '30s'))
    domain_batchexecutecommandrequest_base_command = str(args.get('domain_batchexecutecommandrequest_base_command', ''))
    domain_batchexecutecommandrequest_batch_id = str(args.get('domain_batchexecutecommandrequest_batch_id', ''))
    domain_batchexecutecommandrequest_command_string = str(args.get('domain_batchexecutecommandrequest_command_string', ''))
    domain_batchexecutecommandrequest_optional_hosts = argToList(args.get('domain_batchexecutecommandrequest_optional_hosts', []))
    domain_batchexecutecommandrequest_persist_all = argToBoolean(args.get('domain_batchexecutecommandrequest_persist_all', False))

    response = client.batch_active_responder_cmd_request(timeout, timeout_duration, domain_batchexecutecommandrequest_base_command, domain_batchexecutecommandrequest_batch_id,
                                                         domain_batchexecutecommandrequest_command_string, domain_batchexecutecommandrequest_optional_hosts, domain_batchexecutecommandrequest_persist_all)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def batch_admin_cmd_command(client, args):
    timeout = int(args.get('timeout', 30))
    timeout_duration = str(args.get('timeout_duration', '30s'))
    domain_batchexecutecommandrequest_base_command = str(args.get('domain_batchexecutecommandrequest_base_command', ''))
    domain_batchexecutecommandrequest_batch_id = str(args.get('domain_batchexecutecommandrequest_batch_id', ''))
    domain_batchexecutecommandrequest_command_string = str(args.get('domain_batchexecutecommandrequest_command_string', ''))
    domain_batchexecutecommandrequest_optional_hosts = argToList(args.get('domain_batchexecutecommandrequest_optional_hosts', []))
    domain_batchexecutecommandrequest_persist_all = argToBoolean(args.get('domain_batchexecutecommandrequest_persist_all', False))

    response = client.batch_admin_cmd_request(timeout, timeout_duration, domain_batchexecutecommandrequest_base_command, domain_batchexecutecommandrequest_batch_id,
                                              domain_batchexecutecommandrequest_command_string, domain_batchexecutecommandrequest_optional_hosts, domain_batchexecutecommandrequest_persist_all)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def batch_cmd_command(client, args):
    timeout = int(args.get('timeout', 30))
    timeout_duration = str(args.get('timeout_duration', '30s'))
    domain_batchexecutecommandrequest_base_command = str(args.get('domain_batchexecutecommandrequest_base_command', ''))
    domain_batchexecutecommandrequest_batch_id = str(args.get('domain_batchexecutecommandrequest_batch_id', ''))
    domain_batchexecutecommandrequest_command_string = str(args.get('domain_batchexecutecommandrequest_command_string', ''))
    domain_batchexecutecommandrequest_optional_hosts = argToList(args.get('domain_batchexecutecommandrequest_optional_hosts', []))
    domain_batchexecutecommandrequest_persist_all = argToBoolean(args.get('domain_batchexecutecommandrequest_persist_all', False))

    response = client.batch_cmd_request(timeout, timeout_duration, domain_batchexecutecommandrequest_base_command, domain_batchexecutecommandrequest_batch_id,
                                        domain_batchexecutecommandrequest_command_string, domain_batchexecutecommandrequest_optional_hosts, domain_batchexecutecommandrequest_persist_all)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def batch_get_cmd_command(client, args):
    timeout = int(args.get('timeout', 30))
    timeout_duration = str(args.get('timeout_duration', '30s'))
    domain_batchgetcommandrequest_batch_id = str(args.get('domain_batchgetcommandrequest_batch_id', ''))
    domain_batchgetcommandrequest_file_path = str(args.get('domain_batchgetcommandrequest_file_path', ''))
    domain_batchgetcommandrequest_optional_hosts = argToList(args.get('domain_batchgetcommandrequest_optional_hosts', []))

    response = client.batch_get_cmd_request(timeout, timeout_duration, domain_batchgetcommandrequest_batch_id,
                                            domain_batchgetcommandrequest_file_path, domain_batchgetcommandrequest_optional_hosts)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def batch_get_cmd_status_command(client, args):
    timeout = int(args.get('timeout', 30))
    timeout_duration = str(args.get('timeout_duration', '30s'))
    batch_get_cmd_req_id = str(args.get('batch_get_cmd_req_id', ''))

    response = client.batch_get_cmd_status_request(timeout, timeout_duration, batch_get_cmd_req_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainBatchGetCmdStatusResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def batch_init_sessions_command(client, args):
    timeout = int(args.get('timeout', 30))
    timeout_duration = str(args.get('timeout_duration', '30s'))
    domain_batchinitsessionrequest_existing_batch_id = str(args.get('domain_batchinitsessionrequest_existing_batch_id', ''))
    domain_batchinitsessionrequest_host_ids = argToList(args.get('domain_batchinitsessionrequest_host_ids', []))
    domain_batchinitsessionrequest_queue_offline = argToBoolean(args.get('domain_batchinitsessionrequest_queue_offline', False))

    response = client.batch_init_sessions_request(timeout, timeout_duration, domain_batchinitsessionrequest_existing_batch_id,
                                                  domain_batchinitsessionrequest_host_ids, domain_batchinitsessionrequest_queue_offline)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def batch_refresh_sessions_command(client, args):
    timeout = int(args.get('timeout', 30))
    timeout_duration = str(args.get('timeout_duration', '30s'))
    domain_batchrefreshsessionrequest_batch_id = str(args.get('domain_batchrefreshsessionrequest_batch_id', ''))
    domain_batchrefreshsessionrequest_hosts_to_remove = argToList(
        args.get('domain_batchrefreshsessionrequest_hosts_to_remove', []))

    response = client.batch_refresh_sessions_request(
        timeout, timeout_duration, domain_batchrefreshsessionrequest_batch_id, domain_batchrefreshsessionrequest_hosts_to_remove)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_actionsv1_command(client, args):
    domain_registeractionsrequest_actions = argToList(args.get('domain_registeractionsrequest_actions', []))
    domain_registeractionsrequest_rule_id = str(args.get('domain_registeractionsrequest_rule_id', ''))

    response = client.create_actionsv1_request(domain_registeractionsrequest_actions, domain_registeractionsrequest_rule_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainActionEntitiesResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_device_control_policies_command(client, args):
    requests_createdevicecontrolpoliciesv1_resources = argToList(args.get('requests_createdevicecontrolpoliciesv1_resources', []))

    response = client.create_device_control_policies_request(requests_createdevicecontrolpoliciesv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_firewall_policies_command(client, args):
    requests_createfirewallpoliciesv1_resources = argToList(args.get('requests_createfirewallpoliciesv1_resources', []))
    clone_id = str(args.get('clone_id', ''))

    response = client.create_firewall_policies_request(requests_createfirewallpoliciesv1_resources, clone_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_host_groups_command(client, args):
    requests_creategroupsv1_resources = argToList(args.get('requests_creategroupsv1_resources', []))

    response = client.create_host_groups_request(requests_creategroupsv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_or_updateaws_settings_command(client, args):
    models_modifyawscustomersettingsv1_resources = argToList(args.get('models_modifyawscustomersettingsv1_resources', []))

    response = client.create_or_updateaws_settings_request(models_modifyawscustomersettingsv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_prevention_policies_command(client, args):
    requests_createpreventionpoliciesv1_resources = argToList(args.get('requests_createpreventionpoliciesv1_resources', []))

    response = client.create_prevention_policies_request(requests_createpreventionpoliciesv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_rulesv1_command(client, args):
    sadomain_createrulerequestv1_filter = str(args.get('sadomain_createrulerequestv1_filter', ''))
    sadomain_createrulerequestv1_name = str(args.get('sadomain_createrulerequestv1_name', ''))
    sadomain_createrulerequestv1_permissions = str(args.get('sadomain_createrulerequestv1_permissions', ''))
    sadomain_createrulerequestv1_priority = str(args.get('sadomain_createrulerequestv1_priority', ''))
    sadomain_createrulerequestv1_topic = str(args.get('sadomain_createrulerequestv1_topic', ''))

    response = client.create_rulesv1_request(sadomain_createrulerequestv1_filter, sadomain_createrulerequestv1_name,
                                             sadomain_createrulerequestv1_permissions, sadomain_createrulerequestv1_priority, sadomain_createrulerequestv1_topic)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainRulesEntitiesResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_sensor_update_policies_command(client, args):
    requests_createsensorupdatepoliciesv1_resources = argToList(args.get('requests_createsensorupdatepoliciesv1_resources', []))

    response = client.create_sensor_update_policies_request(requests_createsensorupdatepoliciesv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_sensor_update_policiesv2_command(client, args):
    requests_createsensorupdatepoliciesv2_resources = argToList(args.get('requests_createsensorupdatepoliciesv2_resources', []))

    response = client.create_sensor_update_policiesv2_request(requests_createsensorupdatepoliciesv2_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_user_command(client, args):
    domain_usercreaterequest_firstname = str(args.get('domain_usercreaterequest_firstname', ''))
    domain_usercreaterequest_lastname = str(args.get('domain_usercreaterequest_lastname', ''))
    domain_usercreaterequest_password = str(args.get('domain_usercreaterequest_password', ''))
    domain_usercreaterequest_uid = str(args.get('domain_usercreaterequest_uid', ''))

    response = client.create_user_request(domain_usercreaterequest_firstname, domain_usercreaterequest_lastname,
                                          domain_usercreaterequest_password, domain_usercreaterequest_uid)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_user_groups_command(client, args):
    domain_usergroupsrequestv1_resources = argToList(args.get('domain_usergroupsrequestv1_resources', []))

    response = client.create_user_groups_request(domain_usergroupsrequestv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainUserGroupsResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createaws_account_command(client, args):
    k8sreg_createawsaccreq_resources = argToList(args.get('k8sreg_createawsaccreq_resources', []))

    response = client.createaws_account_request(k8sreg_createawsaccreq_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createcid_groups_command(client, args):
    domain_cidgroupsrequestv1_resources = argToList(args.get('domain_cidgroupsrequestv1_resources', []))

    response = client.createcid_groups_request(domain_cidgroupsrequestv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainCIDGroupsResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createcspm_aws_account_command(client, args):
    registration_awsaccountcreaterequestextv2_resources = argToList(
        args.get('registration_awsaccountcreaterequestextv2_resources', []))

    response = client.createcspm_aws_account_request(registration_awsaccountcreaterequestextv2_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createcspmgcp_account_command(client, args):
    registration_gcpaccountcreaterequestextv1_resources = argToList(
        args.get('registration_gcpaccountcreaterequestextv1_resources', []))

    response = client.createcspmgcp_account_request(registration_gcpaccountcreaterequestextv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createioc_command(client, args):
    api_iocviewrecord_batch_id = str(args.get('api_iocviewrecord_batch_id', ''))
    api_iocviewrecord_created_by = str(args.get('api_iocviewrecord_created_by', ''))
    api_iocviewrecord_created_timestamp = str(args.get('api_iocviewrecord_created_timestamp', ''))
    api_iocviewrecord_description = str(args.get('api_iocviewrecord_description', ''))
    api_iocviewrecord_expiration_days = args.get('api_iocviewrecord_expiration_days', None)
    api_iocviewrecord_expiration_timestamp = str(args.get('api_iocviewrecord_expiration_timestamp', ''))
    api_iocviewrecord_modified_by = str(args.get('api_iocviewrecord_modified_by', ''))
    api_iocviewrecord_modified_timestamp = str(args.get('api_iocviewrecord_modified_timestamp', ''))
    api_iocviewrecord_policy = str(args.get('api_iocviewrecord_policy', ''))
    api_iocviewrecord_share_level = str(args.get('api_iocviewrecord_share_level', ''))
    api_iocviewrecord_source = str(args.get('api_iocviewrecord_source', ''))
    api_iocviewrecord_type = str(args.get('api_iocviewrecord_type', ''))
    api_iocviewrecord_value = str(args.get('api_iocviewrecord_value', ''))

    response = client.createioc_request(api_iocviewrecord_batch_id, api_iocviewrecord_created_by, api_iocviewrecord_created_timestamp, api_iocviewrecord_description, api_iocviewrecord_expiration_days, api_iocviewrecord_expiration_timestamp,
                                        api_iocviewrecord_modified_by, api_iocviewrecord_modified_timestamp, api_iocviewrecord_policy, api_iocviewrecord_share_level, api_iocviewrecord_source, api_iocviewrecord_type, api_iocviewrecord_value)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiMsaReplyIOC',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createml_exclusionsv1_command(client, args):
    requests_mlexclusioncreatereqv1_comment = str(args.get('requests_mlexclusioncreatereqv1_comment', ''))
    requests_mlexclusioncreatereqv1_excluded_from = argToList(args.get('requests_mlexclusioncreatereqv1_excluded_from', []))
    requests_mlexclusioncreatereqv1_groups = argToList(args.get('requests_mlexclusioncreatereqv1_groups', []))
    requests_mlexclusioncreatereqv1_value = str(args.get('requests_mlexclusioncreatereqv1_value', ''))

    response = client.createml_exclusionsv1_request(requests_mlexclusioncreatereqv1_comment, requests_mlexclusioncreatereqv1_excluded_from,
                                                    requests_mlexclusioncreatereqv1_groups, requests_mlexclusioncreatereqv1_value)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesMlExclusionRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def creatert_response_policies_command(client, args):
    requests_creatertresponsepoliciesv1_resources = argToList(args.get('requests_creatertresponsepoliciesv1_resources', []))

    response = client.creatert_response_policies_request(requests_creatertresponsepoliciesv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createrule_command(client, args):
    api_rulecreatev1_comment = str(args.get('api_rulecreatev1_comment', ''))
    api_rulecreatev1_description = str(args.get('api_rulecreatev1_description', ''))
    api_rulecreatev1_disposition_id = args.get('api_rulecreatev1_disposition_id', None)
    api_rulecreatev1_field_values = argToList(args.get('api_rulecreatev1_field_values', []))
    api_rulecreatev1_name = str(args.get('api_rulecreatev1_name', ''))
    api_rulecreatev1_pattern_severity = str(args.get('api_rulecreatev1_pattern_severity', ''))
    api_rulecreatev1_rulegroup_id = str(args.get('api_rulecreatev1_rulegroup_id', ''))
    api_rulecreatev1_ruletype_id = str(args.get('api_rulecreatev1_ruletype_id', ''))

    response = client.createrule_request(api_rulecreatev1_comment, api_rulecreatev1_description, api_rulecreatev1_disposition_id, api_rulecreatev1_field_values,
                                         api_rulecreatev1_name, api_rulecreatev1_pattern_severity, api_rulecreatev1_rulegroup_id, api_rulecreatev1_ruletype_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createrulegroup_command(client, args):
    clone_id = str(args.get('clone_id', ''))
    li_ary = str(args.get('li_ary', ''))
    comment = str(args.get('comment', ''))
    fwmgr_api_rulegroupcreaterequestv1_description = str(args.get('fwmgr_api_rulegroupcreaterequestv1_description', ''))
    fwmgr_api_rulegroupcreaterequestv1_enabled = argToBoolean(args.get('fwmgr_api_rulegroupcreaterequestv1_enabled', False))
    fwmgr_api_rulegroupcreaterequestv1_name = str(args.get('fwmgr_api_rulegroupcreaterequestv1_name', ''))
    fwmgr_api_rulegroupcreaterequestv1_rules = argToList(args.get('fwmgr_api_rulegroupcreaterequestv1_rules', []))

    response = client.createrulegroup_request(clone_id, li_ary, comment, fwmgr_api_rulegroupcreaterequestv1_description,
                                              fwmgr_api_rulegroupcreaterequestv1_enabled, fwmgr_api_rulegroupcreaterequestv1_name, fwmgr_api_rulegroupcreaterequestv1_rules)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createrulegroup_mixin0_command(client, args):
    api_rulegroupcreaterequestv1_comment = str(args.get('api_rulegroupcreaterequestv1_comment', ''))
    api_rulegroupcreaterequestv1_description = str(args.get('api_rulegroupcreaterequestv1_description', ''))
    api_rulegroupcreaterequestv1_name = str(args.get('api_rulegroupcreaterequestv1_name', ''))
    api_rulegroupcreaterequestv1_platform = str(args.get('api_rulegroupcreaterequestv1_platform', ''))

    response = client.createrulegroup_mixin0_request(
        api_rulegroupcreaterequestv1_comment, api_rulegroupcreaterequestv1_description, api_rulegroupcreaterequestv1_name, api_rulegroupcreaterequestv1_platform)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createsv_exclusionsv1_command(client, args):
    requests_svexclusioncreatereqv1_comment = str(args.get('requests_svexclusioncreatereqv1_comment', ''))
    requests_svexclusioncreatereqv1_groups = argToList(args.get('requests_svexclusioncreatereqv1_groups', []))
    requests_svexclusioncreatereqv1_value = str(args.get('requests_svexclusioncreatereqv1_value', ''))

    response = client.createsv_exclusionsv1_request(
        requests_svexclusioncreatereqv1_comment, requests_svexclusioncreatereqv1_groups, requests_svexclusioncreatereqv1_value)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesMlExclusionRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def crowd_score_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.crowd_score_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiMsaEnvironmentScoreResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def customersettingsread_command(client, args):

    response = client.customersettingsread_request()
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apicustomerSettingsResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_actionv1_command(client, args):
    id_ = str(args.get('id_', ''))

    response = client.delete_actionv1_request(id_)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_device_control_policies_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.delete_device_control_policies_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_firewall_policies_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.delete_firewall_policies_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_host_groups_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.delete_host_groups_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_notificationsv1_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.delete_notificationsv1_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainNotificationIDResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_prevention_policies_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.delete_prevention_policies_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_report_command(client, args):
    ids = str(args.get('ids', ''))

    response = client.delete_report_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_rulesv1_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.delete_rulesv1_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainRuleQueryResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_samplev2_command(client, args):
    ids = str(args.get('ids', ''))

    response = client.delete_samplev2_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_samplev3_command(client, args):
    ids = str(args.get('ids', ''))

    response = client.delete_samplev3_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_sensor_update_policies_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.delete_sensor_update_policies_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_sensor_visibility_exclusionsv1_command(client, args):
    ids = argToList(args.get('ids', []))
    comment = str(args.get('comment', ''))

    response = client.delete_sensor_visibility_exclusionsv1_request(ids, comment)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_user_command(client, args):
    user_uuid = str(args.get('user_uuid', ''))

    response = client.delete_user_request(user_uuid)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaReplyMetaOnly',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_user_group_members_command(client, args):
    domain_usergroupmembersrequestv1_resources = argToList(args.get('domain_usergroupmembersrequestv1_resources', []))

    response = client.delete_user_group_members_request(domain_usergroupmembersrequestv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainUserGroupMembersResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_user_groups_command(client, args):
    user_group_ids = argToList(args.get('user_group_ids', []))

    response = client.delete_user_groups_request(user_group_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaEntitiesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deleteaws_accounts_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.deleteaws_accounts_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.modelsBaseResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deleteaws_accounts_mixin0_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.deleteaws_accounts_mixin0_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaMetaInfo',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deletecid_group_members_command(client, args):
    domain_cidgroupmembersrequestv1_resources = argToList(args.get('domain_cidgroupmembersrequestv1_resources', []))

    response = client.deletecid_group_members_request(domain_cidgroupmembersrequestv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainCIDGroupMembersResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deletecid_groups_command(client, args):
    cid_group_ids = argToList(args.get('cid_group_ids', []))

    response = client.deletecid_groups_request(cid_group_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaEntitiesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deletecspm_aws_account_command(client, args):
    ids = argToList(args.get('ids', []))
    organization_ids = argToList(args.get('organization_ids', []))

    response = client.deletecspm_aws_account_request(ids, organization_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationBaseResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deletecspm_azure_account_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.deletecspm_azure_account_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationBaseResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deleted_roles_command(client, args):
    domain_mssprolerequestv1_resources = argToList(args.get('domain_mssprolerequestv1_resources', []))

    response = client.deleted_roles_request(domain_mssprolerequestv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainMSSPRoleResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deleteioa_exclusionsv1_command(client, args):
    ids = argToList(args.get('ids', []))
    comment = str(args.get('comment', ''))

    response = client.deleteioa_exclusionsv1_request(ids, comment)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deleteioc_command(client, args):
    type_ = str(args.get('type_', ''))
    value = str(args.get('value', ''))

    response = client.deleteioc_request(type_, value)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiMsaReplyIOC',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deleteml_exclusionsv1_command(client, args):
    ids = argToList(args.get('ids', []))
    comment = str(args.get('comment', ''))

    response = client.deleteml_exclusionsv1_request(ids, comment)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesMlExclusionRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deletert_response_policies_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.deletert_response_policies_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deleterulegroups_command(client, args):
    ids = argToList(args.get('ids', []))
    comment = str(args.get('comment', ''))

    response = client.deleterulegroups_request(ids, comment)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrapiQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deleterulegroups_mixin0_command(client, args):
    comment = str(args.get('comment', ''))
    ids = argToList(args.get('ids', []))

    response = client.deleterulegroups_mixin0_request(comment, ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaReplyMetaOnly',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deleterules_command(client, args):
    rule_group_id = str(args.get('rule_group_id', ''))
    comment = str(args.get('comment', ''))
    ids = argToList(args.get('ids', []))

    response = client.deleterules_request(rule_group_id, comment, ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaReplyMetaOnly',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def devices_count_command(client, args):
    type_ = str(args.get('type_', ''))
    value = str(args.get('value', ''))

    response = client.devices_count_request(type_, value)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiMsaReplyIOCDevicesCount',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def devices_ran_on_command(client, args):
    type_ = str(args.get('type_', ''))
    value = str(args.get('value', ''))
    limit = str(args.get('limit', ''))
    offset = str(args.get('offset', ''))

    response = client.devices_ran_on_request(type_, value, limit, offset)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiMsaReplyDevicesRanOn',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def download_sensor_installer_by_id_command(client, args):
    id_ = str(args.get('id_', ''))
    response = client.download_sensor_installer_by_id_request(id_)
    data = response.content
    try:
        file_name = response.headers.get('Content-Disposition').split('attachment; filename=')[1]
    except Exception as err:
        demisto.debug(f'Failed extracting filename from response headers - [{str(err)}]')
        file_name = f'cs_installer-id-{id_}'

    return fileResult(filename=file_name, data=data, file_type=EntryType.FILE)


def entitiesprocesses_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.entitiesprocesses_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiMsaProcessDetailResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_actionsv1_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_actionsv1_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainActionEntitiesResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_aggregate_detects_command(client, args):
    msa_aggregatequeryrequest_date_ranges = argToList(args.get('msa_aggregatequeryrequest_date_ranges', []))
    msa_aggregatequeryrequest_field = str(args.get('msa_aggregatequeryrequest_field', ''))
    msa_aggregatequeryrequest_filter = str(args.get('msa_aggregatequeryrequest_filter', ''))
    msa_aggregatequeryrequest_interval = str(args.get('msa_aggregatequeryrequest_interval', ''))
    msa_aggregatequeryrequest_min_doc_count = args.get('msa_aggregatequeryrequest_min_doc_count', None)
    msa_aggregatequeryrequest_missing = str(args.get('msa_aggregatequeryrequest_missing', ''))
    msa_aggregatequeryrequest_name = str(args.get('msa_aggregatequeryrequest_name', ''))
    msa_aggregatequeryrequest_q = str(args.get('msa_aggregatequeryrequest_q', ''))
    msa_aggregatequeryrequest_ranges = argToList(args.get('msa_aggregatequeryrequest_ranges', []))
    msa_aggregatequeryrequest_size = args.get('msa_aggregatequeryrequest_size', None)
    msa_aggregatequeryrequest_sort = str(args.get('msa_aggregatequeryrequest_sort', ''))
    msa_aggregatequeryrequest_sub_aggregates = argToList(args.get('msa_aggregatequeryrequest_sub_aggregates', []))
    msa_aggregatequeryrequest_time_zone = str(args.get('msa_aggregatequeryrequest_time_zone', ''))
    msa_aggregatequeryrequest_type = str(args.get('msa_aggregatequeryrequest_type', ''))

    response = client.get_aggregate_detects_request(msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing,
                                                    msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaAggregatesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_artifacts_command(client, args):
    id_ = str(args.get('id_', ''))
    name = str(args.get('name', ''))

    response = client.get_artifacts_request(id_, name)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_assessmentv1_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_assessmentv1_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainAssessmentsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_available_role_ids_command(client, args):

    response = client.get_available_role_ids_request()
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_behaviors_command(client, args):
    msa_idsrequest_ids = argToList(args.get('msa_idsrequest_ids', []))

    response = client.get_behaviors_request(msa_idsrequest_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiMsaExternalBehaviorResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_children_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_children_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainChildrenResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_cloudconnectazure_entities_account_v1_command(client, args):
    ids = argToList(args.get('ids', []))
    scan_type = str(args.get('scan_type', ''))

    response = client.get_cloudconnectazure_entities_account_v1_request(ids, scan_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationAzureAccountResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_cloudconnectazure_entities_userscriptsdownload_v1_command(client, args):

    response = client.get_cloudconnectazure_entities_userscriptsdownload_v1_request()
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_cloudconnectcspmazure_entities_account_v1_command(client, args):
    ids = argToList(args.get('ids', []))
    scan_type = str(args.get('scan_type', ''))
    status = str(args.get('status', ''))
    limit = int(args.get('limit', 100))
    offset = args.get('offset', None)

    response = client.get_cloudconnectcspmazure_entities_account_v1_request(ids, scan_type, status, limit, offset)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationAzureAccountResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_cloudconnectcspmazure_entities_userscriptsdownload_v1_command(client, args):
    tenant_id = str(args.get('tenant_id', ''))

    response = client.get_cloudconnectcspmazure_entities_userscriptsdownload_v1_request(tenant_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_clusters_command(client, args):
    cluster_names = argToList(args.get('cluster_names', []))
    account_ids = argToList(args.get('account_ids', []))
    locations = argToList(args.get('locations', []))
    cluster_service = str(args.get('cluster_service', ''))
    limit = args.get('limit', None)
    offset = args.get('offset', None)

    response = client.get_clusters_request(cluster_names, account_ids, locations, cluster_service, limit, offset)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.k8sregGetClustersResp',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_combined_sensor_installers_by_query_command(client, args):
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))

    response = client.get_combined_sensor_installers_by_query_request(offset, limit, sort, filter_)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainSensorInstallersV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_detect_summaries_command(client, args):
    msa_idsrequest_ids = argToList(args.get('msa_idsrequest_ids', []))

    response = client.get_detect_summaries_request(msa_idsrequest_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainMsaDetectSummariesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_device_control_policies_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_device_control_policies_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesDeviceControlPoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_device_count_collection_queries_by_filter_command(client, args):
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    offset = str(args.get('offset', ''))

    response = client.get_device_count_collection_queries_by_filter_request(limit, sort, filter_, offset)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_device_details_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_device_details_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainDeviceDetailsResponseSwagger',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_device_login_history_command(client, args):
    ids = argToList(args.get('ids', []))
    response = client.get_device_login_history_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.deviceHistoryLogin',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_device_network_history_command(client, args):
    ids = argToList(args.get('ids', []))
    response = client.get_device_network_history_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.deviceNetworkHistory',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_firewall_policies_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_firewall_policies_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesFirewallPoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_helm_values_yaml_command(client, args):
    cluster_name = str(args.get('cluster_name', ''))

    response = client.get_helm_values_yaml_request(cluster_name)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.k8sregHelmYAMLResp',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_host_groups_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_host_groups_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesHostGroupsV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_incidents_command(client, args):
    msa_idsrequest_ids = argToList(args.get('msa_idsrequest_ids', []))

    response = client.get_incidents_request(msa_idsrequest_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiMsaExternalIncidentResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_intel_actor_entities_command(client, args):
    ids = argToList(args.get('ids', []))
    fields = argToList(args.get('fields', []))

    response = client.get_intel_actor_entities_request(ids, fields)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainActorsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_intel_indicator_entities_command(client, args):
    msa_idsrequest_ids = argToList(args.get('msa_idsrequest_ids', []))

    response = client.get_intel_indicator_entities_request(msa_idsrequest_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainPublicIndicatorsV3Response',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_intel_report_entities_command(client, args):
    ids = argToList(args.get('ids', []))
    fields = argToList(args.get('fields', []))

    response = client.get_intel_report_entities_request(ids, fields)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainNewsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_intel_reportpdf_command(client, args):
    id_ = str(args.get('id_', ''))

    response = client.get_intel_reportpdf_request(id_)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_intel_rule_entities_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_intel_rule_entities_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainRulesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_intel_rule_file_command(client, args):
    id_ = args.get('id_', None)
    format = str(args.get('format', ''))

    response = client.get_intel_rule_file_request(id_, format)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_latest_intel_rule_file_command(client, args):
    type_ = str(args.get('type_', ''))
    format = str(args.get('format', ''))

    response = client.get_latest_intel_rule_file_request(type_, format)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_locations_command(client, args):
    clouds = argToList(args.get('clouds', []))

    response = client.get_locations_request(clouds)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.k8sregGetLocationsResp',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_mal_query_downloadv1_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_mal_query_downloadv1_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_mal_query_entities_samples_fetchv1_command(client, args):
    ids = str(args.get('ids', ''))

    response = client.get_mal_query_entities_samples_fetchv1_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_mal_query_metadatav1_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_mal_query_metadatav1_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.malquerySampleMetadataResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_mal_query_quotasv1_command(client, args):

    response = client.get_mal_query_quotasv1_request()
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.malqueryRateLimitsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_mal_query_requestv1_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_mal_query_requestv1_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.malqueryRequestResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_notifications_detailed_translatedv1_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_notifications_detailed_translatedv1_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainNotificationDetailsResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_notifications_detailedv1_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_notifications_detailedv1_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainNotificationDetailsResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_notifications_translatedv1_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_notifications_translatedv1_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainNotificationEntitiesResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_notificationsv1_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_notificationsv1_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainNotificationEntitiesResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_prevention_policies_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_prevention_policies_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesPreventionPoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_reports_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_reports_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.falconxReportV1Response',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_roles_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_roles_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainUserRoleResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_roles_byid_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_roles_byid_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainMSSPRoleResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_rulesv1_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_rulesv1_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainRulesEntitiesResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_samplev2_command(client, args):
    ids = str(args.get('ids', ''))
    password_protected = str(args.get('password_protected', 'False'))

    response = client.get_samplev2_request(ids, password_protected)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_samplev3_command(client, args):
    ids = str(args.get('ids', ''))
    password_protected = str(args.get('password_protected', 'False'))

    response = client.get_samplev3_request(ids, password_protected)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_scans_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_scans_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.mlscannerScanV1Response',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_scans_aggregates_command(client, args):
    msa_aggregatequeryrequest_date_ranges = argToList(args.get('msa_aggregatequeryrequest_date_ranges', []))
    msa_aggregatequeryrequest_field = str(args.get('msa_aggregatequeryrequest_field', ''))
    msa_aggregatequeryrequest_filter = str(args.get('msa_aggregatequeryrequest_filter', ''))
    msa_aggregatequeryrequest_interval = str(args.get('msa_aggregatequeryrequest_interval', ''))
    msa_aggregatequeryrequest_min_doc_count = args.get('msa_aggregatequeryrequest_min_doc_count', None)
    msa_aggregatequeryrequest_missing = str(args.get('msa_aggregatequeryrequest_missing', ''))
    msa_aggregatequeryrequest_name = str(args.get('msa_aggregatequeryrequest_name', ''))
    msa_aggregatequeryrequest_q = str(args.get('msa_aggregatequeryrequest_q', ''))
    msa_aggregatequeryrequest_ranges = argToList(args.get('msa_aggregatequeryrequest_ranges', []))
    msa_aggregatequeryrequest_size = args.get('msa_aggregatequeryrequest_size', None)
    msa_aggregatequeryrequest_sort = str(args.get('msa_aggregatequeryrequest_sort', ''))
    msa_aggregatequeryrequest_sub_aggregates = argToList(args.get('msa_aggregatequeryrequest_sub_aggregates', []))
    msa_aggregatequeryrequest_time_zone = str(args.get('msa_aggregatequeryrequest_time_zone', ''))
    msa_aggregatequeryrequest_type = str(args.get('msa_aggregatequeryrequest_type', ''))

    response = client.get_scans_aggregates_request(msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing,
                                                   msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_sensor_installers_by_query_command(client, args):
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))

    response = client.get_sensor_installers_by_query_request(offset, limit, sort, filter_)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_sensor_installers_entities_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_sensor_installers_entities_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainSensorInstallersV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_sensor_installersccid_by_query_command(client, args):

    response = client.get_sensor_installersccid_by_query_request()
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_sensor_update_policies_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_sensor_update_policies_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesSensorUpdatePoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_sensor_update_policiesv2_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_sensor_update_policiesv2_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesSensorUpdatePoliciesV2',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_sensor_visibility_exclusionsv1_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_sensor_visibility_exclusionsv1_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesSvExclusionRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_submissions_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_submissions_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.falconxSubmissionV1Response',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_summary_reports_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_summary_reports_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.falconxSummaryReportV1Response',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_user_group_members_byid_command(client, args):
    user_group_ids = str(args.get('user_group_ids', ''))

    response = client.get_user_group_members_byid_request(user_group_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainUserGroupMembersResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_user_groups_byid_command(client, args):
    user_group_ids = argToList(args.get('user_group_ids', []))

    response = client.get_user_groups_byid_request(user_group_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainUserGroupsResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_user_role_ids_command(client, args):
    user_uuid = str(args.get('user_uuid', ''))

    response = client.get_user_role_ids_request(user_uuid)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_vulnerabilities_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.get_vulnerabilities_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainSPAPIVulnerabilitiesEntitiesResponseV2',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getaws_accounts_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.getaws_accounts_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.modelsAWSAccountsV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getaws_accounts_mixin0_command(client, args):
    ids = argToList(args.get('ids', []))
    status = str(args.get('status', ''))
    limit = args.get('limit', None)
    offset = args.get('offset', None)

    response = client.getaws_accounts_mixin0_request(ids, status, limit, offset)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.k8sregGetAWSAccountsResp',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getaws_settings_command(client, args):

    response = client.getaws_settings_request()
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.modelsCustomerConfigurationsV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getcid_group_by_id_command(client, args):
    cid_group_ids = argToList(args.get('cid_group_ids', []))

    response = client.getcid_group_by_id_request(cid_group_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainCIDGroupsResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getcid_group_members_by_command(client, args):
    cid_group_ids = argToList(args.get('cid_group_ids', []))

    response = client.getcid_group_members_by_request(cid_group_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainCIDGroupMembersResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getcspm_aws_account_command(client, args):
    scan_type = str(args.get('scan_type', ''))
    ids = argToList(args.get('ids', []))
    organization_ids = argToList(args.get('organization_ids', []))
    status = str(args.get('status', ''))
    limit = int(args.get('limit', 100))
    offset = args.get('offset', None)
    group_by = str(args.get('group_by', ''))

    response = client.getcspm_aws_account_request(scan_type, ids, organization_ids, status, limit, offset, group_by)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationAWSAccountResponseV2',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getcspm_aws_account_scripts_attachment_command(client, args):

    response = client.getcspm_aws_account_scripts_attachment_request()
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationAWSProvisionGetAccountScriptResponseV2',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getcspm_aws_console_setupur_ls_command(client, args):

    response = client.getcspm_aws_console_setupur_ls_request()
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationAWSAccountConsoleURL',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getcspm_azure_user_scripts_command(client, args):

    response = client.getcspm_azure_user_scripts_request()
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationAzureProvisionGetUserScriptResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getcspm_policy_command(client, args):
    ids = str(args.get('ids', ''))

    response = client.getcspm_policy_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationPolicyResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getcspm_policy_settings_command(client, args):
    service = str(args.get('service', ''))
    policy_id = str(args.get('policy_id', ''))
    cloud_platform = str(args.get('cloud_platform', ''))

    response = client.getcspm_policy_settings_request(service, policy_id, cloud_platform)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationPolicySettingsResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getcspm_scan_schedule_command(client, args):
    cloud_platform = argToList(args.get('cloud_platform', []))

    response = client.getcspm_scan_schedule_request(cloud_platform)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationScanScheduleResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getcspmcgp_account_command(client, args):
    scan_type = str(args.get('scan_type', ''))
    ids = argToList(args.get('ids', []))

    response = client.getcspmcgp_account_request(scan_type, ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationGCPAccountResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getcspmgcp_user_scripts_command(client, args):

    response = client.getcspmgcp_user_scripts_request()
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationGCPProvisionGetUserScriptResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getcspmgcp_user_scripts_attachment_command(client, args):

    response = client.getcspmgcp_user_scripts_attachment_request()
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationGCPProvisionGetUserScriptResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getevents_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.getevents_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrapiEventsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getfirewallfields_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.getfirewallfields_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrapiFirewallFieldsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getioa_events_command(client, args):
    policy_id = str(args.get('policy_id', ''))
    cloud_provider = str(args.get('cloud_provider', ''))
    account_id = str(args.get('account_id', ''))
    azure_tenant_id = str(args.get('azure_tenant_id', ''))
    user_ids = argToList(args.get('user_ids', []))
    offset = args.get('offset', None)
    limit = args.get('limit', None)

    response = client.getioa_events_request(policy_id, cloud_provider, account_id, azure_tenant_id, user_ids, offset, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationExternalIOAEventResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getioa_exclusionsv1_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.getioa_exclusionsv1_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesIoaExclusionRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getioa_users_command(client, args):
    policy_id = str(args.get('policy_id', ''))
    cloud_provider = str(args.get('cloud_provider', ''))
    account_id = str(args.get('account_id', ''))
    azure_tenant_id = str(args.get('azure_tenant_id', ''))

    response = client.getioa_users_request(policy_id, cloud_provider, account_id, azure_tenant_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationIOAUserResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getioc_command(client, args):
    type_ = str(args.get('type_', ''))
    value = str(args.get('value', ''))

    response = client.getioc_request(type_, value)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiMsaReplyIOC',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getml_exclusionsv1_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.getml_exclusionsv1_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesMlExclusionRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getpatterns_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.getpatterns_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiPatternsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getplatforms_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.getplatforms_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrapiPlatformsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getplatforms_mixin0_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.getplatforms_mixin0_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiPlatformsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getpolicycontainers_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.getpolicycontainers_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrapiPolicyContainersResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getrt_response_policies_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.getrt_response_policies_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesRTResponsePoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getrulegroups_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.getrulegroups_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrapiRuleGroupsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getrulegroups_mixin0_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.getrulegroups_mixin0_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiRuleGroupsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getrules_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.getrules_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrapiRulesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getrules_mixin0_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.getrules_mixin0_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiRulesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getrulesget_command(client, args):
    api_rulesgetrequestv1_ids = argToList(args.get('api_rulesgetrequestv1_ids', []))

    response = client.getrulesget_request(api_rulesgetrequestv1_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiRulesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getruletypes_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.getruletypes_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiRuleTypesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def grant_user_role_ids_command(client, args):
    user_uuid = str(args.get('user_uuid', ''))
    domain_roleids_roleids = argToList(args.get('domain_roleids_roleids', []))

    response = client.grant_user_role_ids_request(user_uuid, domain_roleids_roleids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainUserRoleIDsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def indicatorcombinedv1_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.indicatorcombinedv1_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiIndicatorRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def indicatorcreatev1_command(client, args):
    retrodetects = str(args.get('retrodetects', ''))
    ignore_warnings = str(args.get('ignore_warnings', 'False'))
    api_indicatorcreatereqsv1_comment = str(args.get('api_indicatorcreatereqsv1_comment', ''))
    api_indicatorcreatereqsv1_indicators = argToList(args.get('api_indicatorcreatereqsv1_indicators', []))

    response = client.indicatorcreatev1_request(retrodetects, ignore_warnings,
                                                api_indicatorcreatereqsv1_comment, api_indicatorcreatereqsv1_indicators)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def indicatordeletev1_command(client, args):
    filter_ = str(args.get('filter_', ''))
    ids = argToList(args.get('ids', []))
    comment = str(args.get('comment', ''))

    response = client.indicatordeletev1_request(filter_, ids, comment)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiIndicatorQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def indicatorgetv1_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.indicatorgetv1_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiIndicatorRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def indicatorsearchv1_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.indicatorsearchv1_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiIndicatorQueryRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def indicatorupdatev1_command(client, args):
    retrodetects = str(args.get('retrodetects', ''))
    ignore_warnings = str(args.get('ignore_warnings', 'False'))
    api_indicatorupdatereqsv1_bulk_update_action = str(args.get('api_indicatorupdatereqsv1_bulk_update_action', ''))
    api_indicatorupdatereqsv1_bulk_update_applied_globally = argToBoolean(
        args.get('api_indicatorupdatereqsv1_bulk_update_applied_globally', False))
    api_indicatorupdatereqsv1_bulk_update_description = str(args.get('api_indicatorupdatereqsv1_bulk_update_description', ''))
    api_indicatorupdatereqsv1_bulk_update_expiration = str(args.get('api_indicatorupdatereqsv1_bulk_update_expiration', ''))
    api_indicatorupdatereqsv1_bulk_update_filter = str(args.get('api_indicatorupdatereqsv1_bulk_update_filter', ''))
    api_indicatorupdatereqsv1_bulk_update_host_groups = str(args.get('api_indicatorupdatereqsv1_bulk_update_host_groups', ''))
    api_indicatorupdatereqsv1_bulk_update_mobile_action = str(args.get('api_indicatorupdatereqsv1_bulk_update_mobile_action', ''))
    api_indicatorupdatereqsv1_bulk_update_platforms = str(args.get('api_indicatorupdatereqsv1_bulk_update_platforms', ''))
    api_indicatorupdatereqsv1_bulk_update_severity = str(args.get('api_indicatorupdatereqsv1_bulk_update_severity', ''))
    api_indicatorupdatereqsv1_bulk_update_source = str(args.get('api_indicatorupdatereqsv1_bulk_update_source', ''))
    api_indicatorupdatereqsv1_bulk_update_tags = str(args.get('api_indicatorupdatereqsv1_bulk_update_tags', ''))
    api_indicatorupdatereqsv1_bulk_update = assign_params(action=api_indicatorupdatereqsv1_bulk_update_action, applied_globally=api_indicatorupdatereqsv1_bulk_update_applied_globally, description=api_indicatorupdatereqsv1_bulk_update_description, expiration=api_indicatorupdatereqsv1_bulk_update_expiration, filter=api_indicatorupdatereqsv1_bulk_update_filter,
                                                          host_groups=api_indicatorupdatereqsv1_bulk_update_host_groups, mobile_action=api_indicatorupdatereqsv1_bulk_update_mobile_action, platforms=api_indicatorupdatereqsv1_bulk_update_platforms, severity=api_indicatorupdatereqsv1_bulk_update_severity, source=api_indicatorupdatereqsv1_bulk_update_source, tags=api_indicatorupdatereqsv1_bulk_update_tags)
    api_indicatorupdatereqsv1_comment = str(args.get('api_indicatorupdatereqsv1_comment', ''))
    api_indicatorupdatereqsv1_indicators = argToList(args.get('api_indicatorupdatereqsv1_indicators', []))

    response = client.indicatorupdatev1_request(retrodetects, ignore_warnings, api_indicatorupdatereqsv1_bulk_update,
                                                api_indicatorupdatereqsv1_comment, api_indicatorupdatereqsv1_indicators)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiIndicatorRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def list_available_streamso_auth2_command(client, args):
    appId = str(args.get('appId', ''))
    format = str(args.get('format', ''))

    response = client.list_available_streamso_auth2_request(appId, format)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.maindiscoveryResponseV2',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def oauth2_access_token_command(client, args):
    client_id = str(args.get('client_id', ''))
    client_secret = str(args.get('client_secret', ''))
    member_cid = str(args.get('member_cid', ''))

    response = client.oauth2_access_token_request(client_id, client_secret, member_cid)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def oauth2_revoke_token_command(client, args):
    token = str(args.get('token', ''))

    response = client.oauth2_revoke_token_request(token)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaReplyMetaOnly',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def patch_cloudconnectazure_entities_clientid_v1_command(client, args):
    id_ = str(args.get('id_', ''))

    response = client.patch_cloudconnectazure_entities_clientid_v1_request(id_)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def patch_cloudconnectcspmazure_entities_clientid_v1_command(client, args):
    id_ = str(args.get('id_', ''))
    tenant_id = str(args.get('tenant_id', ''))

    response = client.patch_cloudconnectcspmazure_entities_clientid_v1_request(id_, tenant_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def patchcspm_aws_account_command(client, args):
    registration_awsaccountpatchrequest_resources = argToList(args.get('registration_awsaccountpatchrequest_resources', []))

    response = client.patchcspm_aws_account_request(registration_awsaccountpatchrequest_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def perform_actionv2_command(client, args):
    action_name = str(args.get('action_name', ''))
    msa_entityactionrequestv2_action__meters = argToList(args.get('msa_entityactionrequestv2_action__meters', []))
    msa_entityactionrequestv2_ids = argToList(args.get('msa_entityactionrequestv2_ids', []))

    response = client.perform_actionv2_request(
        action_name, msa_entityactionrequestv2_action__meters, msa_entityactionrequestv2_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def perform_device_control_policies_action_command(client, args):
    action_name = str(args.get('action_name', ''))
    msa_entityactionrequestv2_action__meters = argToList(args.get('msa_entityactionrequestv2_action__meters', []))
    msa_entityactionrequestv2_ids = argToList(args.get('msa_entityactionrequestv2_ids', []))

    response = client.perform_device_control_policies_action_request(
        action_name, msa_entityactionrequestv2_action__meters, msa_entityactionrequestv2_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesDeviceControlPoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def perform_firewall_policies_action_command(client, args):
    action_name = str(args.get('action_name', ''))
    msa_entityactionrequestv2_action__meters = argToList(args.get('msa_entityactionrequestv2_action__meters', []))
    msa_entityactionrequestv2_ids = argToList(args.get('msa_entityactionrequestv2_ids', []))

    response = client.perform_firewall_policies_action_request(
        action_name, msa_entityactionrequestv2_action__meters, msa_entityactionrequestv2_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesFirewallPoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def perform_group_action_command(client, args):
    action_name = str(args.get('action_name', ''))
    msa_entityactionrequestv2_action__meters = argToList(args.get('msa_entityactionrequestv2_action__meters', []))
    msa_entityactionrequestv2_ids = argToList(args.get('msa_entityactionrequestv2_ids', []))

    response = client.perform_group_action_request(
        action_name, msa_entityactionrequestv2_action__meters, msa_entityactionrequestv2_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesHostGroupsV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def perform_incident_action_command(client, args):
    msa_entityactionrequestv2_action__meters = argToList(args.get('msa_entityactionrequestv2_action__meters', []))
    msa_entityactionrequestv2_ids = argToList(args.get('msa_entityactionrequestv2_ids', []))

    response = client.perform_incident_action_request(msa_entityactionrequestv2_action__meters, msa_entityactionrequestv2_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaReplyMetaOnly',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def perform_prevention_policies_action_command(client, args):
    action_name = str(args.get('action_name', ''))
    msa_entityactionrequestv2_action__meters = argToList(args.get('msa_entityactionrequestv2_action__meters', []))
    msa_entityactionrequestv2_ids = argToList(args.get('msa_entityactionrequestv2_ids', []))

    response = client.perform_prevention_policies_action_request(
        action_name, msa_entityactionrequestv2_action__meters, msa_entityactionrequestv2_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesPreventionPoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def perform_sensor_update_policies_action_command(client, args):
    action_name = str(args.get('action_name', ''))
    msa_entityactionrequestv2_action__meters = argToList(args.get('msa_entityactionrequestv2_action__meters', []))
    msa_entityactionrequestv2_ids = argToList(args.get('msa_entityactionrequestv2_ids', []))

    response = client.perform_sensor_update_policies_action_request(
        action_name, msa_entityactionrequestv2_action__meters, msa_entityactionrequestv2_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesSensorUpdatePoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def performrt_response_policies_action_command(client, args):
    action_name = str(args.get('action_name', ''))
    msa_entityactionrequestv2_action__meters = argToList(args.get('msa_entityactionrequestv2_action__meters', []))
    msa_entityactionrequestv2_ids = argToList(args.get('msa_entityactionrequestv2_ids', []))

    response = client.performrt_response_policies_action_request(
        action_name, msa_entityactionrequestv2_action__meters, msa_entityactionrequestv2_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesRTResponsePoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def post_cloudconnectazure_entities_account_v1_command(client, args):
    registration_azureaccountcreaterequestexternalv1_resources = argToList(
        args.get('registration_azureaccountcreaterequestexternalv1_resources', []))

    response = client.post_cloudconnectazure_entities_account_v1_request(
        registration_azureaccountcreaterequestexternalv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def post_cloudconnectcspmazure_entities_account_v1_command(client, args):
    registration_azureaccountcreaterequestexternalv1_resources = argToList(
        args.get('registration_azureaccountcreaterequestexternalv1_resources', []))

    response = client.post_cloudconnectcspmazure_entities_account_v1_request(
        registration_azureaccountcreaterequestexternalv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def post_mal_query_entities_samples_multidownloadv1_command(client, args):
    malquery_multidownloadrequestv1_samples = argToList(args.get('malquery_multidownloadrequestv1_samples', []))

    response = client.post_mal_query_entities_samples_multidownloadv1_request(malquery_multidownloadrequestv1_samples)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.malqueryExternalQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def post_mal_query_exact_searchv1_command(client, args):
    malquery_externalexactsearchparametersv1_options_filter_filetypes = str(
        args.get('malquery_externalexactsearchparametersv1_options_filter_filetypes', ''))
    malquery_externalexactsearchparametersv1_options_filter_meta = str(
        args.get('malquery_externalexactsearchparametersv1_options_filter_meta', ''))
    malquery_externalexactsearchparametersv1_options_limit = args.get(
        'malquery_externalexactsearchparametersv1_options_limit', None)
    malquery_externalexactsearchparametersv1_options_max_date = str(
        args.get('malquery_externalexactsearchparametersv1_options_max_date', ''))
    malquery_externalexactsearchparametersv1_options_max_size = str(
        args.get('malquery_externalexactsearchparametersv1_options_max_size', ''))
    malquery_externalexactsearchparametersv1_options_min_date = str(
        args.get('malquery_externalexactsearchparametersv1_options_min_date', ''))
    malquery_externalexactsearchparametersv1_options_min_size = str(
        args.get('malquery_externalexactsearchparametersv1_options_min_size', ''))
    malquery_externalexactsearchparametersv1_options = assign_params(filter_filetypes=malquery_externalexactsearchparametersv1_options_filter_filetypes, filter_meta=malquery_externalexactsearchparametersv1_options_filter_meta, limit=malquery_externalexactsearchparametersv1_options_limit,
                                                                     max_date=malquery_externalexactsearchparametersv1_options_max_date, max_size=malquery_externalexactsearchparametersv1_options_max_size, min_date=malquery_externalexactsearchparametersv1_options_min_date, min_size=malquery_externalexactsearchparametersv1_options_min_size)
    malquery_externalexactsearchparametersv1_patterns = argToList(
        args.get('malquery_externalexactsearchparametersv1_patterns', []))

    response = client.post_mal_query_exact_searchv1_request(
        malquery_externalexactsearchparametersv1_options, malquery_externalexactsearchparametersv1_patterns)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.malqueryExternalQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def post_mal_query_fuzzy_searchv1_command(client, args):
    malquery_fuzzysearchparametersv1_options_filter_meta = str(
        args.get('malquery_fuzzysearchparametersv1_options_filter_meta', ''))
    malquery_fuzzysearchparametersv1_options_limit = args.get('malquery_fuzzysearchparametersv1_options_limit', None)
    malquery_fuzzysearchparametersv1_options = assign_params(
        filter_meta=malquery_fuzzysearchparametersv1_options_filter_meta, limit=malquery_fuzzysearchparametersv1_options_limit)
    malquery_fuzzysearchparametersv1_patterns = argToList(args.get('malquery_fuzzysearchparametersv1_patterns', []))

    response = client.post_mal_query_fuzzy_searchv1_request(
        malquery_fuzzysearchparametersv1_options, malquery_fuzzysearchparametersv1_patterns)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.malqueryFuzzySearchResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def post_mal_query_huntv1_command(client, args):
    malquery_externalhuntparametersv1_options_filter_filetypes = str(
        args.get('malquery_externalhuntparametersv1_options_filter_filetypes', ''))
    malquery_externalhuntparametersv1_options_filter_meta = str(
        args.get('malquery_externalhuntparametersv1_options_filter_meta', ''))
    malquery_externalhuntparametersv1_options_limit = args.get('malquery_externalhuntparametersv1_options_limit', None)
    malquery_externalhuntparametersv1_options_max_date = str(args.get('malquery_externalhuntparametersv1_options_max_date', ''))
    malquery_externalhuntparametersv1_options_max_size = str(args.get('malquery_externalhuntparametersv1_options_max_size', ''))
    malquery_externalhuntparametersv1_options_min_date = str(args.get('malquery_externalhuntparametersv1_options_min_date', ''))
    malquery_externalhuntparametersv1_options_min_size = str(args.get('malquery_externalhuntparametersv1_options_min_size', ''))
    malquery_externalhuntparametersv1_options = assign_params(filter_filetypes=malquery_externalhuntparametersv1_options_filter_filetypes, filter_meta=malquery_externalhuntparametersv1_options_filter_meta, limit=malquery_externalhuntparametersv1_options_limit,
                                                              max_date=malquery_externalhuntparametersv1_options_max_date, max_size=malquery_externalhuntparametersv1_options_max_size, min_date=malquery_externalhuntparametersv1_options_min_date, min_size=malquery_externalhuntparametersv1_options_min_size)
    malquery_externalhuntparametersv1_yara_rule = str(args.get('malquery_externalhuntparametersv1_yara_rule', ''))

    response = client.post_mal_query_huntv1_request(
        malquery_externalhuntparametersv1_options, malquery_externalhuntparametersv1_yara_rule)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.malqueryExternalQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def preview_rulev1_command(client, args):
    domain_rulepreviewrequest_filter = str(args.get('domain_rulepreviewrequest_filter', ''))
    domain_rulepreviewrequest_topic = str(args.get('domain_rulepreviewrequest_topic', ''))

    response = client.preview_rulev1_request(domain_rulepreviewrequest_filter, domain_rulepreviewrequest_topic)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainAggregatesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def processes_ran_on_command(client, args):
    type_ = str(args.get('type_', ''))
    value = str(args.get('value', ''))
    device_id = str(args.get('device_id', ''))
    limit = str(args.get('limit', ''))
    offset = str(args.get('offset', ''))

    response = client.processes_ran_on_request(type_, value, device_id, limit, offset)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiMsaReplyProcessesRanOn',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def provisionaws_accounts_command(client, args):
    mode = str(args.get('mode', 'manual'))
    models_createawsaccountsv1_resources = argToList(args.get('models_createawsaccountsv1_resources', []))

    response = client.provisionaws_accounts_request(mode, models_createawsaccountsv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_actionsv1_command(client, args):
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    q = str(args.get('q', ''))

    response = client.query_actionsv1_request(offset, limit, sort, filter_, q)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_allow_list_filter_command(client, args):
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    offset = str(args.get('offset', ''))

    response = client.query_allow_list_filter_request(limit, sort, filter_, offset)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_behaviors_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_behaviors_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_block_list_filter_command(client, args):
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    offset = str(args.get('offset', ''))

    response = client.query_block_list_filter_request(limit, sort, filter_, offset)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_children_command(client, args):
    sort = str(args.get('sort', 'last_modified_timestamp|desc'))
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 10))

    response = client.query_children_request(sort, offset, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_combined_device_control_policies_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_combined_device_control_policies_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesDeviceControlPoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_combined_device_control_policy_members_command(client, args):
    id_ = str(args.get('id_', ''))
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_combined_device_control_policy_members_request(id_, filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesPolicyMembersRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_combined_firewall_policies_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_combined_firewall_policies_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesFirewallPoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_combined_firewall_policy_members_command(client, args):
    id_ = str(args.get('id_', ''))
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_combined_firewall_policy_members_request(id_, filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesPolicyMembersRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_combined_group_members_command(client, args):
    id_ = str(args.get('id_', ''))
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_combined_group_members_request(id_, filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesHostGroupMembersV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_combined_host_groups_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_combined_host_groups_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesHostGroupsV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_combined_prevention_policies_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_combined_prevention_policies_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesPreventionPoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_combined_prevention_policy_members_command(client, args):
    id_ = str(args.get('id_', ''))
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_combined_prevention_policy_members_request(id_, filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesPolicyMembersRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_combined_sensor_update_builds_command(client, args):
    platform = str(args.get('platform', ''))

    response = client.query_combined_sensor_update_builds_request(platform)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesSensorUpdateBuildsV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_combined_sensor_update_policies_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_combined_sensor_update_policies_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesSensorUpdatePoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_combined_sensor_update_policiesv2_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_combined_sensor_update_policiesv2_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesSensorUpdatePoliciesV2',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_combined_sensor_update_policy_members_command(client, args):
    id_ = str(args.get('id_', ''))
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_combined_sensor_update_policy_members_request(id_, filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesPolicyMembersRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_combinedrt_response_policies_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_combinedrt_response_policies_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesRTResponsePoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_combinedrt_response_policy_members_command(client, args):
    id_ = str(args.get('id_', ''))
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_combinedrt_response_policy_members_request(id_, filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesPolicyMembersRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_detection_ids_by_filter_command(client, args):
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    offset = str(args.get('offset', ''))

    response = client.query_detection_ids_by_filter_request(limit, sort, filter_, offset)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_detects_command(client, args):
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    q = str(args.get('q', ''))

    response = client.query_detects_request(offset, limit, sort, filter_, q)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_device_control_policies_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_device_control_policies_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_device_control_policy_members_command(client, args):
    id_ = str(args.get('id_', ''))
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_device_control_policy_members_request(id_, filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_devices_by_filter_command(client, args):
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))

    response = client.query_devices_by_filter_request(offset, limit, sort, filter_)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_devices_by_filter_scroll_command(client, args):
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))

    response = client.query_devices_by_filter_scroll_request(offset, limit, sort, filter_)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainDeviceResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_escalations_filter_command(client, args):
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    offset = str(args.get('offset', ''))

    response = client.query_escalations_filter_request(limit, sort, filter_, offset)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_firewall_policies_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_firewall_policies_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_firewall_policy_members_command(client, args):
    id_ = str(args.get('id_', ''))
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_firewall_policy_members_request(id_, filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_group_members_command(client, args):
    id_ = str(args.get('id_', ''))
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_group_members_request(id_, filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_hidden_devices_command(client, args):
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))

    response = client.query_hidden_devices_request(offset, limit, sort, filter_)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_host_groups_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_host_groups_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_incident_ids_by_filter_command(client, args):
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    offset = str(args.get('offset', ''))

    response = client.query_incident_ids_by_filter_request(limit, sort, filter_, offset)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_incidents_command(client, args):
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)

    response = client.query_incidents_request(sort, filter_, offset, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiMsaIncidentQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_intel_actor_entities_command(client, args):
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    q = str(args.get('q', ''))
    fields = argToList(args.get('fields', []))

    response = client.query_intel_actor_entities_request(offset, limit, sort, filter_, q, fields)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainActorsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_intel_actor_ids_command(client, args):
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    q = str(args.get('q', ''))

    response = client.query_intel_actor_ids_request(offset, limit, sort, filter_, q)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_intel_indicator_entities_command(client, args):
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    q = str(args.get('q', ''))
    include_deleted = argToBoolean(args.get('include_deleted', False))

    response = client.query_intel_indicator_entities_request(offset, limit, sort, filter_, q, include_deleted)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainPublicIndicatorsV3Response',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_intel_indicator_ids_command(client, args):
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    q = str(args.get('q', ''))
    include_deleted = argToBoolean(args.get('include_deleted', False))

    response = client.query_intel_indicator_ids_request(offset, limit, sort, filter_, q, include_deleted)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_intel_report_entities_command(client, args):
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    q = str(args.get('q', ''))
    fields = argToList(args.get('fields', []))

    response = client.query_intel_report_entities_request(offset, limit, sort, filter_, q, fields)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainNewsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_intel_report_ids_command(client, args):
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    q = str(args.get('q', ''))

    response = client.query_intel_report_ids_request(offset, limit, sort, filter_, q)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_intel_rule_ids_command(client, args):
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    name = argToList(args.get('name', []))
    type_ = str(args.get('type_', ''))
    description = argToList(args.get('description', []))
    tags = argToList(args.get('tags', []))
    min_created_date = args.get('min_created_date', None)
    max_created_date = str(args.get('max_created_date', ''))
    q = str(args.get('q', ''))

    response = client.query_intel_rule_ids_request(
        offset, limit, sort, name, type_, description, tags, min_created_date, max_created_date, q)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_notificationsv1_command(client, args):
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    q = str(args.get('q', ''))

    response = client.query_notificationsv1_request(offset, limit, sort, filter_, q)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_prevention_policies_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_prevention_policies_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_prevention_policy_members_command(client, args):
    id_ = str(args.get('id_', ''))
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_prevention_policy_members_request(id_, filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_remediations_filter_command(client, args):
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    offset = str(args.get('offset', ''))

    response = client.query_remediations_filter_request(limit, sort, filter_, offset)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_reports_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_reports_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_roles_command(client, args):
    user_group_id = str(args.get('user_group_id', ''))
    cid_group_id = str(args.get('cid_group_id', ''))
    role_id = str(args.get('role_id', ''))
    sort = str(args.get('sort', 'last_modified_timestamp|desc'))
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 10))

    response = client.query_roles_request(user_group_id, cid_group_id, role_id, sort, offset, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_rulesv1_command(client, args):
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    q = str(args.get('q', ''))

    response = client.query_rulesv1_request(offset, limit, sort, filter_, q)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainRuleQueryResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_samplev1_command(client, args):
    samplestore_querysamplesrequest_sha256s = argToList(args.get('samplestore_querysamplesrequest_sha256s', []))

    response = client.query_samplev1_request(samplestore_querysamplesrequest_sha256s)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_sensor_update_policies_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_sensor_update_policies_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_sensor_update_policy_members_command(client, args):
    id_ = str(args.get('id_', ''))
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_sensor_update_policy_members_request(id_, filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_sensor_visibility_exclusionsv1_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_sensor_visibility_exclusionsv1_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_submissions_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_submissions_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_submissions_mixin0_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.query_submissions_mixin0_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.mlscannerQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_user_group_members_command(client, args):
    user_uuid = str(args.get('user_uuid', ''))
    sort = str(args.get('sort', 'last_modified_timestamp|desc'))
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 10))

    response = client.query_user_group_members_request(user_uuid, sort, offset, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_user_groups_command(client, args):
    name = str(args.get('name', ''))
    sort = str(args.get('sort', 'name|asc'))
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 10))

    response = client.query_user_groups_request(name, sort, offset, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def query_vulnerabilities_command(client, args):
    after = str(args.get('after', ''))
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))

    response = client.query_vulnerabilities_request(after, limit, sort, filter_)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainSPAPIQueryVulnerabilitiesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def queryaws_accounts_command(client, args):
    limit = int(args.get('limit', 100))
    offset = args.get('offset', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))

    response = client.queryaws_accounts_request(limit, offset, sort, filter_)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.modelsAWSAccountsV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def queryaws_accounts_fori_ds_command(client, args):
    limit = int(args.get('limit', 100))
    offset = args.get('offset', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))

    response = client.queryaws_accounts_fori_ds_request(limit, offset, sort, filter_)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def querycid_group_members_command(client, args):
    cid = str(args.get('cid', ''))
    sort = str(args.get('sort', 'last_modified_timestamp|desc'))
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 10))

    response = client.querycid_group_members_request(cid, sort, offset, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def querycid_groups_command(client, args):
    name = str(args.get('name', ''))
    sort = str(args.get('sort', 'name|asc'))
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 10))

    response = client.querycid_groups_request(name, sort, offset, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def queryevents_command(client, args):
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    q = str(args.get('q', ''))
    offset = str(args.get('offset', ''))
    after = str(args.get('after', ''))
    limit = args.get('limit', None)

    response = client.queryevents_request(sort, filter_, q, offset, after, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrapiQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def queryfirewallfields_command(client, args):
    platform_id = str(args.get('platform_id', ''))
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)

    response = client.queryfirewallfields_request(platform_id, offset, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrmsaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def queryio_cs_command(client, args):
    types = str(args.get('types', ''))
    values = str(args.get('values', ''))
    from_expiration_timestamp = str(args.get('from_expiration_timestamp', ''))
    to_expiration_timestamp = str(args.get('to_expiration_timestamp', ''))
    policies = str(args.get('policies', ''))
    sources = str(args.get('sources', ''))
    share_levels = str(args.get('share_levels', ''))
    created_by = str(args.get('created_by', ''))
    deleted_by = str(args.get('deleted_by', ''))
    include_deleted = str(args.get('include_deleted', ''))

    response = client.queryio_cs_request(types, values, from_expiration_timestamp, to_expiration_timestamp,
                                         policies, sources, share_levels, created_by, deleted_by, include_deleted)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiMsaReplyIOCIDs',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def queryioa_exclusionsv1_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.queryioa_exclusionsv1_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def queryml_exclusionsv1_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.queryml_exclusionsv1_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def querypatterns_command(client, args):
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)

    response = client.querypatterns_request(offset, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def queryplatforms_command(client, args):
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)

    response = client.queryplatforms_request(offset, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrmsaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def queryplatforms_mixin0_command(client, args):
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)

    response = client.queryplatforms_mixin0_request(offset, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def querypolicyrules_command(client, args):
    id_ = str(args.get('id_', ''))
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    q = str(args.get('q', ''))
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)

    response = client.querypolicyrules_request(id_, sort, filter_, q, offset, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrapiQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def queryrt_response_policies_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.queryrt_response_policies_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def queryrt_response_policy_members_command(client, args):
    id_ = str(args.get('id_', ''))
    filter_ = str(args.get('filter_', ''))
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.queryrt_response_policy_members_request(id_, filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def queryrulegroups_command(client, args):
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    q = str(args.get('q', ''))
    offset = str(args.get('offset', ''))
    after = str(args.get('after', ''))
    limit = args.get('limit', None)

    response = client.queryrulegroups_request(sort, filter_, q, offset, after, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrapiQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def queryrulegroups_mixin0_command(client, args):
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    q = str(args.get('q', ''))
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)

    response = client.queryrulegroups_mixin0_request(sort, filter_, q, offset, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def queryrulegroupsfull_command(client, args):
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    q = str(args.get('q', ''))
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)

    response = client.queryrulegroupsfull_request(sort, filter_, q, offset, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def queryrules_command(client, args):
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    q = str(args.get('q', ''))
    offset = str(args.get('offset', ''))
    after = str(args.get('after', ''))
    limit = args.get('limit', None)

    response = client.queryrules_request(sort, filter_, q, offset, after, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrapiQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def queryrules_mixin0_command(client, args):
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))
    q = str(args.get('q', ''))
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)

    response = client.queryrules_mixin0_request(sort, filter_, q, offset, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def queryruletypes_command(client, args):
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)

    response = client.queryruletypes_request(offset, limit)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def refresh_active_stream_session_command(client, args):
    action_name = str(args.get('action_name', ''))
    appId = str(args.get('appId', ''))
    partition = args.get('partition', None)

    response = client.refresh_active_stream_session_request(action_name, appId, partition)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaReplyMetaOnly',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def regenerateapi_key_command(client, args):

    response = client.regenerateapi_key_request()
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.k8sregRegenAPIKeyResp',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def retrieve_emails_bycid_command(client, args):

    response = client.retrieve_emails_bycid_request()
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def retrieve_user_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.retrieve_user_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainUserMetaDataResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def retrieve_useruui_ds_bycid_command(client, args):

    response = client.retrieve_useruui_ds_bycid_request()
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def retrieve_useruuid_command(client, args):
    uid = argToList(args.get('uid', []))

    response = client.retrieve_useruuid_request(uid)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def reveal_uninstall_token_command(client, args):
    requests_revealuninstalltokenv1_audit_message = str(args.get('requests_revealuninstalltokenv1_audit_message', ''))
    requests_revealuninstalltokenv1_device_id = str(args.get('requests_revealuninstalltokenv1_device_id', ''))

    response = client.reveal_uninstall_token_request(
        requests_revealuninstalltokenv1_audit_message, requests_revealuninstalltokenv1_device_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesRevealUninstallTokenRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def revoke_user_role_ids_command(client, args):
    user_uuid = str(args.get('user_uuid', ''))
    ids = argToList(args.get('ids', []))

    response = client.revoke_user_role_ids_request(user_uuid, ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainUserRoleIDsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_aggregate_sessions_command(client, args):
    msa_aggregatequeryrequest_date_ranges = argToList(args.get('msa_aggregatequeryrequest_date_ranges', []))
    msa_aggregatequeryrequest_field = str(args.get('msa_aggregatequeryrequest_field', ''))
    msa_aggregatequeryrequest_filter = str(args.get('msa_aggregatequeryrequest_filter', ''))
    msa_aggregatequeryrequest_interval = str(args.get('msa_aggregatequeryrequest_interval', ''))
    msa_aggregatequeryrequest_min_doc_count = args.get('msa_aggregatequeryrequest_min_doc_count', None)
    msa_aggregatequeryrequest_missing = str(args.get('msa_aggregatequeryrequest_missing', ''))
    msa_aggregatequeryrequest_name = str(args.get('msa_aggregatequeryrequest_name', ''))
    msa_aggregatequeryrequest_q = str(args.get('msa_aggregatequeryrequest_q', ''))
    msa_aggregatequeryrequest_ranges = argToList(args.get('msa_aggregatequeryrequest_ranges', []))
    msa_aggregatequeryrequest_size = args.get('msa_aggregatequeryrequest_size', None)
    msa_aggregatequeryrequest_sort = str(args.get('msa_aggregatequeryrequest_sort', ''))
    msa_aggregatequeryrequest_sub_aggregates = argToList(args.get('msa_aggregatequeryrequest_sub_aggregates', []))
    msa_aggregatequeryrequest_time_zone = str(args.get('msa_aggregatequeryrequest_time_zone', ''))
    msa_aggregatequeryrequest_type = str(args.get('msa_aggregatequeryrequest_type', ''))

    response = client.rtr_aggregate_sessions_request(msa_aggregatequeryrequest_date_ranges, msa_aggregatequeryrequest_field, msa_aggregatequeryrequest_filter, msa_aggregatequeryrequest_interval, msa_aggregatequeryrequest_min_doc_count, msa_aggregatequeryrequest_missing,
                                                     msa_aggregatequeryrequest_name, msa_aggregatequeryrequest_q, msa_aggregatequeryrequest_ranges, msa_aggregatequeryrequest_size, msa_aggregatequeryrequest_sort, msa_aggregatequeryrequest_sub_aggregates, msa_aggregatequeryrequest_time_zone, msa_aggregatequeryrequest_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaAggregatesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_check_active_responder_command_status_command(client, args):
    cloud_request_id = str(args.get('cloud_request_id', ''))
    sequence_id = int(args.get('sequence_id', 0))

    response = client.rtr_check_active_responder_command_status_request(cloud_request_id, sequence_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainStatusResponseWrapper',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_check_admin_command_status_command(client, args):
    cloud_request_id = str(args.get('cloud_request_id', ''))
    sequence_id = int(args.get('sequence_id', 0))

    response = client.rtr_check_admin_command_status_request(cloud_request_id, sequence_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainStatusResponseWrapper',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_check_command_status_command(client, args):
    cloud_request_id = str(args.get('cloud_request_id', ''))
    sequence_id = int(args.get('sequence_id', 0))

    response = client.rtr_check_command_status_request(cloud_request_id, sequence_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainStatusResponseWrapper',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_create_put_files_command(client, args):
    file = str(args.get('file', ''))
    description = str(args.get('description', ''))
    name = str(args.get('name', ''))
    comments_for_audit_log = str(args.get('comments_for_audit_log', ''))

    response = client.rtr_create_put_files_request(file, description, name, comments_for_audit_log)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaReplyMetaOnly',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_create_scripts_command(client, args):
    file = str(args.get('file', ''))
    description = str(args.get('description', ''))
    name = str(args.get('name', ''))
    comments_for_audit_log = str(args.get('comments_for_audit_log', ''))
    permission_type = str(args.get('permission_type', 'none'))
    content = str(args.get('content', ''))
    platform = argToList(args.get('platform', []))

    response = client.rtr_create_scripts_request(
        file, description, name, comments_for_audit_log, permission_type, content, platform)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaReplyMetaOnly',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_delete_file_command(client, args):
    ids = str(args.get('ids', ''))
    session_id = str(args.get('session_id', ''))

    response = client.rtr_delete_file_request(ids, session_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_delete_put_files_command(client, args):
    ids = str(args.get('ids', ''))

    response = client.rtr_delete_put_files_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaReplyMetaOnly',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_delete_queued_session_command(client, args):
    session_id = str(args.get('session_id', ''))
    cloud_request_id = str(args.get('cloud_request_id', ''))

    response = client.rtr_delete_queued_session_request(session_id, cloud_request_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_delete_scripts_command(client, args):
    ids = str(args.get('ids', ''))

    response = client.rtr_delete_scripts_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaReplyMetaOnly',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_delete_session_command(client, args):
    session_id = str(args.get('session_id', ''))

    response = client.rtr_delete_session_request(session_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_execute_active_responder_command_command(client, args):
    domain_commandexecuterequest_base_command = str(args.get('domain_commandexecuterequest_base_command', ''))
    domain_commandexecuterequest_command_string = str(args.get('domain_commandexecuterequest_command_string', ''))
    domain_commandexecuterequest_device_id = str(args.get('domain_commandexecuterequest_device_id', ''))
    domain_commandexecuterequest_id = int(args.get('domain_commandexecuterequest_id', None))
    domain_commandexecuterequest_persist = argToBoolean(args.get('domain_commandexecuterequest_persist', False))
    domain_commandexecuterequest_session_id = str(args.get('domain_commandexecuterequest_session_id', ''))

    response = client.rtr_execute_active_responder_command_request(domain_commandexecuterequest_base_command, domain_commandexecuterequest_command_string,
                                                                   domain_commandexecuterequest_device_id, domain_commandexecuterequest_id, domain_commandexecuterequest_persist, domain_commandexecuterequest_session_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_execute_admin_command_command(client, args):
    domain_commandexecuterequest_base_command = str(args.get('domain_commandexecuterequest_base_command', ''))
    domain_commandexecuterequest_command_string = str(args.get('domain_commandexecuterequest_command_string', ''))
    domain_commandexecuterequest_device_id = str(args.get('domain_commandexecuterequest_device_id', ''))
    domain_commandexecuterequest_id = args.get('domain_commandexecuterequest_id', None)
    domain_commandexecuterequest_persist = argToBoolean(args.get('domain_commandexecuterequest_persist', False))
    domain_commandexecuterequest_session_id = str(args.get('domain_commandexecuterequest_session_id', ''))

    response = client.rtr_execute_admin_command_request(domain_commandexecuterequest_base_command, domain_commandexecuterequest_command_string,
                                                        domain_commandexecuterequest_device_id, domain_commandexecuterequest_id, domain_commandexecuterequest_persist, domain_commandexecuterequest_session_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_execute_command_command(client, args):
    domain_commandexecuterequest_base_command = str(args.get('domain_commandexecuterequest_base_command', ''))
    domain_commandexecuterequest_command_string = str(args.get('domain_commandexecuterequest_command_string', ''))
    domain_commandexecuterequest_device_id = str(args.get('domain_commandexecuterequest_device_id', ''))
    domain_commandexecuterequest_id = args.get('domain_commandexecuterequest_id', None)
    domain_commandexecuterequest_persist = argToBoolean(args.get('domain_commandexecuterequest_persist', False))
    domain_commandexecuterequest_session_id = str(args.get('domain_commandexecuterequest_session_id', ''))

    response = client.rtr_execute_command_request(domain_commandexecuterequest_base_command, domain_commandexecuterequest_command_string,
                                                  domain_commandexecuterequest_device_id, domain_commandexecuterequest_id, domain_commandexecuterequest_persist, domain_commandexecuterequest_session_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_get_extracted_file_contents_command(client, args):
    session_id = str(args.get('session_id', ''))
    sha256 = str(args.get('sha256', ''))
    filename = str(args.get('filename', ''))

    response = client.rtr_get_extracted_file_contents_request(session_id, sha256, filename)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_get_put_files_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.rtr_get_put_files_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.binservclientMsaPFResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_get_scripts_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.rtr_get_scripts_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.binservclientMsaPFResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_init_session_command(client, args):
    domain_initrequest_device_id = str(args.get('domain_initrequest_device_id', ''))
    domain_initrequest_origin = str(args.get('domain_initrequest_origin', ''))
    domain_initrequest_queue_offline = argToBoolean(args.get('domain_initrequest_queue_offline', False))

    response = client.rtr_init_session_request(
        domain_initrequest_device_id, domain_initrequest_origin, domain_initrequest_queue_offline)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_list_all_sessions_command(client, args):
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))

    response = client.rtr_list_all_sessions_request(offset, limit, sort, filter_)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainListSessionsResponseMsa',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_list_files_command(client, args):
    session_id = str(args.get('session_id', ''))

    response = client.rtr_list_files_request(session_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainListFilesResponseWrapper',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_list_put_files_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.rtr_list_put_files_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.binservclientMsaPutFileResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_list_queued_sessions_command(client, args):
    msa_idsrequest_ids = argToList(args.get('msa_idsrequest_ids', []))

    response = client.rtr_list_queued_sessions_request(msa_idsrequest_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainQueuedSessionResponseWrapper',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_list_scripts_command(client, args):
    filter_ = str(args.get('filter_', ''))
    offset = str(args.get('offset', ''))
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))

    response = client.rtr_list_scripts_request(filter_, offset, limit, sort)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.binservclientMsaPutFileResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_list_sessions_command(client, args):
    msa_idsrequest_ids = argToList(args.get('msa_idsrequest_ids', []))

    response = client.rtr_list_sessions_request(msa_idsrequest_ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainSessionResponseWrapper',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_pulse_session_command(client, args):
    domain_initrequest_device_id = str(args.get('domain_initrequest_device_id', ''))
    domain_initrequest_origin = str(args.get('domain_initrequest_origin', ''))
    domain_initrequest_queue_offline = argToBoolean(args.get('domain_initrequest_queue_offline', False))

    response = client.rtr_pulse_session_request(
        domain_initrequest_device_id, domain_initrequest_origin, domain_initrequest_queue_offline)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def rtr_update_scripts_command(client, args):
    id_ = str(args.get('id_', ''))
    file = str(args.get('file', ''))
    description = str(args.get('description', ''))
    name = str(args.get('name', ''))
    comments_for_audit_log = str(args.get('comments_for_audit_log', ''))
    permission_type = str(args.get('permission_type', 'none'))
    content = str(args.get('content', ''))
    platform = argToList(args.get('platform', []))

    response = client.rtr_update_scripts_request(
        id_, file, description, name, comments_for_audit_log, permission_type, content, platform)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaReplyMetaOnly',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def scan_samples_command(client, args):
    mlscanner_samplesscanparameters_samples = argToList(args.get('mlscanner_samplesscanparameters_samples', []))

    response = client.scan_samples_request(mlscanner_samplesscanparameters_samples)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.mlscannerQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def set_device_control_policies_precedence_command(client, args):
    requests_setpolicyprecedencereqv1_ids = argToList(args.get('requests_setpolicyprecedencereqv1_ids', []))
    requests_setpolicyprecedencereqv1_platform_name = str(args.get('requests_setpolicyprecedencereqv1_platform_name', ''))

    response = client.set_device_control_policies_precedence_request(
        requests_setpolicyprecedencereqv1_ids, requests_setpolicyprecedencereqv1_platform_name)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def set_firewall_policies_precedence_command(client, args):
    requests_setpolicyprecedencereqv1_ids = argToList(args.get('requests_setpolicyprecedencereqv1_ids', []))
    requests_setpolicyprecedencereqv1_platform_name = str(args.get('requests_setpolicyprecedencereqv1_platform_name', ''))

    response = client.set_firewall_policies_precedence_request(
        requests_setpolicyprecedencereqv1_ids, requests_setpolicyprecedencereqv1_platform_name)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def set_prevention_policies_precedence_command(client, args):
    requests_setpolicyprecedencereqv1_ids = argToList(args.get('requests_setpolicyprecedencereqv1_ids', []))
    requests_setpolicyprecedencereqv1_platform_name = str(args.get('requests_setpolicyprecedencereqv1_platform_name', ''))

    response = client.set_prevention_policies_precedence_request(
        requests_setpolicyprecedencereqv1_ids, requests_setpolicyprecedencereqv1_platform_name)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def set_sensor_update_policies_precedence_command(client, args):
    requests_setpolicyprecedencereqv1_ids = argToList(args.get('requests_setpolicyprecedencereqv1_ids', []))
    requests_setpolicyprecedencereqv1_platform_name = str(args.get('requests_setpolicyprecedencereqv1_platform_name', ''))

    response = client.set_sensor_update_policies_precedence_request(
        requests_setpolicyprecedencereqv1_ids, requests_setpolicyprecedencereqv1_platform_name)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def setrt_response_policies_precedence_command(client, args):
    requests_setpolicyprecedencereqv1_ids = argToList(args.get('requests_setpolicyprecedencereqv1_ids', []))
    requests_setpolicyprecedencereqv1_platform_name = str(args.get('requests_setpolicyprecedencereqv1_platform_name', ''))

    response = client.setrt_response_policies_precedence_request(
        requests_setpolicyprecedencereqv1_ids, requests_setpolicyprecedencereqv1_platform_name)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def submit_command(client, args):
    falconx_submissionparametersv1_sandbox = argToList(args.get('falconx_submissionparametersv1_sandbox', []))
    falconx_submissionparametersv1_user_tags = argToList(args.get('falconx_submissionparametersv1_user_tags', []))

    response = client.submit_request(falconx_submissionparametersv1_sandbox, falconx_submissionparametersv1_user_tags)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.falconxSubmissionV1Response',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def tokenscreate_command(client, args):
    api_tokencreaterequestv1_expires_timestamp = str(args.get('api_tokencreaterequestv1_expires_timestamp', ''))
    api_tokencreaterequestv1_label = str(args.get('api_tokencreaterequestv1_label', ''))
    api_tokencreaterequestv1_type = str(args.get('api_tokencreaterequestv1_type', ''))

    response = client.tokenscreate_request(api_tokencreaterequestv1_expires_timestamp,
                                           api_tokencreaterequestv1_label, api_tokencreaterequestv1_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def tokensdelete_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.tokensdelete_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaReplyMetaOnly',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def tokensquery_command(client, args):
    offset = args.get('offset', None)
    limit = args.get('limit', None)
    sort = str(args.get('sort', ''))
    filter_ = str(args.get('filter_', ''))

    response = client.tokensquery_request(offset, limit, sort, filter_)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def tokensread_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.tokensread_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apitokenDetailsResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def tokensupdate_command(client, args):
    ids = argToList(args.get('ids', []))
    api_tokenpatchrequestv1_expires_timestamp = str(args.get('api_tokenpatchrequestv1_expires_timestamp', ''))
    api_tokenpatchrequestv1_label = str(args.get('api_tokenpatchrequestv1_label', ''))
    api_tokenpatchrequestv1_revoked = argToBoolean(args.get('api_tokenpatchrequestv1_revoked', False))

    response = client.tokensupdate_request(ids, api_tokenpatchrequestv1_expires_timestamp,
                                           api_tokenpatchrequestv1_label, api_tokenpatchrequestv1_revoked)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def trigger_scan_command(client, args):
    scan_type = str(args.get('scan_type', 'dry-run'))

    response = client.trigger_scan_request(scan_type)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_actionv1_command(client, args):
    domain_updateactionrequest_frequency = str(args.get('domain_updateactionrequest_frequency', ''))
    domain_updateactionrequest_id = str(args.get('domain_updateactionrequest_id', ''))
    domain_updateactionrequest_recipients = argToList(args.get('domain_updateactionrequest_recipients', []))
    domain_updateactionrequest_status = str(args.get('domain_updateactionrequest_status', ''))

    response = client.update_actionv1_request(domain_updateactionrequest_frequency, domain_updateactionrequest_id,
                                              domain_updateactionrequest_recipients, domain_updateactionrequest_status)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainActionEntitiesResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_detects_by_idsv2_command(client, args):
    domain_detectsentitiespatchrequest_assigned_to_uuid = str(args.get('domain_detectsentitiespatchrequest_assigned_to_uuid', ''))
    domain_detectsentitiespatchrequest_comment = str(args.get('domain_detectsentitiespatchrequest_comment', ''))
    domain_detectsentitiespatchrequest_ids = argToList(args.get('domain_detectsentitiespatchrequest_ids', []))
    domain_detectsentitiespatchrequest_show_in_ui = argToBoolean(args.get('domain_detectsentitiespatchrequest_show_in_ui', False))
    domain_detectsentitiespatchrequest_status = str(args.get('domain_detectsentitiespatchrequest_status', ''))

    response = client.update_detects_by_idsv2_request(domain_detectsentitiespatchrequest_assigned_to_uuid, domain_detectsentitiespatchrequest_comment,
                                                      domain_detectsentitiespatchrequest_ids, domain_detectsentitiespatchrequest_show_in_ui, domain_detectsentitiespatchrequest_status)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaReplyMetaOnly',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_device_control_policies_command(client, args):
    requests_updatedevicecontrolpoliciesv1_resources = argToList(args.get('requests_updatedevicecontrolpoliciesv1_resources', []))

    response = client.update_device_control_policies_request(requests_updatedevicecontrolpoliciesv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesDeviceControlPoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_device_tags_command(client, args):
    domain_updatedevicetagsrequestv1_action = str(args.get('domain_updatedevicetagsrequestv1_action', ''))
    domain_updatedevicetagsrequestv1_device_ids = argToList(args.get('domain_updatedevicetagsrequestv1_device_ids', []))
    domain_updatedevicetagsrequestv1_tags = argToList(args.get('domain_updatedevicetagsrequestv1_tags', []))

    response = client.update_device_tags_request(domain_updatedevicetagsrequestv1_action,
                                                 domain_updatedevicetagsrequestv1_device_ids, domain_updatedevicetagsrequestv1_tags)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaEntitiesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_firewall_policies_command(client, args):
    requests_updatefirewallpoliciesv1_resources = argToList(args.get('requests_updatefirewallpoliciesv1_resources', []))

    response = client.update_firewall_policies_request(requests_updatefirewallpoliciesv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesFirewallPoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_host_groups_command(client, args):
    requests_updategroupsv1_resources = argToList(args.get('requests_updategroupsv1_resources', []))

    response = client.update_host_groups_request(requests_updategroupsv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesHostGroupsV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_notificationsv1_command(client, args):
    domain_updatenotificationrequestv1_assigned_to_uuid = str(args.get('domain_updatenotificationrequestv1_assigned_to_uuid', ''))
    domain_updatenotificationrequestv1_id = str(args.get('domain_updatenotificationrequestv1_id', ''))
    domain_updatenotificationrequestv1_status = str(args.get('domain_updatenotificationrequestv1_status', ''))

    response = client.update_notificationsv1_request(
        domain_updatenotificationrequestv1_assigned_to_uuid, domain_updatenotificationrequestv1_id, domain_updatenotificationrequestv1_status)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainNotificationEntitiesResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_prevention_policies_command(client, args):
    requests_updatepreventionpoliciesv1_resources = argToList(args.get('requests_updatepreventionpoliciesv1_resources', []))

    response = client.update_prevention_policies_request(requests_updatepreventionpoliciesv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesPreventionPoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_rulesv1_command(client, args):
    domain_updaterulerequestv1_filter = str(args.get('domain_updaterulerequestv1_filter', ''))
    domain_updaterulerequestv1_id = str(args.get('domain_updaterulerequestv1_id', ''))
    domain_updaterulerequestv1_name = str(args.get('domain_updaterulerequestv1_name', ''))
    domain_updaterulerequestv1_permissions = str(args.get('domain_updaterulerequestv1_permissions', ''))
    domain_updaterulerequestv1_priority = str(args.get('domain_updaterulerequestv1_priority', ''))

    response = client.update_rulesv1_request(domain_updaterulerequestv1_filter, domain_updaterulerequestv1_id,
                                             domain_updaterulerequestv1_name, domain_updaterulerequestv1_permissions, domain_updaterulerequestv1_priority)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainRulesEntitiesResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_sensor_update_policies_command(client, args):
    requests_updatesensorupdatepoliciesv1_resources = argToList(args.get('requests_updatesensorupdatepoliciesv1_resources', []))

    response = client.update_sensor_update_policies_request(requests_updatesensorupdatepoliciesv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesSensorUpdatePoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_sensor_update_policiesv2_command(client, args):
    requests_updatesensorupdatepoliciesv2_resources = argToList(args.get('requests_updatesensorupdatepoliciesv2_resources', []))

    response = client.update_sensor_update_policiesv2_request(requests_updatesensorupdatepoliciesv2_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesSensorUpdatePoliciesV2',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_sensor_visibility_exclusionsv1_command(client, args):
    requests_svexclusionupdatereqv1_comment = str(args.get('requests_svexclusionupdatereqv1_comment', ''))
    requests_svexclusionupdatereqv1_groups = argToList(args.get('requests_svexclusionupdatereqv1_groups', []))
    requests_svexclusionupdatereqv1_id = str(args.get('requests_svexclusionupdatereqv1_id', ''))
    requests_svexclusionupdatereqv1_value = str(args.get('requests_svexclusionupdatereqv1_value', ''))

    response = client.update_sensor_visibility_exclusionsv1_request(
        requests_svexclusionupdatereqv1_comment, requests_svexclusionupdatereqv1_groups, requests_svexclusionupdatereqv1_id, requests_svexclusionupdatereqv1_value)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesSvExclusionRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_user_command(client, args):
    user_uuid = str(args.get('user_uuid', ''))
    domain_updateuserfields_firstname = str(args.get('domain_updateuserfields_firstname', ''))
    domain_updateuserfields_lastname = str(args.get('domain_updateuserfields_lastname', ''))

    response = client.update_user_request(user_uuid, domain_updateuserfields_firstname, domain_updateuserfields_lastname)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainUserMetaDataResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_user_groups_command(client, args):
    domain_usergroupsrequestv1_resources = argToList(args.get('domain_usergroupsrequestv1_resources', []))

    response = client.update_user_groups_request(domain_usergroupsrequestv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainUserGroupsResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateaws_account_command(client, args):
    ids = argToList(args.get('ids', []))
    region = str(args.get('region', ''))

    response = client.updateaws_account_request(ids, region)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.msaBaseEntitiesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateaws_accounts_command(client, args):
    models_updateawsaccountsv1_resources = argToList(args.get('models_updateawsaccountsv1_resources', []))

    response = client.updateaws_accounts_request(models_updateawsaccountsv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.modelsAWSAccountsV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updatecid_groups_command(client, args):
    domain_cidgroupsrequestv1_resources = argToList(args.get('domain_cidgroupsrequestv1_resources', []))

    response = client.updatecid_groups_request(domain_cidgroupsrequestv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.domainCIDGroupsResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updatecspm_azure_tenant_default_subscriptionid_command(client, args):
    tenant_id = str(args.get('tenant_id', ''))
    subscription_id = str(args.get('subscription_id', ''))

    response = client.updatecspm_azure_tenant_default_subscriptionid_request(tenant_id, subscription_id)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updatecspm_policy_settings_command(client, args):
    registration_policyrequestextv1_resources = argToList(args.get('registration_policyrequestextv1_resources', []))

    response = client.updatecspm_policy_settings_request(registration_policyrequestextv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationPolicySettingsResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updatecspm_scan_schedule_command(client, args):
    registration_scanscheduleupdaterequestv1_resources = argToList(
        args.get('registration_scanscheduleupdaterequestv1_resources', []))

    response = client.updatecspm_scan_schedule_request(registration_scanscheduleupdaterequestv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.registrationScanScheduleResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateioa_exclusionsv1_command(client, args):
    requests_ioaexclusionupdatereqv1_cl_regex = str(args.get('requests_ioaexclusionupdatereqv1_cl_regex', ''))
    requests_ioaexclusionupdatereqv1_comment = str(args.get('requests_ioaexclusionupdatereqv1_comment', ''))
    requests_ioaexclusionupdatereqv1_description = str(args.get('requests_ioaexclusionupdatereqv1_description', ''))
    requests_ioaexclusionupdatereqv1_detection_json = str(args.get('requests_ioaexclusionupdatereqv1_detection_json', ''))
    requests_ioaexclusionupdatereqv1_groups = argToList(args.get('requests_ioaexclusionupdatereqv1_groups', []))
    requests_ioaexclusionupdatereqv1_id = str(args.get('requests_ioaexclusionupdatereqv1_id', ''))
    requests_ioaexclusionupdatereqv1_ifn_regex = str(args.get('requests_ioaexclusionupdatereqv1_ifn_regex', ''))
    requests_ioaexclusionupdatereqv1_name = str(args.get('requests_ioaexclusionupdatereqv1_name', ''))
    requests_ioaexclusionupdatereqv1_pattern_id = str(args.get('requests_ioaexclusionupdatereqv1_pattern_id', ''))
    requests_ioaexclusionupdatereqv1_pattern_name = str(args.get('requests_ioaexclusionupdatereqv1_pattern_name', ''))

    response = client.updateioa_exclusionsv1_request(requests_ioaexclusionupdatereqv1_cl_regex, requests_ioaexclusionupdatereqv1_comment, requests_ioaexclusionupdatereqv1_description, requests_ioaexclusionupdatereqv1_detection_json,
                                                     requests_ioaexclusionupdatereqv1_groups, requests_ioaexclusionupdatereqv1_id, requests_ioaexclusionupdatereqv1_ifn_regex, requests_ioaexclusionupdatereqv1_name, requests_ioaexclusionupdatereqv1_pattern_id, requests_ioaexclusionupdatereqv1_pattern_name)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesIoaExclusionRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateioc_command(client, args):
    api_iocviewrecord_batch_id = str(args.get('api_iocviewrecord_batch_id', ''))
    api_iocviewrecord_created_by = str(args.get('api_iocviewrecord_created_by', ''))
    api_iocviewrecord_created_timestamp = str(args.get('api_iocviewrecord_created_timestamp', ''))
    api_iocviewrecord_description = str(args.get('api_iocviewrecord_description', ''))
    api_iocviewrecord_expiration_days = args.get('api_iocviewrecord_expiration_days', None)
    api_iocviewrecord_expiration_timestamp = str(args.get('api_iocviewrecord_expiration_timestamp', ''))
    api_iocviewrecord_modified_by = str(args.get('api_iocviewrecord_modified_by', ''))
    api_iocviewrecord_modified_timestamp = str(args.get('api_iocviewrecord_modified_timestamp', ''))
    api_iocviewrecord_policy = str(args.get('api_iocviewrecord_policy', ''))
    api_iocviewrecord_share_level = str(args.get('api_iocviewrecord_share_level', ''))
    api_iocviewrecord_source = str(args.get('api_iocviewrecord_source', ''))
    api_iocviewrecord_type = str(args.get('api_iocviewrecord_type', ''))
    api_iocviewrecord_value = str(args.get('api_iocviewrecord_value', ''))
    type_ = str(args.get('type_', ''))
    value = str(args.get('value', ''))

    response = client.updateioc_request(api_iocviewrecord_batch_id, api_iocviewrecord_created_by, api_iocviewrecord_created_timestamp, api_iocviewrecord_description, api_iocviewrecord_expiration_days, api_iocviewrecord_expiration_timestamp,
                                        api_iocviewrecord_modified_by, api_iocviewrecord_modified_timestamp, api_iocviewrecord_policy, api_iocviewrecord_share_level, api_iocviewrecord_source, api_iocviewrecord_type, api_iocviewrecord_value, type_, value)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiMsaReplyIOC',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateml_exclusionsv1_command(client, args):
    requests_svexclusionupdatereqv1_comment = str(args.get('requests_svexclusionupdatereqv1_comment', ''))
    requests_svexclusionupdatereqv1_groups = argToList(args.get('requests_svexclusionupdatereqv1_groups', []))
    requests_svexclusionupdatereqv1_id = str(args.get('requests_svexclusionupdatereqv1_id', ''))
    requests_svexclusionupdatereqv1_value = str(args.get('requests_svexclusionupdatereqv1_value', ''))

    response = client.updateml_exclusionsv1_request(
        requests_svexclusionupdatereqv1_comment, requests_svexclusionupdatereqv1_groups,
        requests_svexclusionupdatereqv1_id, requests_svexclusionupdatereqv1_value)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesMlExclusionRespV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updatepolicycontainer_command(client, args):
    fwmgr_api_policycontainerupsertrequestv1_default_inbound = str(
        args.get('fwmgr_api_policycontainerupsertrequestv1_default_inbound', ''))
    fwmgr_api_policycontainerupsertrequestv1_default_outbound = str(
        args.get('fwmgr_api_policycontainerupsertrequestv1_default_outbound', ''))
    fwmgr_api_policycontainerupsertrequestv1_enforce = argToBoolean(
        args.get('fwmgr_api_policycontainerupsertrequestv1_enforce', False))
    fwmgr_api_policycontainerupsertrequestv1_is_default_policy = argToBoolean(
        args.get('fwmgr_api_policycontainerupsertrequestv1_is_default_policy', False))
    fwmgr_api_policycontainerupsertrequestv1_platform_id = str(
        args.get('fwmgr_api_policycontainerupsertrequestv1_platform_id', ''))
    fwmgr_api_policycontainerupsertrequestv1_policy_id = str(args.get('fwmgr_api_policycontainerupsertrequestv1_policy_id', ''))
    fwmgr_api_policycontainerupsertrequestv1_rule_group_ids = argToList(
        args.get('fwmgr_api_policycontainerupsertrequestv1_rule_group_ids', []))
    fwmgr_api_policycontainerupsertrequestv1_test_mode = argToBoolean(
        args.get('fwmgr_api_policycontainerupsertrequestv1_test_mode', False))
    fwmgr_api_policycontainerupsertrequestv1_tracking = str(args.get('fwmgr_api_policycontainerupsertrequestv1_tracking', ''))

    response = client.updatepolicycontainer_request(fwmgr_api_policycontainerupsertrequestv1_default_inbound, fwmgr_api_policycontainerupsertrequestv1_default_outbound, fwmgr_api_policycontainerupsertrequestv1_enforce, fwmgr_api_policycontainerupsertrequestv1_is_default_policy,
                                                    fwmgr_api_policycontainerupsertrequestv1_platform_id, fwmgr_api_policycontainerupsertrequestv1_policy_id, fwmgr_api_policycontainerupsertrequestv1_rule_group_ids, fwmgr_api_policycontainerupsertrequestv1_test_mode, fwmgr_api_policycontainerupsertrequestv1_tracking)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrmsaReplyMetaOnly',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updatert_response_policies_command(client, args):
    requests_updatertresponsepoliciesv1_resources = argToList(args.get('requests_updatertresponsepoliciesv1_resources', []))

    response = client.updatert_response_policies_request(requests_updatertresponsepoliciesv1_resources)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.responsesRTResponsePoliciesV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updaterulegroup_command(client, args):
    comment = str(args.get('comment', ''))
    fwmgr_api_rulegroupmodifyrequestv1_diff_operations = argToList(
        args.get('fwmgr_api_rulegroupmodifyrequestv1_diff_operations', []))
    fwmgr_api_rulegroupmodifyrequestv1_diff_type = str(args.get('fwmgr_api_rulegroupmodifyrequestv1_diff_type', ''))
    fwmgr_api_rulegroupmodifyrequestv1_id = str(args.get('fwmgr_api_rulegroupmodifyrequestv1_id', ''))
    fwmgr_api_rulegroupmodifyrequestv1_rule_ids = argToList(args.get('fwmgr_api_rulegroupmodifyrequestv1_rule_ids', []))
    fwmgr_api_rulegroupmodifyrequestv1_rule_versions = argToList(args.get('fwmgr_api_rulegroupmodifyrequestv1_rule_versions', []))
    fwmgr_api_rulegroupmodifyrequestv1_tracking = str(args.get('fwmgr_api_rulegroupmodifyrequestv1_tracking', ''))

    response = client.updaterulegroup_request(comment, fwmgr_api_rulegroupmodifyrequestv1_diff_operations, fwmgr_api_rulegroupmodifyrequestv1_diff_type, fwmgr_api_rulegroupmodifyrequestv1_id,
                                              fwmgr_api_rulegroupmodifyrequestv1_rule_ids, fwmgr_api_rulegroupmodifyrequestv1_rule_versions, fwmgr_api_rulegroupmodifyrequestv1_tracking)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.fwmgrapiQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updaterulegroup_mixin0_command(client, args):
    api_rulegroupmodifyrequestv1_comment = str(args.get('api_rulegroupmodifyrequestv1_comment', ''))
    api_rulegroupmodifyrequestv1_description = str(args.get('api_rulegroupmodifyrequestv1_description', ''))
    api_rulegroupmodifyrequestv1_enabled = argToBoolean(args.get('api_rulegroupmodifyrequestv1_enabled', False))
    api_rulegroupmodifyrequestv1_id = str(args.get('api_rulegroupmodifyrequestv1_id', ''))
    api_rulegroupmodifyrequestv1_name = str(args.get('api_rulegroupmodifyrequestv1_name', ''))
    api_rulegroupmodifyrequestv1_rulegroup_version = args.get('api_rulegroupmodifyrequestv1_rulegroup_version', None)

    response = client.updaterulegroup_mixin0_request(api_rulegroupmodifyrequestv1_comment, api_rulegroupmodifyrequestv1_description, api_rulegroupmodifyrequestv1_enabled,
                                                     api_rulegroupmodifyrequestv1_id, api_rulegroupmodifyrequestv1_name, api_rulegroupmodifyrequestv1_rulegroup_version)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiRuleGroupsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updaterules_command(client, args):
    api_ruleupdatesrequestv1_comment = str(args.get('api_ruleupdatesrequestv1_comment', ''))
    api_ruleupdatesrequestv1_rule_updates = argToList(args.get('api_ruleupdatesrequestv1_rule_updates', []))
    api_ruleupdatesrequestv1_rulegroup_id = str(args.get('api_ruleupdatesrequestv1_rulegroup_id', ''))
    api_ruleupdatesrequestv1_rulegroup_version = args.get('api_ruleupdatesrequestv1_rulegroup_version', None)

    response = client.updaterules_request(api_ruleupdatesrequestv1_comment, api_ruleupdatesrequestv1_rule_updates,
                                          api_ruleupdatesrequestv1_rulegroup_id, api_ruleupdatesrequestv1_rulegroup_version)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiRulesResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def upload_samplev2_command(client, args):
    body = argToList(args.get('body', []))
    upfile = str(args.get('upfile', ''))
    file_name = str(args.get('file_name', ''))
    comment = str(args.get('comment', ''))
    is_confidential = argToBoolean(args.get('is_confidential', False))

    response = client.upload_samplev2_request(body, upfile, file_name, comment, is_confidential)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.samplestoreSampleMetadataResponseV2',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def upload_samplev3_command(client, args):
    body = argToList(args.get('body', []))
    upfile = str(args.get('upfile', ''))
    file_name = str(args.get('file_name', ''))
    comment = str(args.get('comment', ''))
    is_confidential = argToBoolean(args.get('is_confidential', False))

    response = client.upload_samplev3_request(body, upfile, file_name, comment, is_confidential)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.samplestoreSampleMetadataResponseV2',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def validate_command(client, args):
    api_validationrequestv1_fields = argToList(args.get('api_validationrequestv1_fields', []))

    response = client.validate_request(api_validationrequestv1_fields)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.apiValidationResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def verifyaws_account_access_command(client, args):
    ids = argToList(args.get('ids', []))

    response = client.verifyaws_account_access_request(ids)
    command_results = CommandResults(
        outputs_prefix='CrowdStrike.modelsVerifyAccessResponseV1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client):
    # Test functions here
    return_results('ok')


def main():

    params = demisto.params()
    args = demisto.args()

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        # Disable insecure warnings
        urllib3.disable_warnings()

        client = Client(params)

        commands = {
            'cs-add-role': add_role_command,
            'cs-add-user-group-members': add_user_group_members_command,
            'cs-addcid-group-members': addcid_group_members_command,
            'cs-aggregate-allow-list': aggregate_allow_list_command,
            'cs-aggregate-block-list': aggregate_block_list_command,
            'cs-aggregate-detections': aggregate_detections_command,
            'cs-aggregate-device-count-collection': aggregate_device_count_collection_command,
            'cs-aggregate-escalations': aggregate_escalations_command,
            'cs-aggregate-notificationsv1': aggregate_notificationsv1_command,
            'cs-aggregate-remediations': aggregate_remediations_command,
            'cs-aggregateevents': aggregateevents_command,
            'cs-aggregatefc-incidents': aggregatefc_incidents_command,
            'cs-aggregatepolicyrules': aggregatepolicyrules_command,
            'cs-aggregaterulegroups': aggregaterulegroups_command,
            'cs-aggregaterules': aggregaterules_command,
            'cs-aggregates-detections-global-counts': aggregates_detections_global_counts_command,
            'cs-aggregates-events': aggregates_events_command,
            'cs-aggregates-events-collections': aggregates_events_collections_command,
            'cs-aggregates-incidents-global-counts': aggregates_incidents_global_counts_command,
            'cs-aggregatesow-events-global-counts': aggregatesow_events_global_counts_command,
            'cs-apipreemptproxypostgraphql': apipreemptproxypostgraphql_command,
            'cs-auditeventsquery': auditeventsquery_command,
            'cs-auditeventsread': auditeventsread_command,
            'cs-batch-active-responder-cmd': batch_active_responder_cmd_command,
            'cs-batch-admin-cmd': batch_admin_cmd_command,
            'cs-batch-cmd': batch_cmd_command,
            'cs-batch-get-cmd': batch_get_cmd_command,
            'cs-batch-get-cmd-status': batch_get_cmd_status_command,
            'cs-batch-init-sessions': batch_init_sessions_command,
            'cs-batch-refresh-sessions': batch_refresh_sessions_command,
            'cs-create-actionsv1': create_actionsv1_command,
            'cs-create-device-control-policies': create_device_control_policies_command,
            'cs-create-firewall-policies': create_firewall_policies_command,
            'cs-create-host-groups': create_host_groups_command,
            'cs-create-or-updateaws-settings': create_or_updateaws_settings_command,
            'cs-create-prevention-policies': create_prevention_policies_command,
            'cs-create-rulesv1': create_rulesv1_command,
            'cs-create-sensor-update-policies': create_sensor_update_policies_command,
            'cs-create-sensor-update-policiesv2': create_sensor_update_policiesv2_command,
            'cs-create-user': create_user_command,
            'cs-create-user-groups': create_user_groups_command,
            'cs-createaws-account': createaws_account_command,
            'cs-createcid-groups': createcid_groups_command,
            'cs-createcspm-aws-account': createcspm_aws_account_command,
            'cs-createcspmgcp-account': createcspmgcp_account_command,
            'cs-createioc': createioc_command,
            'cs-createml-exclusionsv1': createml_exclusionsv1_command,
            'cs-creatert-response-policies': creatert_response_policies_command,
            'cs-createrule': createrule_command,
            'cs-createrulegroup': createrulegroup_command,
            'cs-createrulegroup-mixin0': createrulegroup_mixin0_command,
            'cs-createsv-exclusionsv1': createsv_exclusionsv1_command,
            'cs-crowd-score': crowd_score_command,
            'cs-customersettingsread': customersettingsread_command,
            'cs-delete-actionv1': delete_actionv1_command,
            'cs-delete-device-control-policies': delete_device_control_policies_command,
            'cs-delete-firewall-policies': delete_firewall_policies_command,
            'cs-delete-host-groups': delete_host_groups_command,
            'cs-delete-notificationsv1': delete_notificationsv1_command,
            'cs-delete-prevention-policies': delete_prevention_policies_command,
            'cs-delete-report': delete_report_command,
            'cs-delete-rulesv1': delete_rulesv1_command,
            'cs-delete-samplev2': delete_samplev2_command,
            'cs-delete-samplev3': delete_samplev3_command,
            'cs-delete-sensor-update-policies': delete_sensor_update_policies_command,
            'cs-delete-sensor-visibility-exclusionsv1': delete_sensor_visibility_exclusionsv1_command,
            'cs-delete-user': delete_user_command,
            'cs-delete-user-group-members': delete_user_group_members_command,
            'cs-delete-user-groups': delete_user_groups_command,
            'cs-deleteaws-accounts': deleteaws_accounts_command,
            'cs-deleteaws-accounts-mixin0': deleteaws_accounts_mixin0_command,
            'cs-deletecid-group-members': deletecid_group_members_command,
            'cs-deletecid-groups': deletecid_groups_command,
            'cs-deletecspm-aws-account': deletecspm_aws_account_command,
            'cs-deletecspm-azure-account': deletecspm_azure_account_command,
            'cs-deleted-roles': deleted_roles_command,
            'cs-deleteioa-exclusionsv1': deleteioa_exclusionsv1_command,
            'cs-deleteioc': deleteioc_command,
            'cs-deleteml-exclusionsv1': deleteml_exclusionsv1_command,
            'cs-deletert-response-policies': deletert_response_policies_command,
            'cs-deleterulegroups': deleterulegroups_command,
            'cs-deleterulegroups-mixin0': deleterulegroups_mixin0_command,
            'cs-deleterules': deleterules_command,
            'cs-devices-count': devices_count_command,
            'cs-devices-ran-on': devices_ran_on_command,
            'cs-download-sensor-installer-by-id': download_sensor_installer_by_id_command,
            'cs-entitiesprocesses': entitiesprocesses_command,
            'cs-get-actionsv1': get_actionsv1_command,
            'cs-get-aggregate-detects': get_aggregate_detects_command,
            'cs-get-artifacts': get_artifacts_command,
            'cs-get-assessmentv1': get_assessmentv1_command,
            'cs-get-available-role-ids': get_available_role_ids_command,
            'cs-get-behaviors': get_behaviors_command,
            'cs-get-children': get_children_command,
            'cs-get-cloudconnectazure-entities-account-v1': get_cloudconnectazure_entities_account_v1_command,
            'cs-get-cloudconnectazure-entities-userscriptsdownload-v1': get_cloudconnectazure_entities_userscriptsdownload_v1_command,
            'cs-get-cloudconnectcspmazure-entities-account-v1': get_cloudconnectcspmazure_entities_account_v1_command,
            'cs-get-cloudconnectcspmazure-entities-userscriptsdownload-v1': get_cloudconnectcspmazure_entities_userscriptsdownload_v1_command,
            'cs-get-clusters': get_clusters_command,
            'cs-get-combined-sensor-installers-by-query': get_combined_sensor_installers_by_query_command,
            'cs-get-detect-summaries': get_detect_summaries_command,
            'cs-get-device-control-policies': get_device_control_policies_command,
            'cs-get-device-count-collection-queries-by-filter': get_device_count_collection_queries_by_filter_command,
            'cs-get-device-details': get_device_details_command,
            'cs-get-firewall-policies': get_firewall_policies_command,
            'cs-get-helm-values-yaml': get_helm_values_yaml_command,
            'cs-get-host-groups': get_host_groups_command,
            'cs-get-incidents': get_incidents_command,
            'cs-get-intel-actor-entities': get_intel_actor_entities_command,
            'cs-get-intel-indicator-entities': get_intel_indicator_entities_command,
            'cs-get-intel-report-entities': get_intel_report_entities_command,
            'cs-get-intel-reportpdf': get_intel_reportpdf_command,
            'cs-get-intel-rule-entities': get_intel_rule_entities_command,
            'cs-get-intel-rule-file': get_intel_rule_file_command,
            'cs-get-latest-intel-rule-file': get_latest_intel_rule_file_command,
            'cs-get-locations': get_locations_command,
            'cs-get-mal-query-downloadv1': get_mal_query_downloadv1_command,
            'cs-get-mal-query-entities-samples-fetchv1': get_mal_query_entities_samples_fetchv1_command,
            'cs-get-mal-query-metadatav1': get_mal_query_metadatav1_command,
            'cs-get-mal-query-quotasv1': get_mal_query_quotasv1_command,
            'cs-get-mal-query-requestv1': get_mal_query_requestv1_command,
            'cs-get-notifications-detailed-translatedv1': get_notifications_detailed_translatedv1_command,
            'cs-get-notifications-detailedv1': get_notifications_detailedv1_command,
            'cs-get-notifications-translatedv1': get_notifications_translatedv1_command,
            'cs-get-notificationsv1': get_notificationsv1_command,
            'cs-get-prevention-policies': get_prevention_policies_command,
            'cs-get-reports': get_reports_command,
            'cs-get-roles': get_roles_command,
            'cs-get-roles-byid': get_roles_byid_command,
            'cs-get-rulesv1': get_rulesv1_command,
            'cs-get-samplev2': get_samplev2_command,
            'cs-get-samplev3': get_samplev3_command,
            'cs-get-scans': get_scans_command,
            'cs-get-scans-aggregates': get_scans_aggregates_command,
            'cs-get-sensor-installers-by-query': get_sensor_installers_by_query_command,
            'cs-get-sensor-installers-entities': get_sensor_installers_entities_command,
            'cs-get-sensor-installersccid-by-query': get_sensor_installersccid_by_query_command,
            'cs-get-sensor-update-policies': get_sensor_update_policies_command,
            'cs-get-sensor-update-policiesv2': get_sensor_update_policiesv2_command,
            'cs-get-sensor-visibility-exclusionsv1': get_sensor_visibility_exclusionsv1_command,
            'cs-get-submissions': get_submissions_command,
            'cs-get-summary-reports': get_summary_reports_command,
            'cs-get-user-group-members-byid': get_user_group_members_byid_command,
            'cs-get-user-groups-byid': get_user_groups_byid_command,
            'cs-get-user-role-ids': get_user_role_ids_command,
            'cs-get-vulnerabilities': get_vulnerabilities_command,
            'cs-getaws-accounts': getaws_accounts_command,
            'cs-getaws-accounts-mixin0': getaws_accounts_mixin0_command,
            'cs-getaws-settings': getaws_settings_command,
            'cs-getcid-group-by-id': getcid_group_by_id_command,
            'cs-getcid-group-members-by': getcid_group_members_by_command,
            'cs-getcspm-aws-account': getcspm_aws_account_command,
            'cs-getcspm-aws-account-scripts-attachment': getcspm_aws_account_scripts_attachment_command,
            'cs-getcspm-aws-console-setupur-ls': getcspm_aws_console_setupur_ls_command,
            'cs-getcspm-azure-user-scripts': getcspm_azure_user_scripts_command,
            'cs-getcspm-policy': getcspm_policy_command,
            'cs-getcspm-policy-settings': getcspm_policy_settings_command,
            'cs-getcspm-scan-schedule': getcspm_scan_schedule_command,
            'cs-getcspmcgp-account': getcspmcgp_account_command,
            'cs-getcspmgcp-user-scripts': getcspmgcp_user_scripts_command,
            'cs-getcspmgcp-user-scripts-attachment': getcspmgcp_user_scripts_attachment_command,
            'cs-getevents': getevents_command,
            'cs-getfirewallfields': getfirewallfields_command,
            'cs-getioa-events': getioa_events_command,
            'cs-getioa-exclusionsv1': getioa_exclusionsv1_command,
            'cs-getioa-users': getioa_users_command,
            'cs-getioc': getioc_command,
            'cs-getml-exclusionsv1': getml_exclusionsv1_command,
            'cs-getpatterns': getpatterns_command,
            'cs-getplatforms': getplatforms_command,
            'cs-getplatforms-mixin0': getplatforms_mixin0_command,
            'cs-getpolicycontainers': getpolicycontainers_command,
            'cs-getrt-response-policies': getrt_response_policies_command,
            'cs-getrulegroups': getrulegroups_command,
            'cs-getrulegroups-mixin0': getrulegroups_mixin0_command,
            'cs-getrules': getrules_command,
            'cs-getrules-mixin0': getrules_mixin0_command,
            'cs-getrulesget': getrulesget_command,
            'cs-getruletypes': getruletypes_command,
            'cs-grant-user-role-ids': grant_user_role_ids_command,
            'cs-indicatorcombinedv1': indicatorcombinedv1_command,
            'cs-indicatorcreatev1': indicatorcreatev1_command,
            'cs-indicatordeletev1': indicatordeletev1_command,
            'cs-indicatorgetv1': indicatorgetv1_command,
            'cs-indicatorsearchv1': indicatorsearchv1_command,
            'cs-indicatorupdatev1': indicatorupdatev1_command,
            'cs-list-available-streamso-auth2': list_available_streamso_auth2_command,
            'cs-oauth2-access-token': oauth2_access_token_command,
            'cs-oauth2-revoke-token': oauth2_revoke_token_command,
            'cs-patch-cloudconnectazure-entities-clientid-v1': patch_cloudconnectazure_entities_clientid_v1_command,
            'cs-patch-cloudconnectcspmazure-entities-clientid-v1': patch_cloudconnectcspmazure_entities_clientid_v1_command,
            'cs-patchcspm-aws-account': patchcspm_aws_account_command,
            'cs-perform-actionv2': perform_actionv2_command,
            'cs-perform-device-control-policies-action': perform_device_control_policies_action_command,
            'cs-perform-firewall-policies-action': perform_firewall_policies_action_command,
            'cs-perform-group-action': perform_group_action_command,
            'cs-perform-incident-action': perform_incident_action_command,
            'cs-perform-prevention-policies-action': perform_prevention_policies_action_command,
            'cs-perform-sensor-update-policies-action': perform_sensor_update_policies_action_command,
            'cs-performrt-response-policies-action': performrt_response_policies_action_command,
            'cs-post-cloudconnectazure-entities-account-v1': post_cloudconnectazure_entities_account_v1_command,
            'cs-post-cloudconnectcspmazure-entities-account-v1': post_cloudconnectcspmazure_entities_account_v1_command,
            'cs-post-mal-query-entities-samples-multidownloadv1': post_mal_query_entities_samples_multidownloadv1_command,
            'cs-post-mal-query-exact-searchv1': post_mal_query_exact_searchv1_command,
            'cs-post-mal-query-fuzzy-searchv1': post_mal_query_fuzzy_searchv1_command,
            'cs-post-mal-query-huntv1': post_mal_query_huntv1_command,
            'cs-preview-rulev1': preview_rulev1_command,
            'cs-processes-ran-on': processes_ran_on_command,
            'cs-provisionaws-accounts': provisionaws_accounts_command,
            'cs-query-actionsv1': query_actionsv1_command,
            'cs-query-allow-list-filter': query_allow_list_filter_command,
            'cs-query-behaviors': query_behaviors_command,
            'cs-query-block-list-filter': query_block_list_filter_command,
            'cs-query-children': query_children_command,
            'cs-query-combined-device-control-policies': query_combined_device_control_policies_command,
            'cs-query-combined-device-control-policy-members': query_combined_device_control_policy_members_command,
            'cs-query-combined-firewall-policies': query_combined_firewall_policies_command,
            'cs-query-combined-firewall-policy-members': query_combined_firewall_policy_members_command,
            'cs-query-combined-group-members': query_combined_group_members_command,
            'cs-query-combined-host-groups': query_combined_host_groups_command,
            'cs-query-combined-prevention-policies': query_combined_prevention_policies_command,
            'cs-query-combined-prevention-policy-members': query_combined_prevention_policy_members_command,
            'cs-query-combined-sensor-update-builds': query_combined_sensor_update_builds_command,
            'cs-query-combined-sensor-update-policies': query_combined_sensor_update_policies_command,
            'cs-query-combined-sensor-update-policiesv2': query_combined_sensor_update_policiesv2_command,
            'cs-query-combined-sensor-update-policy-members': query_combined_sensor_update_policy_members_command,
            'cs-query-combinedrt-response-policies': query_combinedrt_response_policies_command,
            'cs-query-combinedrt-response-policy-members': query_combinedrt_response_policy_members_command,
            'cs-query-detection-ids-by-filter': query_detection_ids_by_filter_command,
            'cs-query-detects': query_detects_command,
            'cs-query-device-control-policies': query_device_control_policies_command,
            'cs-query-device-control-policy-members': query_device_control_policy_members_command,
            'cs-query-devices-by-filter': query_devices_by_filter_command,
            'cs-query-devices-by-filter-scroll': query_devices_by_filter_scroll_command,
            'cs-query-escalations-filter': query_escalations_filter_command,
            'cs-query-firewall-policies': query_firewall_policies_command,
            'cs-query-firewall-policy-members': query_firewall_policy_members_command,
            'cs-query-group-members': query_group_members_command,
            'cs-query-hidden-devices': query_hidden_devices_command,
            'cs-query-host-groups': query_host_groups_command,
            'cs-query-incident-ids-by-filter': query_incident_ids_by_filter_command,
            'cs-query-incidents': query_incidents_command,
            'cs-query-intel-actor-entities': query_intel_actor_entities_command,
            'cs-query-intel-actor-ids': query_intel_actor_ids_command,
            'cs-query-intel-indicator-entities': query_intel_indicator_entities_command,
            'cs-query-intel-indicator-ids': query_intel_indicator_ids_command,
            'cs-query-intel-report-entities': query_intel_report_entities_command,
            'cs-query-intel-report-ids': query_intel_report_ids_command,
            'cs-query-intel-rule-ids': query_intel_rule_ids_command,
            'cs-query-notificationsv1': query_notificationsv1_command,
            'cs-query-prevention-policies': query_prevention_policies_command,
            'cs-query-prevention-policy-members': query_prevention_policy_members_command,
            'cs-query-remediations-filter': query_remediations_filter_command,
            'cs-query-reports': query_reports_command,
            'cs-query-roles': query_roles_command,
            'cs-query-rulesv1': query_rulesv1_command,
            'cs-query-samplev1': query_samplev1_command,
            'cs-query-sensor-update-policies': query_sensor_update_policies_command,
            'cs-query-sensor-update-policy-members': query_sensor_update_policy_members_command,
            'cs-query-sensor-visibility-exclusionsv1': query_sensor_visibility_exclusionsv1_command,
            'cs-query-submissions': query_submissions_command,
            'cs-query-submissions-mixin0': query_submissions_mixin0_command,
            'cs-query-user-group-members': query_user_group_members_command,
            'cs-query-user-groups': query_user_groups_command,
            'cs-query-vulnerabilities': query_vulnerabilities_command,
            'cs-queryaws-accounts': queryaws_accounts_command,
            'cs-queryaws-accounts-fori-ds': queryaws_accounts_fori_ds_command,
            'cs-querycid-group-members': querycid_group_members_command,
            'cs-querycid-groups': querycid_groups_command,
            'cs-queryevents': queryevents_command,
            'cs-queryfirewallfields': queryfirewallfields_command,
            'cs-queryio-cs': queryio_cs_command,
            'cs-queryioa-exclusionsv1': queryioa_exclusionsv1_command,
            'cs-queryml-exclusionsv1': queryml_exclusionsv1_command,
            'cs-querypatterns': querypatterns_command,
            'cs-queryplatforms': queryplatforms_command,
            'cs-queryplatforms-mixin0': queryplatforms_mixin0_command,
            'cs-querypolicyrules': querypolicyrules_command,
            'cs-queryrt-response-policies': queryrt_response_policies_command,
            'cs-queryrt-response-policy-members': queryrt_response_policy_members_command,
            'cs-queryrulegroups': queryrulegroups_command,
            'cs-queryrulegroups-mixin0': queryrulegroups_mixin0_command,
            'cs-queryrulegroupsfull': queryrulegroupsfull_command,
            'cs-queryrules': queryrules_command,
            'cs-queryrules-mixin0': queryrules_mixin0_command,
            'cs-queryruletypes': queryruletypes_command,
            'cs-refresh-active-stream-session': refresh_active_stream_session_command,
            'cs-regenerateapi-key': regenerateapi_key_command,
            'cs-retrieve-emails-bycid': retrieve_emails_bycid_command,
            'cs-retrieve-user': retrieve_user_command,
            'cs-retrieve-useruui-ds-bycid': retrieve_useruui_ds_bycid_command,
            'cs-retrieve-useruuid': retrieve_useruuid_command,
            'cs-reveal-uninstall-token': reveal_uninstall_token_command,
            'cs-revoke-user-role-ids': revoke_user_role_ids_command,
            'cs-rtr-aggregate-sessions': rtr_aggregate_sessions_command,
            'cs-rtr-check-active-responder-command-status': rtr_check_active_responder_command_status_command,
            'cs-rtr-check-admin-command-status': rtr_check_admin_command_status_command,
            'cs-rtr-check-command-status': rtr_check_command_status_command,
            'cs-rtr-create-put-files': rtr_create_put_files_command,
            'cs-rtr-create-scripts': rtr_create_scripts_command,
            'cs-rtr-delete-file': rtr_delete_file_command,
            'cs-rtr-delete-put-files': rtr_delete_put_files_command,
            'cs-rtr-delete-queued-session': rtr_delete_queued_session_command,
            'cs-rtr-delete-scripts': rtr_delete_scripts_command,
            'cs-rtr-delete-session': rtr_delete_session_command,
            'cs-rtr-execute-active-responder-command': rtr_execute_active_responder_command_command,
            'cs-rtr-execute-admin-command': rtr_execute_admin_command_command,
            'cs-rtr-execute-command': rtr_execute_command_command,
            'cs-rtr-get-extracted-file-contents': rtr_get_extracted_file_contents_command,
            'cs-rtr-get-put-files': rtr_get_put_files_command,
            'cs-rtr-get-scripts': rtr_get_scripts_command,
            'cs-rtr-init-session': rtr_init_session_command,
            'cs-rtr-list-all-sessions': rtr_list_all_sessions_command,
            'cs-rtr-list-files': rtr_list_files_command,
            'cs-rtr-list-put-files': rtr_list_put_files_command,
            'cs-rtr-list-queued-sessions': rtr_list_queued_sessions_command,
            'cs-rtr-list-scripts': rtr_list_scripts_command,
            'cs-rtr-list-sessions': rtr_list_sessions_command,
            'cs-rtr-pulse-session': rtr_pulse_session_command,
            'cs-rtr-update-scripts': rtr_update_scripts_command,
            'cs-scan-samples': scan_samples_command,
            'cs-set-device-control-policies-precedence': set_device_control_policies_precedence_command,
            'cs-set-firewall-policies-precedence': set_firewall_policies_precedence_command,
            'cs-set-prevention-policies-precedence': set_prevention_policies_precedence_command,
            'cs-set-sensor-update-policies-precedence': set_sensor_update_policies_precedence_command,
            'cs-setrt-response-policies-precedence': setrt_response_policies_precedence_command,
            'cs-submit': submit_command,
            'cs-tokenscreate': tokenscreate_command,
            'cs-tokensdelete': tokensdelete_command,
            'cs-tokensquery': tokensquery_command,
            'cs-tokensread': tokensread_command,
            'cs-tokensupdate': tokensupdate_command,
            'cs-trigger-scan': trigger_scan_command,
            'cs-update-actionv1': update_actionv1_command,
            'cs-update-detects-by-idsv2': update_detects_by_idsv2_command,
            'cs-update-device-control-policies': update_device_control_policies_command,
            'cs-update-device-tags': update_device_tags_command,
            'cs-update-firewall-policies': update_firewall_policies_command,
            'cs-update-host-groups': update_host_groups_command,
            'cs-update-notificationsv1': update_notificationsv1_command,
            'cs-update-prevention-policies': update_prevention_policies_command,
            'cs-update-rulesv1': update_rulesv1_command,
            'cs-update-sensor-update-policies': update_sensor_update_policies_command,
            'cs-update-sensor-update-policiesv2': update_sensor_update_policiesv2_command,
            'cs-update-sensor-visibility-exclusionsv1': update_sensor_visibility_exclusionsv1_command,
            'cs-update-user': update_user_command,
            'cs-update-user-groups': update_user_groups_command,
            'cs-updateaws-account': updateaws_account_command,
            'cs-updateaws-accounts': updateaws_accounts_command,
            'cs-updatecid-groups': updatecid_groups_command,
            'cs-updatecspm-azure-tenant-default-subscriptionid': updatecspm_azure_tenant_default_subscriptionid_command,
            'cs-updatecspm-policy-settings': updatecspm_policy_settings_command,
            'cs-updatecspm-scan-schedule': updatecspm_scan_schedule_command,
            'cs-updateioa-exclusionsv1': updateioa_exclusionsv1_command,
            'cs-updateioc': updateioc_command,
            'cs-updateml-exclusionsv1': updateml_exclusionsv1_command,
            'cs-updatepolicycontainer': updatepolicycontainer_command,
            'cs-updatert-response-policies': updatert_response_policies_command,
            'cs-updaterulegroup': updaterulegroup_command,
            'cs-updaterulegroup-mixin0': updaterulegroup_mixin0_command,
            'cs-updaterules': updaterules_command,
            'cs-upload-samplev2': upload_samplev2_command,
            'cs-upload-samplev3': upload_samplev3_command,
            'cs-validate': validate_command,
            'cs-verifyaws-account-access': verifyaws_account_access_command,
            'cs-get-device-login-history': get_device_login_history_command,
            'cs-get-device-network-history': get_device_network_history_command
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}', e)


from CrowdStrikeApiModule import *  # noqa: E402


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
