from http import client
import demistomock as demisto
from CommonServerPython import *


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def create_fact_request(self, fact_unique, fact_name, fact_links, fact_relationships, fact_origin_type, fact_created, fact_limit_count, fact_technique_id, fact_trait, fact_source, fact_score, fact_value, fact_collected_by):
        data = assign_params(unique=fact_unique, name=fact_name, links=fact_links, relationships=fact_relationships, origin_type=fact_origin_type, created=fact_created, limit_count=fact_limit_count, technique_id=fact_technique_id, trait=fact_trait, source=fact_source, score=fact_score, value=fact_value, collected_by=fact_collected_by)
        headers = self._headers

        response = self._http_request('post', 'api/v2/facts', json_data=data, headers=headers)

        return response

    def create_fact_source_request(self, source_name, source_adjustments, source_relationships, source_id, source_rules, source_facts, source_plugin):
        data = assign_params(name=source_name, adjustments=source_adjustments, relationships=source_relationships, id=source_id, rules=source_rules, facts=source_facts, plugin=source_plugin)
        headers = self._headers

        response = self._http_request('post', 'api/v2/sources', json_data=data, headers=headers)

        return response

    def createanewadversary_request(self, adversary_name, adversary_tags, adversary_objective, adversary_adversary_id, adversary_has_repeatable_abilities, adversary_atomic_ordering, adversary_plugin, adversary_description):
        data = assign_params(name=adversary_name, tags=adversary_tags, objective=adversary_objective, adversary_id=adversary_adversary_id, has_repeatable_abilities=adversary_has_repeatable_abilities, atomic_ordering=adversary_atomic_ordering, plugin=adversary_plugin, description=adversary_description)
        headers = self._headers

        response = self._http_request('post', 'api/v2/adversaries', json_data=data, headers=headers)

        return response

    def createanewagent_request(self, agent_watchdog, agent_links, agent_deadman_enabled, agent_ppid, agent_pid, agent_created, agent_proxy_receivers, agent_origin_link_id, agent_available_contacts, agent_last_seen, agent_platform, agent_pending_contact, agent_host, agent_group, agent_location, agent_display_name, agent_upstream_dest, agent_host_ip_addrs, agent_sleep_max, agent_architecture, agent_sleep_min, agent_server, agent_contact, agent_executors, agent_privilege, agent_username, agent_trusted, agent_proxy_chain, agent_paw, agent_exe_name):
        data = assign_params(watchdog=agent_watchdog, links=agent_links, deadman_enabled=agent_deadman_enabled, ppid=agent_ppid, pid=agent_pid, created=agent_created, proxy_receivers=agent_proxy_receivers, origin_link_id=agent_origin_link_id, available_contacts=agent_available_contacts, last_seen=agent_last_seen, platform=agent_platform, pending_contact=agent_pending_contact, host=agent_host, group=agent_group, location=agent_location, display_name=agent_display_name, upstream_dest=agent_upstream_dest, host_ip_addrs=agent_host_ip_addrs, sleep_max=agent_sleep_max, architecture=agent_architecture, sleep_min=agent_sleep_min, server=agent_server, contact=agent_contact, executors=agent_executors, privilege=agent_privilege, username=agent_username, trusted=agent_trusted, proxy_chain=agent_proxy_chain, paw=agent_paw, exe_name=agent_exe_name)
        headers = self._headers

        response = self._http_request('post', 'api/v2/agents', json_data=data, headers=headers)

        return response

    def createanewcalderaoperationrecord_request(self, operation_name, operation_autonomous, operation_id, operation_objective, operation_visibility, operation_state, operation_group, operation_host_group, operation_planner, operation_obfuscator, operation_chain, operation_use_learning_parsers, operation_source, operation_jitter, operation_start, operation_adversary, operation_auto_close):
        data = assign_params(name=operation_name, autonomous=operation_autonomous, id=operation_id, objective=operation_objective, visibility=operation_visibility, state=operation_state, group=operation_group, host_group=operation_host_group, planner=operation_planner, obfuscator=operation_obfuscator, chain=operation_chain, use_learning_parsers=operation_use_learning_parsers, source=operation_source, jitter=operation_jitter, start=operation_start, adversary=operation_adversary, auto_close=operation_auto_close)
        headers = self._headers

        response = self._http_request('post', 'api/v2/operations', json_data=data, headers=headers)

        return response

    def createanewobjective_request(self, objective_name, objective_id, objective_percentage, objective_goals, objective_description):
        data = assign_params(name=objective_name, id=objective_id, percentage=objective_percentage, goals=objective_goals, description=objective_description)
        headers = self._headers

        response = self._http_request('post', 'api/v2/objectives', json_data=data, headers=headers)

        return response

    def createarelationship_request(self, relationship_unique, relationship_origin, relationship_edge, relationship_source, relationship_score, relationship_target):
        data = assign_params(unique=relationship_unique, origin=relationship_origin, edge=relationship_edge, source=relationship_source, score=relationship_score, target=relationship_target)
        headers = self._headers

        response = self._http_request('post', 'api/v2/relationships', json_data=data, headers=headers)

        return response

    def createorupdateanadversary_request(self, adversary_id, partial_adversary_name, partial_adversary_tags, partial_adversary_objective, partial_adversary_adversary_id, partial_adversary_has_repeatable_abilities, partial_adversary_atomic_ordering, partial_adversary_plugin, partial_adversary_description):
        data = assign_params(name=partial_adversary_name, tags=partial_adversary_tags, objective=partial_adversary_objective, adversary_id=partial_adversary_adversary_id, has_repeatable_abilities=partial_adversary_has_repeatable_abilities, atomic_ordering=partial_adversary_atomic_ordering, plugin=partial_adversary_plugin, description=partial_adversary_description)
        headers = self._headers

        response = self._http_request('put', f'api/v2/adversaries/{adversary_id}', json_data=data, headers=headers)

        return response

    def createorupdateanagent_request(self, paw, partial_agent_watchdog, partial_agent_links, partial_agent_deadman_enabled, partial_agent_ppid, partial_agent_pid, partial_agent_created, partial_agent_proxy_receivers, partial_agent_origin_link_id, partial_agent_available_contacts, partial_agent_last_seen, partial_agent_platform, partial_agent_pending_contact, partial_agent_host, partial_agent_group, partial_agent_location, partial_agent_display_name, partial_agent_upstream_dest, partial_agent_host_ip_addrs, partial_agent_sleep_max, partial_agent_architecture, partial_agent_sleep_min, partial_agent_server, partial_agent_contact, partial_agent_executors, partial_agent_privilege, partial_agent_username, partial_agent_trusted, partial_agent_proxy_chain, partial_agent_paw, partial_agent_exe_name):
        data = assign_params(watchdog=partial_agent_watchdog, links=partial_agent_links, deadman_enabled=partial_agent_deadman_enabled, ppid=partial_agent_ppid, pid=partial_agent_pid, created=partial_agent_created, proxy_receivers=partial_agent_proxy_receivers, origin_link_id=partial_agent_origin_link_id, available_contacts=partial_agent_available_contacts, last_seen=partial_agent_last_seen, platform=partial_agent_platform, pending_contact=partial_agent_pending_contact, host=partial_agent_host, group=partial_agent_group, location=partial_agent_location, display_name=partial_agent_display_name, upstream_dest=partial_agent_upstream_dest, host_ip_addrs=partial_agent_host_ip_addrs, sleep_max=partial_agent_sleep_max, architecture=partial_agent_architecture, sleep_min=partial_agent_sleep_min, server=partial_agent_server, contact=partial_agent_contact, executors=partial_agent_executors, privilege=partial_agent_privilege, username=partial_agent_username, trusted=partial_agent_trusted, proxy_chain=partial_agent_proxy_chain, paw=partial_agent_paw, exe_name=partial_agent_exe_name)
        headers = self._headers

        response = self._http_request('put', f'api/v2/agents/{paw}', json_data=data, headers=headers)

        return response

    def createorupdateanobjective_request(self, id_, partial_objective_name, partial_objective_id, partial_objective_percentage, partial_objective_goals, partial_objective_description):
        data = assign_params(name=partial_objective_name, id=partial_objective_id, percentage=partial_objective_percentage, goals=partial_objective_goals, description=partial_objective_description)
        headers = self._headers

        response = self._http_request('put', f'api/v2/objectives/{id_}', json_data=data, headers=headers)

        return response

    def createsanewability_request(self, ability_ability_id, ability_name, ability_buckets, ability_technique_id, ability_delete_payload, ability_executors, ability_privilege, ability_requirements, ability_plugin, ability_access, ability_tactic, ability_additional_info, ability_singleton, ability_technique_name, ability_repeatable, ability_description):
        data = assign_params(ability_id=ability_ability_id, name=ability_name, buckets=ability_buckets, technique_id=ability_technique_id, delete_payload=ability_delete_payload, executors=ability_executors, privilege=ability_privilege, requirements=ability_requirements, plugin=ability_plugin, access=ability_access, tactic=ability_tactic, additional_info=ability_additional_info, singleton=ability_singleton, technique_name=ability_technique_name, repeatable=ability_repeatable, description=ability_description)
        headers = self._headers

        response = self._http_request('post', 'api/v2/abilities', json_data=data, headers=headers)

        return response

    def createsapotentiallink_request(self, id_, link_relationships, link_id, link_collect, link_pid, link_visibility, link_finish, link_pin, link_jitter, link_agent_reported_time, link_deadman, link_used, link_host, link_ability, link_status, link_score, link_command, link_unique, link_cleanup, link_decide, link_facts, link_executor, link_paw, link_output):
        data = assign_params(relationships=link_relationships, id=link_id, collect=link_collect, pid=link_pid, visibility=link_visibility, finish=link_finish, pin=link_pin, jitter=link_jitter, agent_reported_time=link_agent_reported_time, deadman=link_deadman, used=link_used, host=link_host, ability=link_ability, status=link_status, score=link_score, command=link_command, unique=link_unique, cleanup=link_cleanup, decide=link_decide, facts=link_facts, executor=link_executor, paw=link_paw, output=link_output)
        headers = self._headers

        response = self._http_request('post', f'api/v2/operations/{id_}/potential-links', json_data=data, headers=headers)

        return response

    def createschedule_request(self, schedule_schedule, schedule_task, schedule_id):
        data = assign_params(schedule=schedule_schedule, task=schedule_task, id=schedule_id)
        headers = self._headers

        response = self._http_request('post', 'api/v2/schedules', json_data=data, headers=headers)

        return response

    def deleteanagent_request(self, paw):
        headers = self._headers

        response = self._http_request('delete', f'api/v2/agents/{paw}', headers=headers)

        return response

    def deleteanexistingfactsource_request(self, id_):
        headers = self._headers

        response = self._http_request('delete', f'api/v2/sources/{id_}', headers=headers)

        return response

    def deleteanoperationbyoperationid_request(self, id_):
        headers = self._headers

        response = self._http_request('delete', f'api/v2/operations/{id_}', headers=headers)

        return response

    def deleteoneormorefacts_request(self, partial_fact_unique, partial_fact_name, partial_fact_links, partial_fact_relationships, partial_fact_origin_type, partial_fact_created, partial_fact_limit_count, partial_fact_technique_id, partial_fact_trait, partial_fact_source, partial_fact_score, partial_fact_value, partial_fact_collected_by):
        data = assign_params(unique=partial_fact_unique, name=partial_fact_name, links=partial_fact_links, relationships=partial_fact_relationships, origin_type=partial_fact_origin_type, created=partial_fact_created, limit_count=partial_fact_limit_count, technique_id=partial_fact_technique_id, trait=partial_fact_trait, source=partial_fact_source, score=partial_fact_score, value=partial_fact_value, collected_by=partial_fact_collected_by)
        headers = self._headers

        response = self._http_request('delete', 'api/v2/facts', json_data=data, headers=headers)

        return response

    def deleteoneormorerelationships_request(self, partial_relationship_unique, partial_relationship_origin, partial_relationship_edge, partial_relationship_source, partial_relationship_score, partial_relationship_target):
        data = assign_params(unique=partial_relationship_unique, origin=partial_relationship_origin, edge=partial_relationship_edge, source=partial_relationship_source, score=partial_relationship_score, target=partial_relationship_target)
        headers = self._headers

        response = self._http_request('delete', 'api/v2/relationships', json_data=data, headers=headers)

        return response

    def deletesanability_request(self, ability_id):
        headers = self._headers

        response = self._http_request('delete', f'api/v2/abilities/{ability_id}', headers=headers)

        return response

    def deletesanadversary_request(self, adversary_id):
        headers = self._headers

        response = self._http_request('delete', f'api/v2/adversaries/{adversary_id}', headers=headers)

        return response

    def deleteschedule_request(self, id_):
        headers = self._headers

        response = self._http_request('delete', f'api/v2/schedules/{id_}', headers=headers)

        return response

    def get_api_v2_abilities_request(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/abilities', params=params, headers=headers)

        return response

    def get_api_v2_abilities_by_ability_id_request(self, ability_id, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/abilities/{ability_id}', params=params, headers=headers)

        return response

    def get_api_v2_adversaries_request(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/adversaries', params=params, headers=headers)

        return response

    def get_api_v2_adversaries_by_adversary_id_request(self, adversary_id, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/adversaries/{adversary_id}', params=params, headers=headers)

        return response

    def get_api_v2_agents_request(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/agents', params=params, headers=headers)

        return response

    def get_api_v2_agents_by_paw_request(self, paw, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/agents/{paw}', params=params, headers=headers)

        return response

    def get_api_v2_config_by_name_request(self, name):
        headers = self._headers

        response = self._http_request('get', f'api/v2/config/{name}', headers=headers)

        return response

    def get_api_v2_contacts_request(self):
        headers = self._headers

        response = self._http_request('get', 'api/v2/contacts', headers=headers)

        return response

    def get_api_v2_contacts_by_name_request(self, name):
        headers = self._headers

        response = self._http_request('get', f'api/v2/contacts/{name}', headers=headers)

        return response

    def get_api_v2_deploy_commands_request(self):
        headers = self._headers

        response = self._http_request('get', 'api/v2/deploy_commands', headers=headers)

        return response

    def get_api_v2_deploy_commands_by_ability_id_request(self, ability_id):
        headers = self._headers

        response = self._http_request('get', f'api/v2/deploy_commands/{ability_id}', headers=headers)

        return response

    def get_api_v2_facts_request(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/facts', params=params, headers=headers)

        return response

    def get_api_v2_facts_by_operation_id_request(self, sort, include, exclude, operation_id):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/facts/{operation_id}', params=params, headers=headers)

        return response

    def get_api_v2_health_request(self):
        headers = self._headers

        response = self._http_request('get', 'api/v2/health', headers=headers)

        return response

    def get_api_v2_obfuscators_request(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/obfuscators', params=params, headers=headers)

        return response

    def get_api_v2_obfuscators_by_name_request(self, name, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/obfuscators/{name}', params=params, headers=headers)

        return response

    def get_api_v2_objectives_request(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/objectives', params=params, headers=headers)

        return response

    def get_api_v2_objectives_by_id_request(self, id_, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/objectives/{id_}', params=params, headers=headers)

        return response

    def get_api_v2_operations_request(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/operations', params=params, headers=headers)

        return response

    def get_api_v2_operations_by_id_request(self, id_, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/operations/{id_}', params=params, headers=headers)

        return response

    def get_api_v2_operations_links_request(self, id_, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/operations/{id_}/links', params=params, headers=headers)

        return response

    def get_api_v2_operations_links_by_link_id_request(self, id_, link_id, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/operations/{id_}/links/{link_id_}', params=params, headers=headers)

        return response

    def get_api_v2_operations_links_result_request(self, id_, link_id, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/operations/{id_}/links/{link_id_}/result', params=params, headers=headers)

        return response

    def get_api_v2_operations_potentiallinks_request(self, id_, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/operations/{id_}/potential-links', params=params, headers=headers)

        return response

    def get_api_v2_operations_potentiallinks_by_paw_request(self, id_, paw, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/operations/{id_}/potential-links/{paw}', params=params, headers=headers)

        return response

    def get_api_v2_planners_request(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/planners', params=params, headers=headers)

        return response

    def get_api_v2_planners_by_planner_id_request(self, planner_id, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/planners/{planner_id}', params=params, headers=headers)

        return response

    def get_api_v2_plugins_request(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/plugins', params=params, headers=headers)

        return response

    def get_api_v2_plugins_by_name_request(self, name, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/plugins/{name}', params=params, headers=headers)

        return response

    def get_api_v2_relationships_request(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/relationships', params=params, headers=headers)

        return response

    def get_api_v2_relationships_by_operation_id_request(self, sort, include, exclude, operation_id):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/relationships/{operation_id}', params=params, headers=headers)

        return response

    def get_api_v2_schedules_request(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/schedules', params=params, headers=headers)

        return response

    def get_api_v2_schedules_by_id_request(self, id_, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/schedules/{id_}', params=params, headers=headers)

        return response

    def get_api_v2_sources_request(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/sources', params=params, headers=headers)

        return response

    def get_api_v2_sources_by_id_request(self, id_, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/sources/{id_}', params=params, headers=headers)

        return response

    def getoperationeventlogs_request(self, id_, operationoutputrequest_enable_agent_output, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        data = assign_params(enable_agent_output=operationoutputrequest_enable_agent_output)
        headers = self._headers

        response = self._http_request('post', f'api/v2/operations/{id_}/event-logs', params=params, json_data=data, headers=headers)

        return response

    def getoperationreport_request(self, id_, operationoutputrequest_enable_agent_output, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        data = assign_params(enable_agent_output=operationoutputrequest_enable_agent_output)
        headers = self._headers

        response = self._http_request('post', f'api/v2/operations/{id_}/report', params=params, json_data=data, headers=headers)

        return response

    def replacesanexistingability_request(self, ability_id, partial_ability_ability_id, partial_ability_name, partial_ability_buckets, partial_ability_technique_id, partial_ability_delete_payload, partial_ability_executors, partial_ability_privilege, partial_ability_requirements, partial_ability_plugin, partial_ability_access, partial_ability_tactic, partial_ability_additional_info, partial_ability_singleton, partial_ability_technique_name, partial_ability_repeatable, partial_ability_description):
        data = assign_params(ability_id=partial_ability_ability_id, name=partial_ability_name, buckets=partial_ability_buckets, technique_id=partial_ability_technique_id, delete_payload=partial_ability_delete_payload, executors=partial_ability_executors, privilege=partial_ability_privilege, requirements=partial_ability_requirements, plugin=partial_ability_plugin, access=partial_ability_access, tactic=partial_ability_tactic, additional_info=partial_ability_additional_info, singleton=partial_ability_singleton, technique_name=partial_ability_technique_name, repeatable=partial_ability_repeatable, description=partial_ability_description)
        headers = self._headers

        response = self._http_request('put', f'api/v2/abilities/{ability_id}', json_data=data, headers=headers)

        return response

    def replaceschedule_request(self, id_, partial_schedule2_schedule, partial_schedule2_task):
        data = assign_params(schedule=partial_schedule2_schedule, task=partial_schedule2_task)
        headers = self._headers

        response = self._http_request('put', f'api/v2/schedules/{id_}', json_data=data, headers=headers)

        return response

    def updateagentconfig_request(self, agentconfigupdate_watchdog, agentconfigupdate_sleep_min, agentconfigupdate_deployments, agentconfigupdate_deadman_abilities, agentconfigupdate_untrusted_timer, agentconfigupdate_bootstrap_abilities, agentconfigupdate_sleep_max, agentconfigupdate_implant_name):
        data = assign_params(watchdog=agentconfigupdate_watchdog, sleep_min=agentconfigupdate_sleep_min, deployments=agentconfigupdate_deployments, deadman_abilities=agentconfigupdate_deadman_abilities, untrusted_timer=agentconfigupdate_untrusted_timer, bootstrap_abilities=agentconfigupdate_bootstrap_abilities, sleep_max=agentconfigupdate_sleep_max, implant_name=agentconfigupdate_implant_name)
        headers = self._headers

        response = self._http_request('patch', 'api/v2/config/agents', json_data=data, headers=headers)

        return response

    def updateanadversary_request(self, adversary_id, partial_adversary1_name, partial_adversary1_tags, partial_adversary1_objective, partial_adversary1_has_repeatable_abilities, partial_adversary1_atomic_ordering, partial_adversary1_plugin, partial_adversary1_description):
        data = assign_params(name=partial_adversary1_name, tags=partial_adversary1_tags, objective=partial_adversary1_objective, has_repeatable_abilities=partial_adversary1_has_repeatable_abilities, atomic_ordering=partial_adversary1_atomic_ordering, plugin=partial_adversary1_plugin, description=partial_adversary1_description)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/adversaries/{adversary_id}', json_data=data, headers=headers)

        return response

    def updateanagent_request(self, paw, partial_agent1_watchdog, partial_agent1_sleep_min, partial_agent1_trusted, partial_agent1_sleep_max, partial_agent1_pending_contact, partial_agent1_group):
        data = assign_params(watchdog=partial_agent1_watchdog, sleep_min=partial_agent1_sleep_min, trusted=partial_agent1_trusted, sleep_max=partial_agent1_sleep_max, pending_contact=partial_agent1_pending_contact, group=partial_agent1_group)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/agents/{paw}', json_data=data, headers=headers)

        return response

    def updateanexistingfactsource_request(self, id_, partial_source_name, partial_source_adjustments, partial_source_relationships, partial_source_id, partial_source_rules, partial_source_facts, partial_source_plugin):
        data = assign_params(name=partial_source_name, adjustments=partial_source_adjustments, relationships=partial_source_relationships, id=partial_source_id, rules=partial_source_rules, facts=partial_source_facts, plugin=partial_source_plugin)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/sources/{id_}', json_data=data, headers=headers)

        return response

    def updateanexistingorcreateanewfactsource_request(self, id_, partial_source_name, partial_source_adjustments, partial_source_relationships, partial_source_id, partial_source_rules, partial_source_facts, partial_source_plugin):
        data = assign_params(name=partial_source_name, adjustments=partial_source_adjustments, relationships=partial_source_relationships, id=partial_source_id, rules=partial_source_rules, facts=partial_source_facts, plugin=partial_source_plugin)
        headers = self._headers

        response = self._http_request('put', f'api/v2/sources/{id_}', json_data=data, headers=headers)

        return response

    def updateanobjective_request(self, id_, partial_objective1_name, partial_objective1_goals, partial_objective1_description):
        data = assign_params(name=partial_objective1_name, goals=partial_objective1_goals, description=partial_objective1_description)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/objectives/{id_}', json_data=data, headers=headers)

        return response

    def updatefieldswithinanoperation_request(self, id_, partial_operation1_obfuscator, partial_operation1_autonomous, partial_operation1_state):
        data = assign_params(obfuscator=partial_operation1_obfuscator, autonomous=partial_operation1_autonomous, state=partial_operation1_state)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/operations/{id_}', json_data=data, headers=headers)

        return response

    def updatemainconfig_request(self, configupdate_prop, configupdate_value):
        data = assign_params(prop=configupdate_prop, value=configupdate_value)
        headers = self._headers

        response = self._http_request('patch', 'api/v2/config/main', json_data=data, headers=headers)

        return response

    def updateoneormorefacts_request(self, partial_factupdaterequest_updates, partial_factupdaterequest_criteria):
        data = assign_params(updates=partial_factupdaterequest_updates, criteria=partial_factupdaterequest_criteria)
        headers = self._headers

        response = self._http_request('patch', 'api/v2/facts', json_data=data, headers=headers)

        return response

    def updateoneormorerelationships_request(self, partial_relationshipupdate_updates, partial_relationshipupdate_criteria):
        data = assign_params(updates=partial_relationshipupdate_updates, criteria=partial_relationshipupdate_criteria)
        headers = self._headers

        response = self._http_request('patch', 'api/v2/relationships', json_data=data, headers=headers)

        return response

    def updatesanexistingability_request(self, ability_id, partial_ability1_name, partial_ability1_buckets, partial_ability1_technique_id, partial_ability1_delete_payload, partial_ability1_executors, partial_ability1_privilege, partial_ability1_technique_name, partial_ability1_tactic, partial_ability1_singleton, partial_ability1_plugin, partial_ability1_repeatable, partial_ability1_description):
        data = assign_params(name=partial_ability1_name, buckets=partial_ability1_buckets, technique_id=partial_ability1_technique_id, delete_payload=partial_ability1_delete_payload, executors=partial_ability1_executors, privilege=partial_ability1_privilege, technique_name=partial_ability1_technique_name, tactic=partial_ability1_tactic, singleton=partial_ability1_singleton, plugin=partial_ability1_plugin, repeatable=partial_ability1_repeatable, description=partial_ability1_description)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/abilities/{ability_id}', json_data=data, headers=headers)

        return response

    def updateschedule_request(self, id_, partial_schedule1_schedule, partial_schedule1_task):
        data = assign_params(schedule=partial_schedule1_schedule, task=partial_schedule1_task)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/schedules/{id_}', json_data=data, headers=headers)

        return response

    def updatethespecifiedlinkwithinanoperation_request(self, id_, link_id, partial_link1_command, partial_link1_status):
        data = assign_params(command=partial_link1_command, status=partial_link1_status)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/operations/{id_}/links/{link_id_}', json_data=data, headers=headers)

        return response


def create_fact_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    fact_unique = str(args.get('fact_unique', ''))
    fact_name = str(args.get('fact_name', ''))
    fact_links = argToList(args.get('fact_links', []))
    fact_relationships = argToList(args.get('fact_relationships', []))
    fact_origin_type = str(args.get('fact_origin_type', ''))
    fact_created = str(args.get('fact_created', ''))
    fact_limit_count = args.get('fact_limit_count', None)
    fact_technique_id = str(args.get('fact_technique_id', ''))
    fact_trait = str(args.get('fact_trait', ''))
    fact_source = str(args.get('fact_source', ''))
    fact_score = args.get('fact_score', None)
    fact_value = str(args.get('fact_value', ''))
    fact_collected_by = argToList(args.get('fact_collected_by', []))

    response = client.create_fact_request(fact_unique, fact_name, fact_links, fact_relationships, fact_origin_type, fact_created, fact_limit_count, fact_technique_id, fact_trait, fact_source, fact_score, fact_value, fact_collected_by)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Fact',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_fact_source_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    source_name = str(args.get('source_name', ''))
    source_adjustments = argToList(args.get('source_adjustments', []))
    source_relationships = argToList(args.get('source_relationships', []))
    source_id = str(args.get('source_id', ''))
    source_rules = argToList(args.get('source_rules', []))
    source_facts = argToList(args.get('source_facts', []))
    source_plugin = args.get('source_plugin', 'None')

    response = client.create_fact_source_request(source_name, source_adjustments, source_relationships, source_id, source_rules, source_facts, source_plugin)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Source',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createanewadversary_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    adversary_name = str(args.get('adversary_name', ''))
    adversary_tags = argToList(args.get('adversary_tags', []))
    adversary_objective = str(args.get('adversary_objective', ''))
    adversary_adversary_id = str(args.get('adversary_adversary_id', ''))
    adversary_has_repeatable_abilities = argToBoolean(args.get('adversary_has_repeatable_abilities', False))
    adversary_atomic_ordering = argToList(args.get('adversary_atomic_ordering', []))
    adversary_plugin = args.get('adversary_plugin', 'None')
    adversary_description = str(args.get('adversary_description', ''))

    response = client.createanewadversary_request(adversary_name, adversary_tags, adversary_objective, adversary_adversary_id, adversary_has_repeatable_abilities, adversary_atomic_ordering, adversary_plugin, adversary_description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Adversary',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createanewagent_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agent_watchdog = args.get('agent_watchdog', None)
    agent_links = argToList(args.get('agent_links', []))
    agent_deadman_enabled = argToBoolean(args.get('agent_deadman_enabled', False))
    agent_ppid = args.get('agent_ppid', None)
    agent_pid = args.get('agent_pid', None)
    agent_created = str(args.get('agent_created', ''))
    agent_proxy_receivers = str(args.get('agent_proxy_receivers', ''))
    agent_origin_link_id = str(args.get('agent_origin_link_id', ''))
    agent_available_contacts = argToList(args.get('agent_available_contacts', []))
    agent_last_seen = str(args.get('agent_last_seen', ''))
    agent_platform = str(args.get('agent_platform', ''))
    agent_pending_contact = str(args.get('agent_pending_contact', ''))
    agent_host = str(args.get('agent_host', ''))
    agent_group = str(args.get('agent_group', ''))
    agent_location = str(args.get('agent_location', ''))
    agent_display_name = str(args.get('agent_display_name', ''))
    agent_upstream_dest = str(args.get('agent_upstream_dest', ''))
    agent_host_ip_addrs = argToList(args.get('agent_host_ip_addrs', []))
    agent_sleep_max = args.get('agent_sleep_max', None)
    agent_architecture = str(args.get('agent_architecture', ''))
    agent_sleep_min = args.get('agent_sleep_min', None)
    agent_server = str(args.get('agent_server', ''))
    agent_contact = str(args.get('agent_contact', ''))
    agent_executors = argToList(args.get('agent_executors', []))
    agent_privilege = str(args.get('agent_privilege', ''))
    agent_username = str(args.get('agent_username', ''))
    agent_trusted = argToBoolean(args.get('agent_trusted', False))
    agent_proxy_chain = argToList(args.get('agent_proxy_chain', []))
    agent_paw = str(args.get('agent_paw', ''))
    agent_exe_name = str(args.get('agent_exe_name', ''))

    response = client.createanewagent_request(agent_watchdog, agent_links, agent_deadman_enabled, agent_ppid, agent_pid, agent_created, agent_proxy_receivers, agent_origin_link_id, agent_available_contacts, agent_last_seen, agent_platform, agent_pending_contact, agent_host, agent_group, agent_location, agent_display_name, agent_upstream_dest, agent_host_ip_addrs, agent_sleep_max, agent_architecture, agent_sleep_min, agent_server, agent_contact, agent_executors, agent_privilege, agent_username, agent_trusted, agent_proxy_chain, agent_paw, agent_exe_name)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Agent',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createanewcalderaoperationrecord_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_name = str(args.get('operation_name', ''))
    operation_autonomous = args.get('operation_autonomous', None)
    operation_id = str(args.get('operation_id', ''))
    operation_objective_name = str(args.get('operation_objective_name', ''))
    operation_objective_id = str(args.get('operation_objective_id', ''))
    operation_objective_percentage = str(args.get('operation_objective_percentage', ''))
    operation_objective_goals = str(args.get('operation_objective_goals', ''))
    operation_objective_description = str(args.get('operation_objective_description', ''))
    operation_objective = assign_params(name=operation_objective_name, id=operation_objective_id, percentage=operation_objective_percentage, goals=operation_objective_goals, description=operation_objective_description)
    operation_visibility = args.get('operation_visibility', None)
    operation_state = str(args.get('operation_state', ''))
    operation_group = str(args.get('operation_group', ''))
    operation_host_group = argToList(args.get('operation_host_group', []))
    operation_planner_name = str(args.get('operation_planner_name', ''))
    operation_planner_allow_repeatable_abilities = argToBoolean(args.get('operation_planner_allow_repeatable_abilities', False))
    operation_planner_ignore_enforcement_modules = str(args.get('operation_planner_ignore_enforcement_modules', ''))
    operation_planner_stopping_conditions = str(args.get('operation_planner_stopping_conditions', ''))
    operation_planner_id = str(args.get('operation_planner_id', ''))
    operation_planner_plugin = str(args.get('operation_planner_plugin', ''))
    operation_planner_module = str(args.get('operation_planner_module', ''))
    operation_planner_description = str(args.get('operation_planner_description', ''))
    operation_planner_params = str(args.get('operation_planner_params', ''))
    operation_planner = assign_params(name=operation_planner_name, allow_repeatable_abilities=operation_planner_allow_repeatable_abilities, ignore_enforcement_modules=operation_planner_ignore_enforcement_modules, stopping_conditions=operation_planner_stopping_conditions, id=operation_planner_id, plugin=operation_planner_plugin, module=operation_planner_module, description=operation_planner_description, params=operation_planner_params)
    operation_obfuscator = str(args.get('operation_obfuscator', ''))
    operation_chain = str(args.get('operation_chain', ''))
    operation_use_learning_parsers = argToBoolean(args.get('operation_use_learning_parsers', False))
    operation_source_name = str(args.get('operation_source_name', ''))
    operation_source_adjustments = str(args.get('operation_source_adjustments', ''))
    operation_source_relationships = str(args.get('operation_source_relationships', ''))
    operation_source_id = str(args.get('operation_source_id', ''))
    operation_source_rules = str(args.get('operation_source_rules', ''))
    operation_source_facts = str(args.get('operation_source_facts', ''))
    operation_source_plugin = str(args.get('operation_source_plugin', ''))
    operation_source = assign_params(name=operation_source_name, adjustments=operation_source_adjustments, relationships=operation_source_relationships, id=operation_source_id, rules=operation_source_rules, facts=operation_source_facts, plugin=operation_source_plugin)
    operation_jitter = str(args.get('operation_jitter', ''))
    operation_start = str(args.get('operation_start', ''))
    operation_adversary_name = str(args.get('operation_adversary_name', ''))
    operation_adversary_tags = str(args.get('operation_adversary_tags', ''))
    operation_adversary_objective = str(args.get('operation_adversary_objective', ''))
    operation_adversary_adversary_id = str(args.get('operation_adversary_adversary_id', ''))
    operation_adversary_has_repeatable_abilities = argToBoolean(args.get('operation_adversary_has_repeatable_abilities', False))
    operation_adversary_atomic_ordering = str(args.get('operation_adversary_atomic_ordering', ''))
    operation_adversary_plugin = str(args.get('operation_adversary_plugin', ''))
    operation_adversary_description = str(args.get('operation_adversary_description', ''))
    operation_adversary = assign_params(name=operation_adversary_name, tags=operation_adversary_tags, objective=operation_adversary_objective, adversary_id=operation_adversary_adversary_id, has_repeatable_abilities=operation_adversary_has_repeatable_abilities, atomic_ordering=operation_adversary_atomic_ordering, plugin=operation_adversary_plugin, description=operation_adversary_description)
    operation_auto_close = argToBoolean(args.get('operation_auto_close', False))

    response = client.createanewcalderaoperationrecord_request(operation_name, operation_autonomous, operation_id, operation_objective, operation_visibility, operation_state, operation_group, operation_host_group, operation_planner, operation_obfuscator, operation_chain, operation_use_learning_parsers, operation_source, operation_jitter, operation_start, operation_adversary, operation_auto_close)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Operation',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createanewobjective_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    objective_name = str(args.get('objective_name', ''))
    objective_id = str(args.get('objective_id', ''))
    objective_percentage = str(args.get('objective_percentage', ''))
    objective_goals = argToList(args.get('objective_goals', []))
    objective_description = str(args.get('objective_description', ''))

    response = client.createanewobjective_request(objective_name, objective_id, objective_percentage, objective_goals, objective_description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Objective',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createarelationship_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    relationship_unique = str(args.get('relationship_unique', ''))
    relationship_origin = str(args.get('relationship_origin', ''))
    relationship_edge = str(args.get('relationship_edge', ''))
    relationship_source_unique = str(args.get('relationship_source_unique', ''))
    relationship_source_name = str(args.get('relationship_source_name', ''))
    relationship_source_links = str(args.get('relationship_source_links', ''))
    relationship_source_relationships = str(args.get('relationship_source_relationships', ''))
    relationship_source_origin_type = str(args.get('relationship_source_origin_type', ''))
    relationship_source_created = str(args.get('relationship_source_created', ''))
    relationship_source_limit_count = args.get('relationship_source_limit_count', None)
    relationship_source_technique_id = str(args.get('relationship_source_technique_id', ''))
    relationship_source_trait = str(args.get('relationship_source_trait', ''))
    relationship_source_source = str(args.get('relationship_source_source', ''))
    relationship_source_score = args.get('relationship_source_score', None)
    relationship_source_value = str(args.get('relationship_source_value', ''))
    relationship_source_collected_by = str(args.get('relationship_source_collected_by', ''))
    relationship_source = assign_params(unique=relationship_source_unique, name=relationship_source_name, links=relationship_source_links, relationships=relationship_source_relationships, origin_type=relationship_source_origin_type, created=relationship_source_created, limit_count=relationship_source_limit_count, technique_id=relationship_source_technique_id, trait=relationship_source_trait, source=relationship_source_source, score=relationship_source_score, value=relationship_source_value, collected_by=relationship_source_collected_by)
    relationship_score = args.get('relationship_score', None)
    relationship_target = str(args.get('relationship_target', ''))

    response = client.createarelationship_request(relationship_unique, relationship_origin, relationship_edge, relationship_source, relationship_score, relationship_target)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Relationship',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createorupdateanadversary_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    adversary_id = str(args.get('adversary_id', ''))
    partial_adversary_name = str(args.get('partial_adversary_name', ''))
    partial_adversary_tags = argToList(args.get('partial_adversary_tags', []))
    partial_adversary_objective = str(args.get('partial_adversary_objective', ''))
    partial_adversary_adversary_id = str(args.get('partial_adversary_adversary_id', ''))
    partial_adversary_has_repeatable_abilities = argToBoolean(args.get('partial_adversary_has_repeatable_abilities', False))
    partial_adversary_atomic_ordering = argToList(args.get('partial_adversary_atomic_ordering', []))
    partial_adversary_plugin = args.get('partial_adversary_plugin', 'None')
    partial_adversary_description = str(args.get('partial_adversary_description', ''))

    response = client.createorupdateanadversary_request(adversary_id, partial_adversary_name, partial_adversary_tags, partial_adversary_objective, partial_adversary_adversary_id, partial_adversary_has_repeatable_abilities, partial_adversary_atomic_ordering, partial_adversary_plugin, partial_adversary_description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Adversary',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createorupdateanagent_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    paw = str(args.get('paw', ''))
    partial_agent_watchdog = args.get('partial_agent_watchdog', None)
    partial_agent_links = argToList(args.get('partial_agent_links', []))
    partial_agent_deadman_enabled = argToBoolean(args.get('partial_agent_deadman_enabled', False))
    partial_agent_ppid = args.get('partial_agent_ppid', None)
    partial_agent_pid = args.get('partial_agent_pid', None)
    partial_agent_created = str(args.get('partial_agent_created', ''))
    partial_agent_proxy_receivers = str(args.get('partial_agent_proxy_receivers', ''))
    partial_agent_origin_link_id = str(args.get('partial_agent_origin_link_id', ''))
    partial_agent_available_contacts = argToList(args.get('partial_agent_available_contacts', []))
    partial_agent_last_seen = str(args.get('partial_agent_last_seen', ''))
    partial_agent_platform = str(args.get('partial_agent_platform', ''))
    partial_agent_pending_contact = str(args.get('partial_agent_pending_contact', ''))
    partial_agent_host = str(args.get('partial_agent_host', ''))
    partial_agent_group = str(args.get('partial_agent_group', ''))
    partial_agent_location = str(args.get('partial_agent_location', ''))
    partial_agent_display_name = str(args.get('partial_agent_display_name', ''))
    partial_agent_upstream_dest = str(args.get('partial_agent_upstream_dest', ''))
    partial_agent_host_ip_addrs = argToList(args.get('partial_agent_host_ip_addrs', []))
    partial_agent_sleep_max = args.get('partial_agent_sleep_max', None)
    partial_agent_architecture = str(args.get('partial_agent_architecture', ''))
    partial_agent_sleep_min = args.get('partial_agent_sleep_min', None)
    partial_agent_server = str(args.get('partial_agent_server', ''))
    partial_agent_contact = str(args.get('partial_agent_contact', ''))
    partial_agent_executors = argToList(args.get('partial_agent_executors', []))
    partial_agent_privilege = str(args.get('partial_agent_privilege', ''))
    partial_agent_username = str(args.get('partial_agent_username', ''))
    partial_agent_trusted = argToBoolean(args.get('partial_agent_trusted', False))
    partial_agent_proxy_chain = argToList(args.get('partial_agent_proxy_chain', []))
    partial_agent_paw = str(args.get('partial_agent_paw', ''))
    partial_agent_exe_name = str(args.get('partial_agent_exe_name', ''))

    response = client.createorupdateanagent_request(paw, partial_agent_watchdog, partial_agent_links, partial_agent_deadman_enabled, partial_agent_ppid, partial_agent_pid, partial_agent_created, partial_agent_proxy_receivers, partial_agent_origin_link_id, partial_agent_available_contacts, partial_agent_last_seen, partial_agent_platform, partial_agent_pending_contact, partial_agent_host, partial_agent_group, partial_agent_location, partial_agent_display_name, partial_agent_upstream_dest, partial_agent_host_ip_addrs, partial_agent_sleep_max, partial_agent_architecture, partial_agent_sleep_min, partial_agent_server, partial_agent_contact, partial_agent_executors, partial_agent_privilege, partial_agent_username, partial_agent_trusted, partial_agent_proxy_chain, partial_agent_paw, partial_agent_exe_name)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Agent',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createorupdateanobjective_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    partial_objective_name = str(args.get('partial_objective_name', ''))
    partial_objective_id = str(args.get('partial_objective_id', ''))
    partial_objective_percentage = str(args.get('partial_objective_percentage', ''))
    partial_objective_goals = argToList(args.get('partial_objective_goals', []))
    partial_objective_description = str(args.get('partial_objective_description', ''))

    response = client.createorupdateanobjective_request(id_, partial_objective_name, partial_objective_id, partial_objective_percentage, partial_objective_goals, partial_objective_description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Objective',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createsanewability_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ability_ability_id = str(args.get('ability_ability_id', ''))
    ability_name = args.get('ability_name', 'None')
    ability_buckets = argToList(args.get('ability_buckets', []))
    ability_technique_id = args.get('ability_technique_id', 'None')
    ability_delete_payload = argToBoolean(args.get('ability_delete_payload', False))
    ability_executors = argToList(args.get('ability_executors', []))
    ability_privilege = args.get('ability_privilege', 'None')
    ability_requirements = argToList(args.get('ability_requirements', []))
    ability_plugin = args.get('ability_plugin', 'None')
    ability_access = args.get('ability_access', 'None')
    ability_tactic = args.get('ability_tactic', 'None')
    ability_additional_info = str(args.get('ability_additional_info', ''))
    ability_singleton = argToBoolean(args.get('ability_singleton', False))
    ability_technique_name = args.get('ability_technique_name', 'None')
    ability_repeatable = argToBoolean(args.get('ability_repeatable', False))
    ability_description = args.get('ability_description', 'None')

    response = client.createsanewability_request(ability_ability_id, ability_name, ability_buckets, ability_technique_id, ability_delete_payload, ability_executors, ability_privilege, ability_requirements, ability_plugin, ability_access, ability_tactic, ability_additional_info, ability_singleton, ability_technique_name, ability_repeatable, ability_description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Ability',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createsapotentiallink_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    link_relationships = argToList(args.get('link_relationships', []))
    link_id = str(args.get('link_id', ''))
    link_collect = str(args.get('link_collect', ''))
    link_pid = str(args.get('link_pid', ''))
    link_visibility_adjustments = str(args.get('link_visibility_adjustments', ''))
    link_visibility_score = args.get('link_visibility_score', None)
    link_visibility = assign_params(adjustments=link_visibility_adjustments, score=link_visibility_score)
    link_finish = str(args.get('link_finish', ''))
    link_pin = int(args.get('link_pin', 0))
    link_jitter = int(args.get('link_jitter', 0))
    link_agent_reported_time = args.get('link_agent_reported_time', 'None')
    link_deadman = argToBoolean(args.get('link_deadman', False))
    link_used = argToList(args.get('link_used', []))
    link_host = args.get('link_host', 'None')
    link_ability_ability_id = str(args.get('link_ability_ability_id', ''))
    link_ability_name = str(args.get('link_ability_name', ''))
    link_ability_buckets = str(args.get('link_ability_buckets', ''))
    link_ability_technique_id = str(args.get('link_ability_technique_id', ''))
    link_ability_delete_payload = argToBoolean(args.get('link_ability_delete_payload', False))
    link_ability_executors = str(args.get('link_ability_executors', ''))
    link_ability_privilege = str(args.get('link_ability_privilege', ''))
    link_ability_requirements = str(args.get('link_ability_requirements', ''))
    link_ability_plugin = str(args.get('link_ability_plugin', ''))
    link_ability_access = str(args.get('link_ability_access', ''))
    link_ability_tactic = str(args.get('link_ability_tactic', ''))
    link_ability_additional_info = str(args.get('link_ability_additional_info', ''))
    link_ability_singleton = argToBoolean(args.get('link_ability_singleton', False))
    link_ability_technique_name = str(args.get('link_ability_technique_name', ''))
    link_ability_repeatable = argToBoolean(args.get('link_ability_repeatable', False))
    link_ability_description = str(args.get('link_ability_description', ''))
    link_ability = assign_params(ability_id=link_ability_ability_id, name=link_ability_name, buckets=link_ability_buckets, technique_id=link_ability_technique_id, delete_payload=link_ability_delete_payload, executors=link_ability_executors, privilege=link_ability_privilege, requirements=link_ability_requirements, plugin=link_ability_plugin, access=link_ability_access, tactic=link_ability_tactic, additional_info=link_ability_additional_info, singleton=link_ability_singleton, technique_name=link_ability_technique_name, repeatable=link_ability_repeatable, description=link_ability_description)
    link_status = int(args.get('link_status', -3))
    link_score = int(args.get('link_score', 0))
    link_command = str(args.get('link_command', ''))
    link_unique = str(args.get('link_unique', ''))
    link_cleanup = int(args.get('link_cleanup', 0))
    link_decide = str(args.get('link_decide', ''))
    link_facts = argToList(args.get('link_facts', []))
    link_executor_name = str(args.get('link_executor_name', ''))
    link_executor_cleanup = str(args.get('link_executor_cleanup', ''))
    link_executor_platform = str(args.get('link_executor_platform', ''))
    link_executor_language = str(args.get('link_executor_language', ''))
    link_executor_uploads = str(args.get('link_executor_uploads', ''))
    link_executor_variations = str(args.get('link_executor_variations', ''))
    link_executor_build_target = str(args.get('link_executor_build_target', ''))
    link_executor_payloads = str(args.get('link_executor_payloads', ''))
    link_executor_timeout = args.get('link_executor_timeout', None)
    link_executor_parsers = str(args.get('link_executor_parsers', ''))
    link_executor_command = str(args.get('link_executor_command', ''))
    link_executor_additional_info = str(args.get('link_executor_additional_info', ''))
    link_executor_code = str(args.get('link_executor_code', ''))
    link_executor = assign_params(name=link_executor_name, cleanup=link_executor_cleanup, platform=link_executor_platform, language=link_executor_language, uploads=link_executor_uploads, variations=link_executor_variations, build_target=link_executor_build_target, payloads=link_executor_payloads, timeout=link_executor_timeout, parsers=link_executor_parsers, command=link_executor_command, additional_info=link_executor_additional_info, code=link_executor_code)
    link_paw = str(args.get('link_paw', ''))
    link_output = str(args.get('link_output', ''))

    response = client.createsapotentiallink_request(id_, link_relationships, link_id, link_collect, link_pid, link_visibility, link_finish, link_pin, link_jitter, link_agent_reported_time, link_deadman, link_used, link_host, link_ability, link_status, link_score, link_command, link_unique, link_cleanup, link_decide, link_facts, link_executor, link_paw, link_output)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Link',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createschedule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    schedule_schedule = str(args.get('schedule_schedule', ''))
    schedule_task_name = str(args.get('schedule_task_name', ''))
    schedule_task_autonomous = args.get('schedule_task_autonomous', None)
    schedule_task_id = str(args.get('schedule_task_id', ''))
    schedule_task_objective = str(args.get('schedule_task_objective', ''))
    schedule_task_visibility = args.get('schedule_task_visibility', None)
    schedule_task_state = str(args.get('schedule_task_state', ''))
    schedule_task_group = str(args.get('schedule_task_group', ''))
    schedule_task_host_group = str(args.get('schedule_task_host_group', ''))
    schedule_task_planner = str(args.get('schedule_task_planner', ''))
    schedule_task_obfuscator = str(args.get('schedule_task_obfuscator', ''))
    schedule_task_chain = str(args.get('schedule_task_chain', ''))
    schedule_task_use_learning_parsers = argToBoolean(args.get('schedule_task_use_learning_parsers', False))
    schedule_task_source = str(args.get('schedule_task_source', ''))
    schedule_task_jitter = str(args.get('schedule_task_jitter', ''))
    schedule_task_start = str(args.get('schedule_task_start', ''))
    schedule_task_adversary = str(args.get('schedule_task_adversary', ''))
    schedule_task_auto_close = argToBoolean(args.get('schedule_task_auto_close', False))
    schedule_task = assign_params(name=schedule_task_name, autonomous=schedule_task_autonomous, id=schedule_task_id, objective=schedule_task_objective, visibility=schedule_task_visibility, state=schedule_task_state, group=schedule_task_group, host_group=schedule_task_host_group, planner=schedule_task_planner, obfuscator=schedule_task_obfuscator, chain=schedule_task_chain, use_learning_parsers=schedule_task_use_learning_parsers, source=schedule_task_source, jitter=schedule_task_jitter, start=schedule_task_start, adversary=schedule_task_adversary, auto_close=schedule_task_auto_close)
    schedule_id = str(args.get('schedule_id', ''))

    response = client.createschedule_request(schedule_schedule, schedule_task, schedule_id)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Schedule',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deleteanagent_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    paw = str(args.get('paw', ''))

    response = client.deleteanagent_request(paw)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Agent1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deleteanexistingfactsource_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))

    response = client.deleteanexistingfactsource_request(id_)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Source',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deleteanoperationbyoperationid_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))

    response = client.deleteanoperationbyoperationid_request(id_)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Operation',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deleteoneormorefacts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    partial_fact_unique = str(args.get('partial_fact_unique', ''))
    partial_fact_name = str(args.get('partial_fact_name', ''))
    partial_fact_links = argToList(args.get('partial_fact_links', []))
    partial_fact_relationships = argToList(args.get('partial_fact_relationships', []))
    partial_fact_origin_type = str(args.get('partial_fact_origin_type', ''))
    partial_fact_created = str(args.get('partial_fact_created', ''))
    partial_fact_limit_count = args.get('partial_fact_limit_count', None)
    partial_fact_technique_id = str(args.get('partial_fact_technique_id', ''))
    partial_fact_trait = str(args.get('partial_fact_trait', ''))
    partial_fact_source = str(args.get('partial_fact_source', ''))
    partial_fact_score = args.get('partial_fact_score', None)
    partial_fact_value = str(args.get('partial_fact_value', ''))
    partial_fact_collected_by = argToList(args.get('partial_fact_collected_by', []))

    response = client.deleteoneormorefacts_request(partial_fact_unique, partial_fact_name, partial_fact_links, partial_fact_relationships, partial_fact_origin_type, partial_fact_created, partial_fact_limit_count, partial_fact_technique_id, partial_fact_trait, partial_fact_source, partial_fact_score, partial_fact_value, partial_fact_collected_by)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Fact',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deleteoneormorerelationships_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    partial_relationship_unique = str(args.get('partial_relationship_unique', ''))
    partial_relationship_origin = str(args.get('partial_relationship_origin', ''))
    partial_relationship_edge = str(args.get('partial_relationship_edge', ''))
    partial_relationship_source_unique = str(args.get('partial_relationship_source_unique', ''))
    partial_relationship_source_name = str(args.get('partial_relationship_source_name', ''))
    partial_relationship_source_links = str(args.get('partial_relationship_source_links', ''))
    partial_relationship_source_relationships = str(args.get('partial_relationship_source_relationships', ''))
    partial_relationship_source_origin_type = str(args.get('partial_relationship_source_origin_type', ''))
    partial_relationship_source_created = str(args.get('partial_relationship_source_created', ''))
    partial_relationship_source_limit_count = args.get('partial_relationship_source_limit_count', None)
    partial_relationship_source_technique_id = str(args.get('partial_relationship_source_technique_id', ''))
    partial_relationship_source_trait = str(args.get('partial_relationship_source_trait', ''))
    partial_relationship_source_source = str(args.get('partial_relationship_source_source', ''))
    partial_relationship_source_score = args.get('partial_relationship_source_score', None)
    partial_relationship_source_value = str(args.get('partial_relationship_source_value', ''))
    partial_relationship_source_collected_by = str(args.get('partial_relationship_source_collected_by', ''))
    partial_relationship_source = assign_params(unique=partial_relationship_source_unique, name=partial_relationship_source_name, links=partial_relationship_source_links, relationships=partial_relationship_source_relationships, origin_type=partial_relationship_source_origin_type, created=partial_relationship_source_created, limit_count=partial_relationship_source_limit_count, technique_id=partial_relationship_source_technique_id, trait=partial_relationship_source_trait, source=partial_relationship_source_source, score=partial_relationship_source_score, value=partial_relationship_source_value, collected_by=partial_relationship_source_collected_by)
    partial_relationship_score = args.get('partial_relationship_score', None)
    partial_relationship_target = str(args.get('partial_relationship_target', ''))

    response = client.deleteoneormorerelationships_request(partial_relationship_unique, partial_relationship_origin, partial_relationship_edge, partial_relationship_source, partial_relationship_score, partial_relationship_target)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Relationship',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deletesanability_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ability_id = str(args.get('ability_id', ''))

    response = client.deletesanability_request(ability_id)
    command_results = CommandResults(
        outputs_prefix='mitrecaldera',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deletesanadversary_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    adversary_id = str(args.get('adversary_id', ''))

    response = client.deletesanadversary_request(adversary_id)
    command_results = CommandResults(
        outputs_prefix='mitrecaldera',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deleteschedule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))

    response = client.deleteschedule_request(id_)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Schedule',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_abilities_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    sort = str(args.get('sort', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))
    response = client.get_api_v2_abilities_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialAbility',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_abilities_by_ability_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ability_id = str(args.get('ability_id', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_abilities_by_ability_id_request(ability_id, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialAbility',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_adversaries_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    sort = str(args.get('sort', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_adversaries_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialAdversary',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_adversaries_by_adversary_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    adversary_id = str(args.get('adversary_id', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_adversaries_by_adversary_id_request(adversary_id, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialAdversary',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_agents_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    sort = str(args.get('sort', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_agents_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialAgent',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_agents_by_paw_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    paw = str(args.get('paw', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_agents_by_paw_request(paw, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialAgent',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_config_by_name_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = str(args.get('name', ''))

    response = client.get_api_v2_config_by_name_request(name)
    command_results = CommandResults(
        outputs_prefix='mitrecaldera',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_contacts_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    response = client.get_api_v2_contacts_request()
    command_results = CommandResults(
        outputs_prefix='mitrecaldera',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_contacts_by_name_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = str(args.get('name', ''))

    response = client.get_api_v2_contacts_by_name_request(name)
    command_results = CommandResults(
        outputs_prefix='mitrecaldera',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_deploy_commands_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    response = client.get_api_v2_deploy_commands_request()
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.DeployCommands',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_deploy_commands_by_ability_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ability_id = str(args.get('ability_id', ''))

    response = client.get_api_v2_deploy_commands_by_ability_id_request(ability_id)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.DeployCommands',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_facts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    sort = str(args.get('sort', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_facts_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialFact',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_facts_by_operation_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    sort = str(args.get('sort', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))
    operation_id = str(args.get('operation_id', ''))

    response = client.get_api_v2_facts_by_operation_id_request(sort, include, exclude, operation_id)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialFact',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_health_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    response = client.get_api_v2_health_request()
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.CalderaInfo',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_obfuscators_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    sort = str(args.get('sort', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_obfuscators_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialObfuscator',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_obfuscators_by_name_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = str(args.get('name', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_obfuscators_by_name_request(name, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialObfuscator',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_objectives_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    sort = str(args.get('sort', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_objectives_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialObjective',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_objectives_by_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_objectives_by_id_request(id_, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialObjective',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_operations_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    sort = str(args.get('sort', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_operations_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialOperation',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_operations_by_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_operations_by_id_request(id_, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialOperation',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_operations_links_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    sort = str(args.get('sort', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_operations_links_request(id_, sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialLink',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_operations_links_by_link_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    link_id = str(args.get('link_id', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_operations_links_by_link_id_request(id_, link_id, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialLink',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_operations_links_result_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    link_id = str(args.get('link_id', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_operations_links_result_request(id_, link_id, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialLink',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_operations_potentiallinks_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    sort = str(args.get('sort', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_operations_potentiallinks_request(id_, sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialLink',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_operations_potentiallinks_by_paw_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    paw = str(args.get('paw', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_operations_potentiallinks_by_paw_request(id_, paw, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialLink',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_planners_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    sort = str(args.get('sort', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_planners_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialPlanner',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_planners_by_planner_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    planner_id = str(args.get('planner_id', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_planners_by_planner_id_request(planner_id, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialPlanner',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_plugins_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    sort = str(args.get('sort', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_plugins_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialPlugin',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_plugins_by_name_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = str(args.get('name', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_plugins_by_name_request(name, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialPlugin',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_relationships_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    sort = str(args.get('sort', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_relationships_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Relationship',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_relationships_by_operation_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    sort = str(args.get('sort', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))
    operation_id = str(args.get('operation_id', ''))

    response = client.get_api_v2_relationships_by_operation_id_request(sort, include, exclude, operation_id)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Relationship',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_schedules_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    sort = str(args.get('sort', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_schedules_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialSchedule',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_schedules_by_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_schedules_by_id_request(id_, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialSchedule',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_sources_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    sort = str(args.get('sort', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_sources_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialSource',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_sources_by_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_sources_by_id_request(id_, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialSource',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getoperationeventlogs_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    operationoutputrequest_enable_agent_output = argToBoolean(args.get('operationoutputrequest_enable_agent_output', False))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.getoperationeventlogs_request(id_, operationoutputrequest_enable_agent_output, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.OperationOutputRequest',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getoperationreport_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    operationoutputrequest_enable_agent_output = argToBoolean(args.get('operationoutputrequest_enable_agent_output', False))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.getoperationreport_request(id_, operationoutputrequest_enable_agent_output, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.OperationOutputRequest',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def replacesanexistingability_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ability_id = str(args.get('ability_id', ''))
    partial_ability_ability_id = str(args.get('partial_ability_ability_id', ''))
    partial_ability_name = args.get('partial_ability_name', 'None')
    partial_ability_buckets = argToList(args.get('partial_ability_buckets', []))
    partial_ability_technique_id = args.get('partial_ability_technique_id', 'None')
    partial_ability_delete_payload = argToBoolean(args.get('partial_ability_delete_payload', False))
    partial_ability_executors = argToList(args.get('partial_ability_executors', []))
    partial_ability_privilege = args.get('partial_ability_privilege', 'None')
    partial_ability_requirements = argToList(args.get('partial_ability_requirements', []))
    partial_ability_plugin = args.get('partial_ability_plugin', 'None')
    partial_ability_access = args.get('partial_ability_access', 'None')
    partial_ability_tactic = args.get('partial_ability_tactic', 'None')
    partial_ability_additional_info = str(args.get('partial_ability_additional_info', ''))
    partial_ability_singleton = argToBoolean(args.get('partial_ability_singleton', False))
    partial_ability_technique_name = args.get('partial_ability_technique_name', 'None')
    partial_ability_repeatable = argToBoolean(args.get('partial_ability_repeatable', False))
    partial_ability_description = args.get('partial_ability_description', 'None')

    response = client.replacesanexistingability_request(ability_id, partial_ability_ability_id, partial_ability_name, partial_ability_buckets, partial_ability_technique_id, partial_ability_delete_payload, partial_ability_executors, partial_ability_privilege, partial_ability_requirements, partial_ability_plugin, partial_ability_access, partial_ability_tactic, partial_ability_additional_info, partial_ability_singleton, partial_ability_technique_name, partial_ability_repeatable, partial_ability_description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Ability',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def replaceschedule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    partial_schedule2_schedule = str(args.get('partial_schedule2_schedule', ''))
    partial_schedule2_task_name = str(args.get('partial_schedule2_task_name', ''))
    partial_schedule2_task_autonomous = args.get('partial_schedule2_task_autonomous', None)
    partial_schedule2_task_id = str(args.get('partial_schedule2_task_id', ''))
    partial_schedule2_task_objective = str(args.get('partial_schedule2_task_objective', ''))
    partial_schedule2_task_visibility = args.get('partial_schedule2_task_visibility', None)
    partial_schedule2_task_state = str(args.get('partial_schedule2_task_state', ''))
    partial_schedule2_task_group = str(args.get('partial_schedule2_task_group', ''))
    partial_schedule2_task_host_group = str(args.get('partial_schedule2_task_host_group', ''))
    partial_schedule2_task_planner = str(args.get('partial_schedule2_task_planner', ''))
    partial_schedule2_task_obfuscator = str(args.get('partial_schedule2_task_obfuscator', ''))
    partial_schedule2_task_chain = str(args.get('partial_schedule2_task_chain', ''))
    partial_schedule2_task_use_learning_parsers = argToBoolean(args.get('partial_schedule2_task_use_learning_parsers', False))
    partial_schedule2_task_source = str(args.get('partial_schedule2_task_source', ''))
    partial_schedule2_task_jitter = str(args.get('partial_schedule2_task_jitter', ''))
    partial_schedule2_task_start = str(args.get('partial_schedule2_task_start', ''))
    partial_schedule2_task_adversary = str(args.get('partial_schedule2_task_adversary', ''))
    partial_schedule2_task_auto_close = argToBoolean(args.get('partial_schedule2_task_auto_close', False))
    partial_schedule2_task = assign_params(name=partial_schedule2_task_name, autonomous=partial_schedule2_task_autonomous, id=partial_schedule2_task_id, objective=partial_schedule2_task_objective, visibility=partial_schedule2_task_visibility, state=partial_schedule2_task_state, group=partial_schedule2_task_group, host_group=partial_schedule2_task_host_group, planner=partial_schedule2_task_planner, obfuscator=partial_schedule2_task_obfuscator, chain=partial_schedule2_task_chain, use_learning_parsers=partial_schedule2_task_use_learning_parsers, source=partial_schedule2_task_source, jitter=partial_schedule2_task_jitter, start=partial_schedule2_task_start, adversary=partial_schedule2_task_adversary, auto_close=partial_schedule2_task_auto_close)

    response = client.replaceschedule_request(id_, partial_schedule2_schedule, partial_schedule2_task)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Schedule',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateagentconfig_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    agentconfigupdate_watchdog = args.get('agentconfigupdate_watchdog', None)
    agentconfigupdate_sleep_min = args.get('agentconfigupdate_sleep_min', None)
    agentconfigupdate_deployments = argToList(args.get('agentconfigupdate_deployments', []))
    agentconfigupdate_deadman_abilities = argToList(args.get('agentconfigupdate_deadman_abilities', []))
    agentconfigupdate_untrusted_timer = args.get('agentconfigupdate_untrusted_timer', None)
    agentconfigupdate_bootstrap_abilities = argToList(args.get('agentconfigupdate_bootstrap_abilities', []))
    agentconfigupdate_sleep_max = args.get('agentconfigupdate_sleep_max', None)
    agentconfigupdate_implant_name = str(args.get('agentconfigupdate_implant_name', ''))

    response = client.updateagentconfig_request(agentconfigupdate_watchdog, agentconfigupdate_sleep_min, agentconfigupdate_deployments, agentconfigupdate_deadman_abilities, agentconfigupdate_untrusted_timer, agentconfigupdate_bootstrap_abilities, agentconfigupdate_sleep_max, agentconfigupdate_implant_name)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.AgentConfigUpdate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateanadversary_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    adversary_id = str(args.get('adversary_id', ''))
    partial_adversary1_name = str(args.get('partial_adversary1_name', ''))
    partial_adversary1_tags = argToList(args.get('partial_adversary1_tags', []))
    partial_adversary1_objective = str(args.get('partial_adversary1_objective', ''))
    partial_adversary1_has_repeatable_abilities = argToBoolean(args.get('partial_adversary1_has_repeatable_abilities', False))
    partial_adversary1_atomic_ordering = argToList(args.get('partial_adversary1_atomic_ordering', []))
    partial_adversary1_plugin = args.get('partial_adversary1_plugin', 'None')
    partial_adversary1_description = str(args.get('partial_adversary1_description', ''))

    response = client.updateanadversary_request(adversary_id, partial_adversary1_name, partial_adversary1_tags, partial_adversary1_objective, partial_adversary1_has_repeatable_abilities, partial_adversary1_atomic_ordering, partial_adversary1_plugin, partial_adversary1_description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Adversary',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateanagent_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    paw = str(args.get('paw', ''))
    partial_agent1_watchdog = args.get('partial_agent1_watchdog', None)
    partial_agent1_sleep_min = args.get('partial_agent1_sleep_min', None)
    partial_agent1_trusted = argToBoolean(args.get('partial_agent1_trusted', False))
    partial_agent1_sleep_max = args.get('partial_agent1_sleep_max', None)
    partial_agent1_pending_contact = str(args.get('partial_agent1_pending_contact', ''))
    partial_agent1_group = str(args.get('partial_agent1_group', ''))

    response = client.updateanagent_request(paw, partial_agent1_watchdog, partial_agent1_sleep_min, partial_agent1_trusted, partial_agent1_sleep_max, partial_agent1_pending_contact, partial_agent1_group)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Agent',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateanexistingfactsource_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    partial_source_name = str(args.get('partial_source_name', ''))
    partial_source_adjustments = argToList(args.get('partial_source_adjustments', []))
    partial_source_relationships = argToList(args.get('partial_source_relationships', []))
    partial_source_id = str(args.get('partial_source_id', ''))
    partial_source_rules = argToList(args.get('partial_source_rules', []))
    partial_source_facts = argToList(args.get('partial_source_facts', []))
    partial_source_plugin = args.get('partial_source_plugin', 'None')

    response = client.updateanexistingfactsource_request(id_, partial_source_name, partial_source_adjustments, partial_source_relationships, partial_source_id, partial_source_rules, partial_source_facts, partial_source_plugin)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Source',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateanexistingorcreateanewfactsource_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    partial_source_name = str(args.get('partial_source_name', ''))
    partial_source_adjustments = argToList(args.get('partial_source_adjustments', []))
    partial_source_relationships = argToList(args.get('partial_source_relationships', []))
    partial_source_id = str(args.get('partial_source_id', ''))
    partial_source_rules = argToList(args.get('partial_source_rules', []))
    partial_source_facts = argToList(args.get('partial_source_facts', []))
    partial_source_plugin = args.get('partial_source_plugin', 'None')

    response = client.updateanexistingorcreateanewfactsource_request(id_, partial_source_name, partial_source_adjustments, partial_source_relationships, partial_source_id, partial_source_rules, partial_source_facts, partial_source_plugin)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Source',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateanobjective_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    partial_objective1_name = str(args.get('partial_objective1_name', ''))
    partial_objective1_goals = argToList(args.get('partial_objective1_goals', []))
    partial_objective1_description = str(args.get('partial_objective1_description', ''))

    response = client.updateanobjective_request(id_, partial_objective1_name, partial_objective1_goals, partial_objective1_description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Objective',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updatefieldswithinanoperation_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    partial_operation1_obfuscator = str(args.get('partial_operation1_obfuscator', ''))
    partial_operation1_autonomous = args.get('partial_operation1_autonomous', None)
    partial_operation1_state = str(args.get('partial_operation1_state', ''))

    response = client.updatefieldswithinanoperation_request(id_, partial_operation1_obfuscator, partial_operation1_autonomous, partial_operation1_state)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.PartialOperation',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updatemainconfig_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    configupdate_prop = str(args.get('configupdate_prop', ''))
    configupdate_value = str(args.get('configupdate_value', ''))

    response = client.updatemainconfig_request(configupdate_prop, configupdate_value)
    command_results = CommandResults(
        outputs_prefix='mitrecaldera',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateoneormorefacts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    partial_factupdaterequest_updates_unique = str(args.get('partial_factupdaterequest_updates_unique', ''))
    partial_factupdaterequest_updates_name = str(args.get('partial_factupdaterequest_updates_name', ''))
    partial_factupdaterequest_updates_links = str(args.get('partial_factupdaterequest_updates_links', ''))
    partial_factupdaterequest_updates_relationships = str(args.get('partial_factupdaterequest_updates_relationships', ''))
    partial_factupdaterequest_updates_origin_type = str(args.get('partial_factupdaterequest_updates_origin_type', ''))
    partial_factupdaterequest_updates_created = str(args.get('partial_factupdaterequest_updates_created', ''))
    partial_factupdaterequest_updates_limit_count = args.get('partial_factupdaterequest_updates_limit_count', None)
    partial_factupdaterequest_updates_technique_id = str(args.get('partial_factupdaterequest_updates_technique_id', ''))
    partial_factupdaterequest_updates_trait = str(args.get('partial_factupdaterequest_updates_trait', ''))
    partial_factupdaterequest_updates_source = str(args.get('partial_factupdaterequest_updates_source', ''))
    partial_factupdaterequest_updates_score = args.get('partial_factupdaterequest_updates_score', None)
    partial_factupdaterequest_updates_value = str(args.get('partial_factupdaterequest_updates_value', ''))
    partial_factupdaterequest_updates_collected_by = str(args.get('partial_factupdaterequest_updates_collected_by', ''))
    partial_factupdaterequest_updates = assign_params(unique=partial_factupdaterequest_updates_unique, name=partial_factupdaterequest_updates_name, links=partial_factupdaterequest_updates_links, relationships=partial_factupdaterequest_updates_relationships, origin_type=partial_factupdaterequest_updates_origin_type, created=partial_factupdaterequest_updates_created, limit_count=partial_factupdaterequest_updates_limit_count, technique_id=partial_factupdaterequest_updates_technique_id, trait=partial_factupdaterequest_updates_trait, source=partial_factupdaterequest_updates_source, score=partial_factupdaterequest_updates_score, value=partial_factupdaterequest_updates_value, collected_by=partial_factupdaterequest_updates_collected_by)
    partial_factupdaterequest_criteria_unique = str(args.get('partial_factupdaterequest_criteria_unique', ''))
    partial_factupdaterequest_criteria_name = str(args.get('partial_factupdaterequest_criteria_name', ''))
    partial_factupdaterequest_criteria_links = str(args.get('partial_factupdaterequest_criteria_links', ''))
    partial_factupdaterequest_criteria_relationships = str(args.get('partial_factupdaterequest_criteria_relationships', ''))
    partial_factupdaterequest_criteria_origin_type = str(args.get('partial_factupdaterequest_criteria_origin_type', ''))
    partial_factupdaterequest_criteria_created = str(args.get('partial_factupdaterequest_criteria_created', ''))
    partial_factupdaterequest_criteria_limit_count = args.get('partial_factupdaterequest_criteria_limit_count', None)
    partial_factupdaterequest_criteria_technique_id = str(args.get('partial_factupdaterequest_criteria_technique_id', ''))
    partial_factupdaterequest_criteria_trait = str(args.get('partial_factupdaterequest_criteria_trait', ''))
    partial_factupdaterequest_criteria_source = str(args.get('partial_factupdaterequest_criteria_source', ''))
    partial_factupdaterequest_criteria_score = args.get('partial_factupdaterequest_criteria_score', None)
    partial_factupdaterequest_criteria_value = str(args.get('partial_factupdaterequest_criteria_value', ''))
    partial_factupdaterequest_criteria_collected_by = str(args.get('partial_factupdaterequest_criteria_collected_by', ''))
    partial_factupdaterequest_criteria = assign_params(unique=partial_factupdaterequest_criteria_unique, name=partial_factupdaterequest_criteria_name, links=partial_factupdaterequest_criteria_links, relationships=partial_factupdaterequest_criteria_relationships, origin_type=partial_factupdaterequest_criteria_origin_type, created=partial_factupdaterequest_criteria_created, limit_count=partial_factupdaterequest_criteria_limit_count, technique_id=partial_factupdaterequest_criteria_technique_id, trait=partial_factupdaterequest_criteria_trait, source=partial_factupdaterequest_criteria_source, score=partial_factupdaterequest_criteria_score, value=partial_factupdaterequest_criteria_value, collected_by=partial_factupdaterequest_criteria_collected_by)

    response = client.updateoneormorefacts_request(partial_factupdaterequest_updates, partial_factupdaterequest_criteria)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Fact',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateoneormorerelationships_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    partial_relationshipupdate_updates_unique = str(args.get('partial_relationshipupdate_updates_unique', ''))
    partial_relationshipupdate_updates_origin = str(args.get('partial_relationshipupdate_updates_origin', ''))
    partial_relationshipupdate_updates_edge = str(args.get('partial_relationshipupdate_updates_edge', ''))
    partial_relationshipupdate_updates_source = str(args.get('partial_relationshipupdate_updates_source', ''))
    partial_relationshipupdate_updates_score = args.get('partial_relationshipupdate_updates_score', None)
    partial_relationshipupdate_updates_target = str(args.get('partial_relationshipupdate_updates_target', ''))
    partial_relationshipupdate_updates = assign_params(unique=partial_relationshipupdate_updates_unique, origin=partial_relationshipupdate_updates_origin, edge=partial_relationshipupdate_updates_edge, source=partial_relationshipupdate_updates_source, score=partial_relationshipupdate_updates_score, target=partial_relationshipupdate_updates_target)
    partial_relationshipupdate_criteria_unique = str(args.get('partial_relationshipupdate_criteria_unique', ''))
    partial_relationshipupdate_criteria_origin = str(args.get('partial_relationshipupdate_criteria_origin', ''))
    partial_relationshipupdate_criteria_edge = str(args.get('partial_relationshipupdate_criteria_edge', ''))
    partial_relationshipupdate_criteria_source = str(args.get('partial_relationshipupdate_criteria_source', ''))
    partial_relationshipupdate_criteria_score = args.get('partial_relationshipupdate_criteria_score', None)
    partial_relationshipupdate_criteria_target = str(args.get('partial_relationshipupdate_criteria_target', ''))
    partial_relationshipupdate_criteria = assign_params(unique=partial_relationshipupdate_criteria_unique, origin=partial_relationshipupdate_criteria_origin, edge=partial_relationshipupdate_criteria_edge, source=partial_relationshipupdate_criteria_source, score=partial_relationshipupdate_criteria_score, target=partial_relationshipupdate_criteria_target)

    response = client.updateoneormorerelationships_request(partial_relationshipupdate_updates, partial_relationshipupdate_criteria)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Relationship',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updatesanexistingability_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ability_id = str(args.get('ability_id', ''))
    partial_ability1_name = args.get('partial_ability1_name', 'None')
    partial_ability1_buckets = argToList(args.get('partial_ability1_buckets', []))
    partial_ability1_technique_id = args.get('partial_ability1_technique_id', 'None')
    partial_ability1_delete_payload = argToBoolean(args.get('partial_ability1_delete_payload', False))
    partial_ability1_executors = argToList(args.get('partial_ability1_executors', []))
    partial_ability1_privilege = args.get('partial_ability1_privilege', 'None')
    partial_ability1_technique_name = args.get('partial_ability1_technique_name', 'None')
    partial_ability1_tactic = args.get('partial_ability1_tactic', 'None')
    partial_ability1_singleton = argToBoolean(args.get('partial_ability1_singleton', False))
    partial_ability1_plugin = args.get('partial_ability1_plugin', 'None')
    partial_ability1_repeatable = argToBoolean(args.get('partial_ability1_repeatable', False))
    partial_ability1_description = args.get('partial_ability1_description', 'None')

    response = client.updatesanexistingability_request(ability_id, partial_ability1_name, partial_ability1_buckets, partial_ability1_technique_id, partial_ability1_delete_payload, partial_ability1_executors, partial_ability1_privilege, partial_ability1_technique_name, partial_ability1_tactic, partial_ability1_singleton, partial_ability1_plugin, partial_ability1_repeatable, partial_ability1_description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Ability',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateschedule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    partial_schedule1_schedule = str(args.get('partial_schedule1_schedule', ''))
    partial_schedule1_task_obfuscator = str(args.get('partial_schedule1_task_obfuscator', ''))
    partial_schedule1_task_autonomous = args.get('partial_schedule1_task_autonomous', None)
    partial_schedule1_task_state = str(args.get('partial_schedule1_task_state', ''))
    partial_schedule1_task = assign_params(obfuscator=partial_schedule1_task_obfuscator, autonomous=partial_schedule1_task_autonomous, state=partial_schedule1_task_state)

    response = client.updateschedule_request(id_, partial_schedule1_schedule, partial_schedule1_task)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Schedule',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updatethespecifiedlinkwithinanoperation_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    link_id = str(args.get('link_id', ''))
    partial_link1_command = str(args.get('partial_link1_command', ''))
    partial_link1_status = int(args.get('partial_link1_status', -3))

    response = client.updatethespecifiedlinkwithinanoperation_request(id_, link_id, partial_link1_command, partial_link1_status)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Link',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client: Client) -> None:
    client.get_api_v2_abilities_request(None, None, None)
    return_results('ok')


def main() -> None:

    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('url')
    api_key = params.get('api_key')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    headers = {}
    headers['KEY'] = api_key

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=None)
        
        commands = {
    		'caldera-create-fact': create_fact_command,
			'caldera-create-fact-source': create_fact_source_command,
			'caldera-create-adversary': createanewadversary_command,
			'caldera-create-agent': createanewagent_command,
			'caldera-create-operation-record': createanewcalderaoperationrecord_command,
			'caldera-create-objective': createanewobjective_command,
			'caldera-create-relationship': createarelationship_command,
			'caldera-create-ability': createsanewability_command,
			'caldera-create-potential-link': createsapotentiallink_command,
			'caldera-create-schedule': createschedule_command,
			'caldera-delete-agent': deleteanagent_command,
			'caldera-delete-fact-source': deleteanexistingfactsource_command,
			'caldera-delete-operation-by-id': deleteanoperationbyoperationid_command,
			'caldera-delete-facts': deleteoneormorefacts_command,
			'caldera-delete-relationships': deleteoneormorerelationships_command,
			'caldera-delete-ability': deletesanability_command,
			'caldera-delete-adversary': deletesanadversary_command,
			'caldera-delete-schedule': deleteschedule_command,
			'caldera-get-abilities': get_api_v2_abilities_command,
			'caldera-get-abilities-by-ability-id': get_api_v2_abilities_by_ability_id_command,
			'caldera-get-adversaries': get_api_v2_adversaries_command,
			'caldera-get-adversaries-by-adversary-id': get_api_v2_adversaries_by_adversary_id_command,
			'caldera-get-agents': get_api_v2_agents_command,
			'caldera-get-agents-by-paw': get_api_v2_agents_by_paw_command,
			'caldera-get-config-by-name': get_api_v2_config_by_name_command,
			'caldera-get-contacts': get_api_v2_contacts_command,
			'caldera-get-contacts-by-name': get_api_v2_contacts_by_name_command,
			'caldera-get-deploy-commands': get_api_v2_deploy_commands_command,
			'caldera-get-deploy-commands-by-ability-id': get_api_v2_deploy_commands_by_ability_id_command,
			'caldera-get-facts': get_api_v2_facts_command,
			'caldera-get-facts-by-operation-id': get_api_v2_facts_by_operation_id_command,
			'caldera-get-health': get_api_v2_health_command,
			'caldera-get-obfuscators': get_api_v2_obfuscators_command,
			'caldera-get-obfuscators-by-name': get_api_v2_obfuscators_by_name_command,
			'caldera-get-objectives': get_api_v2_objectives_command,
			'caldera-get-objectives-by-id': get_api_v2_objectives_by_id_command,
			'caldera-get-operations': get_api_v2_operations_command,
			'caldera-get-operations-by-id': get_api_v2_operations_by_id_command,
			'caldera-get-operations-links': get_api_v2_operations_links_command,
			'caldera-get-operations-links-by-link-id': get_api_v2_operations_links_by_link_id_command,
			'caldera-get-operations-links-result': get_api_v2_operations_links_result_command,
			'caldera-get-operations-potential-links': get_api_v2_operations_potentiallinks_command,
			'caldera-get-operations-potential-links-by-paw': get_api_v2_operations_potentiallinks_by_paw_command,
			'caldera-get-planners': get_api_v2_planners_command,
			'caldera-get-planners-by-planner-id': get_api_v2_planners_by_planner_id_command,
			'caldera-get-plugins': get_api_v2_plugins_command,
			'caldera-get-plugins-by-name': get_api_v2_plugins_by_name_command,
			'caldera-get-relationships': get_api_v2_relationships_command,
			'caldera-get-relationships-by-operation-id': get_api_v2_relationships_by_operation_id_command,
			'caldera-get-schedules': get_api_v2_schedules_command,
			'caldera-get-schedules-by-id': get_api_v2_schedules_by_id_command,
			'caldera-get-sources': get_api_v2_sources_command,
			'caldera-get-sources-by-id': get_api_v2_sources_by_id_command,
			'caldera-get-operation-event-logs': getoperationeventlogs_command,
			'caldera-get-operation-report': getoperationreport_command,
			'caldera-replace-ability': replacesanexistingability_command,
			'caldera-replace-schedule': replaceschedule_command,
			'caldera-update-agent-config': updateagentconfig_command,
			'caldera-update-adversary': updateanadversary_command,
			'caldera-update-agent': updateanagent_command,
			'caldera-update-fact-source': updateanexistingfactsource_command,
			'caldera-update-objective': updateanobjective_command,
			'caldera-update-fields-in-operation': updatefieldswithinanoperation_command,
			'caldera-update-main-config': updatemainconfig_command,
			'caldera-update-facts': updateoneormorefacts_command,
			'caldera-update-rerelationships': updateoneormorerelationships_command,
			'caldera-update-ability': updatesanexistingability_command,
			'caldera-update-schedule': updateschedule_command,
			'caldera-update-link-in-operation': updatethespecifiedlinkwithinanoperation_command,
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
