from requests import Response
import demistomock as demisto
from CommonServerPython import *


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def create_fact_request(self, fact_unique, fact_name, fact_links, fact_relationships, fact_origin_type, fact_limit_count, fact_technique_id, fact_trait, fact_source, fact_score, fact_value):
        data = assign_params(unique=fact_unique, name=fact_name, links=fact_links, relationships=fact_relationships, origin_type=fact_origin_type,
                             limit_count=fact_limit_count, technique_id=fact_technique_id, trait=fact_trait, source=fact_source, score=fact_score, value=fact_value)
        headers = self._headers

        response = self._http_request('post', 'api/v2/facts', json_data=data, headers=headers)

        return response

    def create_fact_source_request(self, source_name, source_adjustments, source_relationships, source_rules, source_facts, source_plugin):
        data = assign_params(name=source_name, adjustments=source_adjustments, relationships=source_relationships,
                             rules=source_rules, facts=source_facts, plugin=source_plugin)
        headers = self._headers

        response = self._http_request('post', 'api/v2/sources', json_data=data, headers=headers)

        return response

    def createanewadversary_request(self, adversary_name, adversary_tags, adversary_objective, adversary_atomic_ordering, adversary_plugin, adversary_description):
        data = assign_params(name=adversary_name, tags=adversary_tags, objective=adversary_objective,
                             atomic_ordering=adversary_atomic_ordering, plugin=adversary_plugin, description=adversary_description)
        headers = self._headers

        response = self._http_request('post', 'api/v2/adversaries', json_data=data, headers=headers)

        return response

    def createanewagent_request(self, agent_watchdog, agent_deadman_enabled, agent_ppid, agent_pid, agent_proxy_receivers, agent_origin_link_id, agent_available_contacts, agent_platform, agent_host, agent_group, agent_location, agent_display_name, agent_upstream_dest, agent_host_ip_addrs, agent_sleep_max, agent_architecture, agent_sleep_min, agent_server, agent_contact, agent_executors, agent_privilege, agent_username, agent_trusted, agent_proxy_chain, agent_paw, agent_exe_name):
        data = assign_params(watchdog=agent_watchdog, deadman_enabled=agent_deadman_enabled, ppid=agent_ppid, pid=agent_pid, proxy_receivers=agent_proxy_receivers, origin_link_id=agent_origin_link_id, available_contacts=agent_available_contacts, platform=agent_platform, host=agent_host, group=agent_group, location=agent_location,
                             display_name=agent_display_name, upstream_dest=agent_upstream_dest, host_ip_addrs=agent_host_ip_addrs, sleep_max=agent_sleep_max, architecture=agent_architecture, sleep_min=agent_sleep_min, server=agent_server, contact=agent_contact, executors=agent_executors, privilege=agent_privilege, username=agent_username, trusted=agent_trusted, proxy_chain=agent_proxy_chain, paw=agent_paw, exe_name=agent_exe_name)
        headers = self._headers

        response = self._http_request('post', 'api/v2/agents', json_data=data, headers=headers)

        return response

    def createanewcalderaoperationrecord_request(self, name, autonomous, objective, visibility, state, group, host_group, planner, obfuscator, chain, use_learning_parsers, source, jitter, adversary, auto_close):
        data = assign_params(name=name, autonomous=autonomous, objective=objective, visibility=visibility, state=state, group=group, host_group=host_group, planner=planner,
                             obfuscator=obfuscator, chain=chain, use_learning_parsers=use_learning_parsers, source=source, jitter=jitter, adversary=adversary, auto_close=auto_close)
        headers = self._headers

        response = self._http_request('post', 'api/v2/operations', json_data=data, headers=headers)

        return response

    def createanewobjective_request(self, objective_name, objective_id, objective_percentage, objective_goals, objective_description):
        data = assign_params(name=objective_name, id=objective_id, percentage=objective_percentage,
                             goals=objective_goals, description=objective_description)
        headers = self._headers

        response = self._http_request('post', 'api/v2/objectives', json_data=data, headers=headers)

        return response

    def createarelationship_request(self, relationship_unique, relationship_origin, relationship_edge, relationship_source, relationship_score, relationship_target):
        data = assign_params(unique=relationship_unique, origin=relationship_origin, edge=relationship_edge,
                             source=relationship_source, score=relationship_score, target=relationship_target)
        headers = self._headers

        response = self._http_request('post', 'api/v2/relationships', json_data=data, headers=headers)

        return response

    def createorupdateanadversary_request(self, adversary_id, partial_adversary_name, partial_adversary_tags, partial_adversary_objective, partial_adversary_adversary_id, partial_adversary_has_repeatable_abilities, partial_adversary_atomic_ordering, partial_adversary_plugin, partial_adversary_description):
        data = assign_params(name=partial_adversary_name, tags=partial_adversary_tags, objective=partial_adversary_objective, adversary_id=partial_adversary_adversary_id,
                             has_repeatable_abilities=partial_adversary_has_repeatable_abilities, atomic_ordering=partial_adversary_atomic_ordering, plugin=partial_adversary_plugin, description=partial_adversary_description)
        headers = self._headers

        response = self._http_request('put', f'api/v2/adversaries/{adversary_id}', json_data=data, headers=headers)

        return response

    def createorupdateanagent_request(self, paw, partial_agent_watchdog, partial_agent_links, partial_agent_deadman_enabled, partial_agent_ppid, partial_agent_pid, partial_agent_created, partial_agent_proxy_receivers, partial_agent_origin_link_id, partial_agent_available_contacts, partial_agent_last_seen, partial_agent_platform, partial_agent_pending_contact, partial_agent_host, partial_agent_group, partial_agent_location, partial_agent_display_name, partial_agent_upstream_dest, partial_agent_host_ip_addrs, partial_agent_sleep_max, partial_agent_architecture, partial_agent_sleep_min, partial_agent_server, partial_agent_contact, partial_agent_executors, partial_agent_privilege, partial_agent_username, partial_agent_trusted, partial_agent_proxy_chain, partial_agent_paw, partial_agent_exe_name):
        data = assign_params(watchdog=partial_agent_watchdog, links=partial_agent_links, deadman_enabled=partial_agent_deadman_enabled, ppid=partial_agent_ppid, pid=partial_agent_pid, created=partial_agent_created, proxy_receivers=partial_agent_proxy_receivers, origin_link_id=partial_agent_origin_link_id, available_contacts=partial_agent_available_contacts, last_seen=partial_agent_last_seen, platform=partial_agent_platform, pending_contact=partial_agent_pending_contact, host=partial_agent_host, group=partial_agent_group, location=partial_agent_location,
                             display_name=partial_agent_display_name, upstream_dest=partial_agent_upstream_dest, host_ip_addrs=partial_agent_host_ip_addrs, sleep_max=partial_agent_sleep_max, architecture=partial_agent_architecture, sleep_min=partial_agent_sleep_min, server=partial_agent_server, contact=partial_agent_contact, executors=partial_agent_executors, privilege=partial_agent_privilege, username=partial_agent_username, trusted=partial_agent_trusted, proxy_chain=partial_agent_proxy_chain, paw=partial_agent_paw, exe_name=partial_agent_exe_name)
        headers = self._headers

        response = self._http_request('put', f'api/v2/agents/{paw}', json_data=data, headers=headers)

        return response

    def createorupdateanobjective_request(self, id_, partial_objective_name, partial_objective_id, partial_objective_percentage, partial_objective_goals, partial_objective_description):
        data = assign_params(name=partial_objective_name, id=partial_objective_id, percentage=partial_objective_percentage,
                             goals=partial_objective_goals, description=partial_objective_description)
        headers = self._headers

        response = self._http_request('put', f'api/v2/objectives/{id_}', json_data=data, headers=headers)

        return response

    def createsanewability_request(self, ability_ability_id, ability_name, ability_buckets, ability_technique_id, ability_delete_payload, ability_executors, ability_privilege, ability_requirements, ability_plugin, ability_access, ability_tactic, ability_additional_info, ability_singleton, ability_technique_name, ability_repeatable, ability_description):
        data = assign_params(ability_id=ability_ability_id, name=ability_name, buckets=ability_buckets, technique_id=ability_technique_id, delete_payload=ability_delete_payload, executors=ability_executors, privilege=ability_privilege, requirements=ability_requirements,
                             plugin=ability_plugin, access=ability_access, tactic=ability_tactic, additional_info=ability_additional_info, singleton=ability_singleton, technique_name=ability_technique_name, repeatable=ability_repeatable, description=ability_description)
        headers = self._headers

        response = self._http_request('post', 'api/v2/abilities', json_data=data, headers=headers)

        return response

    def createsapotentiallink_request(self, id_, link_relationships, link_id, link_collect, link_pid, link_visibility, link_finish, link_pin, link_jitter, link_agent_reported_time, link_deadman, link_used, link_host, link_ability, link_status, link_score, link_command, link_unique, link_cleanup, link_decide, link_facts, link_executor, link_paw, link_output):
        data = assign_params(relationships=link_relationships, id=link_id, collect=link_collect, pid=link_pid, visibility=link_visibility, finish=link_finish, pin=link_pin, jitter=link_jitter, agent_reported_time=link_agent_reported_time, deadman=link_deadman,
                             used=link_used, host=link_host, ability=link_ability, status=link_status, score=link_score, command=link_command, unique=link_unique, cleanup=link_cleanup, decide=link_decide, facts=link_facts, executor=link_executor, paw=link_paw, output=link_output)
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

        response = self._http_request(
            'delete',
            f'api/v2/agents/{paw}',
            headers=headers,
            resp_type='response',
            ok_codes=[200, 204])

        return response

    def deleteanexistingfactsource_request(self, id_):
        headers = self._headers

        response = self._http_request(
            'delete',
            f'api/v2/sources/{id_}',
            headers=headers,
            resp_type='response')

        return response

    def deleteanoperationbyoperationid_request(self, id_):
        headers = self._headers

        response = self._http_request(
            'delete',
            f'api/v2/operations/{id_}',
            headers=headers,
            resp_type='response',
            ok_codes=[200, 204])
        return response

    def deleteoneormorefacts_request(self, fact_unique, fact_name, fact_links, fact_relationships, fact_origin_type, fact_created, fact_limit_count, fact_technique_id, fact_trait, fact_source, fact_score, fact_value, fact_collected_by):
        data = assign_params(unique=fact_unique, name=fact_name, links=fact_links, relationships=fact_relationships, origin_type=fact_origin_type, created=fact_created,
                             limit_count=fact_limit_count, technique_id=fact_technique_id, trait=fact_trait, source=fact_source, score=fact_score, value=fact_value, collected_by=fact_collected_by)
        headers = self._headers

        response = self._http_request('delete', 'api/v2/facts', json_data=data, headers=headers)

        return response

    def deleteoneormorerelationships_request(self, relationship_unique, relationship_origin, relationship_edge, relationship_source, relationship_score, relationship_target):
        data = assign_params(unique=relationship_unique, origin=relationship_origin, edge=relationship_edge,
                             source=relationship_source, score=relationship_score, target=relationship_target)
        headers = self._headers

        response = self._http_request('delete', 'api/v2/relationships', json_data=data, headers=headers)

        return response

    def deletesanability_request(self, ability_id):
        headers = self._headers

        response = self._http_request(
            'delete',
            f'api/v2/abilities/{ability_id}',
            headers=headers,
            resp_type='response',
            ok_codes=[200,204])

        return response

    def deletesanadversary_request(self, adversary_id):
        headers = self._headers

        response = self._http_request(
            'delete',
            f'api/v2/adversaries/{adversary_id}',
            headers=headers,
            ok_codes=[200,204],
            resp_type='response')

        return response

    def deleteschedule_request(self, id_):
        headers = self._headers

        response = self._http_request(
            'delete',
            f'api/v2/schedules/{id_}',
            headers=headers,
            ok_codes=[200,204],
            resp_type='response')

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

        response = self._http_request('get', f'api/v2/operations/{id_}/links/{link_id}', params=params, headers=headers)

        return response

    def get_api_v2_operations_links_result_request(self, id_, link_id, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/operations/{id_}/links/{link_id}/result', params=params, headers=headers)

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

        response = self._http_request(
            'post', f'api/v2/operations/{id_}/event-logs', params=params, json_data=data, headers=headers)

        return response

    def getoperationreport_request(self, id_, operationoutputrequest_enable_agent_output, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        data = assign_params(enable_agent_output=operationoutputrequest_enable_agent_output)
        headers = self._headers

        response = self._http_request('post', f'api/v2/operations/{id_}/report', params=params, json_data=data, headers=headers)

        return response

    def replacesanexistingability_request(self, ability_id, ability_name, ability_buckets, ability_technique_id, ability_delete_payload, ability_executors, ability_privilege, ability_requirements, ability_plugin, ability_access, ability_tactic, ability_additional_info, ability_singleton, ability_technique_name, ability_repeatable, ability_description):
        data = assign_params(ability_id=ability_id, name=ability_name, buckets=ability_buckets, technique_id=ability_technique_id, delete_payload=ability_delete_payload, executors=ability_executors, privilege=ability_privilege, requirements=ability_requirements,
                             plugin=ability_plugin, access=ability_access, tactic=ability_tactic, additional_info=ability_additional_info, singleton=ability_singleton, technique_name=ability_technique_name, repeatable=ability_repeatable, description=ability_description)
        headers = self._headers

        response = self._http_request('put', f'api/v2/abilities/{ability_id}', json_data=data, headers=headers)

        return response

    def replaceschedule_request(self, id_, partial_schedule2_schedule, partial_schedule2_task):
        data = assign_params(schedule=partial_schedule2_schedule, task=partial_schedule2_task)
        headers = self._headers

        response = self._http_request('put', f'api/v2/schedules/{id_}', json_data=data, headers=headers)

        return response

    def updateagentconfig_request(self, watchdog, sleep_min, deployments, deadman_abilities, untrusted_timer, bootstrap_abilities, sleep_max, implant_name):
        data = assign_params(watchdog=watchdog, sleep_min=sleep_min, deployments=deployments, deadman_abilities=deadman_abilities,
                             untrusted_timer=untrusted_timer, bootstrap_abilities=bootstrap_abilities, sleep_max=sleep_max, implant_name=implant_name)
        headers = self._headers

        response = self._http_request('patch', 'api/v2/config/agents', json_data=data, headers=headers)

        return response

    def updateanadversary_request(self, adversary_id, adversaryname, adversarytags, adversaryobjective, adversaryhas_repeatable_abilities, adversaryatomic_ordering, adversaryplugin, adversarydescription):
        data = assign_params(name=adversaryname, tags=adversarytags, objective=adversaryobjective, has_repeatable_abilities=adversaryhas_repeatable_abilities,
                             atomic_ordering=adversaryatomic_ordering, plugin=adversaryplugin, description=adversarydescription)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/adversaries/{adversary_id}', json_data=data, headers=headers)

        return response

    def updateanagent_request(self, paw, watchdog, sleep_min, trusted, sleep_max, pending_contact, group):
        data = assign_params(watchdog=watchdog, sleep_min=sleep_min, trusted=trusted,
                             sleep_max=sleep_max, pending_contact=pending_contact, group=group)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/agents/{paw}', json_data=data, headers=headers)

        return response

    def updateanexistingfactsource_request(self, id_, source_name, source_adjustments, source_relationships, source_id, source_rules, source_facts, source_plugin):
        data = assign_params(name=source_name, adjustments=source_adjustments, relationships=source_relationships,
                             id=source_id, rules=source_rules, facts=source_facts, plugin=source_plugin)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/sources/{id_}', json_data=data, headers=headers)

        return response

    def updateanobjective_request(self, id_, name, goals, description):
        data = assign_params(name=name, goals=goals,
                             description=description)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/objectives/{id_}', json_data=data, headers=headers)

        return response

    def updatefieldswithinanoperation_request(self, id_, obfuscator, autonomous, state):
        data = assign_params(obfuscator=obfuscator,
                             autonomous=autonomous, state=state)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/operations/{id_}', json_data=data, headers=headers)

        return response

    def updatemainconfig_request(self, property, value):
        data = assign_params(prop=property, value=value)
        headers = self._headers

        response = self._http_request(
            'patch',
            'api/v2/config/main',
            json_data=data,
            headers=headers,
            ok_codes=[200,204],
            resp_type='response')

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

    def updatesanexistingability_request(self, ability_id, name, buckets, technique_id, delete_payload, executors, privilege, technique_name, tactic, singleton, plugin, repeatable, description):
        data = assign_params(name=name, buckets=buckets, technique_id=technique_id, delete_payload=delete_payload, executors=executors, privilege=privilege,
                             technique_name=technique_name, tactic=tactic, singleton=singleton, plugin=plugin, repeatable=repeatable, description=description)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/abilities/{ability_id}', json_data=data, headers=headers)

        return response

    def updateschedule_request(self, id_, schedule_schedule, schedule_task):
        data = assign_params(schedule=schedule_schedule, task=schedule_task)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/schedules/{id_}', json_data=data, headers=headers)

        return response

    def updatethespecifiedlinkwithinanoperation_request(self, id_, link_id, command, status):
        data = assign_params(command=command, status=status)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/operations/{id_}/links/{link_id}', json_data=data, headers=headers)

        return response


def create_fact_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    fact_unique = args.get('fact_unique')
    fact_name = args.get('fact_name')
    fact_links = argToList(args.get('fact_links', []))
    fact_relationships = argToList(args.get('fact_relationships', []))
    fact_origin_type = args.get('fact_origin_type')
    fact_limit_count = arg_to_number(args.get('fact_limit_count'), 0)
    fact_technique_id = args.get('fact_technique_id')
    fact_trait = args.get('fact_trait')
    fact_source = args.get('fact_source')
    fact_score = arg_to_number(args.get('fact_score'))
    fact_value = args.get('fact_value')

    response = client.create_fact_request(fact_unique, fact_name, fact_links, fact_relationships, fact_origin_type,
                                          fact_limit_count, fact_technique_id, fact_trait, fact_source, fact_score, fact_value)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Fact',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_fact_source_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    adjustments = json.loads(args.get('adjustments', []))
    relationships = json.loads(args.get('relationships', []))
    rules = json.loads(args.get('rules', []))
    facts = json.loads(args.get('facts', []))
    plugin = args.get('plugin')

    response = client.create_fact_source_request(name, adjustments, relationships, rules, facts, plugin)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Sources',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createanewadversary_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    tags = argToList(args.get('tags', []))
    objective = args.get('objective')
    atomic_ordering = argToList(args.get('adversary_atomic_ordering', []))
    plugin = args.get('plugin')
    description = args.get('description')

    response = client.createanewadversary_request(name, tags, objective, atomic_ordering, plugin, description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Adversaries',
        outputs_key_field='adversary_id',
        outputs=response,
        raw_response=response
    )

    return command_results


def createanewagent_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    watchdog = arg_to_number(args.get('watchdog'))
    deadman_enabled = argToBoolean(args.get('deadman_enabled', False))
    ppid = arg_to_number(args.get('ppid', 0))
    pid = arg_to_number(args.get('pid', 0))
    proxy_receivers = json.loads(args.get('proxy_receivers'))
    origin_link_id = args.get('origin_link_id')
    available_contacts = argToList(args.get('available_contacts', []))
    platform = args.get('platform')
    host = args.get('host')
    group = args.get('group')
    location = args.get('location')
    display_name = args.get('display_name')
    upstream_dest = args.get('upstream_dest')
    host_ip_addrs = argToList(args.get('host_ip_addrs', []))
    sleep_max = arg_to_number(args.get('sleep_max'))
    architecture = args.get('architecture')
    sleep_min = args.get('sleep_min')
    server = args.get('server')
    contact = args.get('contact')
    exeutors = argToList(args.get('exeutors', []))
    privilege = args.get('privilege')
    username = args.get('username')
    trusted = argToBoolean(args.get('trusted', False))
    proxy_chain = args.get('proxy_chain', [])
    paw = args.get('paw')
    exe_name = args.get('exe_name')

    response = client.createanewagent_request(watchdog, deadman_enabled, ppid, pid, proxy_receivers, origin_link_id, available_contacts, platform, host, group,
                                              location, display_name, upstream_dest, host_ip_addrs, sleep_max, architecture, sleep_min, server, contact, exeutors, privilege, username, trusted, proxy_chain, paw, exe_name)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Agents',
        outputs_key_field='paw',
        outputs=response,
        raw_response=response
    )

    return command_results


def createanewcalderaoperationrecord_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    autonomous = arg_to_number(args.get('autonomous'))
    objective_name = args.get('objective_name')
    objective_id = args.get('objective_id')
    objective_percentage = args.get('objective_percentage')
    objective_goals = args.get('objective_goals')
    objective_description = args.get('objective_description')
    objective = assign_params(name=objective_name, id=objective_id,
                                        percentage=objective_percentage, goals=objective_goals, description=objective_description)
    visibility = arg_to_number(args.get('visibility'))
    state = args.get('state')
    group = args.get('group')
    host_group = argToList(args.get('host_group', []))
    planner_id = args.get('planner_id')
    planner = assign_params(id=planner_id)
    obfuscator = args.get('obfuscator')
    chain = args.get('chain')
    use_learning_parsers = argToBoolean(args.get('use_learning_parsers', False))
    source_id = args.get('source_id')
    source = assign_params(id=source_id)
    jitter = args.get('jitter')
    adversary_id = args.get('adversary_id')
    adversary = assign_params(adversary_id=adversary_id)
    auto_close = argToBoolean(args.get('auto_close', False))

    response = client.  createanewcalderaoperationrecord_request(name, autonomous, objective, visibility, state, group, host_group,
                                                               planner, obfuscator, chain, use_learning_parsers, source, jitter, adversary, auto_close)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Operations',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createanewobjective_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    objective_name = args.get('objective_name')
    objective_id = args.get('objective_id')
    objective_percentage = args.get('objective_percentage')
    objective_goals = argToList(args.get('objective_goals', []))
    objective_description = args.get('objective_description')

    response = client.createanewobjective_request(
        objective_name, objective_id, objective_percentage, objective_goals, objective_description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Objective',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createarelationship_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    relationship_unique = args.get('relationship_unique')
    relationship_origin = args.get('relationship_origin')
    relationship_edge = args.get('relationship_edge')
    relationship_source_unique = args.get('relationship_source_unique')
    relationship_source_name = args.get('relationship_source_name')
    relationship_source_links = args.get('relationship_source_links')
    relationship_source_relationships = args.get('relationship_source_relationships')
    relationship_source_origin_type = args.get('relationship_source_origin_type')
    relationship_source_created = args.get('relationship_source_created')
    relationship_source_limit_count = args.get('relationship_source_limit_count')
    relationship_source_technique_id = args.get('relationship_source_technique_id')
    relationship_source_trait = args.get('relationship_source_trait')
    relationship_source_source = args.get('relationship_source_source')
    relationship_source_score = args.get('relationship_source_score')
    relationship_source_value = args.get('relationship_source_value')
    relationship_source_collected_by = args.get('relationship_source_collected_by')
    relationship_source = assign_params(unique=relationship_source_unique, name=relationship_source_name, links=relationship_source_links, relationships=relationship_source_relationships, origin_type=relationship_source_origin_type, created=relationship_source_created,
                                        limit_count=relationship_source_limit_count, technique_id=relationship_source_technique_id, trait=relationship_source_trait, source=relationship_source_source, score=relationship_source_score, value=relationship_source_value, collected_by=relationship_source_collected_by)
    relationship_score = args.get('relationship_score')
    relationship_target = args.get('relationship_target')

    response = client.createarelationship_request(
        relationship_unique, relationship_origin, relationship_edge, relationship_source, relationship_score, relationship_target)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Relationship',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createorupdateanadversary_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    adversary_id = args.get('adversary_id')
    partial_adversary_name = args.get('partial_adversary_name')
    partial_adversary_tags = argToList(args.get('partial_adversary_tags', []))
    partial_adversary_objective = args.get('partial_adversary_objective')
    partial_adversary_adversary_id = args.get('partial_adversary_adversary_id')
    partial_adversary_has_repeatable_abilities = argToBoolean(args.get('partial_adversary_has_repeatable_abilities', False))
    partial_adversary_atomic_ordering = argToList(args.get('partial_adversary_atomic_ordering', []))
    partial_adversary_plugin = args.get('partial_adversary_plugin')
    partial_adversary_description = args.get('partial_adversary_description')

    response = client.createorupdateanadversary_request(adversary_id, partial_adversary_name, partial_adversary_tags, partial_adversary_objective, partial_adversary_adversary_id,
                                                        partial_adversary_has_repeatable_abilities, partial_adversary_atomic_ordering, partial_adversary_plugin, partial_adversary_description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Adversary',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createorupdateanagent_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    paw = args.get('paw')
    partial_agent_watchdog = args.get('partial_agent_watchdog')
    partial_agent_links = argToList(args.get('partial_agent_links', []))
    partial_agent_deadman_enabled = argToBoolean(args.get('partial_agent_deadman_enabled', False))
    partial_agent_ppid = args.get('partial_agent_ppid')
    partial_agent_pid = args.get('partial_agent_pid')
    partial_agent_created = args.get('partial_agent_created')
    partial_agent_proxy_receivers = args.get('partial_agent_proxy_receivers')
    partial_agent_origin_link_id = args.get('partial_agent_origin_link_id')
    partial_agent_available_contacts = argToList(args.get('partial_agent_available_contacts', []))
    partial_agent_last_seen = args.get('partial_agent_last_seen')
    partial_agent_platform = args.get('partial_agent_platform')
    partial_agent_pending_contact = args.get('partial_agent_pending_contact')
    partial_agent_host = args.get('partial_agent_host')
    partial_agent_group = args.get('partial_agent_group')
    partial_agent_location = args.get('partial_agent_location')
    partial_agent_display_name = args.get('partial_agent_display_name')
    partial_agent_upstream_dest = args.get('partial_agent_upstream_dest')
    partial_agent_host_ip_addrs = argToList(args.get('partial_agent_host_ip_addrs', []))
    partial_agent_sleep_max = args.get('partial_agent_sleep_max')
    partial_agent_architecture = args.get('partial_agent_architecture')
    partial_agent_sleep_min = args.get('partial_agent_sleep_min')
    partial_agent_server = args.get('partial_agent_server')
    partial_agent_contact = args.get('partial_agent_contact')
    partial_agent_executors = argToList(args.get('partial_agent_executors', []))
    partial_agent_privilege = args.get('partial_agent_privilege')
    partial_agent_username = args.get('partial_agent_username')
    partial_agent_trusted = argToBoolean(args.get('partial_agent_trusted', False))
    partial_agent_proxy_chain = argToList(args.get('partial_agent_proxy_chain', []))
    partial_agent_paw = args.get('partial_agent_paw')
    partial_agent_exe_name = args.get('partial_agent_exe_name')

    response = client.createorupdateanagent_request(paw, partial_agent_watchdog, partial_agent_links, partial_agent_deadman_enabled, partial_agent_ppid, partial_agent_pid, partial_agent_created, partial_agent_proxy_receivers, partial_agent_origin_link_id, partial_agent_available_contacts, partial_agent_last_seen, partial_agent_platform, partial_agent_pending_contact, partial_agent_host, partial_agent_group,
                                                    partial_agent_location, partial_agent_display_name, partial_agent_upstream_dest, partial_agent_host_ip_addrs, partial_agent_sleep_max, partial_agent_architecture, partial_agent_sleep_min, partial_agent_server, partial_agent_contact, partial_agent_executors, partial_agent_privilege, partial_agent_username, partial_agent_trusted, partial_agent_proxy_chain, partial_agent_paw, partial_agent_exe_name)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Agent',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createorupdateanobjective_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = args.get('id_')
    partial_objective_name = args.get('partial_objective_name')
    partial_objective_id = args.get('partial_objective_id')
    partial_objective_percentage = args.get('partial_objective_percentage')
    partial_objective_goals = argToList(args.get('partial_objective_goals', []))
    partial_objective_description = args.get('partial_objective_description')

    response = client.createorupdateanobjective_request(
        id_, partial_objective_name, partial_objective_id, partial_objective_percentage, partial_objective_goals, partial_objective_description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Objective',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createsanewability_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ability_ability_id = args.get('ability_ability_id')
    ability_name = args.get('ability_name')
    ability_buckets = argToList(args.get('ability_buckets', []))
    ability_technique_id = args.get('ability_technique_id')
    ability_delete_payload = argToBoolean(args.get('ability_delete_payload', False))
    ability_executors = argToList(args.get('ability_executors', []))
    ability_privilege = args.get('ability_privilege')
    ability_requirements = argToList(args.get('ability_requirements', []))
    ability_plugin = args.get('ability_plugin')
    ability_access = args.get('ability_access')
    ability_tactic = args.get('ability_tactic')
    ability_additional_info = args.get('ability_additional_info')
    ability_singleton = argToBoolean(args.get('ability_singleton', False))
    ability_technique_name = args.get('ability_technique_name')
    ability_repeatable = argToBoolean(args.get('ability_repeatable', False))
    ability_description = args.get('ability_description')

    response = client.createsanewability_request(ability_ability_id, ability_name, ability_buckets, ability_technique_id, ability_delete_payload, ability_executors, ability_privilege,
                                                 ability_requirements, ability_plugin, ability_access, ability_tactic, ability_additional_info, ability_singleton, ability_technique_name, ability_repeatable, ability_description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Ability',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createsapotentiallink_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')
    link_relationships = argToList(args.get('link_relationships', []))
    link_id = args.get('link_id')
    link_collect = args.get('link_collect')
    link_pid = args.get('link_pid')
    link_visibility_adjustments = args.get('link_visibility_adjustments')
    link_visibility_score = args.get('link_visibility_score')
    link_visibility = assign_params(adjustments=link_visibility_adjustments, score=link_visibility_score)
    link_finish = args.get('link_finish')
    link_pin = int(args.get('link_pin', 0))
    link_jitter = int(args.get('link_jitter', 0))
    link_agent_reported_time = args.get('link_agent_reported_time')
    link_deadman = argToBoolean(args.get('link_deadman', False))
    link_used = argToList(args.get('link_used', []))
    link_host = args.get('link_host')
    link_ability_ability_id = args.get('link_ability_ability_id')
    link_ability_name = args.get('link_ability_name')
    link_ability_buckets = args.get('link_ability_buckets')
    link_ability_technique_id = args.get('link_ability_technique_id')
    link_ability_delete_payload = argToBoolean(args.get('link_ability_delete_payload', False))
    link_ability_executors = args.get('link_ability_executors')
    link_ability_privilege = args.get('link_ability_privilege')
    link_ability_requirements = args.get('link_ability_requirements')
    link_ability_plugin = args.get('link_ability_plugin')
    link_ability_access = args.get('link_ability_access')
    link_ability_tactic = args.get('link_ability_tactic')
    link_ability_additional_info = args.get('link_ability_additional_info')
    link_ability_singleton = argToBoolean(args.get('link_ability_singleton', False))
    link_ability_technique_name = args.get('link_ability_technique_name')
    link_ability_repeatable = argToBoolean(args.get('link_ability_repeatable', False))
    link_ability_description = args.get('link_ability_description')
    link_ability = assign_params(ability_id=link_ability_ability_id, name=link_ability_name, buckets=link_ability_buckets, technique_id=link_ability_technique_id, delete_payload=link_ability_delete_payload, executors=link_ability_executors, privilege=link_ability_privilege, requirements=link_ability_requirements,
                                 plugin=link_ability_plugin, access=link_ability_access, tactic=link_ability_tactic, additional_info=link_ability_additional_info, singleton=link_ability_singleton, technique_name=link_ability_technique_name, repeatable=link_ability_repeatable, description=link_ability_description)
    link_status = int(args.get('link_status', -3))
    link_score = int(args.get('link_score', 0))
    link_command = args.get('link_command')
    link_unique = args.get('link_unique')
    link_cleanup = int(args.get('link_cleanup', 0))
    link_decide = args.get('link_decide')
    link_facts = argToList(args.get('link_facts', []))
    link_executor_name = args.get('link_executor_name')
    link_executor_cleanup = args.get('link_executor_cleanup')
    link_executor_platform = args.get('link_executor_platform')
    link_executor_language = args.get('link_executor_language')
    link_executor_uploads = args.get('link_executor_uploads')
    link_executor_variations = args.get('link_executor_variations')
    link_executor_build_target = args.get('link_executor_build_target')
    link_executor_payloads = args.get('link_executor_payloads')
    link_executor_timeout = args.get('link_executor_timeout')
    link_executor_parsers = args.get('link_executor_parsers')
    link_executor_command = args.get('link_executor_command')
    link_executor_additional_info = args.get('link_executor_additional_info')
    link_executor_code = args.get('link_executor_code')
    link_executor = assign_params(name=link_executor_name, cleanup=link_executor_cleanup, platform=link_executor_platform, language=link_executor_language, uploads=link_executor_uploads, variations=link_executor_variations,
                                  build_target=link_executor_build_target, payloads=link_executor_payloads, timeout=link_executor_timeout, parsers=link_executor_parsers, command=link_executor_command, additional_info=link_executor_additional_info, code=link_executor_code)
    link_paw = args.get('link_paw')
    link_output = args.get('link_output')

    response = client.createsapotentiallink_request(operation_id, link_relationships, link_id, link_collect, link_pid, link_visibility, link_finish, link_pin, link_jitter, link_agent_reported_time,
                                                    link_deadman, link_used, link_host, link_ability, link_status, link_score, link_command, link_unique, link_cleanup, link_decide, link_facts, link_executor, link_paw, link_output)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Link',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def createschedule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    schedule_schedule = args.get('schedule_schedule')
    schedule_task_name = args.get('schedule_task_name')
    schedule_task_autonomous = args.get('schedule_task_autonomous')
    schedule_task_id = args.get('schedule_task_id')
    schedule_task_objective = args.get('schedule_task_objective')
    schedule_task_visibility = args.get('schedule_task_visibility')
    schedule_task_state = args.get('schedule_task_state')
    schedule_task_group = args.get('schedule_task_group')
    schedule_task_host_group = args.get('schedule_task_host_group')
    schedule_task_planner = args.get('schedule_task_planner')
    schedule_task_obfuscator = args.get('schedule_task_obfuscator')
    schedule_task_chain = args.get('schedule_task_chain')
    schedule_task_use_learning_parsers = argToBoolean(args.get('schedule_task_use_learning_parsers', False))
    schedule_task_source = args.get('schedule_task_source')
    schedule_task_jitter = args.get('schedule_task_jitter')
    schedule_task_start = args.get('schedule_task_start')
    schedule_task_adversary = args.get('schedule_task_adversary')
    schedule_task_auto_close = argToBoolean(args.get('schedule_task_auto_close', False))
    schedule_task = assign_params(name=schedule_task_name, autonomous=schedule_task_autonomous, id=schedule_task_id, objective=schedule_task_objective, visibility=schedule_task_visibility, state=schedule_task_state, group=schedule_task_group, host_group=schedule_task_host_group, planner=schedule_task_planner,
                                  obfuscator=schedule_task_obfuscator, chain=schedule_task_chain, use_learning_parsers=schedule_task_use_learning_parsers, source=schedule_task_source, jitter=schedule_task_jitter, start=schedule_task_start, adversary=schedule_task_adversary, auto_close=schedule_task_auto_close)
    schedule_id = args.get('schedule_id')

    response = client.createschedule_request(schedule_schedule, schedule_task, schedule_id)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Schedule',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deleteanagent_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    paw = args.get('paw')

    response = client.deleteanagent_request(paw)
    return f"Agent with paw {paw} was deleted successfully."


def deleteanexistingfactsource_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    fact_source_id = args.get('fact_source_id')

    response = client.deleteanexistingfactsource_request(fact_source_id)
    return f"Fact Source with ID {fact_source_id} was deleted successfully."


def deleteanoperationbyoperationid_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')

    client.deleteanoperationbyoperationid_request(operation_id)

    return f"Operation with Id {operation_id} was deleted successfully."
    


def deleteoneormorefacts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    fact_unique = args.get('fact_unique')
    fact_name = args.get('fact_name')
    fact_links = argToList(args.get('fact_links', []))
    fact_relationships = argToList(args.get('fact_relationships', []))
    fact_origin_type = args.get('fact_origin_type')
    fact_created = args.get('fact_created')
    fact_limit_count = args.get('fact_limit_count')
    fact_technique_id = args.get('fact_technique_id')
    fact_trait = args.get('fact_trait')
    fact_source = args.get('fact_source')
    fact_score = args.get('fact_score')
    fact_value = args.get('fact_value')
    fact_collected_by = argToList(args.get('fact_collected_by', []))

    response = client.deleteoneormorefacts_request(fact_unique, fact_name, fact_links, fact_relationships, fact_origin_type, fact_created,
                                                   fact_limit_count, fact_technique_id, fact_trait, fact_source, fact_score, fact_value, fact_collected_by)
    output = response.get('removed')
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Facts',
        outputs_key_field='',
        outputs=output,
        raw_response=response
    )

    return command_results


def deleteoneormorerelationships_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    relationship_unique = args.get('relationship_unique')
    relationship_origin = args.get('relationship_origin')
    relationship_edge = args.get('relationship_edge')
    relationship_source_unique = args.get('relationship_source_unique')
    relationship_source_name = args.get('relationship_source_name')
    relationship_source_links = args.get('relationship_source_links')
    relationship_source_relationships = args.get('relationship_source_relationships')
    relationship_source_origin_type = args.get('relationship_source_origin_type')
    relationship_source_created = args.get('relationship_source_created')
    relationship_source_limit_count = args.get('relationship_source_limit_count')
    relationship_source_technique_id = args.get('relationship_source_technique_id')
    relationship_source_trait = args.get('relationship_source_trait')
    relationship_source_source = args.get('relationship_source_source')
    relationship_source_score = args.get('relationship_source_score')
    relationship_source_value = args.get('relationship_source_value')
    relationship_source_collected_by = args.get('relationship_source_collected_by')
    relationship_source = assign_params(unique=relationship_source_unique, name=relationship_source_name, links=relationship_source_links, relationships=relationship_source_relationships, origin_type=relationship_source_origin_type, created=relationship_source_created,
                                                limit_count=relationship_source_limit_count, technique_id=relationship_source_technique_id, trait=relationship_source_trait, source=relationship_source_source, score=relationship_source_score, value=relationship_source_value, collected_by=relationship_source_collected_by)
    relationship_score = args.get('relationship_score')
    relationship_target = args.get('relationship_target')

    response = client.deleteoneormorerelationships_request(relationship_unique, relationship_origin, relationship_edge, relationship_source, relationship_score, relationship_target)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Relationships',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def deletesanability_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ability_id = args.get('ability_id')

    client.deletesanability_request(ability_id)
    return f"Ability with ID {ability_id} was deleted successfully."


def deletesanadversary_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    adversary_id = args.get('adversary_id')

    client.deletesanadversary_request(adversary_id)
    return f"Adversary with ID {adversary_id} was deleted successfully."


def deleteschedule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    schedule_id = args.get('schedule_id')

    client.deleteschedule_request(schedule_id)
    
    return f"Schedule with ID {schedule_id} deleted successfully."


def get_api_v2_abilities_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ability_id = args.get('ability_id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))
    if ability_id:
        response = client.get_api_v2_abilities_by_ability_id_request(ability_id, include, exclude)
    else:
        response = client.get_api_v2_abilities_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Abilities',
        outputs_key_field='ability_id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_adversaries_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    adversary_id = args.get('adversary_id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if adversary_id:
        response = client.get_api_v2_adversaries_by_adversary_id_request(adversary_id, include, exclude)
    else:
        response = client.get_api_v2_adversaries_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Adversaries',
        outputs_key_field='adversary_id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_agents_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    paw = args.get('paw')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if paw:
        response = client.get_api_v2_agents_by_paw_request(paw, include, exclude)
    else:
        response = client.get_api_v2_agents_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Agents',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_config_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')

    response = client.get_api_v2_config_by_name_request(name)
    response['name'] = name
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Config',
        outputs_key_field='name',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_contacts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    if name:
        response = client.get_api_v2_contacts_by_name_request(name)
    else:
        response = client.get_api_v2_contacts_request()
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Contacts',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_deploy_commands_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ability_id = args.get('ability_id')

    if ability_id:
        response = client.get_api_v2_deploy_commands_by_ability_id_request(ability_id)
    else:
        response = client.get_api_v2_deploy_commands_request()
    output = response.get('abilities')
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.DeployCommands',
        outputs_key_field=['command', 'name'],
        outputs=output,
        raw_response=response
    )

    return command_results


def get_api_v2_facts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))
    operation_id = args.get('operation_id')

    if operation_id:
        response = client.get_api_v2_facts_by_operation_id_request(sort, include, exclude, operation_id)
    else:
        response = client.get_api_v2_facts_request(sort, include, exclude)
    output = response.get('found')
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Facts',
        outputs_key_field='unique',
        outputs=output,
        raw_response=output
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
    name = args.get('name')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if name:
        response = client.get_api_v2_obfuscators_by_name_request(name, include, exclude)
    else:
        response = client.get_api_v2_obfuscators_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Obfuscators',
        outputs_key_field='name',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_objectives_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    objective_id = args.get('id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if objective_id:
        response = client.get_api_v2_objectives_by_id_request(objective_id, include, exclude)
    else:
        response = client.get_api_v2_objectives_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Objectives',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_operations_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if operation_id:
        response = client.get_api_v2_operations_by_id_request(operation_id, include, exclude)
    else:
        response = client.get_api_v2_operations_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Operations',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_operations_links_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')
    link_id = args.get('link_id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if link_id:
        response = client.get_api_v2_operations_links_by_link_id_request(operation_id, link_id, include, exclude)
    else:
        response = client.get_api_v2_operations_links_request(operation_id, sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.OperationLinks',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_operations_links_result_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')
    link_id = args.get('link_id')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_api_v2_operations_links_result_request(operation_id, link_id, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.OperationLinks',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_operations_potentiallinks_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))
    paw = args.get('paw')

    if paw:
        response = client.get_api_v2_operations_potentiallinks_by_paw_request(operation_id, paw, include, exclude)
    else:
        response = client.get_api_v2_operations_potentiallinks_request(operation_id, sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.OperationLinks',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_planners_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    planner_id = args.get('planner_id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if planner_id:
        response = client.get_api_v2_planners_by_planner_id_request(planner_id, include, exclude)
    else:
        response = client.get_api_v2_planners_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Planners',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_plugins_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if name:
        response = client.get_api_v2_plugins_by_name_request(name, include, exclude)
    else:
        response = client.get_api_v2_plugins_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Plugins',
        outputs_key_field='name',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_relationships_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if operation_id:
        response = client.get_api_v2_relationships_by_operation_id_request(sort, include, exclude, operation_id)
    else:
        response = client.get_api_v2_relationships_request(sort, include, exclude)
    output = response.get('found')
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Relationships',
        outputs_key_field='unique',
        outputs=output,
        raw_response=response
    )

    return command_results


def get_api_v2_schedules_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    schedule_id = args.get('schedule_id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if schedule_id:
        response = client.get_api_v2_schedules_by_id_request(schedule_id, include, exclude)
    else:
        response = client.get_api_v2_schedules_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Schedules',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_api_v2_sources_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    source_id = args.get('source_id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if source_id:
        response = client.get_api_v2_sources_by_id_request(source_id, include, exclude)
    else:
        response = client.get_api_v2_sources_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Sources',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def getoperationeventlogs_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')
    enable_agent_output = argToBoolean(args.get('enable_agent_output', False))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.getoperationeventlogs_request(operation_id, enable_agent_output, include, exclude)
    output = {
        'id': operation_id,
        'EventLogs': response
    }
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Operations',
        outputs_key_field='id',
        outputs=output,
        raw_response=response
    )

    return command_results


def getoperationreport_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')
    enable_agent_output = argToBoolean(args.get('enable_agent_output', False))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.getoperationreport_request(operation_id, enable_agent_output, include, exclude)
    output = {
        'id': operation_id,
        'OperationReport': response
    }
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Operations',
        outputs_key_field='id',
        outputs=output,
        raw_response=response
    )

    return command_results


def replacesanexistingability_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ability_id = args.get('ability_id')
    ability_name = args.get('ability_name')
    ability_buckets = argToList(args.get('ability_buckets', []))
    ability_technique_id = args.get('ability_technique_id')
    ability_delete_payload = argToBoolean(args.get('ability_delete_payload', False))
    ability_executors = argToList(args.get('ability_executors', []))
    ability_privilege = args.get('ability_privilege')
    ability_requirements = argToList(args.get('ability_requirements', []))
    ability_plugin = args.get('ability_plugin')
    ability_access = args.get('ability_access')
    ability_tactic = args.get('ability_tactic')
    ability_additional_info = args.get('ability_additional_info')
    ability_singleton = argToBoolean(args.get('ability_singleton', False))
    ability_technique_name = args.get('ability_technique_name')
    ability_repeatable = argToBoolean(args.get('ability_repeatable', False))
    ability_description = args.get('ability_description')

    response = client.replacesanexistingability_request(ability_id, ability_name, ability_buckets, ability_technique_id, ability_delete_payload, ability_executors, ability_privilege,
                                                        ability_requirements, ability_plugin, ability_access, ability_tactic, ability_additional_info, ability_singleton, ability_technique_name, ability_repeatable, ability_description)
    response['id'] = ability_id
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Abilities',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def replaceschedule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = args.get('id_')
    partial_schedule2_schedule = args.get('partial_schedule2_schedule')
    partial_schedule2_task_name = args.get('partial_schedule2_task_name')
    partial_schedule2_task_autonomous = args.get('partial_schedule2_task_autonomous')
    partial_schedule2_task_id = args.get('partial_schedule2_task_id')
    partial_schedule2_task_objective = args.get('partial_schedule2_task_objective')
    partial_schedule2_task_visibility = args.get('partial_schedule2_task_visibility')
    partial_schedule2_task_state = args.get('partial_schedule2_task_state')
    partial_schedule2_task_group = args.get('partial_schedule2_task_group')
    partial_schedule2_task_host_group = args.get('partial_schedule2_task_host_group')
    partial_schedule2_task_planner = args.get('partial_schedule2_task_planner')
    partial_schedule2_task_obfuscator = args.get('partial_schedule2_task_obfuscator')
    partial_schedule2_task_chain = args.get('partial_schedule2_task_chain')
    partial_schedule2_task_use_learning_parsers = argToBoolean(args.get('partial_schedule2_task_use_learning_parsers', False))
    partial_schedule2_task_source = args.get('partial_schedule2_task_source')
    partial_schedule2_task_jitter = args.get('partial_schedule2_task_jitter')
    partial_schedule2_task_start = args.get('partial_schedule2_task_start')
    partial_schedule2_task_adversary = args.get('partial_schedule2_task_adversary')
    partial_schedule2_task_auto_close = argToBoolean(args.get('partial_schedule2_task_auto_close', False))
    partial_schedule2_task = assign_params(name=partial_schedule2_task_name, autonomous=partial_schedule2_task_autonomous, id=partial_schedule2_task_id, objective=partial_schedule2_task_objective, visibility=partial_schedule2_task_visibility, state=partial_schedule2_task_state, group=partial_schedule2_task_group, host_group=partial_schedule2_task_host_group, planner=partial_schedule2_task_planner,
                                           obfuscator=partial_schedule2_task_obfuscator, chain=partial_schedule2_task_chain, use_learning_parsers=partial_schedule2_task_use_learning_parsers, source=partial_schedule2_task_source, jitter=partial_schedule2_task_jitter, start=partial_schedule2_task_start, adversary=partial_schedule2_task_adversary, auto_close=partial_schedule2_task_auto_close)

    response = client.replaceschedule_request(id_, partial_schedule2_schedule, partial_schedule2_task)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Schedules',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateagentconfig_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    watchdog = args.get('watchdog')
    sleep_min = args.get('sleep_min')
    deployments = argToList(args.get('deployments', []))
    deadman_abilities = argToList(args.get('deadman_abilities', []))
    untrusted_timer = args.get('untrusted_timer')
    bootstrap_abilities = argToList(args.get('bootstrap_abilities', []))
    sleep_max = args.get('sleep_max')
    implant_name = args.get('implant_name')

    response = client.updateagentconfig_request(watchdog, sleep_min, deployments, deadman_abilities,
                                                untrusted_timer, bootstrap_abilities, sleep_max, implant_name)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.AgentConfigUpdate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateanadversary_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    adversary_id = args.get('adversary_id')
    adversaryname = args.get('adversaryname')
    adversarytags = argToList(args.get('adversarytags', []))
    adversaryobjective = args.get('adversaryobjective')
    adversaryhas_repeatable_abilities = argToBoolean(args.get('adversaryhas_repeatable_abilities', False))
    adversaryatomic_ordering = argToList(args.get('adversaryatomic_ordering', []))
    adversaryplugin = args.get('adversaryplugin')
    adversarydescription = args.get('adversarydescription')

    response = client.updateanadversary_request(adversary_id, adversaryname, adversarytags, adversaryobjective,
                                                adversaryhas_repeatable_abilities, adversaryatomic_ordering, adversaryplugin, adversarydescription)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Adversaries',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateanagent_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    paw = args.get('paw')
    watchdog = args.get('watchdog')
    sleep_min = args.get('sleep_min')
    trusted = argToBoolean(args.get('trusted', False))
    sleep_max = args.get('sleep_max')
    pending_contact = args.get('pending_contact')
    group = args.get('group')

    response = client.updateanagent_request(paw, watchdog, sleep_min,
                                            trusted, sleep_max, pending_contact, group)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Agents',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateanexistingfactsource_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    fact_source_id = args.get('fact_source_id')
    source_name = args.get('source_name')
    source_adjustments = argToList(args.get('source_adjustments', []))
    source_relationships = argToList(args.get('source_relationships', []))
    source_id = args.get('source_id')
    source_rules = argToList(args.get('source_rules', []))
    source_facts = argToList(args.get('source_facts', []))
    source_plugin = args.get('source_plugin')

    response = client.updateanexistingfactsource_request(fact_source_id, source_name, source_adjustments,
                                                         source_relationships, source_id, source_rules, source_facts, source_plugin)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Sources',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateanobjective_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    objective_id = args.get('objective_id')
    name = args.get('name')
    goals = argToList(args.get('goals', []))
    description = args.get('description')

    response = client.updateanobjective_request(
        objective_id, name, goals, description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Objectives',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updatefieldswithinanoperation_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')
    obfuscator = args.get('obfuscator')
    autonomous = args.get('autonomous')
    state = args.get('state')

    response = client.updatefieldswithinanoperation_request(
        operation_id, obfuscator, autonomous, state)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Operations',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def updatemainconfig_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    property = args.get('property')
    value = args.get('value')

    client.updatemainconfig_request(property, value)
    return f"{property} updated to {value} in main config."


def updateoneormorefacts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    unique = args.get('unique')
    name = args.get('name')
    links = args.get('links')
    relationships = args.get('relationships')
    origin_type = args.get('origin_type')
    created = args.get('created')
    limit_count = args.get('limit_count')
    technique_id = args.get('technique_id')
    trait = args.get('trait')
    source = args.get('source')
    score = args.get('score')
    value = args.get('value')
    collected_by = args.get('collected_by')
    partial_factupdaterequest_updates = assign_params(unique=unique, name=name, links=links, relationships=relationships, origin_type=origin_type, created=created,
                                                      limit_count=limit_count, technique_id=technique_id, trait=trait, source=source, score=score, value=value, collected_by=collected_by)
    criteria_unique = args.get('criteria_unique')
    criteria_name = args.get('criteria_name')
    criteria_links = args.get('criteria_links')
    criteria_relationships = args.get('criteria_relationships')
    criteria_origin_type = args.get('criteria_origin_type')
    criteria_created = args.get('criteria_created')
    criteria_limit_count = args.get('criteria_limit_count')
    criteria_technique_id = args.get('criteria_technique_id')
    criteria_trait = args.get('criteria_trait')
    criteria_source = args.get('criteria_source')
    criteria_score = args.get('criteria_score')
    criteria_value = args.get('criteria_value')
    criteria_collected_by = args.get('criteria_collected_by')
    partial_factupdaterequest_criteria = assign_params(unique=criteria_unique, name=criteria_name, links=criteria_links, relationships=criteria_relationships, origin_type=criteria_origin_type, created=criteria_created,
                                                       limit_count=criteria_limit_count, technique_id=criteria_technique_id, trait=criteria_trait, source=criteria_source, score=criteria_score, value=criteria_value, collected_by=criteria_collected_by)

    response = client.updateoneormorefacts_request(partial_factupdaterequest_updates, partial_factupdaterequest_criteria)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Facts',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateoneormorerelationships_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    unique = args.get('unique')
    origin = args.get('origin')
    edge = args.get('edge')
    source = args.get('source')
    score = args.get('score')
    target = args.get('target')
    partial_relationshipupdate_updates = assign_params(unique=unique, origin=origin, edge=edge,
                                                       source=source, score=score, target=target)
    criteria_unique = args.get('criteria_unique')
    criteria_origin = args.get('criteria_origin')
    criteria_edge = args.get('criteria_edge')
    criteria_source = args.get('criteria_source')
    criteria_score = args.get('criteria_score')
    criteria_target = args.get('criteria_target')
    partial_relationshipupdate_criteria = assign_params(unique=criteria_unique, origin=criteria_origin, edge=criteria_edge,
                                                        source=criteria_source, score=criteria_score, target=criteria_target)

    response = client.updateoneormorerelationships_request(
        partial_relationshipupdate_updates, partial_relationshipupdate_criteria)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Relationships',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updatesanexistingability_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ability_id = args.get('ability_id')
    name = args.get('name')
    buckets = argToList(args.get('buckets', []))
    technique_id = args.get('technique_id')
    delete_payload = argToBoolean(args.get('delete_payload', False))
    executors = argToList(args.get('executors', []))
    privilege = args.get('privilege')
    technique_name = args.get('technique_name')
    tactic = args.get('tactic')
    singleton = argToBoolean(args.get('singleton', False))
    plugin = args.get('plugin')
    repeatable = argToBoolean(args.get('repeatable', False))
    description = args.get('description')

    response = client.updatesanexistingability_request(ability_id, name, buckets, technique_id, delete_payload, executors,
                                                       privilege, technique_name, tactic, singleton, plugin, repeatable, description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Abilities',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def updateschedule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    schedule_id = args.get('schedule_id')
    schedule = args.get('schedule')
    task_obfuscator = args.get('task_obfuscator')
    task_autonomous = args.get('task_autonomous')
    task_state = args.get('task_state')
    schedule_task = assign_params(obfuscator=task_obfuscator, autonomous=task_autonomous, state=task_state)

    response = client.updateschedule_request(schedule_id, schedule, schedule_task)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Schedules',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def updatethespecifiedlinkwithinanoperation_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')
    link_id = args.get('link_id')
    command = args.get('command')
    status = int(args.get('status', -3))

    response = client.updatethespecifiedlinkwithinanoperation_request(operation_id, link_id, command, status)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Links',
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
        client: Client = Client(urljoin(url), verify_certificate, proxy, headers=headers, auth=None)

        commands = {
            'caldera-create-fact': create_fact_command,
            'caldera-create-fact-source': create_fact_source_command,
            'caldera-create-adversary': createanewadversary_command,
            'caldera-create-agent': createanewagent_command,
            'caldera-create-operation': createanewcalderaoperationrecord_command,
            'caldera-create-objective': createanewobjective_command,
            'caldera-create-relationship': createarelationship_command,
            'caldera-create-ability': createsanewability_command,
            'caldera-create-potential-link': createsapotentiallink_command,
            'caldera-create-schedule': createschedule_command,
            'caldera-delete-agent': deleteanagent_command,
            'caldera-delete-fact-source': deleteanexistingfactsource_command,
            'caldera-delete-operation': deleteanoperationbyoperationid_command,
            'caldera-delete-facts': deleteoneormorefacts_command,
            'caldera-delete-relationships': deleteoneormorerelationships_command,
            'caldera-delete-ability': deletesanability_command,
            'caldera-delete-adversary': deletesanadversary_command,
            'caldera-delete-schedule': deleteschedule_command,
            'caldera-get-abilities': get_api_v2_abilities_command,
            'caldera-get-adversaries': get_api_v2_adversaries_command,
            'caldera-get-agents': get_api_v2_agents_command,
            'caldera-get-config': get_api_v2_config_command,
            'caldera-get-contacts': get_api_v2_contacts_command,
            'caldera-get-deploy-commands': get_api_v2_deploy_commands_command,
            'caldera-get-facts': get_api_v2_facts_command,
            'caldera-get-health': get_api_v2_health_command,
            'caldera-get-obfuscators': get_api_v2_obfuscators_command,
            'caldera-get-objectives': get_api_v2_objectives_command,
            'caldera-get-operations': get_api_v2_operations_command,
            'caldera-get-operations-links': get_api_v2_operations_links_command,
            'caldera-get-operations-links-result': get_api_v2_operations_links_result_command,
            'caldera-get-operations-potential-links': get_api_v2_operations_potentiallinks_command,
            'caldera-get-planners': get_api_v2_planners_command,
            'caldera-get-plugins': get_api_v2_plugins_command,
            'caldera-get-relationships': get_api_v2_relationships_command,
            'caldera-get-schedules': get_api_v2_schedules_command,
            'caldera-get-sources': get_api_v2_sources_command,
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
            'caldera-update-relationships': updateoneormorerelationships_command,
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
        return_error(e)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
