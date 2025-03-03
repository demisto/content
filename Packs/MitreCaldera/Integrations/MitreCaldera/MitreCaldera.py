import demistomock as demisto
from CommonServerPython import *
import urllib3


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def create_fact(self, fact_name, fact_links, fact_relationships, fact_origin_type, fact_limit_count, fact_technique_id,
                    fact_trait, fact_source, fact_score, fact_value):
        data = assign_params(name=fact_name, links=fact_links, relationships=fact_relationships, origin_type=fact_origin_type,
                             limit_count=fact_limit_count, technique_id=fact_technique_id, trait=fact_trait,
                             source=fact_source, score=fact_score, value=fact_value)
        headers = self._headers

        response = self._http_request('post', 'api/v2/facts', json_data=data, headers=headers)

        return response

    def create_fact_source(self, source_name, source_adjustments, source_relationships, source_rules,
                           source_facts, source_plugin):
        data = assign_params(name=source_name, adjustments=source_adjustments, relationships=source_relationships,
                             rules=source_rules, facts=source_facts, plugin=source_plugin)
        headers = self._headers

        response = self._http_request('post', 'api/v2/sources', json_data=data, headers=headers)

        return response

    def create_adversary(self, adversary_name, adversary_tags, adversary_objective, adversary_atomic_ordering,
                         adversary_plugin, adversary_description):
        data = assign_params(name=adversary_name, tags=adversary_tags, objective=adversary_objective,
                             atomic_ordering=adversary_atomic_ordering, plugin=adversary_plugin,
                             description=adversary_description)
        headers = self._headers

        response = self._http_request('post', 'api/v2/adversaries', json_data=data, headers=headers)

        return response

    def create_agent(self, agent_watchdog, agent_deadman_enabled, agent_ppid, agent_pid, agent_proxy_receivers,
                     agent_origin_link_id, agent_available_contacts, agent_platform, agent_host, agent_group,
                     agent_location, agent_display_name, agent_upstream_dest, agent_host_ip_addrs, agent_sleep_max,
                     agent_architecture, agent_sleep_min, agent_server, agent_contact, agent_executors, agent_privilege,
                     agent_username, agent_trusted, agent_proxy_chain, agent_paw, agent_exe_name):
        data = assign_params(watchdog=agent_watchdog, deadman_enabled=agent_deadman_enabled, ppid=agent_ppid, pid=agent_pid,
                             proxy_receivers=agent_proxy_receivers, origin_link_id=agent_origin_link_id,
                             available_contacts=agent_available_contacts, platform=agent_platform, host=agent_host,
                             group=agent_group, location=agent_location, display_name=agent_display_name,
                             upstream_dest=agent_upstream_dest, host_ip_addrs=agent_host_ip_addrs, sleep_max=agent_sleep_max,
                             architecture=agent_architecture, sleep_min=agent_sleep_min, server=agent_server,
                             contact=agent_contact, executors=agent_executors, privilege=agent_privilege,
                             username=agent_username, trusted=agent_trusted, proxy_chain=agent_proxy_chain,
                             paw=agent_paw, exe_name=agent_exe_name)
        headers = self._headers

        response = self._http_request('post', 'api/v2/agents', json_data=data, headers=headers)

        return response

    def create_operation(self, name, autonomous, objective, visibility, state, group, host_group, planner, obfuscator,
                         use_learning_parsers, source, jitter, adversary, auto_close):
        data = assign_params(name=name, autonomous=autonomous, objective=objective, visibility=visibility, state=state,
                             group=group, host_group=host_group, planner=planner, obfuscator=obfuscator,
                             use_learning_parsers=use_learning_parsers, source=source, jitter=jitter, adversary=adversary,
                             auto_close=auto_close)
        headers = self._headers

        response = self._http_request('post', 'api/v2/operations', json_data=data, headers=headers)

        return response

    def create_objective(self, objective_name, objective_goals, objective_description):
        data = assign_params(name=objective_name, goals=objective_goals, description=objective_description)
        headers = self._headers

        response = self._http_request('post', 'api/v2/objectives', json_data=data, headers=headers)

        return response

    def create_relationship(self, relationship_unique, relationship_origin, relationship_edge, relationship_source,
                            relationship_score, relationship_target):
        data = assign_params(unique=relationship_unique, origin=relationship_origin, edge=relationship_edge,
                             source=relationship_source, score=relationship_score, target=relationship_target)
        headers = self._headers

        response = self._http_request('post', 'api/v2/relationships', json_data=data, headers=headers)

        return response

    def create_ability(self, ability_ability_id, ability_name, ability_buckets, ability_technique_id, ability_delete_payload,
                       ability_executors, ability_privilege, ability_requirements, ability_plugin, ability_access,
                       ability_tactic, ability_additional_info, ability_singleton, ability_technique_name,
                       ability_repeatable, ability_description):
        data = assign_params(ability_id=ability_ability_id, name=ability_name, buckets=ability_buckets,
                             technique_id=ability_technique_id, delete_payload=ability_delete_payload,
                             executors=ability_executors, privilege=ability_privilege, requirements=ability_requirements,
                             plugin=ability_plugin, access=ability_access, tactic=ability_tactic,
                             additional_info=ability_additional_info, singleton=ability_singleton,
                             technique_name=ability_technique_name, repeatable=ability_repeatable,
                             description=ability_description)
        headers = self._headers

        response = self._http_request('post', 'api/v2/abilities', json_data=data, headers=headers)

        return response

    def create_potentiallink(self, id_, link_relationships, link_id, link_collect, link_pid, link_visibility, link_finish,
                             link_pin, link_jitter, link_agent_reported_time, link_deadman, link_used, link_host,
                             link_ability, link_status, link_score, link_command, link_unique, link_cleanup, link_decide,
                             link_facts, link_executor, link_paw, link_output):
        data = assign_params(relationships=link_relationships, id=link_id, collect=link_collect, pid=link_pid,
                             visibility=link_visibility, finish=link_finish, pin=link_pin, jitter=link_jitter,
                             agent_reported_time=link_agent_reported_time, deadman=link_deadman, used=link_used,
                             host=link_host, ability=link_ability, status=link_status, score=link_score, command=link_command,
                             unique=link_unique, cleanup=link_cleanup, decide=link_decide, facts=link_facts,
                             executor=link_executor, paw=link_paw, output=link_output)
        headers = self._headers

        response = self._http_request('post', f'api/v2/operations/{id_}/potential-links', json_data=data, headers=headers)

        return response

    def create_schedule(self, schedule_schedule, schedule_task, schedule_id):
        data = assign_params(schedule=schedule_schedule, task=schedule_task, id=schedule_id)
        headers = self._headers

        response = self._http_request('post', 'api/v2/schedules', json_data=data, headers=headers)

        return response

    def delete_agent(self, paw):
        headers = self._headers

        response = self._http_request(
            'delete',
            f'api/v2/agents/{paw}',
            headers=headers,
            resp_type='response',
            ok_codes=[200, 204])

        return response

    def delete_fact_source(self, id_):
        headers = self._headers

        response = self._http_request(
            'delete',
            f'api/v2/sources/{id_}',
            headers=headers,
            resp_type='response')

        return response

    def delete_operation(self, id_):
        headers = self._headers

        response = self._http_request(
            'delete',
            f'api/v2/operations/{id_}',
            headers=headers,
            resp_type='response',
            ok_codes=[200, 204])
        return response

    def delete_facts(self, fact_unique, fact_name, fact_links, fact_relationships, fact_origin_type, fact_created,
                     fact_limit_count, fact_technique_id, fact_trait, fact_source, fact_score, fact_value, fact_collected_by):
        data = assign_params(unique=fact_unique, name=fact_name, links=fact_links, relationships=fact_relationships,
                             origin_type=fact_origin_type, created=fact_created, limit_count=fact_limit_count,
                             technique_id=fact_technique_id, trait=fact_trait, source=fact_source, score=fact_score,
                             value=fact_value, collected_by=fact_collected_by)
        headers = self._headers

        response = self._http_request('delete', 'api/v2/facts', json_data=data, headers=headers)

        return response

    def delete_relationships(self, relationship_unique, relationship_origin, relationship_edge, relationship_source,
                             relationship_score, relationship_target):
        data = assign_params(unique=relationship_unique, origin=relationship_origin, edge=relationship_edge,
                             source=relationship_source, score=relationship_score, target=relationship_target)
        headers = self._headers

        response = self._http_request('delete', 'api/v2/relationships', json_data=data, headers=headers)

        return response

    def delete_ability(self, ability_id):
        headers = self._headers

        response = self._http_request(
            'delete',
            f'api/v2/abilities/{ability_id}',
            headers=headers,
            resp_type='response',
            ok_codes=[200, 204])

        return response

    def delete_adversary(self, adversary_id):
        headers = self._headers

        response = self._http_request(
            'delete',
            f'api/v2/adversaries/{adversary_id}',
            headers=headers,
            ok_codes=[200, 204],
            resp_type='response')

        return response

    def delete_schedule(self, id_):
        headers = self._headers

        response = self._http_request(
            'delete',
            f'api/v2/schedules/{id_}',
            headers=headers,
            ok_codes=[200, 204],
            resp_type='response')

        return response

    def get_abilities(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/abilities', params=params, headers=headers)

        return response

    def get_abilities_by_ability_id(self, ability_id, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/abilities/{ability_id}', params=params, headers=headers)

        return response

    def get_adversaries(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/adversaries', params=params, headers=headers)

        return response

    def get_adversaries_by_adversary_id(self, adversary_id, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/adversaries/{adversary_id}', params=params, headers=headers)

        return response

    def get_agents_request(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/agents', params=params, headers=headers)

        return response

    def get_agents_by_paw(self, paw, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/agents/{paw}', params=params, headers=headers)

        return response

    def get_config_by_name(self, name):
        headers = self._headers

        response = self._http_request('get', f'api/v2/config/{name}', headers=headers)

        return response

    def get_contacts(self):
        headers = self._headers

        response = self._http_request('get', 'api/v2/contacts', headers=headers)

        return response

    def get_contacts_by_name(self, name):
        headers = self._headers

        response = self._http_request('get', f'api/v2/contacts/{name}', headers=headers)

        return response

    def get_deploy_commands(self):
        headers = self._headers

        response = self._http_request('get', 'api/v2/deploy_commands', headers=headers)

        return response

    def get_deploy_commands_by_ability_id(self, ability_id):
        headers = self._headers

        response = self._http_request('get', f'api/v2/deploy_commands/{ability_id}', headers=headers)

        return response

    def get_facts(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/facts', params=params, headers=headers)

        return response

    def get_facts_by_operation_id(self, sort, include, exclude, operation_id):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/facts/{operation_id}', params=params, headers=headers)

        return response

    def get_health(self):
        headers = self._headers

        response = self._http_request('get', 'api/v2/health', headers=headers)

        return response

    def get_obfuscators(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/obfuscators', params=params, headers=headers)

        return response

    def get_obfuscators_by_name(self, name, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/obfuscators/{name}', params=params, headers=headers)

        return response

    def get_objectives(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/objectives', params=params, headers=headers)

        return response

    def get_objectives_by_id(self, id_, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/objectives/{id_}', params=params, headers=headers)

        return response

    def get_operations(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/operations', params=params, headers=headers)

        return response

    def get_operations_by_id(self, id_, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/operations/{id_}', params=params, headers=headers)

        return response

    def get_operations_links(self, id_, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/operations/{id_}/links', params=params, headers=headers)

        return response

    def get_operations_links_by_link_id(self, id_, link_id, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/operations/{id_}/links/{link_id}', params=params, headers=headers)

        return response

    def get_operations_links_result(self, id_, link_id, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/operations/{id_}/links/{link_id}/result', params=params, headers=headers)

        return response

    def get_operations_potentiallinks(self, id_, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/operations/{id_}/potential-links', params=params, headers=headers)

        return response

    def get_operations_potentiallinks_by_paw(self, id_, paw, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/operations/{id_}/potential-links/{paw}', params=params, headers=headers)

        return response

    def get_planners(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/planners', params=params, headers=headers)

        return response

    def get_planners_by_planner_id(self, planner_id, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/planners/{planner_id}', params=params, headers=headers)

        return response

    def get_plugins(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/plugins', params=params, headers=headers)

        return response

    def get_plugins_by_name(self, name, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/plugins/{name}', params=params, headers=headers)

        return response

    def get_relationships(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/relationships', params=params, headers=headers)

        return response

    def get_relationships_by_operation_id(self, sort, include, exclude, operation_id):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/relationships/{operation_id}', params=params, headers=headers)

        return response

    def get_schedules(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/schedules', params=params, headers=headers)

        return response

    def get_schedules_by_id(self, id_, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/schedules/{id_}', params=params, headers=headers)

        return response

    def get_sources(self, sort, include, exclude):
        params = assign_params(sort=sort, include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', 'api/v2/sources', params=params, headers=headers)

        return response

    def get_sources_by_id(self, id_, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        headers = self._headers

        response = self._http_request('get', f'api/v2/sources/{id_}', params=params, headers=headers)

        return response

    def get_operation_eventlogs(self, id_, operationoutputrequest_enable_agent_output, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        data = assign_params(enable_agent_output=operationoutputrequest_enable_agent_output)
        headers = self._headers

        response = self._http_request(
            'post', f'api/v2/operations/{id_}/event-logs', params=params, json_data=data, headers=headers)

        return response

    def get_operation_report(self, id_, operationoutputrequest_enable_agent_output, include, exclude):
        params = assign_params(include=include, exclude=exclude)
        data = assign_params(enable_agent_output=operationoutputrequest_enable_agent_output)
        headers = self._headers

        response = self._http_request('post', f'api/v2/operations/{id_}/report', params=params, json_data=data, headers=headers)

        return response

    def replace_ability(self, ability_id, ability_name, ability_buckets, ability_technique_id, ability_delete_payload,
                        ability_executors, ability_privilege, ability_requirements, ability_plugin, ability_access,
                        ability_tactic, ability_additional_info, ability_singleton, ability_technique_name,
                        ability_repeatable, ability_description):
        data = assign_params(ability_id=ability_id, name=ability_name, buckets=ability_buckets,
                             technique_id=ability_technique_id, delete_payload=ability_delete_payload,
                             executors=ability_executors, privilege=ability_privilege, requirements=ability_requirements,
                             plugin=ability_plugin, access=ability_access, tactic=ability_tactic,
                             additional_info=ability_additional_info, singleton=ability_singleton,
                             technique_name=ability_technique_name, repeatable=ability_repeatable,
                             description=ability_description)
        headers = self._headers

        response = self._http_request('put', f'api/v2/abilities/{ability_id}', json_data=data, headers=headers)

        return response

    def replace_schedule(self, id_, partial_schedule_schedule, partial_schedule_task):
        data = assign_params(schedule=partial_schedule_schedule, task=partial_schedule_task)
        headers = self._headers

        response = self._http_request('put', f'api/v2/schedules/{id_}', json_data=data, headers=headers)

        return response

    def update_agent_config(self, watchdog, sleep_min, deployments, deadman_abilities, untrusted_timer, bootstrap_abilities,
                            sleep_max, implant_name):
        data = assign_params(watchdog=watchdog, sleep_min=sleep_min, deployments=deployments,
                             deadman_abilities=deadman_abilities, untrusted_timer=untrusted_timer,
                             bootstrap_abilities=bootstrap_abilities, sleep_max=sleep_max, implant_name=implant_name)
        headers = self._headers

        response = self._http_request('patch', 'api/v2/config/agents', json_data=data, headers=headers)

        return response

    def update_adversary(self, adversary_id, adversaryname, adversarytags, adversaryobjective,
                         adversaryhas_repeatable_abilities, adversaryatomic_ordering, adversaryplugin, adversarydescription):
        data = assign_params(name=adversaryname, tags=adversarytags, objective=adversaryobjective,
                             has_repeatable_abilities=adversaryhas_repeatable_abilities,
                             atomic_ordering=adversaryatomic_ordering, plugin=adversaryplugin,
                             description=adversarydescription)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/adversaries/{adversary_id}', json_data=data, headers=headers)

        return response

    def update_agent(self, paw, watchdog, sleep_min, trusted, sleep_max, pending_contact, group):
        data = assign_params(watchdog=watchdog, sleep_min=sleep_min, trusted=trusted,
                             sleep_max=sleep_max, pending_contact=pending_contact, group=group)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/agents/{paw}', json_data=data, headers=headers)

        return response

    def update_fact_source(self, id_, source_name, source_adjustments, source_relationships, source_id, source_rules,
                           source_facts, source_plugin):
        data = assign_params(name=source_name, adjustments=source_adjustments, relationships=source_relationships,
                             id=source_id, rules=source_rules, facts=source_facts, plugin=source_plugin)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/sources/{id_}', json_data=data, headers=headers)

        return response

    def update_objective(self, id_, name, goals, description):
        data = assign_params(name=name, goals=goals,
                             description=description)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/objectives/{id_}', json_data=data, headers=headers)

        return response

    def update_operation_fileds(self, id_, obfuscator, autonomous, state):
        data = assign_params(obfuscator=obfuscator,
                             autonomous=autonomous, state=state)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/operations/{id_}', json_data=data, headers=headers)

        return response

    def update_main_config(self, property, value):
        data = assign_params(prop=property, value=value)
        headers = self._headers

        response = self._http_request(
            'patch',
            'api/v2/config/main',
            json_data=data,
            headers=headers,
            ok_codes=[200, 204],
            resp_type='response')

        return response

    def update_facts(self, partial_factupdaterequest_updates, partial_factupdaterequest_criteria):
        data = assign_params(updates=partial_factupdaterequest_updates, criteria=partial_factupdaterequest_criteria)
        headers = self._headers

        response = self._http_request('patch', 'api/v2/facts', json_data=data, headers=headers)

        return response

    def update_relationships(self, partial_relationshipupdate_updates, partial_relationshipupdate_criteria):
        data = assign_params(updates=partial_relationshipupdate_updates, criteria=partial_relationshipupdate_criteria)
        headers = self._headers

        response = self._http_request('patch', 'api/v2/relationships', json_data=data, headers=headers)

        return response

    def update_ability(self, ability_id, name, buckets, technique_id, delete_payload, executors, privilege, technique_name,
                       tactic, singleton, plugin, repeatable, description):
        data = assign_params(name=name, buckets=buckets, technique_id=technique_id, delete_payload=delete_payload,
                             executors=executors, privilege=privilege, technique_name=technique_name, tactic=tactic,
                             singleton=singleton, plugin=plugin, repeatable=repeatable, description=description)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/abilities/{ability_id}', json_data=data, headers=headers)

        return response

    def update_schedule(self, id_, schedule_schedule, schedule_task):
        data = assign_params(schedule=schedule_schedule, task=schedule_task)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/schedules/{id_}', json_data=data, headers=headers)

        return response

    def update_operation_link(self, id_, link_id, command, status):
        data = assign_params(command=command, status=status)
        headers = self._headers

        response = self._http_request('patch', f'api/v2/operations/{id_}/links/{link_id}', json_data=data, headers=headers)

        return response


def create_fact_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    fact_name = args.get('fact_name')
    fact_links = argToList(args.get('fact_links', []))
    fact_relationships = argToList(args.get('fact_relationships', []))
    fact_origin_type = args.get('fact_origin_type')
    fact_limit_count = arg_to_number(args.get('fact_limit_count'), "0")
    fact_technique_id = args.get('fact_technique_id')
    fact_trait = args.get('fact_trait')
    fact_source = args.get('fact_source')
    fact_score = arg_to_number(args.get('fact_score'))
    fact_value = args.get('fact_value')

    response = client.create_fact(fact_name, fact_links, fact_relationships, fact_origin_type, fact_limit_count,
                                  fact_technique_id, fact_trait, fact_source, fact_score, fact_value)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Facts',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_fact_source_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    try:
        adjustments = json.loads(args.get('adjustments', []))
    except Exception:
        adjustments = []
    relationships = json.loads(args.get('relationships', []))
    rules = json.loads(args.get('rules', []))
    facts = json.loads(args.get('facts', []))
    plugin = args.get('plugin')

    response = client.create_fact_source(name, adjustments, relationships, rules, facts, plugin)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Sources',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_adversary_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    tags = argToList(args.get('tags', []))
    objective = args.get('objective')
    atomic_ordering = argToList(args.get('adversary_atomic_ordering', []))
    plugin = args.get('plugin')
    description = args.get('description')

    response = client.create_adversary(name, tags, objective, atomic_ordering, plugin, description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Adversaries',
        outputs_key_field='adversary_id',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_agent_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    watchdog = arg_to_number(args.get('watchdog', 0))
    deadman_enabled = argToBoolean(args.get('deadman_enabled', False))
    ppid = arg_to_number(args.get('ppid', 0))
    pid = arg_to_number(args.get('pid', 0))
    proxy_receivers = json.loads(args.get('proxy_receivers', "[]"))
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
    proxy_chain = json.loads(args.get('proxy_chain', "[]"))
    paw = args.get('paw')
    exe_name = args.get('exe_name')

    response = client.create_agent(watchdog, deadman_enabled, ppid, pid, proxy_receivers, origin_link_id, available_contacts,
                                   platform, host, group, location, display_name, upstream_dest, host_ip_addrs, sleep_max,
                                   architecture, sleep_min, server, contact, exeutors, privilege, username, trusted,
                                   proxy_chain, paw, exe_name)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Agents',
        outputs_key_field='paw',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_operation_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    autonomous = 1 if args.get('autonomous', "autonomous") == "autonomous" else 0
    objective_id = args.get('objective_id')
    objective = assign_params(id=objective_id)
    visibility = arg_to_number(args.get('visibility', "51"))
    state = args.get('state', "running")
    group = args.get('group')
    host_group = argToList(args.get('host_group', []))
    planner_id = args.get('planner_id')
    planner = assign_params(id=planner_id)
    obfuscator = args.get('obfuscator')
    use_learning_parsers = argToBoolean(args.get('use_learning_parsers', False))
    source_id = args.get('source_id')
    source = assign_params(id=source_id)
    jitter = args.get('jitter', "2/8")
    adversary_id = args.get('adversary_id')
    adversary = assign_params(adversary_id=adversary_id)
    auto_close = argToBoolean(args.get('auto_close', False))

    response = client.create_operation(name, autonomous, objective, visibility, state, group, host_group, planner, obfuscator,
                                       use_learning_parsers, source, jitter, adversary, auto_close)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Operations',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_objective_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    try:
        goals = json.loads(args.get('goals', []))
    except Exception:
        goals = []
    description = args.get('description')

    response = client.create_objective(
        name, goals, description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Objectives',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_relationship_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    relationship_source = assign_params(unique=relationship_source_unique, name=relationship_source_name,
                                        links=relationship_source_links, relationships=relationship_source_relationships,
                                        origin_type=relationship_source_origin_type, created=relationship_source_created,
                                        limit_count=relationship_source_limit_count,
                                        technique_id=relationship_source_technique_id, trait=relationship_source_trait,
                                        source=relationship_source_source, score=relationship_source_score,
                                        value=relationship_source_value, collected_by=relationship_source_collected_by)
    relationship_score = args.get('relationship_score')
    relationship_target = args.get('relationship_target')

    response = client.create_relationship(relationship_unique, relationship_origin, relationship_edge, relationship_source,
                                          relationship_score, relationship_target)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Relationship',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_ability_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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

    response = client.create_ability(ability_ability_id, ability_name, ability_buckets, ability_technique_id,
                                     ability_delete_payload, ability_executors, ability_privilege, ability_requirements,
                                     ability_plugin, ability_access, ability_tactic, ability_additional_info,
                                     ability_singleton, ability_technique_name, ability_repeatable, ability_description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Abilities',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_potentiallink_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    link_ability = assign_params(ability_id=link_ability_ability_id, name=link_ability_name, buckets=link_ability_buckets,
                                 technique_id=link_ability_technique_id, delete_payload=link_ability_delete_payload,
                                 executors=link_ability_executors, privilege=link_ability_privilege,
                                 requirements=link_ability_requirements, plugin=link_ability_plugin,
                                 access=link_ability_access, tactic=link_ability_tactic,
                                 additional_info=link_ability_additional_info, singleton=link_ability_singleton,
                                 technique_name=link_ability_technique_name, repeatable=link_ability_repeatable,
                                 description=link_ability_description)
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
    link_executor = assign_params(name=link_executor_name, cleanup=link_executor_cleanup, platform=link_executor_platform,
                                  language=link_executor_language, uploads=link_executor_uploads,
                                  variations=link_executor_variations, build_target=link_executor_build_target,
                                  payloads=link_executor_payloads, timeout=link_executor_timeout,
                                  parsers=link_executor_parsers, command=link_executor_command,
                                  additional_info=link_executor_additional_info, code=link_executor_code)
    link_paw = args.get('link_paw')
    link_output = args.get('link_output')

    response = client.create_potentiallink(operation_id, link_relationships, link_id, link_collect, link_pid, link_visibility,
                                           link_finish, link_pin, link_jitter, link_agent_reported_time, link_deadman,
                                           link_used, link_host, link_ability, link_status, link_score, link_command,
                                           link_unique, link_cleanup, link_decide, link_facts, link_executor, link_paw,
                                           link_output)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Link',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_schedule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    schedule_task = assign_params(name=schedule_task_name, autonomous=schedule_task_autonomous, id=schedule_task_id,
                                  objective=schedule_task_objective, visibility=schedule_task_visibility,
                                  state=schedule_task_state, group=schedule_task_group, host_group=schedule_task_host_group,
                                  planner=schedule_task_planner, obfuscator=schedule_task_obfuscator,
                                  chain=schedule_task_chain, use_learning_parsers=schedule_task_use_learning_parsers,
                                  source=schedule_task_source, jitter=schedule_task_jitter, start=schedule_task_start,
                                  adversary=schedule_task_adversary, auto_close=schedule_task_auto_close)
    schedule_id = args.get('schedule_id')

    response = client.create_schedule(schedule_schedule, schedule_task, schedule_id)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Schedule',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_agent_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    paw = args.get('paw')

    client.delete_agent(paw)
    command_results = CommandResults(
        readable_output=f"Agent with paw {paw} was deleted successfully."
    )
    return command_results


def delete_fact_source_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    fact_source_id = args.get('fact_source_id')

    client.delete_fact_source(fact_source_id)
    command_results = CommandResults(
        readable_output=f"Fact Source with ID {fact_source_id} was deleted successfully."
    )
    return command_results


def delete_operation_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')

    client.delete_operation(operation_id)

    command_results = CommandResults(
        readable_output=f"Operation with Id {operation_id} was deleted successfully."
    )
    return command_results


def delete_facts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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

    response = client.delete_facts(fact_unique, fact_name, fact_links, fact_relationships, fact_origin_type, fact_created,
                                   fact_limit_count, fact_technique_id, fact_trait, fact_source, fact_score, fact_value,
                                   fact_collected_by)
    output = response.get('removed')
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Facts',
        outputs_key_field='',
        outputs=output,
        raw_response=response
    )

    return command_results


def delete_relationships_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    relationship_source = assign_params(unique=relationship_source_unique, name=relationship_source_name,
                                        links=relationship_source_links, relationships=relationship_source_relationships,
                                        origin_type=relationship_source_origin_type, created=relationship_source_created,
                                        limit_count=relationship_source_limit_count,
                                        technique_id=relationship_source_technique_id, trait=relationship_source_trait,
                                        source=relationship_source_source, score=relationship_source_score,
                                        value=relationship_source_value, collected_by=relationship_source_collected_by)
    relationship_score = args.get('relationship_score')
    relationship_target = args.get('relationship_target')

    response = client.delete_relationships(relationship_unique, relationship_origin, relationship_edge, relationship_source,
                                           relationship_score, relationship_target)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Relationships',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_ability_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ability_id = args.get('ability_id')

    client.delete_ability(ability_id)
    command_results = CommandResults(
        readable_output=f"Ability with ID {ability_id} was deleted successfully."
    )
    return command_results


def delete_adversary_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    adversary_id = args.get('adversary_id')

    client.delete_adversary(adversary_id)
    command_results = CommandResults(
        readable_output=f"Adversary with ID {adversary_id} was deleted successfully."
    )
    return command_results


def delete_schedule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    schedule_id = args.get('schedule_id')

    client.delete_schedule(schedule_id)

    command_results = CommandResults(
        readable_output=f"Schedule with ID {schedule_id} deleted successfully."
    )
    return command_results


def get_abilities_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ability_id = args.get('ability_id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))
    if ability_id:
        response = client.get_abilities_by_ability_id(ability_id, include, exclude)
    else:
        response = client.get_abilities(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Abilities',
        outputs_key_field='ability_id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_adversaries_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    adversary_id = args.get('adversary_id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if adversary_id:
        response = client.get_adversaries_by_adversary_id(adversary_id, include, exclude)
    else:
        response = client.get_adversaries(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Adversaries',
        outputs_key_field='adversary_id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_agents_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    paw = args.get('paw')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if paw:
        response = client.get_agents_by_paw(paw, include, exclude)
    else:
        response = client.get_agents_request(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Agents',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_config_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')

    response = client.get_config_by_name(name)
    response['name'] = name
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Config',
        outputs_key_field='Name',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_contacts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    if name:
        response = client.get_contacts_by_name(name)
    else:
        response = client.get_contacts()
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Contacts',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_deploy_commands_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ability_id = args.get('ability_id')

    if ability_id:
        response = client.get_deploy_commands_by_ability_id(ability_id)
    else:
        response = client.get_deploy_commands()
    output = response.get('abilities')
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.DeployCommands',
        outputs_key_field=['command', 'name'],
        outputs=output,
        raw_response=response
    )

    return command_results


def get_facts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))
    operation_id = args.get('operation_id')

    if operation_id:
        response = client.get_facts_by_operation_id(sort, include, exclude, operation_id)
    else:
        response = client.get_facts(sort, include, exclude)
    output = response.get('found')
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Facts',
        outputs_key_field='unique',
        outputs=output,
        raw_response=output
    )

    return command_results


def get_health_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    response = client.get_health()
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.CalderaInfo',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_obfuscators_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if name:
        response = client.get_obfuscators_by_name(name, include, exclude)
    else:
        response = client.get_obfuscators(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Obfuscators',
        outputs_key_field='name',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_objectives_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    objective_id = args.get('id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if objective_id:
        response = client.get_objectives_by_id(objective_id, include, exclude)
    else:
        response = client.get_objectives(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Objectives',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_last_fetch_time(last_run, params):
    last_fetch = last_run.get("latest_operation_found")
    if not last_fetch:
        demisto.debug("[Caldera] First run")
        # handle first time fetch
        first_fetch = f"{params.get('first_fetch') or '1 days'} ago"
        default_fetch_datetime = dateparser.parse(first_fetch)
        assert default_fetch_datetime is not None, f"failed parsing {first_fetch}"
        last_fetch = str(default_fetch_datetime.isoformat(timespec="milliseconds")) + "Z"

    demisto.debug(f"[Caldera] last_fetch: {last_fetch}")
    return last_fetch


def filter_operations(operations: list, params: Dict[str, str], last_fetch: str) -> list:
    """
    Filters a list of operations to include only those that contain the specified client name.

    Args:
        operations (list): A list of dictionaries, where each dictionary represents an operation.
        params (dict): The integration parameters.
        last_fetch (str): The last fetch time.

    Returns:
        list: A list of dictionaries containing only the operations after last fetch time and where the client's name, from the
        integration's parameters, is present in the "name" field.
    """
    parsed_last_fetch = dateparser.parse(last_fetch)
    if not parsed_last_fetch:
        raise ValueError(f"Failed parsing {last_fetch}")

    filtered_operations = [
        operation for operation in operations
        if (start_date := dateparser.parse(operation.get("start"))) and start_date > parsed_last_fetch
    ]

    if client_name := params.get("client_name"):
        filtered_operations = [operation for operation in filtered_operations if client_name in operation.get("name")]

    return filtered_operations


def operation_to_incident(operation: dict, operation_date: str) -> dict:
    """
    Converts an operation dictionary into an incident dictionary.

    Args:
        operation (dict): A dictionary containing details of the operation.
        operation_date (str): The date when the operation occurred.

    Returns:
        dict: A dictionary representing the incident, including the operation's ID, name, and the date it occurred.
    """
    operation_id = operation.get("id")
    operation_name = operation.get("name")
    incident = {
        "name": f"Caldera: {operation_id} {operation_name}",
        "occurred": operation_date,
        "rawJSON": json.dumps(operation),
    }
    return incident


def operations_to_incidents(operations: list, params: Dict[str, str], last_fetch_datetime: str) -> tuple[list, str]:
    """
    Converts a list of operations into a list of incidents and updates the latest incident time.

    Args:
        operations (list): A list of dictionaries, where each dictionary represents an operation.
        params (dict): The integration parameters.
        last_fetch_datetime (str): The datetime string representing the last time incidents were fetched.

    Returns:
        tuple: A tuple containing:
            - A list of dictionaries, each representing an incident.
            - A string representing the latest incident time.
    """
    incidents: List[Dict[str, str]] = []
    latest_incident_time = last_fetch_datetime
    max_fetch = int(params.get("max_fetch", 50))

    # Parse last fetch datetime
    parsed_last_fetch_datetime = dateparser.parse(last_fetch_datetime)
    if not parsed_last_fetch_datetime:
        raise ValueError(f"Failed parsing {last_fetch_datetime}")

    # The count of incidents, so as not to pass the limit
    count_incidents = 0

    for operation in operations:
        operation_datetime = operation.get("start", "")
        parsed_datetime = dateparser.parse(operation_datetime)
        if parsed_datetime:
            operation_datetime = parsed_datetime.isoformat()
            demisto.debug(f"Original: {operation.get('start', '')}, ISO 8601: {operation_datetime}")
        else:
            demisto.debug(f"Failed to parse date: {operation_datetime}")
        incident = operation_to_incident(operation, operation_datetime)
        incidents.append(incident)

        if parsed_datetime and parsed_datetime > parsed_last_fetch_datetime:
            latest_incident_time = operation_datetime

        count_incidents += 1
        if count_incidents == max_fetch:
            break

    return incidents, latest_incident_time


def fetch_incidents(client: Client, args: Dict[str, Any], params: Dict[str, str]):
    sort = args.get('sort')
    last_run: Dict[str, str] = demisto.getLastRun()
    demisto.debug(f"[Caldera] last run: {last_run}")

    last_fetch = get_last_fetch_time(last_run, params)
    demisto.debug(f"[Caldera] last fetch is: {last_fetch}")

    operations = client.get_operations(sort, [], [])

    # Fetch only operations after last fetch time
    operations = filter_operations(operations, params, last_fetch)

    incidents, latest_operation_time = operations_to_incidents(operations, params, last_fetch_datetime=last_fetch)

    demisto.debug(f"[Caldera] Fetched {len(incidents)} incidents")

    demisto.debug(f"[Caldera] next run latest_operation_found: {latest_operation_time}")
    last_run = {
        "latest_operation_found": latest_operation_time,
    }

    return incidents, last_run


def get_operations_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if operation_id:
        response = client.get_operations_by_id(operation_id, include, exclude)
    else:
        response = client.get_operations(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Operations',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_operation_links_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')
    link_id = args.get('link_id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if link_id:
        response = client.get_operations_links_by_link_id(operation_id, link_id, include, exclude)
    else:
        response = client.get_operations_links(operation_id, sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.OperationLinks',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_operation_links_result_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')
    link_id = args.get('link_id')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_operations_links_result(operation_id, link_id, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.OperationLinks',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_operation_potentiallinks_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))
    paw = args.get('paw')

    if paw:
        response = client.get_operations_potentiallinks_by_paw(operation_id, paw, include, exclude)
    else:
        response = client.get_operations_potentiallinks(operation_id, sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.OperationLinks',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_planners_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    planner_id = args.get('planner_id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if planner_id:
        response = client.get_planners_by_planner_id(planner_id, include, exclude)
    else:
        response = client.get_planners(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Planners',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_plugins_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if name:
        response = client.get_plugins_by_name(name, include, exclude)
    else:
        response = client.get_plugins(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Plugins',
        outputs_key_field='name',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_relationships_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if operation_id:
        response = client.get_relationships_by_operation_id(sort, include, exclude, operation_id)
    else:
        response = client.get_relationships(sort, include, exclude)
    output = response.get('found')
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Relationships',
        outputs_key_field='unique',
        outputs=output,
        raw_response=response
    )

    return command_results


def get_schedules_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    schedule_id = args.get('schedule_id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if schedule_id:
        response = client.get_schedules_by_id(schedule_id, include, exclude)
    else:
        response = client.get_schedules(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Schedules',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_sources_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    source_id = args.get('source_id')
    sort = args.get('sort')
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    if source_id:
        response = client.get_sources_by_id(source_id, include, exclude)
    else:
        response = client.get_sources(sort, include, exclude)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Sources',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_operation_eventlogs_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')
    enable_agent_output = argToBoolean(args.get('enable_agent_output', False))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_operation_eventlogs(operation_id, enable_agent_output, include, exclude)
    output = {
        'id': operation_id,
        'EventLogs': response
    }
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Operations',
        outputs_key_field='operation_id',
        outputs=output,
        raw_response=response
    )

    return command_results


def get_operation_report_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')
    enable_agent_output = argToBoolean(args.get('enable_agent_output', False))
    include = argToList(args.get('include', []))
    exclude = argToList(args.get('exclude', []))

    response = client.get_operation_report(operation_id, enable_agent_output, include, exclude)
    output = {
        'id': operation_id,
        'OperationReport': response
    }
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Operations',
        outputs_key_field='operation_id',
        outputs=output,
        raw_response=response
    )

    return command_results


def replace_ability_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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

    response = client.replace_ability(ability_id, ability_name, ability_buckets, ability_technique_id, ability_delete_payload,
                                      ability_executors, ability_privilege, ability_requirements, ability_plugin,
                                      ability_access, ability_tactic, ability_additional_info, ability_singleton,
                                      ability_technique_name, ability_repeatable, ability_description)
    response['id'] = ability_id
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Abilities',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def replace_schedule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    schedule_id = args.get('schedule_id')
    partial_schedule_schedule = args.get('partial_schedule_schedule')
    partial_schedule_task_name = args.get('partial_schedule_task_name')
    partial_schedule_task_autonomous = args.get('partial_schedule_task_autonomous')
    partial_schedule_task_id = args.get('partial_schedule_task_id')
    partial_schedule_task_objective = args.get('partial_schedule_task_objective')
    partial_schedule_task_visibility = args.get('partial_schedule_task_visibility')
    partial_schedule_task_state = args.get('partial_schedule_task_state')
    partial_schedule_task_group = args.get('partial_schedule_task_group')
    partial_schedule_task_host_group = args.get('partial_schedule_task_host_group')
    partial_schedule_task_planner = args.get('partial_schedule_task_planner')
    partial_schedule_task_obfuscator = args.get('partial_schedule_task_obfuscator')
    partial_schedule_task_chain = args.get('partial_schedule_task_chain')
    partial_schedule_task_use_learning_parsers = argToBoolean(args.get('partial_schedule_task_use_learning_parsers', False))
    partial_schedule_task_source = args.get('partial_schedule_task_source')
    partial_schedule_task_jitter = args.get('partial_schedule_task_jitter')
    partial_schedule_task_start = args.get('partial_schedule_task_start')
    partial_schedule_task_adversary = args.get('partial_schedule_task_adversary')
    partial_schedule_task_auto_close = argToBoolean(args.get('partial_schedule_task_auto_close', False))
    partial_schedule_task = assign_params(name=partial_schedule_task_name, autonomous=partial_schedule_task_autonomous,
                                          id=partial_schedule_task_id, objective=partial_schedule_task_objective,
                                          visibility=partial_schedule_task_visibility, state=partial_schedule_task_state,
                                          group=partial_schedule_task_group, host_group=partial_schedule_task_host_group,
                                          planner=partial_schedule_task_planner, obfuscator=partial_schedule_task_obfuscator,
                                          chain=partial_schedule_task_chain,
                                          use_learning_parsers=partial_schedule_task_use_learning_parsers,
                                          source=partial_schedule_task_source, jitter=partial_schedule_task_jitter,
                                          start=partial_schedule_task_start, adversary=partial_schedule_task_adversary,
                                          auto_close=partial_schedule_task_auto_close)

    response = client.replace_schedule(schedule_id, partial_schedule_schedule, partial_schedule_task)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Schedules',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_agent_config_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    watchdog = args.get('watchdog')
    sleep_min = args.get('sleep_min')
    deployments = argToList(args.get('deployments', []))
    deadman_abilities = argToList(args.get('deadman_abilities', []))
    untrusted_timer = args.get('untrusted_timer')
    bootstrap_abilities = argToList(args.get('bootstrap_abilities', []))
    sleep_max = args.get('sleep_max')
    implant_name = args.get('implant_name')

    response = client.update_agent_config(watchdog, sleep_min, deployments, deadman_abilities,
                                          untrusted_timer, bootstrap_abilities, sleep_max, implant_name)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.AgentConfig',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_adversary_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    adversary_id = args.get('adversary_id')
    adversaryname = args.get('adversaryname')
    adversarytags = argToList(args.get('adversarytags', []))
    adversaryobjective = args.get('adversaryobjective')
    adversaryhas_repeatable_abilities = argToBoolean(args.get('adversaryhas_repeatable_abilities', False))
    adversaryatomic_ordering = argToList(args.get('adversaryatomic_ordering', []))
    adversaryplugin = args.get('adversaryplugin')
    adversarydescription = args.get('adversarydescription')

    response = client.update_adversary(adversary_id, adversaryname, adversarytags, adversaryobjective,
                                       adversaryhas_repeatable_abilities, adversaryatomic_ordering, adversaryplugin,
                                       adversarydescription)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Adversaries',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_agent_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    paw = args.get('paw')
    watchdog = args.get('watchdog')
    sleep_min = args.get('sleep_min')
    trusted = argToBoolean(args.get('trusted', False))
    sleep_max = args.get('sleep_max')
    pending_contact = args.get('pending_contact')
    group = args.get('group')

    response = client.update_agent(paw, watchdog, sleep_min, trusted, sleep_max, pending_contact, group)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Agents',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_fact_source_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    fact_source_id = args.get('fact_source_id')
    source_name = args.get('source_name')
    source_adjustments = argToList(args.get('source_adjustments', []))
    source_relationships = argToList(args.get('source_relationships', []))
    source_id = args.get('source_id')
    source_rules = argToList(args.get('source_rules', []))
    source_facts = argToList(args.get('source_facts', []))
    source_plugin = args.get('source_plugin')

    response = client.update_fact_source(fact_source_id, source_name, source_adjustments, source_relationships, source_id,
                                         source_rules, source_facts, source_plugin)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Sources',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_objective_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    objective_id = args.get('objective_id')
    name = args.get('name')
    goals = argToList(args.get('goals', []))
    description = args.get('description')

    response = client.update_objective(
        objective_id, name, goals, description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Objectives',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_operation_fields_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')
    obfuscator = args.get('obfuscator')
    autonomous = args.get('autonomous')
    state = args.get('state')

    response = client.update_operation_fileds(
        operation_id, obfuscator, autonomous, state)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Operations',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_main_config_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    property = args.get('property')
    value = args.get('value')

    client.update_main_config(property, value)
    command_results = CommandResults(
        readable_output=f"{property} updated to {value} in main config."
    )
    return command_results


def update_facts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    partial_factupdaterequest_updates = assign_params(unique=unique, name=name, links=links, relationships=relationships,
                                                      origin_type=origin_type, created=created, limit_count=limit_count,
                                                      technique_id=technique_id, trait=trait, source=source, score=score,
                                                      value=value, collected_by=collected_by)
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
    partial_factupdaterequest_criteria = assign_params(unique=criteria_unique, name=criteria_name, links=criteria_links,
                                                       relationships=criteria_relationships, origin_type=criteria_origin_type,
                                                       created=criteria_created, limit_count=criteria_limit_count,
                                                       technique_id=criteria_technique_id, trait=criteria_trait,
                                                       source=criteria_source, score=criteria_score, value=criteria_value,
                                                       collected_by=criteria_collected_by)

    response = client.update_facts(partial_factupdaterequest_updates, partial_factupdaterequest_criteria)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Facts',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_relationships_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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

    response = client.update_relationships(
        partial_relationshipupdate_updates, partial_relationshipupdate_criteria)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Relationships',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_ability_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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

    response = client.update_ability(ability_id, name, buckets, technique_id, delete_payload, executors, privilege,
                                     technique_name, tactic, singleton, plugin, repeatable, description)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Abilities',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_schedule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    schedule_id = args.get('schedule_id')
    schedule = args.get('schedule')
    task_obfuscator = args.get('task_obfuscator')
    task_autonomous = args.get('task_autonomous')
    task_state = args.get('task_state')
    schedule_task = assign_params(obfuscator=task_obfuscator, autonomous=task_autonomous, state=task_state)

    response = client.update_schedule(schedule_id, schedule, schedule_task)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Schedules',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_operation_link_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    operation_id = args.get('operation_id')
    link_id = args.get('link_id')
    command = args.get('command')
    status = int(args.get('status', -3))

    response = client.update_operation_link(operation_id, link_id, command, status)
    command_results = CommandResults(
        outputs_prefix='MitreCaldera.Links',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client: Client) -> None:
    client.get_abilities(None, None, None)
    return_results('ok')


def main() -> None:

    params = demisto.params()
    args = demisto.args()
    url = params.get('url')
    credentials = params.get('api_key')
    api_key = credentials.get('password')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    headers = {}
    headers['KEY'] = api_key

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        urllib3.disable_warnings()
        client: Client = Client(urljoin(url), verify_certificate, proxy, headers=headers, auth=None)

        commands = {
            'caldera-create-fact': create_fact_command,
            'caldera-create-fact-source': create_fact_source_command,
            'caldera-create-adversary': create_adversary_command,
            'caldera-create-agent': create_agent_command,
            'caldera-create-operation': create_operation_command,
            'caldera-create-objective': create_objective_command,
            'caldera-create-relationship': create_relationship_command,
            'caldera-create-ability': create_ability_command,
            'caldera-create-potential-link': create_potentiallink_command,
            'caldera-create-schedule': create_schedule_command,
            'caldera-delete-agent': delete_agent_command,
            'caldera-delete-fact-source': delete_fact_source_command,
            'caldera-delete-operation': delete_operation_command,
            'caldera-delete-facts': delete_facts_command,
            'caldera-delete-relationships': delete_relationships_command,
            'caldera-delete-ability': delete_ability_command,
            'caldera-delete-adversary': delete_adversary_command,
            'caldera-delete-schedule': delete_schedule_command,
            'caldera-get-abilities': get_abilities_command,
            'caldera-get-adversaries': get_adversaries_command,
            'caldera-get-agents': get_agents_command,
            'caldera-get-config': get_config_command,
            'caldera-get-contacts': get_contacts_command,
            'caldera-get-deploy-commands': get_deploy_commands_command,
            'caldera-get-facts': get_facts_command,
            'caldera-get-health': get_health_command,
            'caldera-get-obfuscators': get_obfuscators_command,
            'caldera-get-objectives': get_objectives_command,
            'caldera-get-operations': get_operations_command,
            'caldera-get-operation-links': get_operation_links_command,
            'caldera-get-operation-links-result': get_operation_links_result_command,
            'caldera-get-operations-potential-links': get_operation_potentiallinks_command,
            'caldera-get-planners': get_planners_command,
            'caldera-get-plugins': get_plugins_command,
            'caldera-get-relationships': get_relationships_command,
            'caldera-get-schedules': get_schedules_command,
            'caldera-get-sources': get_sources_command,
            'caldera-get-operation-event-logs': get_operation_eventlogs_command,
            'caldera-get-operation-report': get_operation_report_command,
            'caldera-replace-ability': replace_ability_command,
            'caldera-replace-schedule': replace_schedule_command,
            'caldera-update-agent-config': update_agent_config_command,
            'caldera-update-adversary': update_adversary_command,
            'caldera-update-agent': update_agent_command,
            'caldera-update-fact-source': update_fact_source_command,
            'caldera-update-objective': update_objective_command,
            'caldera-update-operation-fields': update_operation_fields_command,
            'caldera-update-main-config': update_main_config_command,
            'caldera-update-facts': update_facts_command,
            'caldera-update-relationships': update_relationships_command,
            'caldera-update-ability': update_ability_command,
            'caldera-update-schedule': update_schedule_command,
            'caldera-update-operation-link': update_operation_link_command,
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        elif command == "fetch-incidents":
            incidents, last_run = fetch_incidents(client, args, params)
            demisto.incidents(incidents)
            demisto.setLastRun(last_run)
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(e)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
