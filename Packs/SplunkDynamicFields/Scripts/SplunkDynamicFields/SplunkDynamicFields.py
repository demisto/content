import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
inc = args.get('inc', '{.}')
data = args.get('value')

matches = re.findall("\$([^\$]*)\$", data)

for match in matches:
    elif == 'access_count':
        data = data.replace(+match +, inc.get(match))
    elif == 'access_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'action':
        data = data.replace(+match +, inc.get(match))
    elif == 'action_mode':
        data = data.replace(+match +, inc.get(match))
    elif == 'action_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'action_status':
        data = data.replace(+match +, inc.get(match))
    elif == 'additional_answer_count':
        data = data.replace(+match +, inc.get(match))
    elif == 'affect_dest':
        data = data.replace(+match +, inc.get(match))
    elif == 'answer':
        data = data.replace(+match +, inc.get(match))
    elif == 'answer_count':
        data = data.replace(+match +, inc.get(match))
    elif == 'app':
        data = data.replace(+match +, inc.get(match))
    elif == 'app_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'array':
        data = data.replace(+match +, inc.get(match))
    elif == 'authentication_method':
        data = data.replace(+match +, inc.get(match))
    elif == 'authentication_service':
        data = data.replace(+match +, inc.get(match))
    elif == 'authority_answer_count':
        data = data.replace(+match +, inc.get(match))
    elif == 'availability':
        data = data.replace(+match +, inc.get(match))
    elif == 'avg_executions':
        data = data.replace(+match +, inc.get(match))
    elif == 'blocksize':
        data = data.replace(+match +, inc.get(match))
    elif == 'body':
        data = data.replace(+match +, inc.get(match))
    elif == 'buckets':
        data = data.replace(+match +, inc.get(match))
    elif == 'buckets_size':
        data = data.replace(+match +, inc.get(match))
    elif == 'buffer_cache_hit_ratio':
        data = data.replace(+match +, inc.get(match))
    elif == 'bugtraq':
        data = data.replace(+match +, inc.get(match))
    elif == 'bytes':
        data = data.replace(+match +, inc.get(match))
    elif == 'bytes_in':
        data = data.replace(+match +, inc.get(match))
    elif == 'bytes_out':
        data = data.replace(+match +, inc.get(match))
    elif == 'cached':
        data = data.replace(+match +, inc.get(match))
    elif == 'category':
        data = data.replace(+match +, inc.get(match))
    elif == 'cert':
        data = data.replace(+match +, inc.get(match))
    elif == 'change':
        data = data.replace(+match +, inc.get(match))
    elif == 'change_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'channel':
        data = data.replace(+match +, inc.get(match))
    elif == 'cluster':
        data = data.replace(+match +, inc.get(match))
    elif == 'cm_enabled':
        data = data.replace(+match +, inc.get(match))
    elif == 'cm_supported':
        data = data.replace(+match +, inc.get(match))
    elif == 'command':
        data = data.replace(+match +, inc.get(match))
    elif == 'comments':
        data = data.replace(+match +, inc.get(match))
    elif == 'commits':
        data = data.replace(+match +, inc.get(match))
    elif == 'committed_memory':
        data = data.replace(+match +, inc.get(match))
    elif == 'compilation_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'complete':
        data = data.replace(+match +, inc.get(match))
    elif == 'component':
        data = data.replace(+match +, inc.get(match))
    elif == 'cookie':
        data = data.replace(+match +, inc.get(match))
    elif == 'cpu_cores':
        data = data.replace(+match +, inc.get(match))
    elif == 'cpu_count':
        data = data.replace(+match +, inc.get(match))
    elif == 'cpu_load_mhz':
        data = data.replace(+match +, inc.get(match))
    elif == 'cpu_load_percent':
        data = data.replace(+match +, inc.get(match))
    elif == 'cpu_mhz':
        data = data.replace(+match +, inc.get(match))
    elif == 'cpu_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'cpu_time_enabled':
        data = data.replace(+match +, inc.get(match))
    elif == 'cpu_time_supported':
        data = data.replace(+match +, inc.get(match))
    elif == 'cpu_used':
        data = data.replace(+match +, inc.get(match))
    elif == 'cpu_user_percent':
        data = data.replace(+match +, inc.get(match))
    elif == 'creation_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'cron':
        data = data.replace(+match +, inc.get(match))
    elif == 'current_cpu_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'current_loaded':
        data = data.replace(+match +, inc.get(match))
    elif == 'current_user_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'cursor':
        data = data.replace(+match +, inc.get(match))
    elif == 'cve':
        data = data.replace(+match +, inc.get(match))
    elif == 'cvss':
        data = data.replace(+match +, inc.get(match))
    elif == 'daemon_thread_count':
        data = data.replace(+match +, inc.get(match))
    elif == 'datamodel':
        data = data.replace(+match +, inc.get(match))
    elif == 'date':
        data = data.replace(+match +, inc.get(match))
    elif == 'delay':
        data = data.replace(+match +, inc.get(match))
    elif == 'description':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_bunit':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_category':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_dns':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_interface':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_ip':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_ip_range':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_is_expected':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_mac':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_nt_domain':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_nt_host':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_port':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_port_range':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_priority':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_requires_av':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_should_timesync':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_should_update':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_translated_ip':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_translated_port':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_url':
        data = data.replace(+match +, inc.get(match))
    elif == 'dest_zone':
        data = data.replace(+match +, inc.get(match))
    elif == 'digest':
        data = data.replace(+match +, inc.get(match))
    elif == 'direction':
        data = data.replace(+match +, inc.get(match))
    elif == 'dlp_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'dns':
        data = data.replace(+match +, inc.get(match))
    elif == 'dump_area_used':
        data = data.replace(+match +, inc.get(match))
    elif == 'duration':
        data = data.replace(+match +, inc.get(match))
    elif == 'dvc':
        data = data.replace(+match +, inc.get(match))
    elif == 'dvc_bunit':
        data = data.replace(+match +, inc.get(match))
    elif == 'dvc_category':
        data = data.replace(+match +, inc.get(match))
    elif == 'dvc_ip':
        data = data.replace(+match +, inc.get(match))
    elif == 'dvc_mac':
        data = data.replace(+match +, inc.get(match))
    elif == 'dvc_priority':
        data = data.replace(+match +, inc.get(match))
    elif == 'dvc_zone':
        data = data.replace(+match +, inc.get(match))
    elif == 'earliest':
        data = data.replace(+match +, inc.get(match))
    elif == 'elapsed_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'email':
        data = data.replace(+match +, inc.get(match))
    elif == 'enabled':
        data = data.replace(+match +, inc.get(match))
    elif == 'endpoint':
        data = data.replace(+match +, inc.get(match))
    elif == 'endpoint_version':
        data = data.replace(+match +, inc.get(match))
    elif == 'error_code':
        data = data.replace(+match +, inc.get(match))
    elif == 'event_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'family':
        data = data.replace(+match +, inc.get(match))
    elif == 'fan_speed':
        data = data.replace(+match +, inc.get(match))
    elif == 'fd_max':
        data = data.replace(+match +, inc.get(match))
    elif == 'fd_used':
        data = data.replace(+match +, inc.get(match))
    elif == 'file_access_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'file_acl':
        data = data.replace(+match +, inc.get(match))
    elif == 'file_create_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'file_hash':
        data = data.replace(+match +, inc.get(match))
    elif == 'file_modify_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'file_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'file_path':
        data = data.replace(+match +, inc.get(match))
    elif == 'file_size':
        data = data.replace(+match +, inc.get(match))
    elif == 'filter_action':
        data = data.replace(+match +, inc.get(match))
    elif == 'filter_score':
        data = data.replace(+match +, inc.get(match))
    elif == 'flow_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'free_bytes':
        data = data.replace(+match +, inc.get(match))
    elif == 'free_physical_memory':
        data = data.replace(+match +, inc.get(match))
    elif == 'free_swap':
        data = data.replace(+match +, inc.get(match))
    elif == 'heap_committed':
        data = data.replace(+match +, inc.get(match))
    elif == 'heap_initial':
        data = data.replace(+match +, inc.get(match))
    elif == 'heap_max':
        data = data.replace(+match +, inc.get(match))
    elif == 'heap_used':
        data = data.replace(+match +, inc.get(match))
    elif == 'host':
        data = data.replace(+match +, inc.get(match))
    elif == 'http_content_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'http_method':
        data = data.replace(+match +, inc.get(match))
    elif == 'http_referrer':
        data = data.replace(+match +, inc.get(match))
    elif == 'http_referrer_domain':
        data = data.replace(+match +, inc.get(match))
    elif == 'http_user_agent':
        data = data.replace(+match +, inc.get(match))
    elif == 'http_user_agent_length':
        data = data.replace(+match +, inc.get(match))
    elif == 'hypervisor':
        data = data.replace(+match +, inc.get(match))
    elif == 'hypervisor_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'icmp_code':
        data = data.replace(+match +, inc.get(match))
    elif == 'icmp_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'id':
        data = data.replace(+match +, inc.get(match))
    elif == 'ids_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'image_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'incident':
        data = data.replace(+match +, inc.get(match))
    elif == 'indexes_hit':
        data = data.replace(+match +, inc.get(match))
    elif == 'info':
        data = data.replace(+match +, inc.get(match))
    elif == 'inline_nat':
        data = data.replace(+match +, inc.get(match))
    elif == 'instance_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'instance_reads':
        data = data.replace(+match +, inc.get(match))
    elif == 'instance_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'instance_version':
        data = data.replace(+match +, inc.get(match))
    elif == 'instance_writes':
        data = data.replace(+match +, inc.get(match))
    elif == 'interactive':
        data = data.replace(+match +, inc.get(match))
    elif == 'interface':
        data = data.replace(+match +, inc.get(match))
    elif == 'internal_message_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'ip':
        data = data.replace(+match +, inc.get(match))
    elif == 'is_inprogress':
        data = data.replace(+match +, inc.get(match))
    elif == 'jvm_description':
        data = data.replace(+match +, inc.get(match))
    elif == 'last_call_minute':
        data = data.replace(+match +, inc.get(match))
    elif == 'last_error':
        data = data.replace(+match +, inc.get(match))
    elif == 'last_sid':
        data = data.replace(+match +, inc.get(match))
    elif == 'latency':
        data = data.replace(+match +, inc.get(match))
    elif == 'latest':
        data = data.replace(+match +, inc.get(match))
    elif == 'lb_method':
        data = data.replace(+match +, inc.get(match))
    elif == 'lease_duration':
        data = data.replace(+match +, inc.get(match))
    elif == 'lease_scope':
        data = data.replace(+match +, inc.get(match))
    elif == 'lock_mode':
        data = data.replace(+match +, inc.get(match))
    elif == 'lock_session_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'logical_reads':
        data = data.replace(+match +, inc.get(match))
    elif == 'logon_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'mac':
        data = data.replace(+match +, inc.get(match))
    elif == 'machine':
        data = data.replace(+match +, inc.get(match))
    elif == 'max_file_descriptors':
        data = data.replace(+match +, inc.get(match))
    elif == 'mem':
        data = data.replace(+match +, inc.get(match))
    elif == 'mem_committed':
        data = data.replace(+match +, inc.get(match))
    elif == 'mem_free':
        data = data.replace(+match +, inc.get(match))
    elif == 'mem_used':
        data = data.replace(+match +, inc.get(match))
    elif == 'memory_sorts':
        data = data.replace(+match +, inc.get(match))
    elif == 'message':
        data = data.replace(+match +, inc.get(match))
    elif == 'message_consumed_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'message_correlation_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'message_delivered_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'message_delivery_mode':
        data = data.replace(+match +, inc.get(match))
    elif == 'message_expiration_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'message_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'message_info':
        data = data.replace(+match +, inc.get(match))
    elif == 'message_priority':
        data = data.replace(+match +, inc.get(match))
    elif == 'message_properties':
        data = data.replace(+match +, inc.get(match))
    elif == 'message_received_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'message_redelivered':
        data = data.replace(+match +, inc.get(match))
    elif == 'message_reply_dest':
        data = data.replace(+match +, inc.get(match))
    elif == 'message_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'mitre_technique_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'mod_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'mount':
        data = data.replace(+match +, inc.get(match))
    elif == 'msft':
        data = data.replace(+match +, inc.get(match))
    elif == 'mskb':
        data = data.replace(+match +, inc.get(match))
    elif == 'name':
        data = data.replace(+match +, inc.get(match))
    elif == 'node':
        data = data.replace(+match +, inc.get(match))
    elif == 'node_port':
        data = data.replace(+match +, inc.get(match))
    elif == 'non_heap_committed':
        data = data.replace(+match +, inc.get(match))
    elif == 'non_heap_initial':
        data = data.replace(+match +, inc.get(match))
    elif == 'non_heap_max':
        data = data.replace(+match +, inc.get(match))
    elif == 'non_heap_used':
        data = data.replace(+match +, inc.get(match))
    elif == 'number_of_users':
        data = data.replace(+match +, inc.get(match))
    elif == 'obj_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'object':
        data = data.replace(+match +, inc.get(match))
    elif == 'object_attrs':
        data = data.replace(+match +, inc.get(match))
    elif == 'object_category':
        data = data.replace(+match +, inc.get(match))
    elif == 'object_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'object_path':
        data = data.replace(+match +, inc.get(match))
    elif == 'object_size':
        data = data.replace(+match +, inc.get(match))
    elif == 'objects_pending':
        data = data.replace(+match +, inc.get(match))
    elif == 'omu_supported':
        data = data.replace(+match +, inc.get(match))
    elif == 'open_file_descriptors':
        data = data.replace(+match +, inc.get(match))
    elif == 'operation':
        data = data.replace(+match +, inc.get(match))
    elif == 'orig_dest':
        data = data.replace(+match +, inc.get(match))
    elif == 'orig_recipient':
        data = data.replace(+match +, inc.get(match))
    elif == 'orig_rid':
        data = data.replace(+match +, inc.get(match))
    elif == 'orig_sid':
        data = data.replace(+match +, inc.get(match))
    elif == 'orig_src':
        data = data.replace(+match +, inc.get(match))
    elif == 'original_file_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'os':
        data = data.replace(+match +, inc.get(match))
    elif == 'os_architecture':
        data = data.replace(+match +, inc.get(match))
    elif == 'os_pid':
        data = data.replace(+match +, inc.get(match))
    elif == 'os_version':
        data = data.replace(+match +, inc.get(match))
    elif == 'owner':
        data = data.replace(+match +, inc.get(match))
    elif == 'owner_email':
        data = data.replace(+match +, inc.get(match))
    elif == 'owner_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'packets':
        data = data.replace(+match +, inc.get(match))
    elif == 'packets_in':
        data = data.replace(+match +, inc.get(match))
    elif == 'packets_out':
        data = data.replace(+match +, inc.get(match))
    elif == 'parameters':
        data = data.replace(+match +, inc.get(match))
    elif == 'parent':
        data = data.replace(+match +, inc.get(match))
    elif == 'parent_object':
        data = data.replace(+match +, inc.get(match))
    elif == 'parent_object_category':
        data = data.replace(+match +, inc.get(match))
    elif == 'parent_object_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'parent_process':
        data = data.replace(+match +, inc.get(match))
    elif == 'parent_process_exec':
        data = data.replace(+match +, inc.get(match))
    elif == 'parent_process_guid':
        data = data.replace(+match +, inc.get(match))
    elif == 'parent_process_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'parent_process_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'parent_process_path':
        data = data.replace(+match +, inc.get(match))
    elif == 'password':
        data = data.replace(+match +, inc.get(match))
    elif == 'payload':
        data = data.replace(+match +, inc.get(match))
    elif == 'payload_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'peak_thread_count':
        data = data.replace(+match +, inc.get(match))
    elif == 'physical_memory':
        data = data.replace(+match +, inc.get(match))
    elif == 'physical_reads':
        data = data.replace(+match +, inc.get(match))
    elif == 'power':
        data = data.replace(+match +, inc.get(match))
    elif == 'priority':
        data = data.replace(+match +, inc.get(match))
    elif == 'problem':
        data = data.replace(+match +, inc.get(match))
    elif == 'process':
        data = data.replace(+match +, inc.get(match))
    elif == 'process_current_directory':
        data = data.replace(+match +, inc.get(match))
    elif == 'process_exec':
        data = data.replace(+match +, inc.get(match))
    elif == 'process_guid':
        data = data.replace(+match +, inc.get(match))
    elif == 'process_hash':
        data = data.replace(+match +, inc.get(match))
    elif == 'process_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'process_integrity_level':
        data = data.replace(+match +, inc.get(match))
    elif == 'process_limit':
        data = data.replace(+match +, inc.get(match))
    elif == 'process_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'process_path':
        data = data.replace(+match +, inc.get(match))
    elif == 'processes':
        data = data.replace(+match +, inc.get(match))
    elif == 'product_version':
        data = data.replace(+match +, inc.get(match))
    elif == 'protocol':
        data = data.replace(+match +, inc.get(match))
    elif == 'protocol_version':
        data = data.replace(+match +, inc.get(match))
    elif == 'query':
        data = data.replace(+match +, inc.get(match))
    elif == 'query_count':
        data = data.replace(+match +, inc.get(match))
    elif == 'query_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'query_plan_hit':
        data = data.replace(+match +, inc.get(match))
    elif == 'query_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'query_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'read_blocks':
        data = data.replace(+match +, inc.get(match))
    elif == 'read_latency':
        data = data.replace(+match +, inc.get(match))
    elif == 'read_ops':
        data = data.replace(+match +, inc.get(match))
    elif == 'reason':
        data = data.replace(+match +, inc.get(match))
    elif == 'recipient':
        data = data.replace(+match +, inc.get(match))
    elif == 'recipient_count':
        data = data.replace(+match +, inc.get(match))
    elif == 'recipient_domain':
        data = data.replace(+match +, inc.get(match))
    elif == 'recipient_status':
        data = data.replace(+match +, inc.get(match))
    elif == 'record_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'records_affected':
        data = data.replace(+match +, inc.get(match))
    elif == 'registry_hive':
        data = data.replace(+match +, inc.get(match))
    elif == 'registry_key_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'registry_path':
        data = data.replace(+match +, inc.get(match))
    elif == 'registry_value_data':
        data = data.replace(+match +, inc.get(match))
    elif == 'registry_value_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'registry_value_text':
        data = data.replace(+match +, inc.get(match))
    elif == 'registry_value_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'reply_code':
        data = data.replace(+match +, inc.get(match))
    elif == 'reply_code_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'request_payload':
        data = data.replace(+match +, inc.get(match))
    elif == 'request_payload_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'request_sent_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'resource_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'response_code':
        data = data.replace(+match +, inc.get(match))
    elif == 'response_payload_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'response_received_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'response_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'result':
        data = data.replace(+match +, inc.get(match))
    elif == 'result_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'retention':
        data = data.replace(+match +, inc.get(match))
    elif == 'retries':
        data = data.replace(+match +, inc.get(match))
    elif == 'return_addr':
        data = data.replace(+match +, inc.get(match))
    elif == 'return_message':
        data = data.replace(+match +, inc.get(match))
    elif == 'rid':
        data = data.replace(+match +, inc.get(match))
    elif == 'rpc_protocol':
        data = data.replace(+match +, inc.get(match))
    elif == 'rule':
        data = data.replace(+match +, inc.get(match))
    elif == 'rule_action':
        data = data.replace(+match +, inc.get(match))
    elif == 'savedsearch_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'search':
        data = data.replace(+match +, inc.get(match))
    elif == 'search_et':
        data = data.replace(+match +, inc.get(match))
    elif == 'search_lt':
        data = data.replace(+match +, inc.get(match))
    elif == 'search_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'search_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'seconds_in_wait':
        data = data.replace(+match +, inc.get(match))
    elif == 'sender':
        data = data.replace(+match +, inc.get(match))
    elif == 'serial':
        data = data.replace(+match +, inc.get(match))
    elif == 'serial_num':
        data = data.replace(+match +, inc.get(match))
    elif == 'service':
        data = data.replace(+match +, inc.get(match))
    elif == 'service_dll':
        data = data.replace(+match +, inc.get(match))
    elif == 'service_dll_hash':
        data = data.replace(+match +, inc.get(match))
    elif == 'service_dll_path':
        data = data.replace(+match +, inc.get(match))
    elif == 'service_dll_signature_exists':
        data = data.replace(+match +, inc.get(match))
    elif == 'service_dll_signature_verified':
        data = data.replace(+match +, inc.get(match))
    elif == 'service_exec':
        data = data.replace(+match +, inc.get(match))
    elif == 'service_hash':
        data = data.replace(+match +, inc.get(match))
    elif == 'service_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'service_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'service_path':
        data = data.replace(+match +, inc.get(match))
    elif == 'service_signature_exists':
        data = data.replace(+match +, inc.get(match))
    elif == 'service_signature_verified':
        data = data.replace(+match +, inc.get(match))
    elif == 'session_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'session_limit':
        data = data.replace(+match +, inc.get(match))
    elif == 'session_status':
        data = data.replace(+match +, inc.get(match))
    elif == 'sessions':
        data = data.replace(+match +, inc.get(match))
    elif == 'severity':
        data = data.replace(+match +, inc.get(match))
    elif == 'severity_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'sga_buffer_cache_size':
        data = data.replace(+match +, inc.get(match))
    elif == 'sga_buffer_hit_limit':
        data = data.replace(+match +, inc.get(match))
    elif == 'sga_data_dict_hit_ratio':
        data = data.replace(+match +, inc.get(match))
    elif == 'sga_fixed_area_size':
        data = data.replace(+match +, inc.get(match))
    elif == 'sga_free_memory':
        data = data.replace(+match +, inc.get(match))
    elif == 'sga_library_cache_size':
        data = data.replace(+match +, inc.get(match))
    elif == 'sga_redo_log_buffer_size':
        data = data.replace(+match +, inc.get(match))
    elif == 'sga_shared_pool_size':
        data = data.replace(+match +, inc.get(match))
    elif == 'sga_sql_area_size':
        data = data.replace(+match +, inc.get(match))
    elif == 'shell':
        data = data.replace(+match +, inc.get(match))
    elif == 'sid':
        data = data.replace(+match +, inc.get(match))
    elif == 'signature':
        data = data.replace(+match +, inc.get(match))
    elif == 'signature_extra':
        data = data.replace(+match +, inc.get(match))
    elif == 'signature_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'signature_version':
        data = data.replace(+match +, inc.get(match))
    elif == 'site':
        data = data.replace(+match +, inc.get(match))
    elif == 'size':
        data = data.replace(+match +, inc.get(match))
    elif == 'snapshot':
        data = data.replace(+match +, inc.get(match))
    elif == 'source':
        data = data.replace(+match +, inc.get(match))
    elif == 'sourcetype':
        data = data.replace(+match +, inc.get(match))
    elif == 'spent':
        data = data.replace(+match +, inc.get(match))
    elif == 'splunk_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'splunk_realm':
        data = data.replace(+match +, inc.get(match))
    elif == 'splunk_server':
        data = data.replace(+match +, inc.get(match))
    elif == 'src':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_bunit':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_category':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_dns':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_interface':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_ip':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_ip_range':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_mac':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_nt_domain':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_nt_host':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_port':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_port_range':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_priority':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_requires_av':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_should_timesync':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_should_update':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_translated_ip':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_translated_port':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_user':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_user_bunit':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_user_category':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_user_domain':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_user_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_user_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_user_priority':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_user_role':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_user_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'src_zone':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssid':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_end_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_engine':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_hash':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_is_valid':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_issuer':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_issuer_common_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_issuer_email':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_issuer_email_domain':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_issuer_locality':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_issuer_organization':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_issuer_state':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_issuer_street':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_issuer_unit':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_policies':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_publickey':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_publickey_algorithm':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_serial':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_session_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_signature_algorithm':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_start_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_subject':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_subject_common_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_subject_email':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_subject_email_domain':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_subject_locality':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_subject_organization':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_subject_state':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_subject_street':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_subject_unit':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_validity_window':
        data = data.replace(+match +, inc.get(match))
    elif == 'ssl_version':
        data = data.replace(+match +, inc.get(match))
    elif == 'start_mode':
        data = data.replace(+match +, inc.get(match))
    elif == 'start_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'state':
        data = data.replace(+match +, inc.get(match))
    elif == 'status':
        data = data.replace(+match +, inc.get(match))
    elif == 'status_code':
        data = data.replace(+match +, inc.get(match))
    elif == 'storage':
        data = data.replace(+match +, inc.get(match))
    elif == 'storage_free':
        data = data.replace(+match +, inc.get(match))
    elif == 'storage_free_percent':
        data = data.replace(+match +, inc.get(match))
    elif == 'storage_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'storage_used':
        data = data.replace(+match +, inc.get(match))
    elif == 'storage_used_percent':
        data = data.replace(+match +, inc.get(match))
    elif == 'stored_procedures_called':
        data = data.replace(+match +, inc.get(match))
    elif == 'subject':
        data = data.replace(+match +, inc.get(match))
    elif == 'summary_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'swap':
        data = data.replace(+match +, inc.get(match))
    elif == 'swap_free':
        data = data.replace(+match +, inc.get(match))
    elif == 'swap_space':
        data = data.replace(+match +, inc.get(match))
    elif == 'swap_used':
        data = data.replace(+match +, inc.get(match))
    elif == 'synch_supported':
        data = data.replace(+match +, inc.get(match))
    elif == 'system_load':
        data = data.replace(+match +, inc.get(match))
    elif == 'table_scans':
        data = data.replace(+match +, inc.get(match))
    elif == 'tables_hit':
        data = data.replace(+match +, inc.get(match))
    elif == 'tablespace_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'tablespace_reads':
        data = data.replace(+match +, inc.get(match))
    elif == 'tablespace_status':
        data = data.replace(+match +, inc.get(match))
    elif == 'tablespace_used':
        data = data.replace(+match +, inc.get(match))
    elif == 'tablespace_writes':
        data = data.replace(+match +, inc.get(match))
    elif == 'tag':
        data = data.replace(+match +, inc.get(match))
    elif == 'tcp_flag':
        data = data.replace(+match +, inc.get(match))
    elif == 'temperature':
        data = data.replace(+match +, inc.get(match))
    elif == 'tenant_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'thread_count':
        data = data.replace(+match +, inc.get(match))
    elif == 'threads_started':
        data = data.replace(+match +, inc.get(match))
    elif == 'thruput':
        data = data.replace(+match +, inc.get(match))
    elif == 'thruput_max':
        data = data.replace(+match +, inc.get(match))
    elif == 'ticket_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'time':
        data = data.replace(+match +, inc.get(match))
    elif == 'time_submitted':
        data = data.replace(+match +, inc.get(match))
    elif == 'tos':
        data = data.replace(+match +, inc.get(match))
    elif == 'total_loaded':
        data = data.replace(+match +, inc.get(match))
    elif == 'total_processors':
        data = data.replace(+match +, inc.get(match))
    elif == 'total_unloaded':
        data = data.replace(+match +, inc.get(match))
    elif == 'transaction_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'transport':
        data = data.replace(+match +, inc.get(match))
    elif == 'transport_dest_port':
        data = data.replace(+match +, inc.get(match))
    elif == 'ttl':
        data = data.replace(+match +, inc.get(match))
    elif == 'type':
        data = data.replace(+match +, inc.get(match))
    elif == 'uptime':
        data = data.replace(+match +, inc.get(match))
    elif == 'uri':
        data = data.replace(+match +, inc.get(match))
    elif == 'uri_path':
        data = data.replace(+match +, inc.get(match))
    elif == 'uri_query':
        data = data.replace(+match +, inc.get(match))
    elif == 'url':
        data = data.replace(+match +, inc.get(match))
    elif == 'url_domain':
        data = data.replace(+match +, inc.get(match))
    elif == 'url_length':
        data = data.replace(+match +, inc.get(match))
    elif == 'user':
        data = data.replace(+match +, inc.get(match))
    elif == 'user_agent':
        data = data.replace(+match +, inc.get(match))
    elif == 'user_bunit':
        data = data.replace(+match +, inc.get(match))
    elif == 'user_category':
        data = data.replace(+match +, inc.get(match))
    elif == 'user_group':
        data = data.replace(+match +, inc.get(match))
    elif == 'user_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'user_name':
        data = data.replace(+match +, inc.get(match))
    elif == 'user_priority':
        data = data.replace(+match +, inc.get(match))
    elif == 'user_role':
        data = data.replace(+match +, inc.get(match))
    elif == 'user_type':
        data = data.replace(+match +, inc.get(match))
    elif == 'vendor_account':
        data = data.replace(+match +, inc.get(match))
    elif == 'vendor_product':
        data = data.replace(+match +, inc.get(match))
    elif == 'vendor_product_id':
        data = data.replace(+match +, inc.get(match))
    elif == 'vendor_region':
        data = data.replace(+match +, inc.get(match))
    elif == 'version':
        data = data.replace(+match +, inc.get(match))
    elif == 'view':
        data = data.replace(+match +, inc.get(match))
    elif == 'vip_port':
        data = data.replace(+match +, inc.get(match))
    elif == 'vlan':
        data = data.replace(+match +, inc.get(match))
    elif == 'wait_state':
        data = data.replace(+match +, inc.get(match))
    elif == 'wait_time':
        data = data.replace(+match +, inc.get(match))
    elif == 'wifi':
        data = data.replace(+match +, inc.get(match))
    elif == 'write_blocks':
        data = data.replace(+match +, inc.get(match))
    elif == 'write_latency':
        data = data.replace(+match +, inc.get(match))
    elif == 'write_ops':
        data = data.replace(+match +, inc.get(match))
    elif == 'xdelay':
        data = data.replace(+match +, inc.get(match))
    elif == 'xref':
        data = data.replace(+match +, inc.get(match))
    else:
        pass

return_results(data)
