import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
inc = args.get('inc', '${.}')
data = args.get('value')

matches = re.findall("\$([^\$]*)\$", data)

for match in matches:
    if match == 'access_count':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'access_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'action':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'action_mode':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'action_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'action_status':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'additional_answer_count':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'affect_dest':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'answer':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'answer_count':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'app':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'app_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'array':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'authentication_method':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'authentication_service':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'authority_answer_count':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'availability':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'avg_executions':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'blocksize':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'body':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'buckets':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'buckets_size':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'buffer_cache_hit_ratio':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'bugtraq':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'bytes':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'bytes_in':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'bytes_out':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cached':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'category':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cert':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'change':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'change_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'channel':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cluster':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cm_enabled':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cm_supported':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'command':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'comments':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'commits':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'committed_memory':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'compilation_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'complete':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'component':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cookie':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cpu_cores':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cpu_count':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cpu_load_mhz':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cpu_load_percent':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cpu_mhz':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cpu_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cpu_time_enabled':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cpu_time_supported':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cpu_used':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cpu_user_percent':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'creation_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cron':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'current_cpu_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'current_loaded':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'current_user_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cursor':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cve':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'cvss':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'daemon_thread_count':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'datamodel':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'date':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'delay':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'description':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_bunit':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_category':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_dns':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_interface':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_ip':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_ip_range':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_is_expected':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_mac':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_nt_domain':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_nt_host':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_port':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_port_range':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_priority':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_requires_av':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_should_timesync':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_should_update':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_translated_ip':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_translated_port':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_url':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dest_zone':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'digest':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'direction':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dlp_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dns':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dump_area_used':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'duration':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dvc':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dvc_bunit':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dvc_category':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dvc_ip':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dvc_mac':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dvc_priority':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'dvc_zone':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'earliest':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'elapsed_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'email':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'enabled':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'endpoint':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'endpoint_version':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'error_code':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'event_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'family':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'fan_speed':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'fd_max':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'fd_used':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'file_access_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'file_acl':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'file_create_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'file_hash':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'file_modify_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'file_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'file_path':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'file_size':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'filter_action':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'filter_score':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'flow_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'free_bytes':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'free_physical_memory':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'free_swap':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'heap_committed':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'heap_initial':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'heap_max':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'heap_used':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'host':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'http_content_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'http_method':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'http_referrer':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'http_referrer_domain':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'http_user_agent':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'http_user_agent_length':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'hypervisor':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'hypervisor_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'icmp_code':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'icmp_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ids_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'image_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'incident':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'indexes_hit':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'info':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'inline_nat':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'instance_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'instance_reads':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'instance_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'instance_version':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'instance_writes':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'interactive':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'interface':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'internal_message_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ip':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'is_inprogress':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'jvm_description':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'last_call_minute':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'last_error':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'last_sid':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'latency':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'latest':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'lb_method':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'lease_duration':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'lease_scope':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'lock_mode':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'lock_session_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'logical_reads':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'logon_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'mac':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'machine':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'max_file_descriptors':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'mem':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'mem_committed':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'mem_free':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'mem_used':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'memory_sorts':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'message':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'message_consumed_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'message_correlation_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'message_delivered_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'message_delivery_mode':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'message_expiration_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'message_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'message_info':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'message_priority':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'message_properties':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'message_received_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'message_redelivered':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'message_reply_dest':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'message_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'mitre_technique_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'mod_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'mount':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'msft':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'mskb':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'node':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'node_port':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'non_heap_committed':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'non_heap_initial':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'non_heap_max':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'non_heap_used':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'number_of_users':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'obj_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'object':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'object_attrs':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'object_category':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'object_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'object_path':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'object_size':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'objects_pending':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'omu_supported':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'open_file_descriptors':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'operation':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'orig_dest':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'orig_recipient':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'orig_rid':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'orig_sid':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'orig_src':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'original_file_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'os':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'os_architecture':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'os_pid':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'os_version':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'owner':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'owner_email':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'owner_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'packets':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'packets_in':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'packets_out':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'parameters':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'parent':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'parent_object':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'parent_object_category':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'parent_object_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'parent_process':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'parent_process_exec':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'parent_process_guid':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'parent_process_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'parent_process_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'parent_process_path':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'password':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'payload':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'payload_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'peak_thread_count':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'physical_memory':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'physical_reads':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'power':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'priority':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'problem':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'process':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'process_current_directory':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'process_exec':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'process_guid':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'process_hash':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'process_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'process_integrity_level':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'process_limit':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'process_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'process_path':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'processes':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'product_version':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'protocol':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'protocol_version':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'query':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'query_count':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'query_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'query_plan_hit':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'query_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'query_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'read_blocks':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'read_latency':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'read_ops':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'reason':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'recipient':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'recipient_count':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'recipient_domain':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'recipient_status':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'record_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'records_affected':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'registry_hive':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'registry_key_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'registry_path':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'registry_value_data':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'registry_value_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'registry_value_text':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'registry_value_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'reply_code':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'reply_code_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'request_payload':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'request_payload_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'request_sent_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'resource_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'response_code':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'response_payload_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'response_received_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'response_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'result':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'result_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'retention':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'retries':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'return_addr':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'return_message':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'rid':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'rpc_protocol':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'rule':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'rule_action':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'savedsearch_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'search':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'search_et':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'search_lt':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'search_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'search_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'seconds_in_wait':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'sender':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'serial':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'serial_num':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'service':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'service_dll':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'service_dll_hash':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'service_dll_path':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'service_dll_signature_exists':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'service_dll_signature_verified':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'service_exec':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'service_hash':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'service_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'service_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'service_path':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'service_signature_exists':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'service_signature_verified':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'session_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'session_limit':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'session_status':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'sessions':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'severity':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'severity_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'sga_buffer_cache_size':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'sga_buffer_hit_limit':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'sga_data_dict_hit_ratio':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'sga_fixed_area_size':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'sga_free_memory':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'sga_library_cache_size':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'sga_redo_log_buffer_size':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'sga_shared_pool_size':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'sga_sql_area_size':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'shell':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'sid':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'signature':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'signature_extra':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'signature_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'signature_version':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'site':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'size':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'snapshot':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'source':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'sourcetype':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'spent':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'splunk_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'splunk_realm':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'splunk_server':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_bunit':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_category':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_dns':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_interface':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_ip':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_ip_range':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_mac':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_nt_domain':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_nt_host':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_port':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_port_range':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_priority':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_requires_av':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_should_timesync':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_should_update':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_translated_ip':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_translated_port':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_user':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_user_bunit':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_user_category':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_user_domain':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_user_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_user_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_user_priority':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_user_role':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_user_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'src_zone':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssid':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_end_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_engine':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_hash':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_is_valid':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_issuer':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_issuer_common_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_issuer_email':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_issuer_email_domain':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_issuer_locality':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_issuer_organization':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_issuer_state':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_issuer_street':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_issuer_unit':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_policies':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_publickey':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_publickey_algorithm':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_serial':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_session_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_signature_algorithm':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_start_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_subject':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_subject_common_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_subject_email':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_subject_email_domain':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_subject_locality':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_subject_organization':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_subject_state':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_subject_street':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_subject_unit':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_validity_window':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ssl_version':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'start_mode':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'start_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'state':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'status':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'status_code':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'storage':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'storage_free':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'storage_free_percent':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'storage_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'storage_used':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'storage_used_percent':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'stored_procedures_called':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'subject':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'summary_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'swap':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'swap_free':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'swap_space':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'swap_used':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'synch_supported':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'system_load':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'table_scans':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'tables_hit':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'tablespace_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'tablespace_reads':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'tablespace_status':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'tablespace_used':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'tablespace_writes':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'tag':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'tcp_flag':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'temperature':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'tenant_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'thread_count':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'threads_started':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'thruput':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'thruput_max':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ticket_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'time_submitted':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'tos':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'total_loaded':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'total_processors':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'total_unloaded':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'transaction_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'transport':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'transport_dest_port':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'ttl':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'uptime':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'uri':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'uri_path':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'uri_query':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'url':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'url_domain':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'url_length':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'user':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'user_agent':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'user_bunit':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'user_category':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'user_group':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'user_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'user_name':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'user_priority':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'user_role':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'user_type':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'vendor_account':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'vendor_product':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'vendor_product_id':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'vendor_region':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'version':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'view':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'vip_port':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'vlan':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'wait_state':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'wait_time':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'wifi':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'write_blocks':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'write_latency':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'write_ops':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'xdelay':
        data = data.replace('$' + match + '$', inc.get(match))
    elif match == 'xref':
        data = data.replace('$' + match + '$', inc.get(match))
    else:
        pass

return_results(data)
