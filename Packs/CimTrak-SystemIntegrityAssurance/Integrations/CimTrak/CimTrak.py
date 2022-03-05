import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Cimtrak Integration for Cortex XSOAR (aka Demisto)
"""
import json
import time
import traceback
from datetime import datetime
from operator import itemgetter
from typing import Any, Dict, List, Optional, Union

import dateparser
################################################################
# CimTrak Python API Begin
################################################################
import requests
import urllib3


class CimTrak:
    OBJECT_TYPE_REPOSITORY = -1
    OBJECT_TYPE_AGENT = 1
    OBJECT_TYPE_AREA = 2
    OBJECT_TYPE_SYSTEM = 3
    OBJECT_TYPE_NETWORK_AGENT = 4

    OBJECT_SUBTYPE_FILESYSTEM_AGENT = 1
    OBJECT_SUBTYPE_COLLECTOR_AGENT = 2
    OBJECT_SUBTYPE_FILESYSTEM = 3
    OBJECT_SUBTYPE_NETWORKDEVICE = 4
    OBJECT_SUBTYPE_REGISTRY = 5
    OBJECT_SUBTYPE_FTP = 6
    OBJECT_SUBTYPE_INDUSTRIAL_AGENT = 7
    OBJECT_SUBTYPE_PLC = 8
    OBJECT_SUBTYPE_SOURCE_CONTROL = 9
    OBJECT_SUBTYPE_COMPLIANCE = 10
    OBJECT_SUBTYPE_VIRTUAL_DEVICE_NODE = 11

    url_root = "/CimTrakRestAPI/v1/"
    app_server_url = ""
    verify_cert = False
    auth_token = ""
    debug = 0
    connected = False
    api_key = ""
    server = ""
    port = 0

    def __init__(self, app_server_url, api_key, server, port):
        self.app_server_url = app_server_url
        self.api_key = api_key
        self.server = server
        self.port = port

    def __del__(self):
        self.disconnect()

    def debug_print(self, text):
        return 1

    def http_post(self, url, data, verify_cert):
        response = requests.post(self.app_server_url + url, data=data, verify=verify_cert)
        return response.text

    def disconnect(self):
        if self.connected is True:
            if self.debug >= 1:
                self.debug_print("Disconnecting")
            request_data = {"authToken": self.auth_token}
            if self.debug >= 4:
                self.debug_print("Request Data:" + json.dumps(request_data))
            response = self.http_post(
                self.url_root + "Client.logoff", json.dumps(request_data), self.verify_cert
            )
            if self.debug >= 4:
                self.debug_print("Response:" + response)
            request_response = json.loads(response)
            if request_response["status"] == "success":
                self.connected = False
                self.auth_token = ""
                if self.debug >= 1:
                    self.debug_print("Success logging off")
            else:
                if self.debug >= 1:
                    self.debug_print("Failed logging off")

    def connect(self, url, port, username, password):
        if self.debug >= 1:
            self.debug_print("connect")
        self.disconnect()
        request_data = {
            "username": username,
            "password": password,
            "server": url,
            "port": port,
        }
        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.connectToServer",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            self.connected = True
            for item in request_response["results"]:
                self.auth_token = item["authToken"]
            if self.debug >= 1:
                self.debug_print("Logon successful, authToken:" + self.auth_token)
        else:
            self.connected = False
            self.auth_token = ""
            if self.debug >= 1:
                self.debug_print("Logon failed")

    def get_events(self, start=1, end=500, filter=None, sorts=None):
        if self.debug >= 1:
            self.debug_print("get_events")
        request_data = {
            "authToken": self.auth_token,
            "cursorName": self.auth_token + "pythonLibrary",
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "refresh": True,
            "start": start,
            "end": end,
        }
        if sorts is not None and sorts != "":
            request_data["sorts"] = sorts
        if filter is not None and filter != "":
            request_data["filter"] = filter
        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.getEventLogRaw",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("get_events successful")
        else:
            if self.debug >= 1:
                self.debug_print("get_events failed")
        return request_response

    def get_unreconciled_items(self, start=1, end=500, object_id=0, sorts=None):
        if self.debug >= 1:
            self.debug_print("get_unreconciled_items")
        request_data = {
            "authToken": self.auth_token,
            "cursorName": self.auth_token + "pythonLibrary",
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "refresh": True,
            "start": start,
            "end": end,
            "objectId": object_id,
        }
        if sorts is not None and sorts != "":
            request_data["sorts"] = sorts
        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.getUnreconciledItems",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("get_unreconciled_items successful")
        else:
            if self.debug >= 1:
                self.debug_print("get_unreconciled_items failed")
        return request_response

    def file_analysis_by_hash(self, hash):
        if self.debug >= 1:
            self.debug_print("file_analysis_by_hash")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "hash": hash,
        }
        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.fileAnalysisByHash",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("file_analysis_by_hash successful")
        else:
            if self.debug >= 1:
                self.debug_print("file_analysis_by_hash failed")
        return request_response

    def file_analysis_by_object_detail_id(self, object_detail_id):
        if self.debug >= 1:
            self.debug_print("file_analysis_by_object_detail_id")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "objectDetailId": object_detail_id,
        }
        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.fileAnalysisByObjectDetailId",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("file_analysis_by_object_detail_id successful")
        else:
            if self.debug >= 1:
                self.debug_print("file_analysis_by_object_detail_id failed")
        return request_response

    def check_file_against_trusted_file_registry_by_hash(self, hashes):
        if self.debug >= 1:
            self.debug_print("check_file_against_trusted_file_registry_by_hash")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "hashes": hashes,
        }
        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.checkFileAgainstTrustedFileRegistryByHash",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("check_file_against_trusted_file_registry_by_hash successful")
        else:
            if self.debug >= 1:
                self.debug_print("check_file_against_trusted_file_registry_by_hash failed")
        return request_response

    def search_trusted_file_registry_by_hash(self, hash):
        if self.debug >= 1:
            self.debug_print("search_trusted_file_registry_by_hash")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "hash": hash,
        }
        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.searchTrustedFileRegistryByHash",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("search_trusted_file_registry_by_hash successful")
        else:
            if self.debug >= 1:
                self.debug_print("search_trusted_file_registry_by_hash failed")
        return request_response

    def promote_authoritative_baseline_files(self, object_detail_ids):
        if self.debug >= 1:
            self.debug_print("promote_authoritative_baseline_files")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "objectDetailId": object_detail_ids,
        }
        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.promoteAuthoritativeBaselineFiles",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("promote_authoritative_baseline_files successful")
        else:
            if self.debug >= 1:
                self.debug_print("promote_authoritative_baseline_files failed")
        return request_response

    def demote_authoritative_baseline_files(self, object_detail_ids):
        if self.debug >= 1:
            self.debug_print("demote_authoritative_baseline_files")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "objectDetailId": object_detail_ids,
        }
        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.demoteAuthoritativeBaselineFiles",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("demote_authoritative_baseline_files successful")
        else:
            if self.debug >= 1:
                self.debug_print("demote_authoritative_baseline_files failed")
        return request_response

    def get_tickets(self, user_id=-99, filters=None):
        if self.debug >= 1:
            self.debug_print("get_tickets")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
        }
        if user_id != -99:
            request_data["userId"] = user_id
        if filters is not None and filters != "":
            request_data["filters"] = filters

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.getTickets", json.dumps(request_data), self.verify_cert
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("get_tickets successful")
        else:
            if self.debug >= 1:
                self.debug_print("get_tickets failed")
        return request_response

    def get_ticket_tasks(self, showAdminView=False, user_id=-99, filters=None):
        if self.debug >= 1:
            self.debug_print("get_ticket_tasks")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "showAdminView": showAdminView,
        }
        if user_id != -99:
            request_data["userId"] = user_id
        if filters is not None and filters != "":
            request_data["filters"] = filters

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.getTicketTasks",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("get_ticket_tasks successful")
        else:
            if self.debug >= 1:
                self.debug_print("get_ticket_tasks failed")
        return request_response

    def add_ticket(
        self,
        title,
        priority,
        description="",
        start_date="",
        end_date="",
        external_ticket_number="",
        external_ticket_type="",
        auto_promote=False,
        disposition="OPEN",
        requires_acknowledgement=False,
        requires_assessment=False,
        requires_confirmation=False,
        assigned_to_user_id=0,
        assigned_to_user="",
        assigned_to_group_id=0,
        assigned_to_group="",
        tasks=None,
    ):
        if self.debug >= 1:
            self.debug_print("add_ticket")
        ticket = {
            "title": title,
            "priority": priority,
            "description": description,
            "externalTicketNumber": external_ticket_number,
            "externalTicketType": external_ticket_type,
            "autoPromote": auto_promote,
            "disposition": disposition,
            "requiresAcknowledgement": requires_acknowledgement,
            "requiresAssessment": requires_assessment,
            "requiresConfirmation": requires_confirmation,
            "assignedToUserId": assigned_to_user_id,
            "assignedToUser": assigned_to_user,
            "assignedToGroupId": assigned_to_group_id,
            "assignedToGroup": assigned_to_group,
        }
        if start_date != "":
            ticket["startDate"] = start_date
        if end_date != "":
            ticket["endDate"] = end_date
        if tasks is not None and tasks != "":
            ticket["tasks"] = tasks

        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "ticket": ticket,
        }

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.addTicket", json.dumps(request_data), self.verify_cert
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("add_ticket successful")
        else:
            if self.debug >= 1:
                self.debug_print("add_ticket failed")
        return request_response

    def update_ticket(
        self,
        ticket_id,
        title,
        priority,
        description="",
        start_date="",
        end_date="",
        external_ticket_number="",
        external_ticket_type="",
        auto_promote=False,
        disposition="OPEN",
        requires_acknowledgement=False,
        requires_assessment=False,
        requires_confirmation=False,
        assigned_to_user_id=0,
        assigned_to_user="",
        assigned_to_group_id=0,
        assigned_to_group="",
        tasks=None,
    ):
        if self.debug >= 1:
            self.debug_print("update_ticket")
        ticket = {
            "title": title,
            "priority": priority,
            "description": description,
            "externalTicketNumber": external_ticket_number,
            "externalTicketType": external_ticket_type,
            "autoPromote": auto_promote,
            "disposition": disposition,
            "requiresAcknowledgement": requires_acknowledgement,
            "requiresAssessment": requires_assessment,
            "requiresConfirmation": requires_confirmation,
            "assignedToUserId": assigned_to_user_id,
            "assignedToUser": assigned_to_user,
            "assignedToGroupId": assigned_to_group_id,
            "assignedToGroup": assigned_to_group,
        }
        if start_date != "":
            ticket["startDate"] = start_date
        if end_date != "":
            ticket["endDate"] = end_date
        if tasks is not None and tasks != "":
            ticket["tasks"] = tasks

        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "filter": [{"name": "id", "operator": "=", "value": ticket_id}],
            "data": ticket,
        }

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.updateTickets",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("update_ticket successful")
        else:
            if self.debug >= 1:
                self.debug_print("update_ticket failed")
        return request_response

    def add_ticket_comment(self, ticket_id, comment):
        if self.debug >= 1:
            self.debug_print("add_ticket_comment")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "ticketId": ticket_id,
            "taskId": 0,
            "comment": comment,
        }

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.addTicketComment",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("add_ticket_comment successful")
        else:
            if self.debug >= 1:
                self.debug_print("add_ticket_comment failed")
        return request_response

    def update_task_disposition(self, task_id, disposition):
        if self.debug >= 1:
            self.debug_print("update_task_disposition")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "taskIdArray": [task_id],
            "disposition": disposition,
        }

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.updateTaskDisposition",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("update_task_disposition successful")
        else:
            if self.debug >= 1:
                self.debug_print("update_task_disposition failed")
        return request_response

    def add_hash_allow_list(self, hash, filename="", source="", source_reference=""):
        if self.debug >= 1:
            self.debug_print("add_hash_allow_list")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "tagId": [0],
            "hashList": [
                {
                    "hash": hash,
                    "filename": filename,
                    "source": source,
                    "sourceReference": source_reference,
                }
            ],
        }

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.addHashWhitelist",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("add_hash_allow_list successful")
        else:
            if self.debug >= 1:
                self.debug_print("add_hash_allow_list failed")
        return request_response

    def add_hash_deny_list(self, hash, filename="", source="", source_reference=""):
        if self.debug >= 1:
            self.debug_print("add_hash_deny_list")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "tagId": [0],
            "hashList": [
                {
                    "hash": hash,
                    "filename": filename,
                    "source": source,
                    "sourceReference": source_reference,
                }
            ],
        }

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.addHashBlacklist",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("add_hash_deny_list successful")
        else:
            if self.debug >= 1:
                self.debug_print("add_hash_deny_list failed")
        return request_response

    def delete_hash_allow_list(self, reason, hash):
        if self.debug >= 1:
            self.debug_print("delete_hash_allow_list")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "reason": reason,
            "hashTagIdArray": [{"hash": hash, "tag": 0}],
        }

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.deleteHashWhitelist",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("delete_hash_allow_list successful")
        else:
            if self.debug >= 1:
                self.debug_print("delete_hash_allow_list failed")
        return request_response

    def delete_hash_deny_list(self, reason, hash):
        if self.debug >= 1:
            self.debug_print("delete_hash_deny_list")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "reason": reason,
            "hashTagIdArray": [{"hash": hash, "tag": 0}],
        }

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.deleteHashBlacklist",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("delete_hash_deny_list successful")
        else:
            if self.debug >= 1:
                self.debug_print("delete_hash_deny_list failed")
        return request_response

    def get_sub_generations(self, object_id):
        if self.debug >= 1:
            self.debug_print("get_sub_generations")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "objectId": object_id,
        }

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.getSubGenerations",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("get_sub_generations successful")
        else:
            if self.debug >= 1:
                self.debug_print("get_sub_generations failed")
        return request_response

    def deploy(self, agent_object_id, sub_generation_id, notes=""):
        if self.debug >= 1:
            self.debug_print("deploy")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "agentObjectId": agent_object_id,
            "subGenerationId": sub_generation_id,
            "notes": notes,
        }

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.deploy", json.dumps(request_data), self.verify_cert
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("deploy successful")
        else:
            if self.debug >= 1:
                self.debug_print("deploy failed")
        return request_response

    def get_object_group(self, object_id):
        if self.debug >= 1:
            self.debug_print("get_object_group")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "objectId": object_id,
        }

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.getObjectGroup",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("get_object_group successful")
        else:
            if self.debug >= 1:
                self.debug_print("get_object_group failed")
        return request_response

    def unlock(self, object_id):
        if self.debug >= 1:
            self.debug_print("unlock")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "objectId": object_id,
        }

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.unlock", json.dumps(request_data), self.verify_cert
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("unlock successful")
        else:
            if self.debug >= 1:
                self.debug_print("unlock failed")
        return request_response

    def lock(self, object_id):
        if self.debug >= 1:
            self.debug_print("lock")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "objectId": object_id,
        }

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.lock", json.dumps(request_data), self.verify_cert
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("lock successful")
        else:
            if self.debug >= 1:
                self.debug_print("lock failed")
        return request_response

    def get_object(self, object_id):
        if self.debug >= 1:
            self.debug_print("get_object")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "objectId": object_id,
        }

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.getObject", json.dumps(request_data), self.verify_cert
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("get_object successful")
        else:
            if self.debug >= 1:
                self.debug_print("get_object failed")
        return request_response

    def force_sync(self, object_id):
        if self.debug >= 1:
            self.debug_print("force_sync")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "objectId": object_id,
        }

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.forceSync", json.dumps(request_data), self.verify_cert
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("force_sync successful")
        else:
            if self.debug >= 1:
                self.debug_print("force_sync failed")
        return request_response

    def view_file(self, object_detail_id):
        if self.debug >= 1:
            self.debug_print("view_file")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "objectDetailId": object_detail_id,
        }

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.viewFile", json.dumps(request_data), self.verify_cert
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("view_file successful")
        else:
            if self.debug >= 1:
                self.debug_print("view_file failed")
        return request_response

    def run_report_by_name(self, name, object_id=0, report_parameter_values=None):
        if self.debug >= 1:
            self.debug_print("run_report_by_name")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "name": name,
            "objectId": object_id,
        }

        if report_parameter_values is not None and report_parameter_values != "":
            request_data["reportParameterValues"] = report_parameter_values

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.runReportByName",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("run_report_by_name successful")
        else:
            if self.debug >= 1:
                self.debug_print("run_report_by_name failed")
        return request_response

    def get_current_compliance_items(self, object_id, compliance_scan_id=-1):
        if self.debug >= 1:
            self.debug_print("get_current_compliance_items")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "objectId": object_id,
        }
        if compliance_scan_id != -1:
            request_data["complianceScanId"] = compliance_scan_id

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.getCurrentComplianceItems",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("get_current_compliance_items successful")
        else:
            if self.debug >= 1:
                self.debug_print("get_current_compliance_items failed")
        return request_response

    def get_objects(
        self,
        object_type=-1,
        object_subtype=-1,
        parent_id=-1,
        object_id=-1,
        object_path_and_name="",
        recursive=False,
        filter=None,
    ):
        if self.debug >= 1:
            self.debug_print("get_objects")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "recursive": recursive,
            "objectPathAndName": object_path_and_name,
            "includeAllRepositories": True,
        }
        if filter is not None and filter != "":
            request_data["filter"] = filter
        if parent_id != -1:
            request_data["parentId"] = parent_id
        if object_id != -1:
            request_data["objectId"] = object_id
        if object_type != -1:
            request_data["objectType"] = object_type
        if object_subtype != -1:
            request_data["objectSubType"] = object_subtype

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.getObjects",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("get_objects successful")
        else:
            if self.debug >= 1:
                self.debug_print("get_objects failed")
        return request_response

    def get_agent_info(self, object_id):
        if self.debug >= 1:
            self.debug_print("get_agent_info")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "objectId": object_id,
        }

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.getAgentInfo",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("get_agent_info successful")
        else:
            if self.debug >= 1:
                self.debug_print("get_agent_info failed")
        return request_response

    def get_compliance_archive_details(self, object_id, compliance_scan_id=-1, filter=None, start=-1, end=-1):
        if self.debug >= 1:
            self.debug_print("get_compliance_archive_details")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "objectId": object_id,
        }
        if compliance_scan_id != -1:
            request_data["complianceScanId"] = compliance_scan_id
        if start != -1:
            request_data["start"] = start
        if end != -1:
            request_data["end"] = end
        if filter is not None and filter != "":
            request_data["filter"] = filter

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.getComplianceArchiveDetails",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("get_compliance_archive_details successful")
        else:
            if self.debug >= 1:
                self.debug_print("get_compliance_archive_details failed")
        return request_response

    def get_compliance_archive_summary(self, object_id, compliance_scan_id=-1, filter=None, start=-1, end=-1):
        if self.debug >= 1:
            self.debug_print("get_compliance_archive_summary")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "objectId": object_id,
        }
        if compliance_scan_id != -1:
            request_data["complianceScanId"] = compliance_scan_id
        if start != -1:
            request_data["start"] = start
        if end != -1:
            request_data["end"] = end
        if filter is not None and filter != "":
            request_data["filter"] = filter

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.getComplianceArchiveSummary",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("get_compliance_archive_summary successful")
        else:
            if self.debug >= 1:
                self.debug_print("get_compliance_archive_summary failed")
        return request_response

    def get_agent_object_id_by_alternate_system_id(self, alternate_system_id):
        if self.debug >= 1:
            self.debug_print("get_agent_object_id_by_alternate_system_id")
        request_data = {
            "authToken": self.auth_token,
            "server": self.server,
            "port": self.port,
            "apiKey": self.api_key,
            "alternateSystemId": alternate_system_id,
        }

        if self.debug >= 4:
            self.debug_print("Request Data:" + json.dumps(request_data))
        response = self.http_post(
            self.url_root + "Client.getAgentObjectIdByAlternateSystemId",
            json.dumps(request_data),
            self.verify_cert,
        )
        if self.debug >= 4:
            self.debug_print("Response:" + response)
        request_response = json.loads(response)
        if request_response["status"] == "success":
            if self.debug >= 1:
                self.debug_print("get_agent_object_id_by_alternate_system_id successful")
        else:
            if self.debug >= 1:
                self.debug_print("get_agent_object_id_by_alternate_system_id failed")
        return request_response

    def deploy_by_date(self, date, object_id):
        if self.debug >= 4:
            self.debug_print("deploy_by_date")
        request_response = self.get_sub_generations(object_id)
        results = request_response["results"]
        results = sorted(results, key=itemgetter("subGenerationId"), reverse=True)
        target_datetime = datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
        target_gen = 0
        agent_objectId = 0
        for subgen in results:
            subgen_datetime = datetime.strptime(
                subgen["creationDate"], "%Y-%m-%d %H:%M:%S"
            )
            if subgen_datetime <= target_datetime and target_gen == 0:
                objectGroupResponse = self.get_object_group(subgen["objectId"])
                objectGroupResults = objectGroupResponse.get("results")
                canDeploy = True
                isLocked = False
                for result in objectGroupResults:
                    for watch in result["watchArray"]:
                        if watch["storeAuthoritative"] is False:
                            canDeploy = False
                    if result["objectStatus"] == 2:
                        isLocked = True

                if canDeploy is True:
                    if isLocked is True:
                        self.unlock(subgen["objectId"])
                        while isLocked is True:
                            objectResponse = self.get_object(subgen["objectId"])
                            objectResults = objectResponse["results"]
                            for objectResult in objectResults:
                                if objectResult["objectStatus"] == 1:
                                    isLocked = False
                                else:
                                    time.sleep(2)

                    target_gen = subgen["subGenerationId"]
                    agent_objectId = subgen["agentObjectId"]
        if self.debug >= 4:
            self.debug_print("Got targetgent:" + str(target_gen))
        if target_gen != 0:
            return self.deploy(agent_objectId, target_gen)

    def compliance_scan_children(self, object_parent_id):
        request_response = self.get_objects(parent_id=object_parent_id)
        results = request_response["results"]

        for object in results:
            if object["objectSubType"] == self.OBJECT_SUBTYPE_COMPLIANCE:
                if self.debug >= 4:
                    self.debug_print("Scanning compliance object:" + str(object["objectId"]))
                self.force_sync(object["objectId"])

    def compliance_scan_with_summary(self, object_id, retry_count=20, retry_seconds=10):
        if self.debug >= 4:
            self.debug_print("compliance_scan_with_summary")
        # Get the last scan id for this object
        request_response = self.get_compliance_archive_summary(object_id)
        results = request_response["results"]
        results = sorted(results, key=itemgetter("scanid"))
        last_scanid = 0

        for scan in results:
            last_scanid = scan["scanid"]
        if self.debug >= 4:
            self.debug_print("Got last scan id:" + str(last_scanid))
        # Get the last log id
        filter = [{"name": "lObjectID", "operator": "=", "value": object_id}]
        sorts = [{"field": "id", "descending": True}]
        request_response = self.get_events(start=1, end=1, filter=filter, sorts=sorts)
        results = request_response["results"]
        last_logid = 0

        for log in results:
            last_logid = log["id"]
        if self.debug >= 4:
            self.debug_print("Got last log id:" + str(last_logid))

        # Start the scan
        self.force_sync(object_id)
        # Wait for sync to complete
        filter = [
            {"name": "lObjectID", "operator": "=", "value": object_id},
            {"name": "", "operator": "AND", "value": 0},
            {"name": "szMessageID", "operator": "=", "value": "S_LOGMSG_0000000135             "},
            {"name": "", "operator": "AND", "value": 0},
            {"name": "id", "operator": ">", "value": last_logid},
        ]
        resultcount = 0
        tries = 0
        while resultcount == 0 and tries < retry_count:
            tries = tries + 1
            if self.debug >= 4:
                self.debug_print("Polling log entries")
            request_response = self.get_events(filter=filter)
            results = request_response["results"]
            for scan in results:
                resultcount = resultcount + 1
            if resultcount == 0:
                if self.debug >= 4:
                    self.debug_print("Sleeping to wait for compliance results: Try " + str(tries) + " of " + str(retry_count))
                time.sleep(retry_seconds)

        if resultcount == 0:
            if self.debug >= 4:
                self.debug_print("Timeout waiting for compliance scan to complete")
        # Get results
        filter = [{"name": "scanid", "operator": ">", "value": last_scanid}]
        request_response = self.get_compliance_archive_summary(object_id, filter=filter)
        return request_response

    def get_agent_object_by_name(self, agent_name):
        if self.debug >= 4:
            self.debug_print("get_agent_object_id_by_name")

        request_response = self.get_objects(object_path_and_name=agent_name, object_type=self.OBJECT_TYPE_AGENT)
        results = request_response["results"]
        ret_data: Dict[str, Any] = {}
        ret_results: List[Dict[str, Any]] = []
        for object in results:
            if object['name'] == agent_name:
                ret_results.append(object)
        ret_data['status'] = 'Success'
        ret_data['errorCode'] = ''
        ret_data['errorDescription'] = ''
        ret_data['results'] = ret_results
        if self.debug >= 4:
            self.debug_print("get_agent_object_id_by_name returning:" + str(ret_data))

        return ret_data

    def get_agent_object_by_alternate_id(self, alternate_system_id):
        if self.debug >= 4:
            self.debug_print("get_agent_object_by_alternate_id")

        request_response = self.get_agent_object_id_by_alternate_system_id(alternate_system_id=alternate_system_id)
        results = request_response["results"]
        ret_data: Dict[str, Any] = {}
        ret_results: List[Dict[str, Any]] = []
        for result in results:
            if result['agentObjectId'] > 0:
                request_response_object = self.get_object(result['agentObjectId'])
                results_object = request_response_object["results"]
                for result_object in results_object:
                    ret_results.append(result_object)
        ret_data['status'] = 'Success'
        ret_data['errorCode'] = ''
        ret_data['errorDescription'] = ''
        ret_data['results'] = ret_results
        if self.debug >= 4:
            self.debug_print("get_agent_object_by_alternate_id returning:" + str(ret_data))

        return ret_data

    def get_agent_object_by_ip(self, ip):
        if self.debug >= 4:
            self.debug_print("get_agent_object_by_ip")
        if ip.find(':') == -1:
            ip_fixed = "cast($DQ$" + ip + "$DQ$::inet - $DQ$0.0.0.0$DQ$::inet as bigint)"
        else:
            ip_fixed = "cast($DQ$" + ip + "$DQ$::inet - $DQ$::ffff:0.0.0.0$DQ$::inet as bigint)"
        filter = [
            {"name": "", "operator": "(", "value": ""},
            {"name": "position($DQ$.$DQ$ in get_objects.szlastip)", "operator": ">", "value": 0},
            {"name": "", "operator": "or", "value": ""},
            {"name": "position($DQ$:$DQ$ in get_objects.szlastip)", "operator": ">", "value": 0},
            {"name": "", "operator": ")", "value": ""},
            {"name": "", "operator": "AND", "value": ""},
            {"name": "cast(iif(position($DQ$:$DQ$ in get_objects.szlastip) > 0  ,cast(get_objects.szlastip::inet - $DQ$::ffff:0.0.0.0$DQ$::inet  as text),iif(position($DQ$.$DQ$ in get_objects.szlastip) > 0 ,cast(get_objects.szlastip::inet - $DQ$::ffff:0.0.0.0$DQ$::inet as text),$DQ$0$DQ$)) as bigint) - " + ip_fixed, "operator": "=", "value": 0},
        ]
        request_response = self.get_objects(object_type=self.OBJECT_TYPE_AGENT, filter=filter)
        results = request_response["results"]
        ret_data: Dict[str, Any] = {}
        ret_results: List[Dict[str, Any]] = []
        for object in results:
            ret_results.append(object)
        ret_data['status'] = 'Success'
        ret_data['errorCode'] = ''
        ret_data['errorDescription'] = ''
        ret_data['results'] = ret_results

        if self.debug >= 4:
            self.debug_print("get_agent_object_by_ip returning:" + str(ret_data))
        return ret_data


################################################################
# CimTrak Python API End
################################################################

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """
MAX_INCIDENTS_TO_FETCH = 50

""" CLIENT CLASS """


class Client(BaseClient, CimTrak):
    def http_post(self, URL, data, verify_cert):
        response = self._http_request(
            method="POST", url_suffix=URL, data=data, resp_type="text"
        )
        return response

    def debug_print(self, text):
        demisto.debug(text)

    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def test(self) -> Dict[str, Any]:
        request_response = self.get_unreconciled_items(1, MAX_INCIDENTS_TO_FETCH)
        return request_response


""" HELPER FUNCTIONS """


def parse_domain_date(
    domain_date: Union[List[str], str], date_format: str = "%Y-%m-%dT%H:%M:%S.000Z"
) -> Optional[str]:
    """Converts whois date format to an ISO8601 string

    Converts the HelloWorld domain WHOIS date (YYYY-mm-dd HH:MM:SS) format
    in a datetime. If a list is returned with multiple elements, takes only
    the first one.

    :type domain_date: ``Union[List[str],str]``
    :param date_format:
            a string or list of strings with the format 'YYYY-mm-DD HH:MM:SS'

    :return: Parsed time in ISO8601 format
    :rtype: ``Optional[str]``
    """

    if isinstance(domain_date, str):
        # if str parse the value
        domain_date_dt = dateparser.parse(domain_date)
        if domain_date_dt:
            return domain_date_dt.strftime(date_format)
    elif (
        isinstance(domain_date, list)
        and len(domain_date) > 0
        and isinstance(domain_date[0], str)
    ):
        # if list with at least one element, parse the first element
        domain_date_dt = dateparser.parse(domain_date[0])
        if domain_date_dt:
            return domain_date_dt.strftime(date_format)
    # in any other case return nothing
    return None


""" COMMAND FUNCTIONS """


def test_module(client: Client, first_fetch_time: int) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type name: ``str``
    :param name: name to append to the 'Hello' string

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        request_response = client.test()
        if request_response["status"] == "success":
            return "ok"
    except DemistoException as e:
        if "Forbidden" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return "Unknown error"


def fetch_incidents(
    client: Client,
    max_results: int,
    last_run: Dict[str, int],
    first_fetch_time: Optional[int],
    alert_status: Optional[str],
    min_severity: str,
    alert_type: Optional[str],
):
    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get("last_fetch", None)
    # Handle first fetch time
    if last_fetch is None or last_fetch == "":
        # if missing, use what provided via first_fetch_time
        last_fetch = 0
    else:
        # otherwise use the stored last fetch
        last_fetch = int(last_fetch)
    # for type checking, making sure that latest_created_time is int

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []
    # Get the CSV list of severities from min_severity
    # severity = ',Low'
    request_response = client.get_unreconciled_items(1, MAX_INCIDENTS_TO_FETCH)

    if request_response["status"] == "success":
        for item in request_response["results"]:
            if item.get("id") > last_fetch:
                incident_name = "CimTrak - " + item["changeFromPrevious"]
                agent_ip = ""
                request_response_agent_info = client.get_agent_info(item.get("parentId"))
                event_results_agent_info = request_response_agent_info["results"]
                for agent_info in event_results_agent_info:
                    agent_info_state = agent_info['state']
                    agent_ip = agent_info_state['agentIp']
                item['ip'] = agent_ip
                incident = {
                    "name": incident_name,
                    "details": item["changeFromPrevious"] + ": " + item["dirAndFile"],
                    "occurred": parse_domain_date(item.get("eventTime")),
                    "rawJSON": json.dumps(item),
                    "type": "CimTrak Alert",  # Map to a specific XSOAR incident Type
                    "severity": IncidentSeverity.MEDIUM,
                    "CustomFields": {  # Map specific XSOAR Custom Fields
                        "hash": item.get("hash"),
                        "fileSize": item.get("fileSize"),
                        "ticketNumber": item.get("ticketNumber"),
                        "objectPath": item.get("objectPath"),
                    },
                }

                incidents.append(incident)

                # Update last run and add incident if the incident is newer than last fetch

                # if incident_created_time > latest_created_time:
                last_fetch = item.get("id")

    next_run = {"last_fetch": last_fetch}
    return next_run, incidents


################################################################
# CimTrak Palo Alto Custom Functions Begin
################################################################
def ResolveBool(value):
    if value.lower() == "false" or value == "0":
        return False
    else:
        return True


def ResolveString(value):
    if not value or value == "":
        return ""
    else:
        return value


def ResolveJson(value):
    if not value or value == "":
        return None
    else:
        return json.loads(value)


def get_events_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    start = int(ResolveString(args.get('Start')))
    end = int(ResolveString(args.get('End')))
    filter = ResolveJson(args.get('Filter'))
    sorts = ResolveJson(args.get('Sorts'))
    response = client.get_events(
        start=start,
        end=end,
        filter=filter,
        sorts=sorts
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'id' not in result:
            result['id'] = ''
        if 'leventid' not in result:
            result['leventid'] = ''
        if 'lagentid' not in result:
            result['lagentid'] = ''
        if 'lobjectid' not in result:
            result['lobjectid'] = ''
        if 'lobjectdetailid' not in result:
            result['lobjectdetailid'] = ''
        if 'lobjectdetailidint' not in result:
            result['lobjectdetailidint'] = ''
        if 'lmessagelevel' not in result:
            result['lmessagelevel'] = ''
        if 'szuser' not in result:
            result['szuser'] = ''
        if 'szfileuser' not in result:
            result['szfileuser'] = ''
        if 'szmessageid' not in result:
            result['szmessageid'] = ''
        if 'szmessage' not in result:
            result['szmessage'] = ''
        if 'szfile' not in result:
            result['szfile'] = ''
        if 'szcorrectionid' not in result:
            result['szcorrectionid'] = ''
        if 'szcorrection' not in result:
            result['szcorrection'] = ''
        if 'lcategory' not in result:
            result['lcategory'] = ''
        if 'lemailsent' not in result:
            result['lemailsent'] = ''
        if 'lstoragestatus' not in result:
            result['lstoragestatus'] = ''
        if 'dtmdatetime1' not in result:
            result['dtmdatetime1'] = ''
        if 'dtmdatetime2' not in result:
            result['dtmdatetime2'] = ''
        if 'szchecksum' not in result:
            result['szchecksum'] = ''
        if 'status' not in result:
            result['status'] = ''
        if 'lprocessid' not in result:
            result['lprocessid'] = ''
        if 'lthreadid' not in result:
            result['lthreadid'] = ''
        if 'szprocess' not in result:
            result['szprocess'] = ''
        if 'szforensicdata' not in result:
            result['szforensicdata'] = ''
        if 'dtmdeleted' not in result:
            result['dtmdeleted'] = ''
        if 'ltickcount' not in result:
            result['ltickcount'] = ''
        if 'lsubtype' not in result:
            result['lsubtype'] = ''
        if 'ticketNumber' not in result:
            result['ticketNumber'] = ''
        if 'ldeleteobjectdetailid' not in result:
            result['ldeleteobjectdetailid'] = ''
        if 'bfoundinblacklist' not in result:
            result['bfoundinblacklist'] = ''
        if 'filecontenthash' not in result:
            result['filecontenthash'] = ''
        if 'lobjectsettingid' not in result:
            result['lobjectsettingid'] = ''
        if 'reconciled' not in result:
            result['reconciled'] = ''
        if 'isauthcopy' not in result:
            result['isauthcopy'] = ''
        if 'externalticketnumber' not in result:
            result['externalticketnumber'] = ''
        if 'lparentid' not in result:
            result['lparentid'] = ''
        if 'szobjectpath' not in result:
            result['szobjectpath'] = ''
        if 'dfilesize' not in result:
            result['dfilesize'] = ''
        result_final = {
            'id': result['id'],
            'leventid': result['leventid'],
            'lagentid': result['lagentid'],
            'lobjectid': result['lobjectid'],
            'lobjectdetailid': result['lobjectdetailid'],
            'lobjectdetailidint': result['lobjectdetailidint'],
            'lmessagelevel': result['lmessagelevel'],
            'szuser': result['szuser'],
            'szfileuser': result['szfileuser'],
            'szmessageid': result['szmessageid'],
            'szmessage': result['szmessage'],
            'szfile': result['szfile'],
            'szcorrectionid': result['szcorrectionid'],
            'szcorrection': result['szcorrection'],
            'lcategory': result['lcategory'],
            'lemailsent': result['lemailsent'],
            'lstoragestatus': result['lstoragestatus'],
            'dtmdatetime1': result['dtmdatetime1'],
            'dtmdatetime2': result['dtmdatetime2'],
            'szchecksum': result['szchecksum'],
            'status': result['status'],
            'lprocessid': result['lprocessid'],
            'lthreadid': result['lthreadid'],
            'szprocess': result['szprocess'],
            'szforensicdata': result['szforensicdata'],
            'dtmdeleted': result['dtmdeleted'],
            'ltickcount': result['ltickcount'],
            'lsubtype': result['lsubtype'],
            'ticketNumber': result['ticketNumber'],
            'ldeleteobjectdetailid': result['ldeleteobjectdetailid'],
            'bfoundinblacklist': result['bfoundinblacklist'],
            'filecontenthash': result['filecontenthash'],
            'lobjectsettingid': result['lobjectsettingid'],
            'reconciled': result['reconciled'],
            'isauthcopy': result['isauthcopy'],
            'externalticketnumber': result['externalticketnumber'],
            'lparentid': result['lparentid'],
            'szobjectpath': result['szobjectpath'],
            'dfilesize': result['dfilesize'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.Event',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def file_analysis_by_hash_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    hash = ResolveString(args.get('Hash'))
    response = client.file_analysis_by_hash(
        hash=hash
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'analysisEngine' not in result:
            result['analysisEngine'] = ''
        if 'analysisSuccess' not in result:
            result['analysisSuccess'] = ''
        if 'analysisResults' not in result:
            result['analysisResults'] = ''
        result_final = {
            'analysisEngine': result['analysisEngine'],
            'analysisSuccess': result['analysisSuccess'],
            'analysisResults': result['analysisResults'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.FileAnalysis',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def file_analysis_by_object_detail_id_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    object_detail_id = int(ResolveString(args.get('ObjectDetailId')))
    response = client.file_analysis_by_object_detail_id(
        object_detail_id=object_detail_id
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'analysisEngine' not in result:
            result['analysisEngine'] = ''
        if 'analysisSuccess' not in result:
            result['analysisSuccess'] = ''
        if 'analysisResults' not in result:
            result['analysisResults'] = ''
        result_final = {
            'analysisEngine': result['analysisEngine'],
            'analysisSuccess': result['analysisSuccess'],
            'analysisResults': result['analysisResults'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.FileAnalysis',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def check_file_against_trusted_file_registry_by_hash_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    hashes = ResolveString(args.get('Hashes')).split(',')
    response = client.check_file_against_trusted_file_registry_by_hash(
        hashes=hashes
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'hash' not in result:
            result['hash'] = ''
        result_final = {
            'hash': result['hash'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.TrustedFileRegistry',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def promote_authoritative_baseline_files_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    object_detail_ids = ResolveString(args.get('ObjectDetaildIds')).split(',')
    response = client.promote_authoritative_baseline_files(
        object_detail_ids=object_detail_ids
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'objectDetailId' not in result:
            result['objectDetailId'] = ''
        if 'status' not in result:
            result['status'] = ''
        if 'errorCode' not in result:
            result['errorCode'] = ''
        if 'errorDescription' not in result:
            result['errorDescription'] = ''
        result_final = {
            'objectDetailId': result['objectDetailId'],
            'status': result['status'],
            'errorCode': result['errorCode'],
            'errorDescription': result['errorDescription'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.AuthoritizeBaseline',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def demote_authoritative_baseline_files_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    object_detail_ids = ResolveString(args.get('ObjectDetaildIds')).split(',')
    response = client.demote_authoritative_baseline_files(
        object_detail_ids=object_detail_ids
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'objectDetailId' not in result:
            result['objectDetailId'] = ''
        if 'status' not in result:
            result['status'] = ''
        result_final = {
            'objectDetailId': result['objectDetailId'],
            'status': result['status'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.AuthoritizeBaseline',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def update_task_disposition_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    task_id = int(ResolveString(args.get('taskId')))
    disposition = ResolveString(args.get('Disposition'))
    response = client.update_task_disposition(
        task_id=task_id,
        disposition=disposition
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'taskId' not in result:
            result['taskId'] = ''
        if 'status' not in result:
            result['status'] = ''
        result_final = {
            'taskId': result['taskId'],
            'status': result['status'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.TaskDisposition',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def get_tickets_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    response = client.get_tickets(

    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'id' not in result:
            result['id'] = ''
        if 'sentiment' not in result:
            result['sentiment'] = ''
        if 'sentimenttypeid' not in result:
            result['sentimenttypeid'] = ''
        if 'title' not in result:
            result['title'] = ''
        if 'description' not in result:
            result['description'] = ''
        if 'priority' not in result:
            result['priority'] = ''
        if 'disposition' not in result:
            result['disposition'] = ''
        if 'creationDate' not in result:
            result['creationDate'] = ''
        if 'createdByUser' not in result:
            result['createdByUser'] = ''
        if 'modificationDate' not in result:
            result['modificationDate'] = ''
        if 'modifiedByUser' not in result:
            result['modifiedByUser'] = ''
        if 'requiresAcknowledgement' not in result:
            result['requiresAcknowledgement'] = ''
        if 'requiresConfirmation' not in result:
            result['requiresConfirmation'] = ''
        if 'requiresAssessment' not in result:
            result['requiresAssessment'] = ''
        if 'startDate' not in result:
            result['startDate'] = ''
        if 'endDate' not in result:
            result['endDate'] = ''
        if 'autoPromote' not in result:
            result['autoPromote'] = ''
        if 'assignedToUserId' not in result:
            result['assignedToUserId'] = ''
        if 'assignedToUser' not in result:
            result['assignedToUser'] = ''
        if 'assignedToGroupId' not in result:
            result['assignedToGroupId'] = ''
        if 'assignedToGroup' not in result:
            result['assignedToGroup'] = ''
        if 'externalTicketNumber' not in result:
            result['externalTicketNumber'] = ''
        if 'externalTicketType' not in result:
            result['externalTicketType'] = ''
        if 'tasks' not in result:
            result['tasks'] = ''
        if 'comments' not in result:
            result['comments'] = ''
        if 'events' not in result:
            result['events'] = ''
        result_final = {
            'taskId': result['id'],
            'sentiment': result['sentiment'],
            'sentimenttypeid': result['sentimenttypeid'],
            'title': result['title'],
            'description': result['description'],
            'priority': result['priority'],
            'disposition': result['disposition'],
            'creationDate': result['creationDate'],
            'createdByUser': result['createdByUser'],
            'modificationDate': result['modificationDate'],
            'modifiedByUser': result['modifiedByUser'],
            'requiresAcknowledgement': result['requiresAcknowledgement'],
            'requiresConfirmation': result['requiresConfirmation'],
            'requiresAssessment': result['requiresAssessment'],
            'startDate': result['startDate'],
            'endDate': result['endDate'],
            'autoPromote': result['autoPromote'],
            'assignedToUserId': result['assignedToUserId'],
            'assignedToUser': result['assignedToUser'],
            'assignedToGroupId': result['assignedToGroupId'],
            'assignedToGroup': result['assignedToGroup'],
            'externalTicketNumber': result['externalTicketNumber'],
            'externalTicketType': result['externalTicketType'],
            'tasks': result['tasks'],
            'comments': result['comments'],
            'events': result['events'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.Ticket',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def get_ticket_tasks_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    response = client.get_ticket_tasks(

    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'id' not in result:
            result['id'] = ''
        if 'ticketId' not in result:
            result['ticketId'] = ''
        if 'agentObjectId' not in result:
            result['agentObjectId'] = ''
        if 'startDate' not in result:
            result['startDate'] = ''
        if 'endDate' not in result:
            result['endDate'] = ''
        if 'disposition' not in result:
            result['disposition'] = ''
        if 'creationDate' not in result:
            result['creationDate'] = ''
        if 'createdByUserId' not in result:
            result['createdByUserId'] = ''
        if 'modificationDate' not in result:
            result['modificationDate'] = ''
        if 'modifiedByUserId' not in result:
            result['modifiedByUserId'] = ''
        if 'assignedToUserId' not in result:
            result['assignedToUserId'] = ''
        if 'assignedToGroupId' not in result:
            result['assignedToGroupId'] = ''
        if 'assigneeDisposition' not in result:
            result['assigneeDisposition'] = ''
        if 'ticketTitle' not in result:
            result['ticketTitle'] = ''
        if 'description' not in result:
            result['description'] = ''
        if 'priority' not in result:
            result['priority'] = ''
        if 'ticketDisposition' not in result:
            result['ticketDisposition'] = ''
        if 'ticketCreationDate' not in result:
            result['ticketCreationDate'] = ''
        if 'ticketCreatedByUserId' not in result:
            result['ticketCreatedByUserId'] = ''
        if 'ticketModificationDate' not in result:
            result['ticketModificationDate'] = ''
        if 'requiresAcknowledgement' not in result:
            result['requiresAcknowledgement'] = ''
        if 'requiresConfirmation' not in result:
            result['requiresConfirmation'] = ''
        if 'requiresAssessment' not in result:
            result['requiresAssessment'] = ''
        if 'ticketNumber' not in result:
            result['ticketNumber'] = ''
        if 'agentName' not in result:
            result['agentName'] = ''
        if 'createdByUsername' not in result:
            result['createdByUsername'] = ''
        if 'modifiedByUsername' not in result:
            result['modifiedByUsername'] = ''
        if 'assigneeName' not in result:
            result['assigneeName'] = ''
        result_final = {
            'taskId': result['id'],
            'ticketId': result['ticketId'],
            'agentObjectId': result['agentObjectId'],
            'startDate': result['startDate'],
            'endDate': result['endDate'],
            'disposition': result['disposition'],
            'creationDate': result['creationDate'],
            'createdByUserId': result['createdByUserId'],
            'modificationDate': result['modificationDate'],
            'modifiedByUserId': result['modifiedByUserId'],
            'assignedToUserId': result['assignedToUserId'],
            'assignedToGroupId': result['assignedToGroupId'],
            'assigneeDisposition': result['assigneeDisposition'],
            'ticketTitle': result['ticketTitle'],
            'description': result['description'],
            'priority': result['priority'],
            'ticketDisposition': result['ticketDisposition'],
            'ticketCreationDate': result['ticketCreationDate'],
            'ticketCreatedByUserId': result['ticketCreatedByUserId'],
            'ticketModificationDate': result['ticketModificationDate'],
            'requiresAcknowledgement': result['requiresAcknowledgement'],
            'requiresConfirmation': result['requiresConfirmation'],
            'requiresAssessment': result['requiresAssessment'],
            'ticketNumber': result['ticketNumber'],
            'agentName': result['agentName'],
            'createdByUsername': result['createdByUsername'],
            'modifiedByUsername': result['modifiedByUsername'],
            'assigneeName': result['assigneeName'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.TicketTask',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def add_ticket_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    title = ResolveString(args.get('title'))
    priority = int(ResolveString(args.get('priority')))
    description = ResolveString(args.get('description'))
    start_date = ResolveString(args.get('startDate'))
    end_date = ResolveString(args.get('endDate'))
    external_ticket_number = ResolveString(args.get('externalTicketNumber'))
    external_ticket_type = ResolveString(args.get('externalTicketType'))
    auto_promote = ResolveBool(args.get('autoPromote'))
    disposition = ResolveString(args.get('disposition'))
    requires_acknowledgement = ResolveBool(args.get('requiresAcknowledgement'))
    requires_assessment = ResolveBool(args.get('requiresAssessment'))
    requires_confirmation = ResolveBool(args.get('requiresConfirmation'))
    assigned_to_user_id = int(ResolveString(args.get('assignedToUserId')))
    assigned_to_user = ResolveString(args.get('assignedToUser'))
    assigned_to_group_id = int(ResolveString(args.get('assignedToGroupId')))
    assigned_to_group = ResolveString(args.get('assignedToGroup'))
    response = client.add_ticket(
        title=title,
        priority=priority,
        description=description,
        start_date=start_date,
        end_date=end_date,
        external_ticket_number=external_ticket_number,
        external_ticket_type=external_ticket_type,
        auto_promote=auto_promote,
        disposition=disposition,
        requires_acknowledgement=requires_acknowledgement,
        requires_assessment=requires_assessment,
        requires_confirmation=requires_confirmation,
        assigned_to_user_id=assigned_to_user_id,
        assigned_to_user=assigned_to_user,
        assigned_to_group_id=assigned_to_group_id,
        assigned_to_group=assigned_to_group
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'id' not in result:
            result['id'] = ''
        if 'ticketNumber' not in result:
            result['ticketNumber'] = ''
        if 'sentiment' not in result:
            result['sentiment'] = ''
        if 'sentimenttypeid' not in result:
            result['sentimenttypeid'] = ''
        if 'title' not in result:
            result['title'] = ''
        if 'description' not in result:
            result['description'] = ''
        if 'priority' not in result:
            result['priority'] = ''
        if 'disposition' not in result:
            result['disposition'] = ''
        if 'creationDate' not in result:
            result['creationDate'] = ''
        if 'createdByUser' not in result:
            result['createdByUser'] = ''
        if 'modificationDate' not in result:
            result['modificationDate'] = ''
        if 'modifiedByUser' not in result:
            result['modifiedByUser'] = ''
        if 'requiresAcknowledgement' not in result:
            result['requiresAcknowledgement'] = ''
        if 'requiresConfirmation' not in result:
            result['requiresConfirmation'] = ''
        if 'requiresAssessment' not in result:
            result['requiresAssessment'] = ''
        if 'startDate' not in result:
            result['startDate'] = ''
        if 'endDate' not in result:
            result['endDate'] = ''
        if 'autoPromote' not in result:
            result['autoPromote'] = ''
        if 'assignedToUserId' not in result:
            result['assignedToUserId'] = ''
        if 'assignedToUser' not in result:
            result['assignedToUser'] = ''
        if 'assignedToGroupId' not in result:
            result['assignedToGroupId'] = ''
        if 'assignedToGroup' not in result:
            result['assignedToGroup'] = ''
        if 'externalTicketNumber' not in result:
            result['externalTicketNumber'] = ''
        if 'externalTicketType' not in result:
            result['externalTicketType'] = ''
        if 'tasks' not in result:
            result['tasks'] = ''
        if 'comments' not in result:
            result['comments'] = ''
        if 'events' not in result:
            result['events'] = ''
        result_final = {
            'taskId': result['id'],
            'ticketNumber': result['ticketNumber'],
            'sentiment': result['sentiment'],
            'sentimenttypeid': result['sentimenttypeid'],
            'title': result['title'],
            'description': result['description'],
            'priority': result['priority'],
            'disposition': result['disposition'],
            'creationDate': result['creationDate'],
            'createdByUser': result['createdByUser'],
            'modificationDate': result['modificationDate'],
            'modifiedByUser': result['modifiedByUser'],
            'requiresAcknowledgement': result['requiresAcknowledgement'],
            'requiresConfirmation': result['requiresConfirmation'],
            'requiresAssessment': result['requiresAssessment'],
            'startDate': result['startDate'],
            'endDate': result['endDate'],
            'autoPromote': result['autoPromote'],
            'assignedToUserId': result['assignedToUserId'],
            'assignedToUser': result['assignedToUser'],
            'assignedToGroupId': result['assignedToGroupId'],
            'assignedToGroup': result['assignedToGroup'],
            'externalTicketNumber': result['externalTicketNumber'],
            'externalTicketType': result['externalTicketType'],
            'tasks': result['tasks'],
            'comments': result['comments'],
            'events': result['events'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.Ticket',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def update_ticket_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    ticket_id = int(ResolveString(args.get('ticketId')))
    title = ResolveString(args.get('title'))
    priority = int(ResolveString(args.get('priority')))
    description = ResolveString(args.get('description'))
    start_date = ResolveString(args.get('startDate'))
    end_date = ResolveString(args.get('endDate'))
    external_ticket_number = ResolveString(args.get('externalTicketNumber'))
    external_ticket_type = ResolveString(args.get('externalTicketType'))
    auto_promote = ResolveBool(args.get('autoPromote'))
    disposition = ResolveString(args.get('disposition'))
    requires_acknowledgement = ResolveBool(args.get('requiresAcknowledgement'))
    requires_assessment = ResolveBool(args.get('requiresAssessment'))
    requires_confirmation = ResolveBool(args.get('requiresConfirmation'))
    assigned_to_user_id = int(ResolveString(args.get('assignedToUserId')))
    assigned_to_user = ResolveString(args.get('assignedToUser'))
    assigned_to_group_id = int(ResolveString(args.get('assignedToGroupId')))
    assigned_to_group = ResolveString(args.get('assignedToGroup'))
    response = client.update_ticket(
        ticket_id=ticket_id,
        title=title,
        priority=priority,
        description=description,
        start_date=start_date,
        end_date=end_date,
        external_ticket_number=external_ticket_number,
        external_ticket_type=external_ticket_type,
        auto_promote=auto_promote,
        disposition=disposition,
        requires_acknowledgement=requires_acknowledgement,
        requires_assessment=requires_assessment,
        requires_confirmation=requires_confirmation,
        assigned_to_user_id=assigned_to_user_id,
        assigned_to_user=assigned_to_user,
        assigned_to_group_id=assigned_to_group_id,
        assigned_to_group=assigned_to_group
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'id' not in result:
            result['id'] = ''
        if 'ticketNumber' not in result:
            result['ticketNumber'] = ''
        if 'sentiment' not in result:
            result['sentiment'] = ''
        if 'sentimenttypeid' not in result:
            result['sentimenttypeid'] = ''
        if 'title' not in result:
            result['title'] = ''
        if 'description' not in result:
            result['description'] = ''
        if 'priority' not in result:
            result['priority'] = ''
        if 'disposition' not in result:
            result['disposition'] = ''
        if 'creationDate' not in result:
            result['creationDate'] = ''
        if 'createdByUser' not in result:
            result['createdByUser'] = ''
        if 'modificationDate' not in result:
            result['modificationDate'] = ''
        if 'modifiedByUser' not in result:
            result['modifiedByUser'] = ''
        if 'requiresAcknowledgement' not in result:
            result['requiresAcknowledgement'] = ''
        if 'requiresConfirmation' not in result:
            result['requiresConfirmation'] = ''
        if 'requiresAssessment' not in result:
            result['requiresAssessment'] = ''
        if 'startDate' not in result:
            result['startDate'] = ''
        if 'endDate' not in result:
            result['endDate'] = ''
        if 'autoPromote' not in result:
            result['autoPromote'] = ''
        if 'assignedToUserId' not in result:
            result['assignedToUserId'] = ''
        if 'assignedToUser' not in result:
            result['assignedToUser'] = ''
        if 'assignedToGroupId' not in result:
            result['assignedToGroupId'] = ''
        if 'assignedToGroup' not in result:
            result['assignedToGroup'] = ''
        if 'externalTicketNumber' not in result:
            result['externalTicketNumber'] = ''
        if 'externalTicketType' not in result:
            result['externalTicketType'] = ''
        if 'tasks' not in result:
            result['tasks'] = ''
        if 'comments' not in result:
            result['comments'] = ''
        if 'events' not in result:
            result['events'] = ''
        result_final = {
            'taskId': result['id'],
            'ticketNumber': result['ticketNumber'],
            'sentiment': result['sentiment'],
            'sentimenttypeid': result['sentimenttypeid'],
            'title': result['title'],
            'description': result['description'],
            'priority': result['priority'],
            'disposition': result['disposition'],
            'creationDate': result['creationDate'],
            'createdByUser': result['createdByUser'],
            'modificationDate': result['modificationDate'],
            'modifiedByUser': result['modifiedByUser'],
            'requiresAcknowledgement': result['requiresAcknowledgement'],
            'requiresConfirmation': result['requiresConfirmation'],
            'requiresAssessment': result['requiresAssessment'],
            'startDate': result['startDate'],
            'endDate': result['endDate'],
            'autoPromote': result['autoPromote'],
            'assignedToUserId': result['assignedToUserId'],
            'assignedToUser': result['assignedToUser'],
            'assignedToGroupId': result['assignedToGroupId'],
            'assignedToGroup': result['assignedToGroup'],
            'externalTicketNumber': result['externalTicketNumber'],
            'externalTicketType': result['externalTicketType'],
            'tasks': result['tasks'],
            'comments': result['comments'],
            'events': result['events'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.Ticket',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def add_ticket_comment_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    ticket_id = int(ResolveString(args.get('ticketId')))
    comment = ResolveString(args.get('comment'))
    response = client.add_ticket_comment(
        ticket_id=ticket_id,
        comment=comment
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    return command_results


def add_hash_allow_list_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    hash = ResolveString(args.get('hash'))
    filename = ResolveString(args.get('filename'))
    source = ResolveString(args.get('source'))
    source_reference = ResolveString(args.get('sourceReference'))
    response = client.add_hash_allow_list(
        hash=hash,
        filename=filename,
        source=source,
        source_reference=source_reference
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'status' not in result:
            result['status'] = ''
        if 'errorCode' not in result:
            result['errorCode'] = ''
        if 'errorDescription' not in result:
            result['errorDescription'] = ''
        if 'hash' not in result:
            result['hash'] = ''
        if 'tagId' not in result:
            result['tagId'] = ''
        result_final = {
            'status': result['status'],
            'errorCode': result['errorCode'],
            'errorDescription': result['errorDescription'],
            'hash': result['hash'],
            'tagId': result['tagId'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.AllowList',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def add_hash_deny_list_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    hash = ResolveString(args.get('hash'))
    filename = ResolveString(args.get('filename'))
    source = ResolveString(args.get('source'))
    source_reference = ResolveString(args.get('sourceReference'))
    response = client.add_hash_deny_list(
        hash=hash,
        filename=filename,
        source=source,
        source_reference=source_reference
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'status' not in result:
            result['status'] = ''
        if 'errorCode' not in result:
            result['errorCode'] = ''
        if 'errorDescription' not in result:
            result['errorDescription'] = ''
        if 'hash' not in result:
            result['hash'] = ''
        if 'tagId' not in result:
            result['tagId'] = ''
        result_final = {
            'status': result['status'],
            'errorCode': result['errorCode'],
            'errorDescription': result['errorDescription'],
            'hash': result['hash'],
            'tagId': result['tagId'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.DenyList',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def delete_hash_allow_list_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    hash = ResolveString(args.get('hash'))
    reason = ResolveString(args.get('reason'))
    response = client.delete_hash_allow_list(
        hash=hash,
        reason=reason
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'status' not in result:
            result['status'] = ''
        if 'hash' not in result:
            result['hash'] = ''
        if 'tagId' not in result:
            result['tagId'] = ''
        result_final = {
            'status': result['status'],
            'hash': result['hash'],
            'tagId': result['tagId'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.AllowList',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def delete_hash_deny_list_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    hash = ResolveString(args.get('hash'))
    reason = ResolveString(args.get('reason'))
    response = client.delete_hash_deny_list(
        hash=hash,
        reason=reason
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'status' not in result:
            result['status'] = ''
        if 'hash' not in result:
            result['hash'] = ''
        if 'tagId' not in result:
            result['tagId'] = ''
        result_final = {
            'status': result['status'],
            'hash': result['hash'],
            'tagId': result['tagId'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.DenyList',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def get_sub_generations_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    object_id = int(ResolveString(args.get('objectId')))
    response = client.get_sub_generations(
        object_id=object_id
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'caseSensitive' not in result:
            result['caseSensitive'] = ''
        if 'agentObjectId' not in result:
            result['agentObjectId'] = ''
        if 'subGenerationId' not in result:
            result['subGenerationId'] = ''
        if 'objectId' not in result:
            result['objectId'] = ''
        if 'generationId' not in result:
            result['generationId'] = ''
        if 'subRevision' not in result:
            result['subRevision'] = ''
        if 'notes' not in result:
            result['notes'] = ''
        if 'creationDate' not in result:
            result['creationDate'] = ''
        if 'files' not in result:
            result['files'] = ''
        if 'directories' not in result:
            result['directories'] = ''
        if 'totalSize' not in result:
            result['totalSize'] = ''
        if 'revision' not in result:
            result['revision'] = ''
        if 'userName' not in result:
            result['userName'] = ''
        result_final = {
            'caseSensitive': result['caseSensitive'],
            'agentObjectId': result['agentObjectId'],
            'subGenerationId': result['subGenerationId'],
            'objectId': result['objectId'],
            'generationId': result['generationId'],
            'subRevision': result['subRevision'],
            'notes': result['notes'],
            'creationDate': result['creationDate'],
            'files': result['files'],
            'directories': result['directories'],
            'totalSize': result['totalSize'],
            'revision': result['revision'],
            'userName': result['userName'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.SubGenerations',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def deploy_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    agent_object_id = int(ResolveString(args.get('agentObjectId')))
    sub_generation_id = int(ResolveString(args.get('subGenerationId')))
    notes = ResolveString(args.get('notes'))
    response = client.deploy(
        agent_object_id=agent_object_id,
        sub_generation_id=sub_generation_id,
        notes=notes
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    return command_results


def get_object_group_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    object_id = int(ResolveString(args.get('objectId')))
    response = client.get_object_group(
        object_id=object_id
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'agentIsFilesystem' not in result:
            result['agentIsFilesystem'] = ''
        if 'cancel' not in result:
            result['cancel'] = ''
        if 'connected' not in result:
            result['connected'] = ''
        if 'logsByDays' not in result:
            result['logsByDays'] = ''
        if 'requireNotes' not in result:
            result['requireNotes'] = ''
        if 'inService' not in result:
            result['inService'] = ''
        if 'children' not in result:
            result['children'] = ''
        if 'events' not in result:
            result['events'] = ''
        if 'intrusions' not in result:
            result['intrusions'] = ''
        if 'intrusionSize' not in result:
            result['intrusionSize'] = ''
        if 'objectId' not in result:
            result['objectId'] = ''
        if 'objectStatus' not in result:
            result['objectStatus'] = ''
        if 'objectSubType' not in result:
            result['objectSubType'] = ''
        if 'objectType' not in result:
            result['objectType'] = ''
        if 'parentId' not in result:
            result['parentId'] = ''
        if 'revisions' not in result:
            result['revisions'] = ''
        if 'templateId' not in result:
            result['templateId'] = ''
        if 'securityAdd' not in result:
            result['securityAdd'] = ''
        if 'securityEdit' not in result:
            result['securityEdit'] = ''
        if 'securityLock' not in result:
            result['securityLock'] = ''
        if 'securityReport' not in result:
            result['securityReport'] = ''
        if 'securityUnlock' not in result:
            result['securityUnlock'] = ''
        if 'securityView' not in result:
            result['securityView'] = ''
        if 'warnMinutes' not in result:
            result['warnMinutes'] = ''
        if 'contact' not in result:
            result['contact'] = ''
        if 'createDate' not in result:
            result['createDate'] = ''
        if 'description' not in result:
            result['description'] = ''
        if 'location' not in result:
            result['location'] = ''
        if 'name' not in result:
            result['name'] = ''
        if 'objectPath' not in result:
            result['objectPath'] = ''
        if 'url' not in result:
            result['url'] = ''
        if 'agentObjectId' not in result:
            result['agentObjectId'] = ''
        if 'objectsCustom' not in result:
            result['objectsCustom'] = ''
        if 'watchArray' not in result:
            result['watchArray'] = ''
        if 'comparisonMethod' not in result:
            result['comparisonMethod'] = ''
        result_final = {
            'agentIsFilesystem': result['agentIsFilesystem'],
            'cancel': result['cancel'],
            'connected': result['connected'],
            'logsByDays': result['logsByDays'],
            'requireNotes': result['requireNotes'],
            'inService': result['inService'],
            'children': result['children'],
            'events': result['events'],
            'intrusions': result['intrusions'],
            'intrusionSize': result['intrusionSize'],
            'objectId': result['objectId'],
            'objectStatus': result['objectStatus'],
            'objectSubType': result['objectSubType'],
            'objectType': result['objectType'],
            'parentId': result['parentId'],
            'revisions': result['revisions'],
            'templateId': result['templateId'],
            'securityAdd': result['securityAdd'],
            'securityEdit': result['securityEdit'],
            'securityLock': result['securityLock'],
            'securityReport': result['securityReport'],
            'securityUnlock': result['securityUnlock'],
            'securityView': result['securityView'],
            'warnMinutes': result['warnMinutes'],
            'contact': result['contact'],
            'createDate': result['createDate'],
            'description': result['description'],
            'location': result['location'],
            'name': result['name'],
            'objectPath': result['objectPath'],
            'url': result['url'],
            'agentObjectId': result['agentObjectId'],
            'objectsCustom': result['objectsCustom'],
            'watchArray': result['watchArray'],
            'comparisonMethod': result['comparisonMethod'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.ObjectGroup',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def unlock_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    object_id = int(ResolveString(args.get('objectId')))
    response = client.unlock(
        object_id=object_id
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    return command_results


def lock_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    object_id = int(ResolveString(args.get('objectId')))
    response = client.lock(
        object_id=object_id
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    return command_results


def get_object_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    object_id = int(ResolveString(args.get('objectId')))
    response = client.get_object(
        object_id=object_id
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'agentIsFilesystem' not in result:
            result['agentIsFilesystem'] = ''
        if 'cancel' not in result:
            result['cancel'] = ''
        if 'connected' not in result:
            result['connected'] = ''
        if 'logsByDays' not in result:
            result['logsByDays'] = ''
        if 'requireNotes' not in result:
            result['requireNotes'] = ''
        if 'inService' not in result:
            result['inService'] = ''
        if 'children' not in result:
            result['children'] = ''
        if 'events' not in result:
            result['events'] = ''
        if 'intrusions' not in result:
            result['intrusions'] = ''
        if 'intrusionSize' not in result:
            result['intrusionSize'] = ''
        if 'objectId' not in result:
            result['objectId'] = ''
        if 'objectStatus' not in result:
            result['objectStatus'] = ''
        if 'objectSubType' not in result:
            result['objectSubType'] = ''
        if 'objectType' not in result:
            result['objectType'] = ''
        if 'parentId' not in result:
            result['parentId'] = ''
        if 'revisions' not in result:
            result['revisions'] = ''
        if 'templateId' not in result:
            result['templateId'] = ''
        if 'securityAdd' not in result:
            result['securityAdd'] = ''
        if 'securityEdit' not in result:
            result['securityEdit'] = ''
        if 'securityLock' not in result:
            result['securityLock'] = ''
        if 'securityReport' not in result:
            result['securityReport'] = ''
        if 'securityUnlock' not in result:
            result['securityUnlock'] = ''
        if 'securityView' not in result:
            result['securityView'] = ''
        if 'warnMinutes' not in result:
            result['warnMinutes'] = ''
        if 'contact' not in result:
            result['contact'] = ''
        if 'createDate' not in result:
            result['createDate'] = ''
        if 'description' not in result:
            result['description'] = ''
        if 'location' not in result:
            result['location'] = ''
        if 'name' not in result:
            result['name'] = ''
        if 'objectPath' not in result:
            result['objectPath'] = ''
        if 'url' not in result:
            result['url'] = ''
        if 'agentObjectId' not in result:
            result['agentObjectId'] = ''
        result_final = {
            'agentIsFilesystem': result['agentIsFilesystem'],
            'cancel': result['cancel'],
            'connected': result['connected'],
            'logsByDays': result['logsByDays'],
            'requireNotes': result['requireNotes'],
            'inService': result['inService'],
            'children': result['children'],
            'events': result['events'],
            'intrusions': result['intrusions'],
            'intrusionSize': result['intrusionSize'],
            'objectId': result['objectId'],
            'objectStatus': result['objectStatus'],
            'objectSubType': result['objectSubType'],
            'objectType': result['objectType'],
            'parentId': result['parentId'],
            'revisions': result['revisions'],
            'templateId': result['templateId'],
            'securityAdd': result['securityAdd'],
            'securityEdit': result['securityEdit'],
            'securityLock': result['securityLock'],
            'securityReport': result['securityReport'],
            'securityUnlock': result['securityUnlock'],
            'securityView': result['securityView'],
            'warnMinutes': result['warnMinutes'],
            'contact': result['contact'],
            'createDate': result['createDate'],
            'description': result['description'],
            'location': result['location'],
            'name': result['name'],
            'objectPath': result['objectPath'],
            'url': result['url'],
            'agentObjectId': result['agentObjectId'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.Object',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def force_sync_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    object_id = int(ResolveString(args.get('objectId')))
    response = client.force_sync(
        object_id=object_id
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    return command_results


def view_file_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    object_detail_id = int(ResolveString(args.get('objectDetailId')))
    response = client.view_file(
        object_detail_id=object_detail_id
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'contents' not in result:
            result['contents'] = ''
        result_final = {
            'contents': result['contents'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.Sync',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def run_report_by_name_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    name = ResolveString(args.get('name'))
    object_id = int(ResolveString(args.get('objectId')))
    report_parameter_values = ResolveJson(args.get('ReportParameters'))
    response = client.run_report_by_name(
        name=name,
        object_id=object_id,
        report_parameter_values=report_parameter_values
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'html' not in result:
            result['html'] = ''
        result_final = {
            'html': result['html'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.Sync',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def deploy_by_date_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    date = ResolveString(args.get('date'))
    object_id = int(ResolveString(args.get('objectId')))
    response = client.deploy_by_date(
        date=date,
        object_id=object_id
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    return command_results


def get_current_compliance_items_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    object_id = int(ResolveString(args.get('ObjectId')))
    compliance_scan_id = int(ResolveString(args.get('ComplianceScanId')))
    response = client.get_current_compliance_items(
        object_id=object_id,
        compliance_scan_id=compliance_scan_id
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'objectid' not in result:
            result['objectid'] = ''
        if 'type' not in result:
            result['type'] = ''
        if 'name' not in result:
            result['name'] = ''
        if 'description' not in result:
            result['description'] = ''
        if 'scanstarttime' not in result:
            result['scanstarttime'] = ''
        if 'scanendtime' not in result:
            result['scanendtime'] = ''
        if 'scanid' not in result:
            result['scanid'] = ''
        if 'compliancemappingid' not in result:
            result['compliancemappingid'] = ''
        if 'id' not in result:
            result['id'] = ''
        result_final = {
            'objectid': result['objectid'],
            'type': result['type'],
            'name': result['name'],
            'description': result['description'],
            'scanstarttime': result['scanstarttime'],
            'scanendtime': result['scanendtime'],
            'scanid': result['scanid'],
            'compliancemappingid': result['compliancemappingid'],
            'id': result['id'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.ComplianceItems',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def get_objects_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    object_type = int(ResolveString(args.get('ObjectType')))
    object_subtype = int(ResolveString(args.get('ObjectSubType')))
    parent_id = int(ResolveString(args.get('ParentId')))
    object_id = int(ResolveString(args.get('ObjectId')))
    object_path_and_name = ResolveString(args.get('ObjectPathAndName'))
    recursive = ResolveBool(args.get('Recursive'))
    response = client.get_objects(
        object_type=object_type,
        object_subtype=object_subtype,
        parent_id=parent_id,
        object_id=object_id,
        object_path_and_name=object_path_and_name,
        recursive=recursive
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'repositoryDisplayName' not in result:
            result['repositoryDisplayName'] = ''
        if 'connected' not in result:
            result['connected'] = ''
        if 'agentObjectId' not in result:
            result['agentObjectId'] = ''
        if 'description' not in result:
            result['description'] = ''
        if 'name' not in result:
            result['name'] = ''
        if 'objectPath' not in result:
            result['objectPath'] = ''
        if 'agentIsFilesystem' not in result:
            result['agentIsFilesystem'] = ''
        if 'cancel' not in result:
            result['cancel'] = ''
        if 'logsByDays' not in result:
            result['logsByDays'] = ''
        if 'requireNotes' not in result:
            result['requireNotes'] = ''
        if 'inService' not in result:
            result['inService'] = ''
        if 'events' not in result:
            result['events'] = ''
        if 'intrusions' not in result:
            result['intrusions'] = ''
        if 'intrusionSize' not in result:
            result['intrusionSize'] = ''
        if 'objectId' not in result:
            result['objectId'] = ''
        if 'objectStatus' not in result:
            result['objectStatus'] = ''
        if 'objectSubType' not in result:
            result['objectSubType'] = ''
        if 'objectType' not in result:
            result['objectType'] = ''
        if 'parentId' not in result:
            result['parentId'] = ''
        if 'revisions' not in result:
            result['revisions'] = ''
        if 'templateId' not in result:
            result['templateId'] = ''
        if 'securityAdd' not in result:
            result['securityAdd'] = ''
        if 'securityEdit' not in result:
            result['securityEdit'] = ''
        if 'securityLock' not in result:
            result['securityLock'] = ''
        if 'securityReport' not in result:
            result['securityReport'] = ''
        if 'securityUnlock' not in result:
            result['securityUnlock'] = ''
        if 'securityView' not in result:
            result['securityView'] = ''
        if 'warnMinutes' not in result:
            result['warnMinutes'] = ''
        if 'contact' not in result:
            result['contact'] = ''
        if 'createDate' not in result:
            result['createDate'] = ''
        if 'location' not in result:
            result['location'] = ''
        if 'url' not in result:
            result['url'] = ''
        if 'parentName' not in result:
            result['parentName'] = ''
        if 'children' not in result:
            result['children'] = ''
        if 'agentVersion' not in result:
            result['agentVersion'] = ''
        if 'agentBuild' not in result:
            result['agentBuild'] = ''
        if 'agentOsVersion' not in result:
            result['agentOsVersion'] = ''
        if 'agentIp' not in result:
            result['agentIp'] = ''
        if 'agentName' not in result:
            result['agentName'] = ''
        if 'agentInstalled' not in result:
            result['agentInstalled'] = ''
        result_final = {
            'repositoryDisplayName': result['repositoryDisplayName'],
            'connected': result['connected'],
            'agentObjectId': result['agentObjectId'],
            'description': result['description'],
            'name': result['name'],
            'objectPath': result['objectPath'],
            'agentIsFilesystem': result['agentIsFilesystem'],
            'cancel': result['cancel'],
            'logsByDays': result['logsByDays'],
            'requireNotes': result['requireNotes'],
            'inService': result['inService'],
            'events': result['events'],
            'intrusions': result['intrusions'],
            'intrusionSize': result['intrusionSize'],
            'objectId': result['objectId'],
            'objectStatus': result['objectStatus'],
            'objectSubType': result['objectSubType'],
            'objectType': result['objectType'],
            'parentId': result['parentId'],
            'revisions': result['revisions'],
            'templateId': result['templateId'],
            'securityAdd': result['securityAdd'],
            'securityEdit': result['securityEdit'],
            'securityLock': result['securityLock'],
            'securityReport': result['securityReport'],
            'securityUnlock': result['securityUnlock'],
            'securityView': result['securityView'],
            'warnMinutes': result['warnMinutes'],
            'contact': result['contact'],
            'createDate': result['createDate'],
            'location': result['location'],
            'url': result['url'],
            'parentName': result['parentName'],
            'children': result['children'],
            'agentVersion': result['agentVersion'],
            'agentBuild': result['agentBuild'],
            'agentOsVersion': result['agentOsVersion'],
            'agentIp': result['agentIp'],
            'agentName': result['agentName'],
            'agentInstalled': result['agentInstalled'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.Objects',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def get_agent_info_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    object_id = int(ResolveString(args.get('ObjectId')))
    response = client.get_agent_info(
        object_id=object_id
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'objectData' not in result:
            result['objectData'] = ''
        if 'objectsCustom' not in result:
            result['objectsCustom'] = ''
        if 'agentData' not in result:
            result['agentData'] = ''
        if 'state' not in result:
            result['state'] = ''
        result_final = {
            'objectData': result['objectData'],
            'objectsCustom': result['objectsCustom'],
            'agentData': result['agentData'],
            'state': result['state'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.AgentInfo',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def get_compliance_archive_details_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    object_id = int(ResolveString(args.get('ObjectId')))
    compliance_scan_id = int(ResolveString(args.get('ComplianceScanId')))
    filter = ResolveJson(args.get('Filter'))
    start = int(ResolveString(args.get('Start')))
    end = int(ResolveString(args.get('End')))
    response = client.get_compliance_archive_details(
        object_id=object_id,
        compliance_scan_id=compliance_scan_id,
        filter=filter,
        start=start,
        end=end
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'testdate' not in result:
            result['testdate'] = ''
        if 'datatype' not in result:
            result['datatype'] = ''
        if 'scanid' not in result:
            result['scanid'] = ''
        if 'ipaddress' not in result:
            result['ipaddress'] = ''
        if 'lobjectid' not in result:
            result['lobjectid'] = ''
        if 'alternatesystemid' not in result:
            result['alternatesystemid'] = ''
        if 'agentuuid' not in result:
            result['agentuuid'] = ''
        if 'agentname' not in result:
            result['agentname'] = ''
        if 'objectpath' not in result:
            result['objectpath'] = ''
        if 'benchmark' not in result:
            result['benchmark'] = ''
        if 'profile' not in result:
            result['profile'] = ''
        if 'test' not in result:
            result['test'] = ''
        if 'pass' not in result:
            result['pass'] = ''
        if 'iswaived' not in result:
            result['iswaived'] = ''
        if 'adjustedscore' not in result:
            result['adjustedscore'] = ''
        if 'possiblescore' not in result:
            result['possiblescore'] = ''
        if 'rawscore' not in result:
            result['rawscore'] = ''
        if 'weight' not in result:
            result['weight'] = ''
        if 'testran' not in result:
            result['testran'] = ''
        if 'remediation' not in result:
            result['remediation'] = ''
        if 'severity' not in result:
            result['severity'] = ''
        if 'version' not in result:
            result['version'] = ''
        if 'rationale' not in result:
            result['rationale'] = ''
        if 'description' not in result:
            result['description'] = ''
        if 'assessment' not in result:
            result['assessment'] = ''
        if 'disposition' not in result:
            result['disposition'] = ''
        if 'conjunction' not in result:
            result['conjunction'] = ''
        if 'negatatevalue' not in result:
            result['negatatevalue'] = ''
        if 'comment' not in result:
            result['comment'] = ''
        if 'controlversion' not in result:
            result['controlversion'] = ''
        if 'controlnumber' not in result:
            result['controlnumber'] = ''
        if 'osversion' not in result:
            result['osversion'] = ''
        if 'personality' not in result:
            result['personality'] = ''
        if 'objectid' not in result:
            result['objectid'] = ''
        if 'userId' not in result:
            result['userId'] = ''
        if 'block' not in result:
            result['block'] = ''
        if 'bunlock' not in result:
            result['bunlock'] = ''
        if 'bview' not in result:
            result['bview'] = ''
        if 'bedit' not in result:
            result['bedit'] = ''
        if 'badd' not in result:
            result['badd'] = ''
        if 'breports' not in result:
            result['breports'] = ''
        if 'blogon' not in result:
            result['blogon'] = ''
        if 'isadmin' not in result:
            result['isadmin'] = ''
        result_final = {
            'testdate': result['testdate'],
            'datatype': result['datatype'],
            'scanid': result['scanid'],
            'ipaddress': result['ipaddress'],
            'lobjectid': result['lobjectid'],
            'alternatesystemid': result['alternatesystemid'],
            'agentuuid': result['agentuuid'],
            'agentname': result['agentname'],
            'objectpath': result['objectpath'],
            'benchmark': result['benchmark'],
            'profile': result['profile'],
            'test': result['test'],
            'pass': result['pass'],
            'iswaived': result['iswaived'],
            'adjustedscore': result['adjustedscore'],
            'possiblescore': result['possiblescore'],
            'rawscore': result['rawscore'],
            'weight': result['weight'],
            'testran': result['testran'],
            'remediation': result['remediation'],
            'severity': result['severity'],
            'version': result['version'],
            'rationale': result['rationale'],
            'description': result['description'],
            'assessment': result['assessment'],
            'disposition': result['disposition'],
            'conjunction': result['conjunction'],
            'negatatevalue': result['negatatevalue'],
            'comment': result['comment'],
            'controlversion': result['controlversion'],
            'controlnumber': result['controlnumber'],
            'osversion': result['osversion'],
            'personality': result['personality'],
            'objectid': result['objectid'],
            'userId': result['userId'],
            'block': result['block'],
            'bunlock': result['bunlock'],
            'bview': result['bview'],
            'bedit': result['bedit'],
            'badd': result['badd'],
            'breports': result['breports'],
            'blogon': result['blogon'],
            'isadmin': result['isadmin'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.Compliance',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def get_compliance_archive_summary_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    object_id = int(ResolveString(args.get('ObjectId')))
    compliance_scan_id = int(ResolveString(args.get('ComplianceScanId')))
    filter = ResolveJson(args.get('Filter'))
    start = int(ResolveString(args.get('Start')))
    end = int(ResolveString(args.get('End')))
    response = client.get_compliance_archive_summary(
        object_id=object_id,
        compliance_scan_id=compliance_scan_id,
        filter=filter,
        start=start,
        end=end
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'testdate' not in result:
            result['testdate'] = ''
        if 'scanid' not in result:
            result['scanid'] = ''
        if 'ipaddress' not in result:
            result['ipaddress'] = ''
        if 'datatype' not in result:
            result['datatype'] = ''
        if 'alternatesystemid' not in result:
            result['alternatesystemid'] = ''
        if 'agentuuid' not in result:
            result['agentuuid'] = ''
        if 'agentname' not in result:
            result['agentname'] = ''
        if 'objectpath' not in result:
            result['objectpath'] = ''
        if 'lobjectid' not in result:
            result['lobjectid'] = ''
        if 'benchmark' not in result:
            result['benchmark'] = ''
        if 'profile' not in result:
            result['profile'] = ''
        if 'totalfailcount' not in result:
            result['totalfailcount'] = ''
        if 'totalpasscount' not in result:
            result['totalpasscount'] = ''
        if 'totaltestsskipped' not in result:
            result['totaltestsskipped'] = ''
        if 'totalwaivecount' not in result:
            result['totalwaivecount'] = ''
        if 'pass' not in result:
            result['pass'] = ''
        if 'totaltestsran' not in result:
            result['totaltestsran'] = ''
        if 'osversion' not in result:
            result['osversion'] = ''
        if 'personality' not in result:
            result['personality'] = ''
        if 'userId' not in result:
            result['userId'] = ''
        if 'objectid' not in result:
            result['objectid'] = ''
        if 'block' not in result:
            result['block'] = ''
        if 'bunlock' not in result:
            result['bunlock'] = ''
        if 'bview' not in result:
            result['bview'] = ''
        if 'bedit' not in result:
            result['bedit'] = ''
        if 'badd' not in result:
            result['badd'] = ''
        if 'breports' not in result:
            result['breports'] = ''
        if 'blogon' not in result:
            result['blogon'] = ''
        result_final = {
            'testdate': result['testdate'],
            'scanid': result['scanid'],
            'ipaddress': result['ipaddress'],
            'datatype': result['datatype'],
            'alternatesystemid': result['alternatesystemid'],
            'agentuuid': result['agentuuid'],
            'agentname': result['agentname'],
            'objectpath': result['objectpath'],
            'lobjectid': result['lobjectid'],
            'benchmark': result['benchmark'],
            'profile': result['profile'],
            'totalfailcount': result['totalfailcount'],
            'totalpasscount': result['totalpasscount'],
            'totaltestsskipped': result['totaltestsskipped'],
            'totalwaivecount': result['totalwaivecount'],
            'pass': result['pass'],
            'totaltestsran': result['totaltestsran'],
            'osversion': result['osversion'],
            'personality': result['personality'],
            'userId': result['userId'],
            'objectid': result['objectid'],
            'block': result['block'],
            'bunlock': result['bunlock'],
            'bview': result['bview'],
            'bedit': result['bedit'],
            'badd': result['badd'],
            'breports': result['breports'],
            'blogon': result['blogon'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.Compliance',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def compliance_scan_children_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    object_parent_id = int(ResolveString(args.get('objectParentId')))
    response = client.compliance_scan_children(
        object_parent_id=object_parent_id
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    return command_results


def compliance_scan_with_summary_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    object_id = int(ResolveString(args.get('objectId')))
    retry_count = int(ResolveString(args.get('retryCount')))
    retry_seconds = int(ResolveString(args.get('retrySeconds')))
    response = client.compliance_scan_with_summary(
        object_id=object_id,
        retry_count=retry_count,
        retry_seconds=retry_seconds
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'testdate' not in result:
            result['testdate'] = ''
        if 'scanid' not in result:
            result['scanid'] = ''
        if 'ipaddress' not in result:
            result['ipaddress'] = ''
        if 'datatype' not in result:
            result['datatype'] = ''
        if 'alternatesystemid' not in result:
            result['alternatesystemid'] = ''
        if 'agentuuid' not in result:
            result['agentuuid'] = ''
        if 'agentname' not in result:
            result['agentname'] = ''
        if 'objectpath' not in result:
            result['objectpath'] = ''
        if 'lobjectid' not in result:
            result['lobjectid'] = ''
        if 'benchmark' not in result:
            result['benchmark'] = ''
        if 'profile' not in result:
            result['profile'] = ''
        if 'totalfailcount' not in result:
            result['totalfailcount'] = ''
        if 'totalpasscount' not in result:
            result['totalpasscount'] = ''
        if 'totaltestsskipped' not in result:
            result['totaltestsskipped'] = ''
        if 'totalwaivecount' not in result:
            result['totalwaivecount'] = ''
        if 'pass' not in result:
            result['pass'] = ''
        if 'totaltestsran' not in result:
            result['totaltestsran'] = ''
        if 'osversion' not in result:
            result['osversion'] = ''
        if 'personality' not in result:
            result['personality'] = ''
        if 'userId' not in result:
            result['userId'] = ''
        if 'objectid' not in result:
            result['objectid'] = ''
        if 'block' not in result:
            result['block'] = ''
        if 'bunlock' not in result:
            result['bunlock'] = ''
        if 'bview' not in result:
            result['bview'] = ''
        if 'bedit' not in result:
            result['bedit'] = ''
        if 'badd' not in result:
            result['badd'] = ''
        if 'breports' not in result:
            result['breports'] = ''
        if 'blogon' not in result:
            result['blogon'] = ''
        result_final = {
            'testdate': result['testdate'],
            'scanid': result['scanid'],
            'ipaddress': result['ipaddress'],
            'datatype': result['datatype'],
            'alternatesystemid': result['alternatesystemid'],
            'agentuuid': result['agentuuid'],
            'agentname': result['agentname'],
            'objectpath': result['objectpath'],
            'lobjectid': result['lobjectid'],
            'benchmark': result['benchmark'],
            'profile': result['profile'],
            'totalfailcount': result['totalfailcount'],
            'totalpasscount': result['totalpasscount'],
            'totaltestsskipped': result['totaltestsskipped'],
            'totalwaivecount': result['totalwaivecount'],
            'pass': result['pass'],
            'totaltestsran': result['totaltestsran'],
            'osversion': result['osversion'],
            'personality': result['personality'],
            'userId': result['userId'],
            'objectid': result['objectid'],
            'block': result['block'],
            'bunlock': result['bunlock'],
            'bview': result['bview'],
            'bedit': result['bedit'],
            'badd': result['badd'],
            'breports': result['breports'],
            'blogon': result['blogon'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.Compliance',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def get_agent_object_id_by_alternate_system_id_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    alternate_system_id = ResolveString(args.get('alternateSystemId'))
    response = client.get_agent_object_id_by_alternate_system_id(
        alternate_system_id=alternate_system_id
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'agentObjectId' not in result:
            result['agentObjectId'] = ''
        result_final = {
            'agentObjectId': result['agentObjectId'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.Object',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def get_agent_object_by_name_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    agent_name = ResolveString(args.get('agentName'))
    response = client.get_agent_object_by_name(
        agent_name=agent_name
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'agentIsFilesystem' not in result:
            result['agentIsFilesystem'] = ''
        if 'cancel' not in result:
            result['cancel'] = ''
        if 'connected' not in result:
            result['connected'] = ''
        if 'logsByDays' not in result:
            result['logsByDays'] = ''
        if 'requireNotes' not in result:
            result['requireNotes'] = ''
        if 'inService' not in result:
            result['inService'] = ''
        if 'children' not in result:
            result['children'] = ''
        if 'events' not in result:
            result['events'] = ''
        if 'intrusions' not in result:
            result['intrusions'] = ''
        if 'intrusionSize' not in result:
            result['intrusionSize'] = ''
        if 'objectId' not in result:
            result['objectId'] = ''
        if 'objectStatus' not in result:
            result['objectStatus'] = ''
        if 'objectSubType' not in result:
            result['objectSubType'] = ''
        if 'objectType' not in result:
            result['objectType'] = ''
        if 'parentId' not in result:
            result['parentId'] = ''
        if 'revisions' not in result:
            result['revisions'] = ''
        if 'templateId' not in result:
            result['templateId'] = ''
        if 'securityAdd' not in result:
            result['securityAdd'] = ''
        if 'securityEdit' not in result:
            result['securityEdit'] = ''
        if 'securityLock' not in result:
            result['securityLock'] = ''
        if 'securityReport' not in result:
            result['securityReport'] = ''
        if 'securityUnlock' not in result:
            result['securityUnlock'] = ''
        if 'securityView' not in result:
            result['securityView'] = ''
        if 'warnMinutes' not in result:
            result['warnMinutes'] = ''
        if 'contact' not in result:
            result['contact'] = ''
        if 'createDate' not in result:
            result['createDate'] = ''
        if 'description' not in result:
            result['description'] = ''
        if 'location' not in result:
            result['location'] = ''
        if 'name' not in result:
            result['name'] = ''
        if 'objectPath' not in result:
            result['objectPath'] = ''
        if 'url' not in result:
            result['url'] = ''
        if 'agentObjectId' not in result:
            result['agentObjectId'] = ''
        result_final = {
            'agentIsFilesystem': result['agentIsFilesystem'],
            'cancel': result['cancel'],
            'connected': result['connected'],
            'logsByDays': result['logsByDays'],
            'requireNotes': result['requireNotes'],
            'inService': result['inService'],
            'children': result['children'],
            'events': result['events'],
            'intrusions': result['intrusions'],
            'intrusionSize': result['intrusionSize'],
            'objectId': result['objectId'],
            'objectStatus': result['objectStatus'],
            'objectSubType': result['objectSubType'],
            'objectType': result['objectType'],
            'parentId': result['parentId'],
            'revisions': result['revisions'],
            'templateId': result['templateId'],
            'securityAdd': result['securityAdd'],
            'securityEdit': result['securityEdit'],
            'securityLock': result['securityLock'],
            'securityReport': result['securityReport'],
            'securityUnlock': result['securityUnlock'],
            'securityView': result['securityView'],
            'warnMinutes': result['warnMinutes'],
            'contact': result['contact'],
            'createDate': result['createDate'],
            'description': result['description'],
            'location': result['location'],
            'name': result['name'],
            'objectPath': result['objectPath'],
            'url': result['url'],
            'agentObjectId': result['agentObjectId'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.Object',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def get_agent_object_by_alternate_id_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    alternate_system_id = ResolveString(args.get('alternateSystemId'))
    response = client.get_agent_object_by_alternate_id(
        alternate_system_id=alternate_system_id
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'agentIsFilesystem' not in result:
            result['agentIsFilesystem'] = ''
        if 'cancel' not in result:
            result['cancel'] = ''
        if 'connected' not in result:
            result['connected'] = ''
        if 'logsByDays' not in result:
            result['logsByDays'] = ''
        if 'requireNotes' not in result:
            result['requireNotes'] = ''
        if 'inService' not in result:
            result['inService'] = ''
        if 'children' not in result:
            result['children'] = ''
        if 'events' not in result:
            result['events'] = ''
        if 'intrusions' not in result:
            result['intrusions'] = ''
        if 'intrusionSize' not in result:
            result['intrusionSize'] = ''
        if 'objectId' not in result:
            result['objectId'] = ''
        if 'objectStatus' not in result:
            result['objectStatus'] = ''
        if 'objectSubType' not in result:
            result['objectSubType'] = ''
        if 'objectType' not in result:
            result['objectType'] = ''
        if 'parentId' not in result:
            result['parentId'] = ''
        if 'revisions' not in result:
            result['revisions'] = ''
        if 'templateId' not in result:
            result['templateId'] = ''
        if 'securityAdd' not in result:
            result['securityAdd'] = ''
        if 'securityEdit' not in result:
            result['securityEdit'] = ''
        if 'securityLock' not in result:
            result['securityLock'] = ''
        if 'securityReport' not in result:
            result['securityReport'] = ''
        if 'securityUnlock' not in result:
            result['securityUnlock'] = ''
        if 'securityView' not in result:
            result['securityView'] = ''
        if 'warnMinutes' not in result:
            result['warnMinutes'] = ''
        if 'contact' not in result:
            result['contact'] = ''
        if 'createDate' not in result:
            result['createDate'] = ''
        if 'description' not in result:
            result['description'] = ''
        if 'location' not in result:
            result['location'] = ''
        if 'name' not in result:
            result['name'] = ''
        if 'objectPath' not in result:
            result['objectPath'] = ''
        if 'url' not in result:
            result['url'] = ''
        if 'agentObjectId' not in result:
            result['agentObjectId'] = ''
        result_final = {
            'agentIsFilesystem': result['agentIsFilesystem'],
            'cancel': result['cancel'],
            'connected': result['connected'],
            'logsByDays': result['logsByDays'],
            'requireNotes': result['requireNotes'],
            'inService': result['inService'],
            'children': result['children'],
            'events': result['events'],
            'intrusions': result['intrusions'],
            'intrusionSize': result['intrusionSize'],
            'objectId': result['objectId'],
            'objectStatus': result['objectStatus'],
            'objectSubType': result['objectSubType'],
            'objectType': result['objectType'],
            'parentId': result['parentId'],
            'revisions': result['revisions'],
            'templateId': result['templateId'],
            'securityAdd': result['securityAdd'],
            'securityEdit': result['securityEdit'],
            'securityLock': result['securityLock'],
            'securityReport': result['securityReport'],
            'securityUnlock': result['securityUnlock'],
            'securityView': result['securityView'],
            'warnMinutes': result['warnMinutes'],
            'contact': result['contact'],
            'createDate': result['createDate'],
            'description': result['description'],
            'location': result['location'],
            'name': result['name'],
            'objectPath': result['objectPath'],
            'url': result['url'],
            'agentObjectId': result['agentObjectId'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.Object',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


def get_agent_object_by_ip_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    command_results: List[CommandResults] = []
    client.debug = 5
    ip = ResolveString(args.get('ip'))
    response = client.get_agent_object_by_ip(
        ip=ip
    )
    command_status = {
        'status': response['status'],
        'errorCode': response['errorCode'],
        'errorDescription': response['errorDescription']
    }
    command_results.append(
        CommandResults(
            readable_output=response['status'],
            outputs_prefix='CimTrak.CommandStatus',
            outputs_key_field='status',
            outputs=command_status
        )
    )
    results = response['results']
    for result in results:
        if 'agentIsFilesystem' not in result:
            result['agentIsFilesystem'] = ''
        if 'cancel' not in result:
            result['cancel'] = ''
        if 'connected' not in result:
            result['connected'] = ''
        if 'logsByDays' not in result:
            result['logsByDays'] = ''
        if 'requireNotes' not in result:
            result['requireNotes'] = ''
        if 'inService' not in result:
            result['inService'] = ''
        if 'children' not in result:
            result['children'] = ''
        if 'events' not in result:
            result['events'] = ''
        if 'intrusions' not in result:
            result['intrusions'] = ''
        if 'intrusionSize' not in result:
            result['intrusionSize'] = ''
        if 'objectId' not in result:
            result['objectId'] = ''
        if 'objectStatus' not in result:
            result['objectStatus'] = ''
        if 'objectSubType' not in result:
            result['objectSubType'] = ''
        if 'objectType' not in result:
            result['objectType'] = ''
        if 'parentId' not in result:
            result['parentId'] = ''
        if 'revisions' not in result:
            result['revisions'] = ''
        if 'templateId' not in result:
            result['templateId'] = ''
        if 'securityAdd' not in result:
            result['securityAdd'] = ''
        if 'securityEdit' not in result:
            result['securityEdit'] = ''
        if 'securityLock' not in result:
            result['securityLock'] = ''
        if 'securityReport' not in result:
            result['securityReport'] = ''
        if 'securityUnlock' not in result:
            result['securityUnlock'] = ''
        if 'securityView' not in result:
            result['securityView'] = ''
        if 'warnMinutes' not in result:
            result['warnMinutes'] = ''
        if 'contact' not in result:
            result['contact'] = ''
        if 'createDate' not in result:
            result['createDate'] = ''
        if 'description' not in result:
            result['description'] = ''
        if 'location' not in result:
            result['location'] = ''
        if 'name' not in result:
            result['name'] = ''
        if 'objectPath' not in result:
            result['objectPath'] = ''
        if 'url' not in result:
            result['url'] = ''
        if 'agentObjectId' not in result:
            result['agentObjectId'] = ''
        result_final = {
            'agentIsFilesystem': result['agentIsFilesystem'],
            'cancel': result['cancel'],
            'connected': result['connected'],
            'logsByDays': result['logsByDays'],
            'requireNotes': result['requireNotes'],
            'inService': result['inService'],
            'children': result['children'],
            'events': result['events'],
            'intrusions': result['intrusions'],
            'intrusionSize': result['intrusionSize'],
            'objectId': result['objectId'],
            'objectStatus': result['objectStatus'],
            'objectSubType': result['objectSubType'],
            'objectType': result['objectType'],
            'parentId': result['parentId'],
            'revisions': result['revisions'],
            'templateId': result['templateId'],
            'securityAdd': result['securityAdd'],
            'securityEdit': result['securityEdit'],
            'securityLock': result['securityLock'],
            'securityReport': result['securityReport'],
            'securityUnlock': result['securityUnlock'],
            'securityView': result['securityView'],
            'warnMinutes': result['warnMinutes'],
            'contact': result['contact'],
            'createDate': result['createDate'],
            'description': result['description'],
            'location': result['location'],
            'name': result['name'],
            'objectPath': result['objectPath'],
            'url': result['url'],
            'agentObjectId': result['agentObjectId'],
        }
        command_results.append(
            CommandResults(
                readable_output=result,
                outputs_prefix='CimTrak.Object',
                outputs_key_field='id',
                outputs=result_final
            )
        )
    return command_results


################################################################
# CimTrak Palo Alto Custom Functions End
################################################################


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    api_key = demisto.params().get("apikey")

    # get the service API url
    base_url = demisto.params()["url"]
    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get("insecure", False)
    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_datetime(
        arg=demisto.params().get("first_fetch", "3 days"),
        arg_name="First fetch time",
        required=True,
    )

    first_fetch_timestamp = (
        int(first_fetch_time.timestamp()) if first_fetch_time else None
    )
    # Using assert as a type guard (since first_fetch_time is always an int when required=True)
    assert isinstance(first_fetch_timestamp, int)

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        client = Client(base_url=base_url, verify=verify_certificate)
        Client.api_key = api_key
        Client.server = demisto.params().get("Repository URL")
        Client.port = demisto.params().get("Repository Port")

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client, first_fetch_timestamp)
            return_results(result)

        elif demisto.command() == "fetch-incidents":
            # Set and define the fetch incidents command to run after activated via integration settings.
            alert_status = demisto.params().get("alert_status", None)
            alert_type = demisto.params().get("alert_type", None)
            min_severity = demisto.params().get("min_severity", None)
            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = arg_to_number(
                arg=demisto.params().get("max_fetch"),
                arg_name="max_fetch",
                required=False,
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH
            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_timestamp,
                alert_status=alert_status,
                min_severity=min_severity,
                alert_type=alert_type,
            )
            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.incidents(incidents)
        ################################################################
        # CimTrak Palo Alto Custom Functions Dispatch Begin
        ################################################################
        elif demisto.command() == 'get-events':
            return_results(get_events_command(client, demisto.args()))
        elif demisto.command() == 'file-analysis-by-hash':
            return_results(file_analysis_by_hash_command(client, demisto.args()))
        elif demisto.command() == 'file-analysis-by-objectdetail-id':
            return_results(file_analysis_by_object_detail_id_command(client, demisto.args()))
        elif demisto.command() == 'check-file-against-trusted-file-registry-by-hash':
            return_results(check_file_against_trusted_file_registry_by_hash_command(client, demisto.args()))
        elif demisto.command() == 'promote-authoritative-baseline-files':
            return_results(promote_authoritative_baseline_files_command(client, demisto.args()))
        elif demisto.command() == 'demote-authoritative-baseline-files':
            return_results(demote_authoritative_baseline_files_command(client, demisto.args()))
        elif demisto.command() == 'update-task-disposition':
            return_results(update_task_disposition_command(client, demisto.args()))
        elif demisto.command() == 'get-tickets':
            return_results(get_tickets_command(client, demisto.args()))
        elif demisto.command() == 'get-ticket-tasks':
            return_results(get_ticket_tasks_command(client, demisto.args()))
        elif demisto.command() == 'add-ticket':
            return_results(add_ticket_command(client, demisto.args()))
        elif demisto.command() == 'update-ticket':
            return_results(update_ticket_command(client, demisto.args()))
        elif demisto.command() == 'add-ticket-comment':
            return_results(add_ticket_comment_command(client, demisto.args()))
        elif demisto.command() == 'add-hash-allow-list':
            return_results(add_hash_allow_list_command(client, demisto.args()))
        elif demisto.command() == 'add-hash-deny-list':
            return_results(add_hash_deny_list_command(client, demisto.args()))
        elif demisto.command() == 'delete-hash-allow-list':
            return_results(delete_hash_allow_list_command(client, demisto.args()))
        elif demisto.command() == 'delete-hash-deny-list':
            return_results(delete_hash_deny_list_command(client, demisto.args()))
        elif demisto.command() == 'get-sub-generations':
            return_results(get_sub_generations_command(client, demisto.args()))
        elif demisto.command() == 'deploy':
            return_results(deploy_command(client, demisto.args()))
        elif demisto.command() == 'get-object-group':
            return_results(get_object_group_command(client, demisto.args()))
        elif demisto.command() == 'unlock':
            return_results(unlock_command(client, demisto.args()))
        elif demisto.command() == 'lock':
            return_results(lock_command(client, demisto.args()))
        elif demisto.command() == 'get-object':
            return_results(get_object_command(client, demisto.args()))
        elif demisto.command() == 'force-sync':
            return_results(force_sync_command(client, demisto.args()))
        elif demisto.command() == 'view-file':
            return_results(view_file_command(client, demisto.args()))
        elif demisto.command() == 'run-report-by-name':
            return_results(run_report_by_name_command(client, demisto.args()))
        elif demisto.command() == 'deploy-by-date':
            return_results(deploy_by_date_command(client, demisto.args()))
        elif demisto.command() == 'get-current-compliance-items':
            return_results(get_current_compliance_items_command(client, demisto.args()))
        elif demisto.command() == 'get-objects':
            return_results(get_objects_command(client, demisto.args()))
        elif demisto.command() == 'get-agent-info':
            return_results(get_agent_info_command(client, demisto.args()))
        elif demisto.command() == 'get-compliance-archive-details':
            return_results(get_compliance_archive_details_command(client, demisto.args()))
        elif demisto.command() == 'get-compliance-archive-summary':
            return_results(get_compliance_archive_summary_command(client, demisto.args()))
        elif demisto.command() == 'compliance-scan-children':
            return_results(compliance_scan_children_command(client, demisto.args()))
        elif demisto.command() == 'compliance-scan-with-summary':
            return_results(compliance_scan_with_summary_command(client, demisto.args()))
        elif demisto.command() == 'get-agent-object-id-by-alternate-system-id':
            return_results(get_agent_object_id_by_alternate_system_id_command(client, demisto.args()))
        elif demisto.command() == 'get-agent-object-by-name':
            return_results(get_agent_object_by_name_command(client, demisto.args()))
        elif demisto.command() == 'get-agent-object-by-alternate-id':
            return_results(get_agent_object_by_alternate_id_command(client, demisto.args()))
        elif demisto.command() == 'get-agent-object-by-ip':
            return_results(get_agent_object_by_ip_command(client, demisto.args()))
        ################################################################
        # CimTrak Palo Alto Custom Functions Dispatch End
        ################################################################
######

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
