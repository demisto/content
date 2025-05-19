FETCHINCIDENTS_SEARCHTICKET = {
    "data": [
        {
            "1": "testing fetch incident",
            "12": 2,
            "15": "2022-04-14 11:47:34",
            "18": None,
            "19": "2022-04-14 11:47:34",
            "2": 291,
            "3": 3,
            "4": "2",
            "5": "2",
            "7": None,
        }
    ]
}

FETCHINCIDENTS_TICKET = {
    "actiontime": 0,
    "begin_waiting_date": None,
    "close_delay_stat": 0,
    "closedate": None,
    "content": "&lt;p&gt;verdict ?&lt;/p&gt;",
    "date": "2022-04-14 11:47:34",
    "date_creation": "2022-04-14 11:47:34",
    "date_mod": "2022-04-14 11:47:34",
    "entities_id": 0,
    "global_validation": 1,
    "id": 291,
    "impact": 3,
    "internal_time_to_own": None,
    "internal_time_to_resolve": None,
    "is_deleted": 0,
    "itilcategories_id": 0,
    "links": [
        {"href": "http://myglpi.mydomain.tld/apirest.php/Entity/0", "rel": "Entity"},
        {"href": "http://myglpi.mydomain.tld/apirest.php/User/2", "rel": "User"},
        {"href": "http://myglpi.mydomain.tld/apirest.php/User/2", "rel": "User"},
        {"href": "http://myglpi.mydomain.tld/apirest.php/RequestType/1", "rel": "RequestType"},
        {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291/Document_Item/", "rel": "Document_Item"},
        {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291/TicketTask/", "rel": "TicketTask"},
        {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291/TicketValidation/", "rel": "TicketValidation"},
        {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291/TicketCost/", "rel": "TicketCost"},
        {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291/Problem_Ticket/", "rel": "Problem_Ticket"},
        {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291/Change_Ticket/", "rel": "Change_Ticket"},
        {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291/Item_Ticket/", "rel": "Item_Ticket"},
        {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291/ITILSolution/", "rel": "ITILSolution"},
        {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291/ITILFollowup/", "rel": "ITILFollowup"},
    ],
    "locations_id": 0,
    "name": "testing fetch incident",
    "ola_ttr_begin_date": None,
    "ola_waiting_duration": 0,
    "olalevels_id_ttr": 0,
    "olas_id_tto": 0,
    "olas_id_ttr": 0,
    "priority": 3,
    "requesttypes_id": 1,
    "sla_waiting_duration": 0,
    "slalevels_id_ttr": 0,
    "slas_id_tto": 0,
    "slas_id_ttr": 0,
    "solve_delay_stat": 0,
    "solvedate": None,
    "status": 2,
    "takeintoaccount_delay_stat": 1,
    "time_to_own": None,
    "time_to_resolve": None,
    "type": 1,
    "urgency": 3,
    "users_id_lastupdater": 2,
    "users_id_recipient": 2,
    "validation_percent": 0,
    "waiting_duration": 0,
}

FETCHINCIDENTS_TICKETUSER = [
    {
        "alternative_email": "",
        "id": 584,
        "links": [
            {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291", "rel": "Ticket"},
            {"href": "http://myglpi.mydomain.tld/apirest.php/User/2", "rel": "User"},
        ],
        "tickets_id": "testing fetch incident",
        "type": 1,
        "use_notification": 1,
        "users_id": "glpi",
    },
    {
        "alternative_email": "",
        "id": 585,
        "links": [
            {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291", "rel": "Ticket"},
            {"href": "http://myglpi.mydomain.tld/apirest.php/User/2", "rel": "User"},
        ],
        "tickets_id": "testing fetch incident",
        "type": 2,
        "use_notification": 1,
        "users_id": "glpi",
    },
]

FETCHINCIDENTS_TICKETDOC = [
    {
        "id": 37,
        "documents_id": 33847,
        "items_id": 292,
        "itemtype": "Ticket",
        "entities_id": 0,
        "is_recursive": 1,
        "date_mod": "2022-04-19 09:57:18",
        "users_id": 2,
        "timeline_position": 1,
        "date_creation": "2022-04-19 09:57:18",
        "links": [
            {"rel": "Document", "href": "http://myglpi.mydomain.tld/apirest.php/Document/33847"},
            {"rel": "Ticket", "href": "http://myglpi.mydomain.tld/apirest.php/Ticket/292"},
            {"rel": "Entity", "href": "http://myglpi.mydomain.tld/apirest.php/Entity/0"},
            {"rel": "User", "href": "http://myglpi.mydomain.tld/apirest.php/User/2"},
        ],
    }
]

FETCHINCIDENTS_TICKETDOCFILE = {
    "id": 33847,
    "entities_id": 0,
    "is_recursive": 1,
    "name": "Document Ticket 292",
    "filename": "testingupload.txt",
    "filepath": "TXT/8e/9e1326a0e9880971cd8db9f04b4fe3f3157897.TXT",
    "documentcategories_id": 0,
    "mime": "text/plain",
    "date_mod": "2022-04-19 09:57:18",
    "comment": None,
    "is_deleted": 0,
    "link": None,
    "users_id": 2,
    "tickets_id": 292,
    "sha1sum": "8e9e1326a0e9880971cd8db9f04b4fe3f3157897",
    "is_blacklisted": 0,
    "tag": "47fbac13-d9d62df8-625e6b59593eb3.43759312",
    "date_creation": "2022-04-19 09:57:18",
    "links": [
        {"rel": "Entity", "href": "http://myglpi.mydomain.tld/apirest.php/Entity/0"},
        {"rel": "User", "href": "http://myglpi.mydomain.tld/apirest.php/User/2"},
        {"rel": "Ticket", "href": "http://myglpi.mydomain.tld/apirest.php/Ticket/292"},
        {"rel": "Document_Item", "href": "http://myglpi.mydomain.tld/apirest.php/Document/33847/Document_Item/"},
    ],
}

FETCHINCIDENTS_INCIDENTS = [
    {
        "name": "testing fetch incident",
        "occurred": "2022-04-14T11:47:34Z",
        "attachment": [{"path": "f07e9487-b0bc-4a05-b1c8-a707c7dd1328", "name": "testingupload.txt"}],
        "rawJSON": '{"actiontime": 0, "begin_waiting_date": null, "close_delay_stat": 0, "closedate": null, "content": "<p>verdict ?</p>", "date": "2022-04-14 11:47:34", "date_creation": "2022-04-14 11:47:34", "date_mod": "2022-04-14 11:47:34", "entities_id": 0, "global_validation": 1, "id": 291, "impact": 3, "internal_time_to_own": null, "internal_time_to_resolve": null, "is_deleted": 0, "itilcategories_id": 0, "links": [{"href": "http://myglpi.mydomain.tld/apirest.php/Entity/0", "rel": "Entity"}, {"href": "http://myglpi.mydomain.tld/apirest.php/User/2", "rel": "User"}, {"href": "http://myglpi.mydomain.tld/apirest.php/User/2", "rel": "User"}, {"href": "http://myglpi.mydomain.tld/apirest.php/RequestType/1", "rel": "RequestType"}, {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291/Document_Item/", "rel": "Document_Item"}, {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291/TicketTask/", "rel": "TicketTask"}, {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291/TicketValidation/", "rel": "TicketValidation"}, {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291/TicketCost/", "rel": "TicketCost"}, {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291/Problem_Ticket/", "rel": "Problem_Ticket"}, {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291/Change_Ticket/", "rel": "Change_Ticket"}, {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291/Item_Ticket/", "rel": "Item_Ticket"}, {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291/ITILSolution/", "rel": "ITILSolution"}, {"href": "http://myglpi.mydomain.tld/apirest.php/Ticket/291/ITILFollowup/", "rel": "ITILFollowup"}], "locations_id": 0, "name": "testing fetch incident", "ola_ttr_begin_date": null, "ola_waiting_duration": 0, "olalevels_id_ttr": 0, "olas_id_tto": 0, "olas_id_ttr": 0, "priority": 3, "requesttypes_id": 1, "sla_waiting_duration": 0, "slalevels_id_ttr": 0, "slas_id_tto": 0, "slas_id_ttr": 0, "solve_delay_stat": 0, "solvedate": null, "status": 2, "takeintoaccount_delay_stat": 1, "time_to_own": null, "time_to_resolve": null, "type": 1, "urgency": 3, "users_id_lastupdater": 2, "users_id_recipient": 2, "validation_percent": 0, "waiting_duration": 0, "requester_users": ["glpi"], "assigned_users": ["glpi"], "watcher_users": [], "requester_groups": [], "assigned_groups": [], "watcher_groups": [], "mirror_direction": null, "mirror_instance": "", "mirror_tags": [null, null, null]}',
    }
]
