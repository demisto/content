# adding so null don't get seen as variable.
null = None
false = False
true = True

EXTERNAL_EXPOSURES_RESPONSE = [
    {
        "asm_ids": [
            "1111-1111-1111-1111"
        ],
        "name": "example.com",
        "asset_type": "DOMAIN",
    },
    {
        "asm_ids": [
            "2222-2222-2222-2222"
        ],
        "name": "192.168.1.1",
        "asset_type": "UNASSOCIATED_RESPONSIVE_IP",
    },
    {
        "asm_ids": [
            "3333-3333-3333-3333"
        ],
        "name": "192.168.1.2",
        "asset_type": "UNASSOCIATED_RESPONSIVE_IP",
    },
]
