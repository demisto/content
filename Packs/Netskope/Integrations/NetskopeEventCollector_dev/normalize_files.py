import json

headers_dict = {
    "Action": "action",
    "Activity": "activity",
    "Alert Type": "alert_type",
    "Application": "application",
    "Browser": "browser",
    "Category": "category",
    "IP Address": "userip",
    "Time (GMT)": "_time",
    "User": "user",
    "Website": "app"
}
# with open("netskope_events.json", 'r') as f1:
with open("Netskope Application Events 03 Jul'23 0900-0910 UTC.json", 'r') as f1:
    saved_events = f1.read()
    parsed_events = []
    count = 0
    for eve in saved_events.split('\n'):
        parsed_events.append(json.loads(eve))
        count += 1
    fixed_events = []

    for event in parsed_events:
        new_event = {}
        new_event_id = [event.get(val) for val in headers_dict.values()]
        test_list = [i for i in new_event_id if i]  # remove empty strings
        # print(new_event_id)
        event['new_event_id'] = ' '.join(test_list)
    # print(parsed_events)

    # fixed_events = [{val: event.get(val) for val in headers_dict.values()} for event in parsed_events]

with open('netskope_events_with_id.json', 'w') as f2:
    str_events = '\n'.join([json.dumps(eve) for eve in parsed_events])
    f2.write(str_events)

# with open('netskope_test.json', 'w') as f2:
#     str_events = '\n'.join([json.dumps(eve) for eve in parsed_events])
#     f2.write(str_events)


with open("4_hours_sorted_events_new.json", 'r') as f1:
    saved_events = f1.read()
    parsed_events = []
    count = 0
    for eve in saved_events.split('\n'):
        parsed_events.append(json.loads(eve))
        count += 1
    fixed_events = []

    for event in parsed_events:
        new_event = {}
        new_event_id = [event.get(val) for val in headers_dict.values()]
        test_list = [i for i in new_event_id if i]  # remove empty strings
        # print(new_event_id)
        event['new_event_id'] = ' '.join(test_list)

    # fixed_events = [{val: event.get(val) for val in headers_dict.values()} for event in parsed_events]

with open('4_hours_sorted_events_with_id.json', 'w') as f2:
    str_events = '\n'.join([json.dumps(eve) for eve in parsed_events])
    f2.write(str_events)
