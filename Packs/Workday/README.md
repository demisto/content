<~XSIAM>

This pack supports collection and modeling of the following event types:
- *User activity* audit log entries.
- *Sign-on* events. 

Note: Regarding the *user activity* audit log entries, 
in order to parse the timestamp correctly, 
make sure that the "requestTime" field is in UTC time zone (timestamp ends with "Z").
The supported time format is *YYYY-MM-DDTHH:MM:SS.E3Z%z* (e.g, *2023-09-05T14:00:00.123Z*).

</~XSIAM>