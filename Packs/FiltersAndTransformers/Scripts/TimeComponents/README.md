Takes a date or time input and get time components in a specific time zone.
Returns a dictionary with the following components.
- year
- year_4_digit
- month
- month_3_letter
- month_full_name
- month_2_digit
- day
- day_2_digit
- day_of_week (Sun:0, Sat:6)
- day_of_week_3_letter
- day_of_week_full_name
- day_of_year
- day_of_year_3_digit
- hour
- hour_12_clock
- hour_2_digit_24_clock
- hour_2_digit_12_clock
- hour_of_day
- minute
- minute_2_digit
- minute_of_day
- second
- second_2_digit
- second_of_day
- millisecond
- period_12_clock
- time_zone_hhmm
- time_zone_offset
- time_zone_abbreviations
- unix_epoch_time
- iso_8601
- y-m-d
- yyyy-mm-dd
- h:m:s
- H:m:s
- hh:mm:ss
- HH:mm:ss

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, date |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | Input date or time in a format that is supported by the dateparser.parse\(\) function as outlined here- https://dateparser.readthedocs.io/en/latest/#popular-formats. For example: '2020-01-01' or '1999/02/03 12:01:59'. \(Default is the current time\). Assume given time is in UTC if time zone is not detected. |
| time_zone | The time zone \(e.g. -0400, \+09:00\) or time string to extract a time zone |
| key | The name of a key to choose which time component to return |

## Outputs
---
There are no outputs for this script.


## Examples
---

### Get all the time components from the time taken

#### Parameters
| **Argument Name** | **Value** |
| --- | --- |
| value | 2022-01-23 01:23:45 +00:00 |
| time_zone | |
| key | |

#### Output
```json
{
  "year": 2022,
  "year_4_digit": "2022",
  "month": 1,
  "month_3_letter": "Jan",
  "month_full_name": "January",
  "month_2_digit": "01",
  "day": 23,
  "day_2_digit": "23",
  "day_of_week": 0,
  "day_of_week_3_letter": "Sun",
  "day_of_week_full_name": "Sunday",
  "day_of_year": 23,
  "day_of_year_3_digit": "023",
  "hour": 1,
  "hour_12_clock": 1,
  "hour_2_digit_24_clock": "01",
  "hour_2_digit_12_clock": "01",
  "hour_of_day": 1.3958333333333333,
  "minute": 23,
  "minute_2_digit": "23",
  "minute_of_day": 47.75,
  "second": 45,
  "second_2_digit": "45",
  "second_of_day": 2865,
  "millisecond": 0,
  "period_12_clock": "AM",
  "time_zone_hhmm": "+0000",
  "time_zone_offset": 0.0,
  "time_zone_abbreviations": ["GMT", "UTC", "WET"],
  "unix_epoch_time": 1642901025,
  "iso_8601": "2022-01-23T01:23:45+00:00",
  "y-m-d": "2022-1-23",
  "yyyy-mm-dd": "2022-01-23",
  "h:m:s": "1:23:45",
  "H:m:s": "1:23:45",
  "hh:mm:ss": "01:23:45",
  "HH:mm:ss": "01:23:45"
}
```

---

### Get all the time components in a specific time zone

#### Parameters
| **Argument Name** | **Value** |
| --- | --- |
| value | 2022-01-23 01:23:45 +00:00 |
| time_zone | +09:00 |
| key | |

#### Output
```json
{
  "year": 2022,
  "year_4_digit": "2022",
  "month": 1,
  "month_3_letter": "Jan",
  "month_full_name": "January",
  "month_2_digit": "01",
  "day": 23,
  "day_2_digit": "23",
  "day_of_week": 0,
  "day_of_week_3_letter": "Sun",
  "day_of_week_full_name": "Sunday",
  "day_of_year": 23,
  "day_of_year_3_digit": "023",
  "hour": 10,
  "hour_12_clock": 10,
  "hour_2_digit_24_clock": "10",
  "hour_2_digit_12_clock": "10",
  "hour_of_day": 10.395833333333332,
  "minute": 23,
  "minute_2_digit": "23",
  "minute_of_day": 263.75,
  "second": 45,
  "second_2_digit": "45",
  "second_of_day": 15825,
  "millisecond": 0,
  "period_12_clock": "AM",
  "time_zone_hhmm": "+0900",
  "time_zone_offset": 540.0,
  "time_zone_abbreviations": ["JST", "KST", "WIT"],
  "unix_epoch_time": 1642901025,
  "iso_8601": "2022-01-23T10:23:45+09:00",
  "y-m-d": "2022-1-23",
  "yyyy-mm-dd": "2022-01-23",
  "h:m:s": "10:23:45",
  "H:m:s": "10:23:45",
  "hh:mm:ss": "10:23:45",
  "HH:mm:ss": "10:23:45"
}
```

---

### Get all the time components from the unix timestamp

#### Parameters
| **Argument Name** | **Value** |
| --- | --- |
| value | 1642868625 |
| time_zone | |
| key | |

#### Output
```json
{
  "year": 2022,
  "year_4_digit": "2022",
  "month": 1,
  "month_3_letter": "Jan",
  "month_full_name": "January",
  "month_2_digit": "01",
  "day": 22,
  "day_2_digit": "22",
  "day_of_week": 6,
  "day_of_week_3_letter": "Sat",
  "day_of_week_full_name": "Saturday",
  "day_of_year": 22,
  "day_of_year_3_digit": "022",
  "hour": 16,
  "hour_12_clock": 4,
  "hour_2_digit_24_clock": "16",
  "hour_2_digit_12_clock": "04",
  "hour_of_day": 16.395833333333332,
  "minute": 23,
  "minute_2_digit": "23",
  "minute_of_day": 407.75,
  "second": 45,
  "second_2_digit": "45",
  "second_of_day": 24465,
  "millisecond": 0,
  "period_12_clock": "PM",
  "time_zone_hhmm": "+0000",
  "time_zone_offset": 0.0,
  "time_zone_abbreviations": ["GMT", "UTC", "WET"],
  "unix_epoch_time": 1642868625,
  "iso_8601": "2022-01-22T16:23:45+00:00",
  "y-m-d": "2022-1-22",
  "yyyy-mm-dd": "2022-01-22",
  "h:m:s": "16:23:45",
  "H:m:s": "4:23:45",
  "hh:mm:ss": "04:23:45",
  "HH:mm:ss": "16:23:45"
}
```

---

### Get a specific time component (day_of_week_full_name)

#### Parameters
| **Argument Name** | **Value** |
| --- | --- |
| value | 2022-01-23 01:23:45 +00:00 |
| time_zone | |
| key | day_of_week_full_name |

#### Output
```
Sunday
```

---

### Get a time component in a specific time zone given by zone info

#### Parameters
| **Argument Name** | **Value** |
| --- | --- |
| value | 2022-01-23 01:23:45 +00:00 |
| time_zone | Asia/Tokyo |
| key | iso_8601 |

#### Output
```
2022-01-23T10:23:45+09:00
```

---

### Get a time component in a time zone which is extracted from the time string given to `time_zone`

#### Parameters
| **Argument Name** | **Value** |
| --- | --- |
| value | 2022-01-23 01:23:45 +00:00 |
| time_zone | 2022-01-01 00:00:00 +09:00 |
| key | iso_8601 |

#### Output
```
2022-01-23T10:23:45+09:00
```

---

### Get a current time in a specific time zone

#### Parameters
| **Argument Name** | **Value** |
| --- | --- |
| value | now |
| time_zone | +09:00 |
| key | iso_8601 |

#### Output
```
2022-09-30T12:34:56+09:00
```


## Tips

### Build a custom time format string

You can create a custom time format in combination with the `DT` transformer on the chain of transformers. For example, now you want to create a RFC 1123 date string such as `Thu, 10 Nov 2022 08:01:44 +0200`, and have the following results from the `TimeComponents`.

**Table 1**
```json
{
    "year": 2022,
    "year_4_digit": "2022",
    "month": 11,
    "month_3_letter": "Nov",
    "month_full_name": "November",
    "month_2_digit": "11",
    "day": 10,
    "day_2_digit": "10",
    "day_of_week": 4,
    "day_of_week_3_letter": "Thu",
    "day_of_week_full_name": "Thursday",
    "day_of_year": 314,
    "day_of_year_3_digit": "314",
    "hour": 8,
    "hour_12_clock": 8,
    "hour_2_digit_24_clock": "08",
    "hour_2_digit_12_clock": "08",
    "hour_of_day": 8.02888888888889,
    "minute": 1,
    "minute_2_digit": "01",
    "minute_of_day": 193.73333333333332,
    "second": 44,
    "second_2_digit": "44",
    "second_of_day": 11624,
    "millisecond": 0,
    "period_12_clock": "AM",
    "time_zone_hhmm": "+0200",
    "time_zone_offset": 120.0,
    "unix_epoch_time": 1668060104,
    "iso_8601": "2022-11-10T08:01:44+02:00",
    "y-m-d": "2022-11-10",
    "yyyy-mm-dd": "2022-11-10",
    "h:m:s": "8:1:44",
    "H:m:s": "8:1:44",
    "hh:mm:ss": "08:01:44",
    "HH:mm:ss": "08:01:44"
}
```

You can set the following value to the `dt` parameter of the `DT` transformer to build the RFC 1123 date string you want.

#### Parameters to DT
| **Argument Name** | **Value** |
| --- | --- |
| value | **<Table 1>** |
| dt | .=val.day_of_week_3_letter + ", " + val.day + " " + val.month_3_letter + " " + val.year + " " + val["HH:mm:ss"] + " " + val.time_zone_hhmm |

#### Output
```
Thu, 10 Nov 2022 08:01:44 +0200
```
