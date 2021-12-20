import demistomock as demisto
import json


def side_effect_demisto_dt(obj, dt):
    try:
        for month in ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'):
            pattern = ".={Jan:'01', Feb: '02', Mar:'03', Apr:'04', May:'05', Jun:'06', " +\
                      "Jul:'07', Aug:'08', Sep:'09', Oct:'10', Nov:'11', Dec:'12'}['" + month + "']"
            if dt == pattern:
                return {
                    'Jan': '01',
                    'Feb': '02',
                    'Mar': '03',
                    'Apr': '04',
                    'May': '05',
                    'Jun': '06',
                    'Jul': '07',
                    'Aug': '08',
                    'Sep': '09',
                    'Oct': '10',
                    'Nov': '11',
                    'Dec': '12'
                }.get(month)

        for day in range(1, 31):
            if dt == f".=('0'+'{day}').slice(-2)":
                return f'0{day}'[-2:]

        if dt.startswith('month='):
            obj = obj.get('month')
            dt = '.' + dt[len('month'):]

        if dt == '.=val.day == 29 && (val.year % 4) == 0 && !((val.year % 100) == 0 && (val.year % 400) != 0)':
            day = int(obj.get('day'))
            year = int(obj.get('year'))
            return day == 29 and (year % 4) == 0 and not ((year % 100) == 0 and (year % 400) != 0)

        elif dt.startswith('.=val <='):
            return int(obj) <= int(dt[len('.=val <='):])
        elif dt.startswith('.=val <'):
            if int(obj) == 6:
                raise RuntimeError(dt)
            return int(obj) < int(dt[len('.=val <'):])
        elif dt.startswith('.=val >='):
            return int(obj) >= int(dt[len('.=val >='):])
        elif dt.startswith('.=val >'):
            return int(obj) > int(dt[len('.=val >'):])
        elif dt.startswith('.=val =='):
            return int(obj) == int(dt[len('.=val =='):])
        elif dt.startswith('.=val !='):
            return int(obj) != int(dt[len('.=val !='):])
    except Exception:
        return False

    if isinstance(obj, dict):
        return obj.get(dt)
    return None


def test_main(mocker):
    from MapPattern import main

    with open('./test_data/test-1.json', 'r') as f:
        test_list = json.load(f)

    mocker.patch.object(demisto, 'dt', side_effect=side_effect_demisto_dt)

    for t in test_list:
        for pattern in t['patterns']:
            mocker.patch.object(demisto, 'args', return_value={
                'value': pattern['value'],
                'algorithm': t['algorithm'],
                'caseless': t['caseless'],
                'priority': t['priority'],
                'context': t['context'],
                'flags': t['flags'],
                'compare_fields': t['compare_fields'],
                'wildcards': t['wildcards'],
                'mappings': t['mappings'],
            })
            mocker.patch.object(demisto, 'results')
            main()
            assert demisto.results.call_count == 1
            results = demisto.results.call_args[0][0]
            assert json.dumps(results) == json.dumps(pattern['result'])
