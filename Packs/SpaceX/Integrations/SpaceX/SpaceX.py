import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''

import json
from datetime import datetime
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


''' GLOBAL VARIABLES '''

SCHEMA = {
    "flight_number": 99,
    "mission_type": "mission",
    "mission_name": "Starlink-9 (v1.0) & BlackSky Global 5-6",
    "mission_id": [],
    "launch_year": "2020",
    "launch_date_unix": 1594339200,
    "launch_date_utc": "2020-07-10T00:00:00.000Z",
    "launch_date_local": "2020-07-09T20:00:00-04:00",
    "is_tentative": False,
    "tentative_max_precision": "month",
    "tbd": False,
    "launch_window": None,
    "rocket": {
        "rocket_id": "falcon9",
        "rocket_name": "Falcon 9",
        "rocket_type": "FT",
        "first_stage": {
            "cores": [{
                "core_serial": "B1051",
                "flight": 5,
                "block": 5,
                "gridfins": True,
                "legs": True,
                "reused": True,
                "land_success": None,
                "landing_intent": True,
                "landing_type": "ASDS",
                "landing_vehicle": "OCISLY"
            }]
        },
        "second_stage": {
            "block": 5,
            "payloads": [{
                "payload_id": "Starlink-9",
                "norad_id": [],
                "reused": False,
                "customers": ["SpaceX"],
                "nationality": "United States",
                "manufacturer": "SpaceX",
                "payload_type": "Satellite",
                "payload_mass_kg": 15080,
                "payload_mass_lbs": 33245.7,
                "orbit": "VLEO",
                "orbit_params": {
                    "reference_system": "geocentric",
                    "regime": "very-low-earth",
                    "longitude": None,
                    "semi_major_axis_km": None,
                    "eccentricity": None,
                    "periapsis_km": None,
                    "apoapsis_km": None,
                    "inclination_deg": None,
                    "period_min": None,
                    "lifespan_years": None,
                    "epoch": None,
                    "mean_motion": None,
                    "raan": None,
                    "arg_of_pericenter": None,
                    "mean_anomaly": None
                }
            }, {
                "payload_id": "BlackSky Global 5-6",
                "norad_id": [],
                "reused": False,
                "customers": ["BlackSky Global"],
                "nationality": "United States",
                "manufacturer": "BlackSky Global",
                "payload_type": "Satellite",
                "payload_mass_kg": 110,
                "payload_mass_lbs": 242.5,
                "orbit": "SSO",
                "orbit_params": {
                    "reference_system": "geocentric",
                    "regime": "sun-synchronous",
                    "longitude": None,
                    "semi_major_axis_km": None,
                    "eccentricity": None,
                    "periapsis_km": None,
                    "apoapsis_km": None,
                    "inclination_deg": None,
                    "period_min": None,
                    "lifespan_years": None,
                    "epoch": None,
                    "mean_motion": None,
                    "raan": None,
                    "arg_of_pericenter": None,
                    "mean_anomaly": None
                }
            }]
        },
        "fairings": {
            "reused": None,
            "recovery_attempt": True,
            "recovered": None,
            "ship": "GOMSTREE"
        }
    },
    "ships": ["GOMSCHIEF", "GOMSTREE", "OCISLY"],
    "telemetry": {
        "flight_club": None
    },
    "launch_site": {
        "site_id": "ksc_lc_39a",
        "site_name": "KSC LC 39A",
        "site_name_long": "Kennedy Space Center Historic Launch Complex 39A"
    },
    "launch_success": None,
    "links": {
        "mission_patch": "https://images2.imgbox.com/d2/3b/bQaWiil0_o.png",
        "mission_patch_small": "https://images2.imgbox.com/9a/96/nLppz9HW_o.png",
        "reddit_campaign": "https://www.reddit.com/r/spacex/comments/h8mold/starlink9_launch_campaign_thread/",
        "reddit_launch": "https://www.reddit.com/r/spacex/comments/hfksxj/rspacex_starlink9_official_launch_discussion/",
        "reddit_recovery": None,
        "reddit_media": "https://www.reddit.com/r/spacex/comments/hg499n/rspacex_starlink9_media_thread_photographer/",
        "presskit": None,
        "article_link": None,
        "wikipedia": "https://en.wikipedia.org/wiki/Starlink",
        "video_link": "https://youtu.be/KU6KogxG5BE",
        "youtube_id": "KU6KogxG5BE",
        "flickr_images": []
    },
    "details": "This mission will launch the ninth batch of operational Starlink satellites...",
    "upcoming": True,
    "static_fire_date_utc": "2020-06-24T18:18:00.000Z",
    "static_fire_date_unix": 1593022680,
    "timeline": None,
    "crew": None,
    "last_date_update": "2020-07-11T15:20:15.000Z",
    "last_ll_launch_date": None,
    "last_ll_update": None,
    "last_wiki_launch_date": "2020-07-14T00:00:00.000Z",
    "last_wiki_revision": "055d2188-c38a-11ea-a73d-0eba21617ca7",
    "last_wiki_update": "2020-07-11T15:20:15.000Z",
    "launch_date_source": "wiki"
}


''' CLASSES '''


class Client(BaseClient):

    """
    Client will implement the service API, should not contain Cortex
    XSOAR logic. Should do requests and return data
    """

    def get_company_info(self) -> dict:
        return self._http_request(
            method='GET',
            url_suffix='/info'
        )

    def get_api_info(self) -> dict:
        return self._http_request(
            method='GET',
            url_suffix=''
        )

    def get_launches(self, params: dict = None) -> dict:
        return self._http_request(
            method='GET',
            url_suffix='/launches',
            params=params
        )

    def get_upcoming_launches(self, params: dict = None) -> dict:
        return self._http_request(
            method='GET',
            url_suffix='/launches/upcoming',
            params=params
        )

    def get_launch_details_command(self, flight_number: int = None) -> dict:
        return self._http_request(
            method='GET',
            url_suffix=f'/launches/{flight_number}'
        )

    def get_next_launch(self) -> dict:
        return self._http_request(
            method='GET',
            url_suffix='/launches/next',
        )

    def get_all_landing_pads(self, params: dict = None):
        return self._http_request(
            method='GET',
            url_suffix='/landpads',
            params=params
        )

    def get_landing_pad(self, pad_id: str):
        return self._http_request(
            method='GET',
            url_suffix=f'/landpads/{pad_id}',
        )

    def get_roadster_data(self):
        return self._http_request(
            method='GET',
            url_suffix='/roadster',
        )

    def get_all_missions(self, params: dict = None):
        return self._http_request(
            method='GET',
            url_suffix='/missions',
            params=params
        )

    def get_mission(self, mission_id: str):
        return self._http_request(
            method='GET',
            url_suffix=f'/missions/{mission_id}',
        )

    def get_launch_pads(self, params: dict = None):
        return self._http_request(
            method='GET',
            url_suffix='/launchpads',
            params=params
        )

    def get_launch_pad(self, site_id: str):
        return self._http_request(
            method='GET',
            url_suffix=f'/launchpads/{site_id}',
        )

    def get_ships(self, params: dict = None):
        return self._http_request(
            method='GET',
            url_suffix='/ships',
            params=params
        )

    def get_ship(self, ship_id: str):
        return self._http_request(
            method='GET',
            url_suffix=f'/ships/{ship_id}',
        )

    def get_capsules(self, params: dict = None):
        return self._http_request(
            method='GET',
            url_suffix='/capsules',
            params=params
        )

    def get_capsule(self, capsule_serial: str):
        return self._http_request(
            method='GET',
            url_suffix=f'/capsules/{capsule_serial}',
        )

    def get_upcoming_capsules(self, params: dict = None):
        return self._http_request(
            method='GET',
            url_suffix='/capsules/upcoming',
            params=params
        )

    def get_past_capsules(self, params: dict = None):
        return self._http_request(
            method='GET',
            url_suffix='/capsules/past',
            params=params
        )

    def get_cores(self, params: dict = None):
        return self._http_request(
            method='GET',
            url_suffix='/cores',
            params=params
        )

    def get_core(self, core_serial: str):
        return self._http_request(
            method='GET',
            url_suffix=f'/cores/{core_serial}',
        )

    def get_upcoming_cores(self, params: dict = None):
        return self._http_request(
            method='GET',
            url_suffix='/cores/upcoming',
            params=params
        )

    def get_past_cores(self, params: dict = None):
        return self._http_request(
            method='GET',
            url_suffix='/cores/past',
            params=params
        )

    def get_dragons(self, params: dict = None):
        return self._http_request(
            method='GET',
            url_suffix='/dragons',
            params=params
        )

    def get_dragon(self, dragon_id: str):
        return self._http_request(
            method='GET',
            url_suffix=f'/dragons/{dragon_id}',
        )

    def get_historical_events(self, params: dict = None):
        return self._http_request(
            method='GET',
            url_suffix=f'/history',
            params=params
        )

    def get_historical_event(self, event_id: int):
        return self._http_request(
            method='GET',
            url_suffix=f'/history/{event_id}',
        )

    def get_payloads(self, params: dict = None):
        return self._http_request(
            method='GET',
            url_suffix='/payloads',
            params=params
        )

    def get_payload(self, payload_id: str):
        return self._http_request(
            method='GET',
            url_suffix=f'/payloads/{payload_id}',
        )

    def get_rockets(self, params: dict = None):
        return self._http_request(
            method='GET',
            url_suffix='/rockets',
            params=params
        )

    def get_rocket(self, rocket_id: str):
        return self._http_request(
            method='GET',
            url_suffix=f'/rockets/{rocket_id}',
        )


def get_company_info_command(client):
    res = client.get_company_info()
    md = tableToMarkdown('SpaceX Company Info:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Company.Info',
        outputs_key_field='name',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_api_info_command(client, args):
    res = client.get_api_info()
    md = tableToMarkdown('SpaceX API Info:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.API.Info',
        outputs_key_field=['project_name', 'version'],
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_launches_command(client, args):
    params = args
    res = client.get_launches(params)
    launches = list()
    for launch in res:
        thisLaunch = dict()
        for k, v in launch.items():
            if type(v) not in [dict, list]:
                thisLaunch[k] = v
        thisLaunch['rocket'] = {k: v for k, v in launch['rocket'].items()
                                if type(v) not in [dict, list]}
        thisLaunch['ships'] = launch['ships']
        thisLaunch['links'] = [launch['links'][x] for x in launch['links']
                               if type(x) not in [list, dict]]
        launches.append(thisLaunch)

    md = tableToMarkdown('SpaceX Launches:', launches)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Launches',
        outputs_key_field='flight_number',
        outputs=launches,
        readable_output=md
    )
    return_results(command_results)


def get_launch_details_command(client, args):
    flight_number = args.get('flight_number')
    res = client.get_launch_details_command(flight_number)
    md = tableToMarkdown(f'SpaceX Flight Number {flight_number} details:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Launches',
        outputs_key_field='flight_number',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_upcoming_launches_command(client, args):
    params = args
    res = client.get_upcoming_launches(params)
    launches = list()
    for launch in res:
        thisLaunch = dict()
        for k, v in launch.items():
            if type(v) not in [dict, list]:
                thisLaunch[k] = v
        thisLaunch['rocket'] = {k: v for k, v in launch['rocket'].items()
                                if type(v) not in [dict, list]}
        thisLaunch['ships'] = launch['ships']
        thisLaunch['links'] = [launch['links'][x] for x in launch['links']
                               if type(x) not in [list, dict]]
        launches.append(thisLaunch)

    md = tableToMarkdown('SpaceX Upcoming launches:', launches)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Launches',
        outputs_key_field='flight_number',
        outputs=launches,
        readable_output=md
    )
    return_results(command_results)


def get_next_launch_command(client, args):
    res = client.get_next_launch()
    md = tableToMarkdown('SpaceX Next launch:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Launches',
        outputs_key_field='flight_number',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_launch_images_command(client, args):
    flight_number = args.get('flight_number')
    res = client.get_launch_details_command(flight_number)
    images = res.get('links', {}).get('flickr_images', [])
    images = [{'link': x} for x in images]
    md = ""
    for image in images:
        md += f'![{image["link"]}]({image["link"]})\n'

    command_results = CommandResults(
        outputs_prefix=f'SpaceX.Images.Flight-{flight_number}',
        outputs_key_field='link',
        outputs=images,
        readable_output=md
    )
    return_results(command_results)


def get_all_landing_pads_command(client, args):
    res = client.get_all_landing_pads(args)
    parsed_res = [
        {
            "Full Name": x['full_name'],
            "ID": x['id'],
            "Status": x['status'],
            "Location": x['location']['name']
        }
        for x in res]
    md = tableToMarkdown('SpaceX Landing pads:', parsed_res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.LandingPads',
        outputs_key_field='id',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_landing_pad_command(client, args):
    pad_id = args.get('id')
    res = client.get_landing_pad(pad_id)
    md = tableToMarkdown(f'SpaceX Landing pad ID {pad_id}:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.LandingPads',
        outputs_key_field='id',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_roadster_data_command(client, args):
    res = client.get_roadster_data()
    md = tableToMarkdown(f'SpaceX Roadster Data:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Roadster',
        outputs_key_field='launch_date_utc',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_all_missions_command(client, args):
    res = client.get_all_missions(args)
    md = tableToMarkdown(f'SpaceX Missions:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Missions',
        outputs_key_field='mission_id',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_mission_command(client, args):
    mission_id = args.get('mission_id')
    res = client.get_mission(mission_id)
    md = tableToMarkdown(f'SpaceX Mission ID {mission_id}:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Missions',
        outputs_key_field='mission_id',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_launch_pads_command(client, args):
    res = client.get_launch_pads(args)
    md = tableToMarkdown(f'SpaceX Launch Pads:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.LaunchPads',
        outputs_key_field='id',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_launch_pad_command(client, args):
    site_id = args.get('site_id')
    res = client.get_launch_pad(site_id)
    md = tableToMarkdown(f'SpaceX Launch Pad site ID {site_id}:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.LaunchPads',
        outputs_key_field='id',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_ships_command(client, args):
    res = client.get_ships(args)
    md = tableToMarkdown(f'SpaceX Ships:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Ships',
        outputs_key_field='ship_id',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_ship_command(client, args):
    ship_id = args.get('ship_id')
    res = client.get_ship(ship_id)
    md = tableToMarkdown(f'SpaceX Ship ID {ship_id}:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Ships',
        outputs_key_field='ship_id',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_capsules_command(client, args):
    res = client.get_capsules(args)
    # This limits the results as the API seems to return
    # one more than it should do
    res = res[0:int(args['limit'])] if "limit" in args else res
    md = tableToMarkdown(f'SpaceX Capsules:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Capsules',
        outputs_key_field='capsule_serial',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_capsule_command(client, args):
    capsule_serial = args.get('capsule_serial')
    res = client.get_capsule(capsule_serial)
    md = tableToMarkdown(f'SpaceX Capsule Serial {capsule_serial}:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Capsules',
        outputs_key_field='capsule_serial',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_upcoming_capsules_command(client, args):
    res = client.get_upcoming_capsules(args)
    md = tableToMarkdown(f'SpaceX Upcoming Capsules:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Capsules',
        outputs_key_field='capsule_serial',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_past_capsules_command(client, args):
    res = client.get_past_capsules(args)
    md = tableToMarkdown(f'SpaceX Past Capsules:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Capsules',
        outputs_key_field='capsule_serial',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_cores_command(client, args):
    res = client.get_cores(args)
    md = tableToMarkdown(f'SpaceX Cores:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Cores',
        outputs_key_field='core_serial',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_core_command(client, args):
    core_serial = args.get('core_serial')
    res = client.get_core(core_serial)
    md = tableToMarkdown(f'SpaceX Core Serial {core_serial}:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Cores',
        outputs_key_field='core_serial',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_upcoming_cores_command(client, args):
    res = client.get_upcoming_cores(args)
    md = tableToMarkdown(f'SpaceX Upcoming Cores:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Cores',
        outputs_key_field='core_serial',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_past_cores_command(client, args):
    res = client.get_past_cores(args)
    md = tableToMarkdown(f'SpaceX Past Cores:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Cores',
        outputs_key_field='core_serial',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_dragons_command(client, args):
    res = client.get_dragons(args)
    md = tableToMarkdown(f'SpaceX Dragons:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Dragons',
        outputs_key_field='id',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_dragon_command(client, args):
    dragon_id = args.get('dragon_id')
    res = client.get_dragon(dragon_id)
    md = tableToMarkdown(f'SpaceX Dragon ID {dragon_id}:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Dragons',
        outputs_key_field='id',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_historical_events_command(client, args):
    res = client.get_historical_events(args)
    md = tableToMarkdown(f'SpaceX Historical Events:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.History',
        outputs_key_field='id',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_historical_event_command(client, args):
    event_id = args.get('event_id')
    res = client.get_historical_event(event_id)
    md = tableToMarkdown(f'SpaceX Historical Event ID {event_id}:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.History',
        outputs_key_field='id',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_payloads_command(client, args):
    res = client.get_payloads(args)
    md = tableToMarkdown(f'SpaceX Payloads:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Payloads',
        outputs_key_field='payload_id',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_payload_command(client, args):
    payload_id = args.get('payload_id')
    res = client.get_payload(payload_id)
    md = tableToMarkdown(f'SpaceX Payload ID {payload_id}:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Payloads',
        outputs_key_field='payload_id',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_rockets_command(client, args):
    res = client.get_rockets(args)
    md = tableToMarkdown(f'SpaceX Rockets:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Rockets',
        outputs_key_field='id',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_rocket_command(client, args):
    rocket_id = args.get('rocket_id')
    res = client.get_rocket(rocket_id)
    md = tableToMarkdown(f'SpaceX Rocket ID {rocket_id}:', res)
    command_results = CommandResults(
        outputs_prefix='SpaceX.Rockets',
        outputs_key_field='id',
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def fetch_incidents_command(client, params):

    incidents = []
    last_run = demisto.getLastRun()
    if last_run:
        latest_id = int(last_run.get('id', 0))

    else:
        latest_id = 0
    upcoming_launches = client.get_upcoming_launches()
    upcoming_launches[:] = [x for x in upcoming_launches
                            if int(x['flight_number']) > latest_id]
    upcoming_launches = sorted(
        upcoming_launches,
        key=lambda x: x['flight_number']
    )
    all_ids = [latest_id]
    instance_name = demisto.integrationInstance()
    mirror_direction = "In" if demisto.params().get('mirror') else ""
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    for launch in upcoming_launches:
        launch['dbotMirrorDirection'] = mirror_direction
        launch['dbotMirrorInstance'] = instance_name
        launch['mission_type'] = "mission"
        incident = {
            "name": f"SpaceX Flight Number {launch['flight_number']}",
            "details": launch['details'],
            "occurred": now,
            "rawJSON": json.dumps(launch)
        }
        incidents.append(incident)
        all_ids.append(int(launch['flight_number']))

    all_ids = sorted(all_ids, reverse=True)
    last_run = {'id': str(all_ids[0])}
    demisto.setLastRun(last_run)
    demisto.incidents(incidents)


def test_module(client, args):
    res = client.get_api_info()
    if res:
        demisto.results('ok')
    else:
        return_error("Error")


def get_remote_data_command(client, args, params):
    mission_id = args.get('id')
    entries = list()
    mission = client.get_launch_details_command(mission_id)
    return [mission] + entries


def update_remote_system_command(client, args, params):
    case_id = args.get('remoteId')
    return case_id


def get_mapping_fields_command(client, args, params):
    instance_name = demisto.integrationInstance()
    mirror_direction = "In" if params.get('mirror') else ""
    SCHEMA['dbotMirrorDirection'] = mirror_direction
    SCHEMA['dbotMirrorInstance'] = instance_name
    return {"Default schema": SCHEMA}


def main():
    params = demisto.params()
    args = demisto.args()
    proxies = handle_proxy()
    verify = not params.get('insecure')
    base_url = params.get('url')
    client = Client(base_url, verify=verify, proxy=proxies)

    command = demisto.command()
    demisto.info(f"Command being executed is {command}")
    try:
        commands = {
            'spacex-get-company-info': get_company_info_command,
            'spacex-get-api-info': get_api_info_command,
            'spacex-get-launches': get_launches_command,
            'spacex-get-upcoming-launches': get_upcoming_launches_command,
            'spacex-get-launch-details': get_launch_details_command,
            'spacex-get-next-launch': get_next_launch_command,
            'spacex-get-launch-images': get_launch_images_command,
            'spacex-get-landing-pads': get_all_landing_pads_command,
            'spacex-get-landing-pad': get_landing_pad_command,
            'spacex-get-roadster': get_roadster_data_command,
            'spacex-get-missions': get_all_missions_command,
            'spacex-get-mission': get_mission_command,
            'spacex-get-launch-pads': get_launch_pads_command,
            'spacex-get-launch-pad': get_launch_pad_command,
            'spacex-get-ships': get_ships_command,
            'spacex-get-ship': get_ship_command,
            'spacex-get-capsules': get_capsules_command,
            'spacex-get-capsule': get_capsule_command,
            'spacex-get-upcoming-capsules': get_upcoming_capsules_command,
            'spacex-get-past-capsules': get_past_capsules_command,
            'spacex-get-cores': get_cores_command,
            'spacex-get-core': get_core_command,
            'spacex-get-upcoming-cores': get_upcoming_cores_command,
            'spacex-get-past-cores': get_past_cores_command,
            'spacex-get-dragons': get_dragons_command,
            'spacex-get-dragon': get_dragon_command,
            'spacex-get-historical-events': get_historical_events_command,
            'spacex-get-historical-event': get_historical_event_command,
            'spacex-get-payloads': get_payloads_command,
            'spacex-get-payload': get_payload_command,
            'spacex-get-rockets': get_rockets_command,
            'spacex-get-rocket': get_rocket_command,
        }

        if command == 'fetch-incidents':
            fetch_incidents_command(client, params)
        elif command == 'test-module':
            test_module(client, params)
        elif command == 'get-mapping-fields':
            demisto.results(get_mapping_fields_command(client, args, params))
        elif command == 'get-remote-data':
            demisto.results(get_remote_data_command(client, args, params))
        elif command == 'update-remote-system':
            demisto.results(update_remote_system_command(client, args, params))
        elif command in commands:
            commands[command](client, args)
        else:
            return_error(f"{command} does not exist in SpaceX integration.")
    except Exception as err:
        return_error(f'Failed to execute {command} command. Error: {str(err)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
