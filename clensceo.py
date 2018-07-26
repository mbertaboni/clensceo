#!/usr/bin/env python
#
# C-lens-CEO - Cylance Python Wrapper - https://github.com/lazycedar/clensceo
# Copyright (C) 2018 Maurizio Bertaboni
# LOOK DOWN for SETUP !
# C-lens-CEO (this file) is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# Nagios Cylance Checker (this file) is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# If not, see <http://www.gnu.org/licenses/>.
#
import jwt  # PyJWT version 1.5.3 as of the time of authoring.
import uuid
import requests  # requests version 2.18.4 as of the time of authoring.
import json
import sys
import argparse
import collections
import urllib2
from datetime import datetime, timedelta
# The tenant's unique identifier.
tid_val = ""
# The application's unique identifier.
app_id = ""
# The application's secret to sign the auth token with.
app_secret = ""
# choose your region (us for USgov, -euc1 for EMEA, let empty for North America)
prefix = "-euc1"

AUTH_URL = "https://protectapi" + prefix + ".cylance.com/auth/v2/token"
GLIST_URL = "https://protectapi" + prefix + \
    ".cylance.com/globallists/v2/?listTypeId=1&page=m&page_size=200"


def build_url(object_type, page_number, page_size):
    the_url = "https://protectapi" + prefix + ".cylance.com/" + object_type + \
        "/v2/?" + "page=" + str(page_number) + "&page_size=" + str(page_size)
    return the_url


def usage():
    print('Usage')


def parse_args(argv):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title="commands")

    get_parser = subparsers.add_parser("get", help="Get elements from VENUE")
    configure_get_parser(get_parser)
    update_parser = subparsers.add_parser(
        "update", help="Update elements from VENUE")
    configure_update_parser(update_parser)

    args = parser.parse_args(argv)
    return args


def configure_update_parser(parser):
    update_commands = parser.add_subparsers(title="update commands")
    # USERS
    parser_update_device = update_commands.add_parser(
        "device", help='update a device')
    parser_update_device.add_argument(
        'device_name', help='name of the device')
    parser_update_device.add_argument(
        '--policy_id', help='policy id to assign to the device')
    parser_update_device.add_argument(
        '--zone_add', help='list of zone ids which the device is to be assigned')
    parser_update_device.add_argument(
        '--zone_remove', help='list of zone ids which the device is to be removed')
    parser_update_device.set_defaults(cmd="update_device")


def configure_get_parser(parser):
    get_commands = parser.add_subparsers(title="get commands")
    # USERS
    get_users = get_commands.add_parser("users", help='get list of users')
    get_users.add_argument('-A', '--awk_friendly', action='store_true',
                           help='Try to output AWK friendly', default=0)
    get_users.add_argument('-S', '--short', action='store_true',
                           help="Try to output in a short scriptable fashion way", default=0)
    get_users.set_defaults(cmd="get_users")
    # DEVICES
    get_devices = get_commands.add_parser(
        "devices", help='get list of devices')
    get_devices.add_argument('-A', '--awk_friendly', action='store_true',
                             help="Try to output AWK friendly", default=0)
    get_devices.add_argument('-S', '--short', action='store_true',
                             help="Try to output in a short scriptable fashion way", default=0)
    get_devices.set_defaults(cmd="get_devices")
    # POLICIES
    get_policies = get_commands.add_parser(
        "policies", help='get list of policies')
    get_policies.add_argument('-A', '--awk_friendly', action='store_true',
                              help="Try to output AWK friendly", default=0)
    get_policies.add_argument('-S', '--short', action='store_true',
                              help="Try to output in a short scriptable fashion way", default=0)
    get_policies.add_argument('-p', '--page', type=int, nargs=1,
                              help="Page number to request", default=0)
    get_policies.add_argument('-pp', '--page_size', type=int, nargs=1,
                              help="Page number of device records to retrieve per page", default=200)
    get_policies.set_defaults(cmd="get_policies")
    # ZONES
    get_zones = get_commands.add_parser(
        "zones", help='get list of zones')
    get_zones.add_argument('-A', '--awk_friendly', action='store_true',
                           help="Try to output AWK friendly", default=0)
    get_zones.add_argument('-S', '--short', action='store_true',
                           help="Try to output in a short scriptable fashion way", default=0)
    get_zones.set_defaults(cmd="get_zones")
    # GLIST
    get_glist = get_commands.add_parser(
        "global_list", help='get global list')
    get_glist.add_argument('-A', '--awk_friendly', action='store_true',
                           help="Try to output AWK friendly", default=0)
    get_glist.add_argument('-S', '--short', action='store_true',
                           help="Try to output in a short scriptable fashion way", default=0)
    get_glist.set_defaults(cmd="get_glist")


def get_users():
    compute_request = requests.get(
        build_url('users', 1, 200), headers=headers_request)
    number_elements = json.loads(compute_request.text)
    total_pages = int(number_elements['total_pages'])
    #total_number_of_items = number_elements['total_number_of_items']
    page = 0
    for page in str(total_pages):
        users_request = requests.get(
            build_url('users', int(page), 200), headers=headers_request)
    #print "http_status_code: " + str(users.status_code)
        utenti = json.loads(users_request.text)
        for utente in utenti['page_items']:
            if args.awk_friendly == True:
                print utente['id'] + "::" + utente['first_name'] + \
                    "::" + utente['last_name'] + "::" + utente['email']
            elif args.short == True:
                print utente['id'] + "\t" + utente['first_name'] + \
                    "\t" + utente['last_name'] + "\t" + utente['email']
            else:
                print "=" * 12
                for dettagli in utente.items():
                    print dettagli[0] + ": " + str(dettagli[1])


def get_zones():
    compute_request = requests.get(
        build_url('zones', 1, 200), headers=headers_request)
    number_elements = json.loads(compute_request.text)
    total_pages = int(number_elements['total_pages'])
    #total_number_of_items = number_elements['total_number_of_items']
    page = 0
    for page in str(total_pages):
        zones = requests.get(build_url('zones', int(page), 200),
                             headers=headers_request)
        impostazioni_zone = json.loads(zones.text)
        print "Id" + "\t" + "Name" + "\t" + "Date Modified" + "\t" + \
            "Date Created" + "\t" + "Criticality" + "\t" + "Policy"
        for zone in impostazioni_zone['page_items']:
            if args.awk_friendly == True:
                print zone['id'] + "::" + zone['name'] + "::" + str(zone['date_modified']) + "::" + str(
                    zone['date_created']) + "::" + str(zone['criticality']) + "::" + get_policy(zone['policy_id'])
            elif args.short == True:
                print zone['id'] + "\t" + zone['name'] + "\t" + zone['date_modified'] + \
                    "\t" + zone['date_created'] + \
                    "\t" + str(zone['criticality'])
            else:
                print "=" * 12
                for dettagli in zone.items():
                    print dettagli[0] + ": " + str(dettagli[1])


def get_policy(ref):
    policies = requests.get(
        build_url('policies', 1, 200), headers=headers_request)
    impostazioni_policy = json.loads(policies.text)
    for policy in impostazioni_policy['page_items']:
        if policy['id'] == ref:
            policyname = policy['name']
            return policyname


def get_policies():
    compute_request = requests.get(
        build_url('policies', 1, 200), headers=headers_request)
    number_elements = json.loads(compute_request.text)
    total_pages = int(number_elements['total_pages'])
    #total_number_of_items = number_elements['total_number_of_items']
    page = 0
    for page in str(total_pages):
        policies = requests.get(
            build_url('policies', int(page), 200), headers=headers_request)
        impostazioni_policy = json.loads(policies.text)
        for impostazioni in impostazioni_policy['page_items']:
            if args.awk_friendly == True:
                print impostazioni['id'] + "::" + impostazioni['name'] + "::" + str(impostazioni['date_modified']) + "::" + str(
                    impostazioni['date_added']) + "::" + str(impostazioni['device_count'])
            elif args.short == True:
                print impostazioni['id'] + "\t" + impostazioni['name'] + "\t" + impostazioni['date_modified'] + \
                    "\t" + impostazioni['date_added'] + \
                    "\t" + str(impostazioni['device_count'])
            else:
                print "=" * 12
                for impostazione in impostazioni.items():
                    print impostazione[0] + ": " + str(impostazione[1])


def get_vtotal(hash):
    params = {
        'apikey': 'e9bf6a62b9f7460306b3cfed2deb58671fe1dca01e35c0dc16297d0022c63e9b', 'resource': hash}
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "gzip,  My Python requests library example client or username"
    }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                            params=params, headers=headers)
    json_response = response.json()
    result = str(json_response['positives']) + \
        "/" + str(json_response['total'])
    return result


def get_glist():
    compute_request = requests.get(GLIST_URL, headers=headers_request)
    number_elements = json.loads(compute_request.text)
    total_pages = int(number_elements['total_pages'])
    #total_number_of_items = number_elements['total_number_of_items']
    page = 0
    for page in str(total_pages):
        glist = requests.get(GLIST_URL, headers=headers_request)
        #print "http_status_code: " + str(users.status_code)
        lists = json.loads(glist.text)
        for item in lists['page_items']:
            if args.awk_friendly == True:
                print item['name'] + "::" + item['classification'] + \
                    "::" + str(item['cylance_score']) + "::" + str(item['added']) + "::" + get_username(str(
                        item['added_by'])) + "::" + str(item['reason']) + "::" + str(item['sha256'])
            elif args.short == True:
                print item['name'] + "\t" + item['classification'] + \
                    "\t" + str(item['cylance_score']) + "\t" + str(item['added']) + "\t" + get_username(str(
                        item['added_by'])) + "\t" + str(item['reason']) + "\t" + str(item['sha256'])
            else:
                print "=" * 12
                for dettagli in item.items():
                    print dettagli[0] + ": " + str(dettagli[1]).strip()


def get_devices():
    compute_request = requests.get(
        build_url('devices', 1, 200), headers=headers_request)
    number_elements = json.loads(compute_request.text)
    total_pages = int(number_elements['total_pages'])
    #total_number_of_items = number_elements['total_number_of_items']
    page = 0
    for page in str(total_pages):
        devices = requests.get(build_url('devices', int(page), 200),
                               headers=headers_request)
        devices = json.loads(devices.text)
        str_ip = ""
        str_mac = ""
        for device in devices['page_items']:
            for ip in device['ip_addresses']:
                str_ip += ip + ","
            for mac in device['mac_addresses']:
                str_mac += mac + ","
            if args.awk_friendly == True:
                print device['name'] + "::" + device['state'] + "::" + device['agent_version'] + "::" + device['policy']['name'] + \
                    "::" + str_ip[:-1] + "::" + str_mac[:-1] + "::" + \
                    device['date_first_registered'] + "::" + device['id']
            elif args.short == True:
                print device['id'] + "\t" + device['name'] + "\t" + \
                    device['state'] + "\t" + \
                    device['agent_version'] + "\t" + str_ip[:-1]
            else:
                print "=" * 12
                print "name: " + device['name']
                print "agent_version: " + device['agent_version']
                print "state: " + device['state']
                print "policy: " + device['policy']['name']
                print "ip_addresses: " + str_ip[:-1]
                print "mac_addresses: " + str_mac[:-1]
                print "date_first_registered: " + \
                    device['date_first_registered']
                print "id: " + device['id']
            str_ip = ""
            str_mac = ""


def update_device(devicename, policy_id, zone_add, zone_remove):
    device_id = get_device_id(devicename)
    if device_id:
        UPDATE_DEVICE_URL = "https://protectapi-euc1.cylance.com/devices/v2/" + device_id
        if policy_id:
            payload = {"name": devicename, "policy_id": policy_id}
            resp = requests.put(
                UPDATE_DEVICE_URL, headers=headers_request, data=json.dumps(payload))
            if str(resp.status_code) == "200":
                print devicename + " changed policy correctly"
            else:
                if str(resp.status_code) == "400":
                    message = json.loads(resp.text)['message']
                    print "Parameters are not ok - " + str(message)
        if zone_add:
            current_policy = get_policy_id(device_id)
            zone_ids = [zone_add]
            payload = {"name": devicename,
                       "policy_id": current_policy, "add_zone_ids": zone_ids}
            resp = requests.put(
                UPDATE_DEVICE_URL, headers=headers_request, data=json.dumps(payload))
            if str(resp.status_code) == "200":
                print devicename + " changed zone correctly"
            else:
                if str(resp.status_code) == "400":
                    message = json.loads(resp.text)['message']
                    print "Parameters are not ok - " + str(message)
        if zone_remove:
            current_policy = get_policy_id(device_id)
            zone_ids = [zone_remove]
            payload = {"name": devicename,
                       "policy_id": current_policy, "remove_zone_ids": zone_ids}
            resp = requests.put(
                UPDATE_DEVICE_URL, headers=headers_request, data=json.dumps(payload))
            if str(resp.status_code) == "200":
                print devicename + " removed zone correctly"
            else:
                if str(resp.status_code) == "400":
                    message = json.loads(resp.text)['message']
                    print "Parameters are not ok - " + str(message)
    else:
        print "Device not found"


def get_username(userid):
    users = requests.get(build_url('users', 1, 200),
                         headers=headers_request)
    impostazioni_users = json.loads(users.text)
    for user in impostazioni_users['page_items']:
        if user['id'] == userid:
            username = user['first_name'] + " " + user['last_name']
            return username


def get_device_id(devname):
    devices = requests.get(build_url('devices', 1, 200),
                           headers=headers_request)
    impostazioni_devices = json.loads(devices.text)
    for device in impostazioni_devices['page_items']:
        if device['name'] == devname:
            deviceid = device['id']
            return deviceid


def get_policy_id(devid):
    devices = requests.get(build_url('devices', 1, 200),
                           headers=headers_request)
    impostazioni_devices = json.loads(devices.text)
    for device in impostazioni_devices['page_items']:
        if device['id'] == devid:
            policyid = device['policy']['id']
            return policyid


def get_device(ref):
    devices = requests.get(build_url('devices', 1, 200),
                           headers=headers_request)
    impostazioni_devices = json.loads(devices.text)
    for device in impostazioni_devices['page_items']:
        if device['id'] == ref:
            devicename = device['name']
            return devicename


def get_device_threats(device):
    DEV_THREATS = "https://protectapi-euc1.cylance.com/devices/v2/" + device + "/threats"
    threats = requests.get(DEV_THREATS, headers=headers_request)
    threats = json.loads(threats.text)
    for threat in threats['page_items']:
        print threat['name'] + "::" + \
            threat['classification'] + "::" + threat['date_found']


def get_token():
    timeout = 1800
    now = datetime.utcnow()
    timeout_datetime = now + timedelta(seconds=timeout)
    epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
    epoch_timeout = int(
        (timeout_datetime - datetime(1970, 1, 1)).total_seconds())
    jti_val = str(uuid.uuid4())
    claims = {
        "exp": epoch_timeout,
        "iat": epoch_time,
        "iss": "http://cylance.com",
        "sub": app_id,
        "tid": tid_val,
        "jti": jti_val
        # The following is optional and is being noted here as an example on how one can restrict
        # the list of scopes being requested
        # "scp": "policy:create, policy:list, policy:read, policy:update"
    }
    encoded = jwt.encode(claims, app_secret, algorithm='HS256')
    #print "auth_token:\n" + encoded + "\n"
    payload = {"auth_token": encoded}
    headers = {"Content-Type": "application/json; charset=utf-8"}
    resp = requests.post(AUTH_URL, headers=headers, data=json.dumps(payload))
    #print "http_status_code: " + str(resp.status_code)
    #print "access_token:\n" + json.loads(resp.text)['access_token'] + "\n"
    access_token = json.loads(resp.text)['access_token']
    global headers_request
    headers_request = {"Accept": "application/json",
                       "Authorization": "Bearer " + access_token,
                       "Content-Type": "application/json"}
    return access_token


if __name__ == "__main__":
    access_token = get_token()
    args = parse_args(sys.argv[1:])
    if args.cmd == "get_users":
        get_users()
    elif args.cmd == "get_devices":
        get_devices()
    elif args.cmd == "get_policies":
        get_policies()
    elif args.cmd == "get_zones":
        get_zones()
    elif args.cmd == "get_glist":
        get_glist()
    elif args.cmd == "update_device":
        update_device(args.device_name, args.policy_id,
                      args.zone_add, args.zone_remove)
    else:
        sys.exit("Not implemented: " + args.cmd)
