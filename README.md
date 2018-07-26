# clensceo
a Python wrapper on Cylance API

Second Attempt with python and Cylance API

## Disclaimer

This software is NOT provided or written by Cylance.
I'm not from Cylance, this code is not validated or approved by Cylance.

## Requirements:

jwt, requests, python 2.7

## Limitations:

- A lot, no proxy support, no support for duplicated device as we use the ip address as primary connection between nagios and Venue.
- Probably a plenty of bugs
- Dates are in UTC ( no support for local TZ)

## Setup:
Open the file and insert
- Venue Tenant ID
- Venue App ID
- Venue App Secret
- Your Tenant's Region

## Clensceo
pronounced *cee-lens-ceeoh* :) - is a wrapper on the API. You can perform multiple operations on a tenant.

Basically you have two commands: get and update.

You can get common objects from venue and manipulate them in a script-style
I found it very convenient whenever you need to perform operations on multiple device in combination with xargs or awk

What you can do at the moment:

### GET
You can get users, devices, policies, zones and global list
For each of these object you can output in a AWK "friendly" way or in a short simplified way (look at the help)
### UPDATE
You can update device, changing policy or zones
