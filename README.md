# OrbiPro6Mini-API
API interaction with [Netgear Orbi Pro Wifi 6 Mini](https://www.netgear.com/business/wifi/mesh/sxk30/) routers

## Current Functionality

Currently, the tool allows you to:
  * Pull the connected devices as a dictionary, with device name as the keys and a nested dictionary containing some information under each key.
  * Pull down administrative logs.
  * Scan administrative logs for remote access to your LAN and/or successful logins to the router webpage.

## Planned Functionality
  * Service blocking
  * Address blocking
  * ACL control
  * Device pausing
  * Reboot
  * AbuseIPDB API integration to allow for further fine tuning of the ```scan_logs()``` function. This will allow you to whitelist your own hosts from showing as an alert as well as pull good metrics on a malicious IP when somebody scans your router.
  * SMTP/SMS alerting
  * VLAN control
## CLI Usage
```
usage: OrbiMini_API.py [-h] [-u USERNAME] [-p PASSWORD] [--host HOST] -a
                       {get_logs,scan_logs,get_devices,generate_config}

Interact with the Netgear Orbi Pro Wifi 6 Mini router.

options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Username for the router.
  -p PASSWORD, --password PASSWORD
                        Password for the router.
  --host HOST           IP address/DNS of the router.
  -a {get_logs,scan_logs,get_devices,generate_config}, --action {get_logs,scan_logs,get_devices,generate_config}
                        Action to perform.
```
## Python Usage
```python
from OrbiMini_API import Router
r = Router(username='username', password='password', host='DNS/IP_of_router')
r.login()

#Get logs as a list:
logs = r.get_logs()

#Scan logs for outside access to LAN, router interface logins as a dict:
logs = r.get_logs()
scanned = r.scan_logs(logs)

#Get devices as a dictionary:
devices = r.get_devices()
```
## Structure of the ```get_devices()``` Dictionary:
```
devices[<NAME_OF_DEVICE>] : {

  <DEVICE_DETAIL_NAME> : <DEVICE_DETAIL_VALUE>
  
  <DEVICE_DETAIL_NAME> : <DEVICE_DETAIL_VALUE>
  
}
```
