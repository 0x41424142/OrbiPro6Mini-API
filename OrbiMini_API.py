"""
Package to interact with the Netgear Orbi Pro Wifi 6 Mini router.
At this time, it just pulls down admin logs, but I will probably
add the ability to mess with firewall/VLAN/devices in the future.
"""
from os import path
from sys import version_info
from json import loads
from argparse import ArgumentParser
from datetime import datetime
from ipaddress import ip_address
from bs4 import BeautifulSoup
import requests

__author__ = "Jake Lindsay <jakelindsayp@gmail.com>"

if version_info < (3, 10): raise Exception("This package requires Python 3.10 or higher.")
#disable self-signed cert warnings
requests.packages.urllib3.disable_warnings()

class Router:
    def __init__(self, username: str|None = None, password:str|None = None, host: str|None =None, verbose: bool = False) -> object:
        '''
        Object to interact with the Netgear Orbi Pro Wifi 6 Mini router.
        '''
        self.username = username
        self.password = password
        self.host = host
        self.session = requests.Session()
        try: self.device_config = open(path.join(path.dirname(__file__), 'device_fields.txt'), 'r').read().split('\n')
        except FileNotFoundError: raise FileNotFoundError("Please run with the --action generate_config flag first.")

    def __str__(self) -> str:
        return f"Router({self.host})"
    
    def login(self, username: str| None = None, password: str|None = None, host: str|None = None) -> None:
        '''
        Authenticate to the router with HTTP Basic Auth.
        '''
        if username is not None: self.username = username
        if password is not None: self.password = password
        if host is not None: self.host = host
        
        for arg in [self.username, self.password, self.host]:
            if arg is None: raise Exception("Please provide a username, password, and IP address/DNS name for the router.")

        for i in range(2): #try twice. the router can fail to respond to the first request sometimes...
            page = requests.get(f"https://{self.host}", verify=False, auth=(self.username, self.password))
            if page.status_code == 200:
                print("Login successful.")
                return
            else:
                if i == 1: raise Exception("Login failed. Please check your username and password.")
        
    def get_logs(self) -> list:
        '''
        Pull the logs text box from the advanced administration page.
        '''
        #pull the logs page
        logs_page = self.session.get(f"https://{self.host}/FW_log.htm", verify=False, auth=(self.username, self.password))
        if logs_page.status_code != 200:
            raise Exception("Failed to pull logs page.")
        #parse the logs page
        soup = BeautifulSoup(logs_page.content, 'html.parser')
        #get the logs text box <textarea NAME="log_detail" id="log_detail"...>
        logs = soup.find('textarea', {'name': 'log_detail', 'id': 'log_detail'})
        if logs is None:
            raise Exception("Failed to find logs text box.")
        #return the logs as a dict
        else: print("Logs pulled successfully.")
        return logs.text.split('\n')
    
    def scan_logs(self, logs: list) -> dict:
        '''
        Scan the logs for juicy events
        (logins to router, external IPs accessing LAN)

        param: logs: list of log lines
        return: dict of events
        '''
        events = {
            'logins': {
                'internal': [],
                'external': []
            },
            'external_access': []
            }
        
        for log in logs:
            if '[remote login]' in log:
                if not ip_address(ip:=log.split()[4].replace(',','')).is_private:
                    events['logins']['external'].append(log)
                    print(f'[!] External login detected from: {ip} on {" ".join(log[6:9])} - Review your firewall rules immediately!')
                else:
                    events['logins']['internal'].append(log)
                    print(f'[!] LAN Login detected from: {ip} on {" ".join(log.split()[6:10])}')
                #TODO: add abuseipdb lookup
            if 'LAN access from remote' in log:
                events['external_access'].append(log)
                print(f'[!] External access detected: {log}')
                #TODO: add abuseipdb lookup
        return 
    
    def get_devices(self) -> dict:
        '''
        Return a dict of devices connected to the router.
        This is a bit of a mess, but it works.
        relies on dict-like strings, so it gets a bit wonky.
        '''
        #orbi expects a unix timestamp in MS?
        ts = int(datetime.now().timestamp() * 1000)
        #pull the devices page
        devices_page = self.session.get(f"https://{self.host}/DEV_device_first_info.htm?ts={ts}", verify=False, auth=(self.username, self.password))
        if devices_page.status_code != 200:
            raise Exception("Failed to pull devices page.")
        #parse the devices page
        cleaner = devices_page.content.decode().replace('device= ', '').split('\n')
        devices = [
            d.replace(d[~0], '') if d[~0] == ',' else d for d in cleaner #remove trailing commas
            if # add to list if they do not match these patterns
                not d.startswith('mesh_topo')
                and not d.startswith('sate_mesh_topo')
                and d not in ['}', ']', '[', '']
            ]
        cleaned_devices = {}
        for device in devices:
            device = device.replace('" ', '", ')
            #i really hate text searches on stringed-dictionaries, but 
            #eval/literal_eval probably would have required even more cleaning
            #to use properly.
            cache = [] #cleaned_devices['dev_name'] = key:val format requires a cache to hold found values until the name is found
            name_found = None
            for datakey in self.device_config:
                if datakey in device:
                    #grab the index of the 1st char of the datakey all the way until the next instance of: ,"
                    #this is the value of the datakey
                    try: 
                        startIdx = device.index(datakey+': ')
                        endIdx = device.index(',', device.index(datakey))
                        if datakey == 'mac':
                            data= device[startIdx:endIdx].replace('"','').removeprefix('mac: ')
                        elif datakey == 'conn_orbi_mac':
                            data = device[startIdx:endIdx].replace('"','').removeprefix('conn_orbi_mac: ')
                        else:
                            data = device[startIdx:endIdx].replace(' ', '').split(':')[1]
                    except ValueError: #data on the actual router itself is in a different format
                        #we can actually use the json module to parse this data! thank god!
                        data = loads(device.replace('base_data = ', ''))
                        newKey = {data['device name']: data}
                        cleaned_devices.update(newKey)
                        #add the rest of the data to the cleaned_devices dict
                        for k,v in data.items():
                            if k != 'device name' and k != 'wireless':
                                cleaned_devices[data['device name']].update({k:v})
                        #skip to the next device
                        break
                    cache.append((datakey, data.replace('"', '')) if datakey != 'mac' else (datakey, data))
            for item in cache:
                if item[0] == 'dev_name':
                    cleaned_devices[NAME:=item[1]] = {} #walrus to set the overall key in cleaned_devices
                    break
            cleaned_devices[NAME].update({k:v for k,v in cache})
            if 'wireless' in cleaned_devices[NAME]:
                cleaned_devices[NAME].pop('wireless') #dirty data. underlying keys are already in the dict anyway
        return cleaned_devices
                    


if __name__ == '__main__':
    parser = ArgumentParser(description="Interact with the Netgear Orbi Pro Wifi 6 Mini router.")
    parser.add_argument("-u", "--username", help="Username for the router.")
    parser.add_argument("-p", "--password", help="Password for the router.")
    parser.add_argument("--host", help="IP address/DNS of the router.")
    parser.add_argument('-a', '--action', choices=['get_logs', 'scan_logs', 'get_devices', 'generate_config'], required=True, help="Action to perform.")
    args = parser.parse_args()

    router = Router(username=args.username, password=args.password, host=args.host)
    match args.action:
        case 'get_logs':
            router.login()
            logs = router.get_logs()
            for log in logs:
                print(log)
        case 'scan_logs':
            logs = router.get_logs()
            router.scan_logs(logs)
        case 'get_devices':
            router.login()
            devices = router.get_devices()
            for device in devices:
                print(f"Device: {device}")
                for field in devices[device]:
                    print(f"\t{field}: {devices[device][field]}")
        case 'generate_config':
            config = {
                'dev_kind','ip', 'mac', 'connect_interface',
                'conn_orbi_mac','dev_name','dev_model','new_devtype_name',
                'conn_orbi_name','qos_uprate','qos_downrate','wireless',
                'sec_type','channel','rssi','tx_rate','rx_rate',
                'ssid','acl_status',
                'base_data',"module name",'device name',
                'current version','device mac','device ip'
            }
            with open(path.join(path.dirname(__file__), 'device_fields.txt'), 'w') as configfile:
                configfile.write('\n'.join(config))
                configfile.close()
            print("Config file generated.")

        case _:
            raise Exception("Invalid action.")