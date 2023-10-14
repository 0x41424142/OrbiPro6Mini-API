"""
Package to interact with the Netgear Orbi Pro Wifi 6 Mini router.
At this time, it just pulls down admin logs, but I will probably
add the ability to mess with firewall/VLAN/devices in the future.
"""
from sys import version_info
from argparse import ArgumentParser
from ipaddress import ip_address
import ipaddress
from bs4 import BeautifulSoup
import requests

__author__ = "Jake Lindsay <jakelindsayp@gmail.com>"

if version_info < (3, 10): raise Exception("This package requires Python 3.10 or higher.")
#disable self-signed cert warnings
requests.packages.urllib3.disable_warnings()

class Router:
    def __init__(self, username: str|None = None, password:str|None = None, ip: str|None =None, verbose: bool = False) -> object:
        '''
        Object to interact with the Netgear Orbi Pro Wifi 6 Mini router.
        '''
        for arg in [username, password, ip]:
            if arg is None: raise Exception("Please provide a username, password, and IP address.")

        self.username = username
        self.password = password
        self.ip = ip
        self.verbose = verbose
        self.session = requests.Session()

    def __str__(self) -> str:
        return f"Router({self.ip} {'with username: '+self.username + 'and password: ', self.password}" if self.verbose else f"Router({self.ip})"
    
    def login(self) -> None:
        '''
        Authenticate to the router with HTTP Basic Auth.
        '''
        page = requests.get(f"https://{self.ip}", verify=False, auth=(self.username, self.password))
        if page.status_code == 200:
            print("Login successful.")
        else:
            raise Exception("Login failed. Please check your username and password.")
        
    def get_logs(self) -> list:
        '''
        Pull the logs text box from the advanced administration page.
        '''
        #pull the logs page
        logs_page = self.session.get(f"https://{self.ip}/FW_log.htm", verify=False, auth=(self.username, self.password))
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
            'logins': [],
            'external_access': []
            }
        
        for log in logs:
            if '[remote login]' in log:
                events['logins'].append(log)
                if not ip_address(log.split()[4]).is_private:
                    print(f'[!] External login detected from: {log.split()[4]} at {"".join(log[6:9])}! Review your firewall rules immediately!')
                else:
                    print(f'[!] LAN Login detected: {log}')
                #TODO: add abuseipdb lookup
            if 'LAN access from remote' in log:
                events['external_access'].append(log)
                print(f'[!] External access detected: {log}')
                #TODO: add abuseipdb lookup
        return events


if __name__ == '__main__':
    parser = ArgumentParser(description="Interact with the Netgear Orbi Pro Wifi 6 Mini router.")
    parser.add_argument("-u", "--username", required=True, help="Username for the router.")
    parser.add_argument("-p", "--password", required=True, help="Password for the router.")
    parser.add_argument("-i", "--ip", required=True, help="IP address of the router.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose output.")
    parser.add_argument('-a', '--action', choices=['get_logs', 'scan_logs'], required=True, help="Action to perform.")
    args = parser.parse_args()

    router = Router(username=args.username, password=args.password, ip=args.ip, verbose=args.verbose)
    router.login()
    match args.action:
        case 'get_logs':
            logs = router.get_logs()
            for log in logs:
                print(log)
        case _:
            raise Exception("Invalid action.")