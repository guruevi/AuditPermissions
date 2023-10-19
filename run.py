#!/usr/bin/env python3
# Collects the ACLs from SMB shares and store them in MongoDB

from os import path
from configparser import ConfigParser
from datetime import datetime
from sys import setrecursionlimit

from typing import List

from dns import resolver
import paramiko
import json
from netrc import netrc

from pymongo import MongoClient
import ldap

# Read in credentials from ini file
config = ConfigParser(interpolation=None)
config.read(path.join(path.dirname(__file__), 'config.ini'))

# Settings for the SSH connection
ssh_host = config['windows_powershell']['host']
domain_creds = config['domain']

# Read creds from a netrc file in home folder
creds = netrc(path.expanduser("~/.ansible/creds"))
admin_user = creds.hosts[domain_creds['fqdn']][0]
admin_pass = creds.hosts[domain_creds['fqdn']][2]

# Connect to the ssh_host
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# Must connect using Password Authentication otherwise SMB doesn't have credentials
ssh.connect(ssh_host, 22, admin_user, admin_pass, look_for_keys=False)

# Copy the PowerShell script to the remote ssh_host
sftp = ssh.open_sftp()
sftp.put("share_acl.ps1", f"C:/Users/{admin_user}/share_acl.ps1")
sftp.close()

# Run the PowerShell script
stdin, stdout, stderr = ssh.exec_command(f"C:/Users/{admin_user}/share_acl.ps1")

try:
    # To debug, uncomment the following line and change the slice to the range you want to see
    # str_output = stdout.read()
    # print(str_output[7033722:7033922])
    output = json.loads(stdout.read())
    error = stderr.read()
except json.decoder.JSONDecodeError:
    print("Error decoding JSON")
    exit(1)
finally:
    ssh.close()

# Each object looks like this:
# print(json.dumps(output, indent=4))
# {
#   "\\server\path": [
#      {
#         "IdentityReference": "DOMAIN\\group_name",   <- AD Object
#         "AccessControlType": "Allow",                        <- Allow/Deny
#         "AccessControlTypeInt": 0,                           <- 0/1 (Allow/Deny)
#         "FileSystemRights": "ReadAndExecute, Synchronize",   <- Permissions
#         "FileSystemRightsInt": 1179817,                      <- Integer representation of permissions
#         "IsInherited": false,                                <- Is this inherited from a parent folder?
#         "InheritanceFlagsInt": 0,                            <- 0/+1/+2 (None/+Container/+Object)
#         "InheritanceFlags": "None",                          <- None/Container/Object
#         "PropagationFlags": "None",                          <- None/InheritOnly/NoPropagateInherit
#         "PropagationFlagsInt": 0                             <- 0/+1/+2 (None/+NoPropagateInherit/+InheritOnly)
#      },
#      ...
#   ],
# ...
# }
# Connect to our MongoDB instance
client = MongoClient(config["mongodb"]["uri"])
db = client[config["mongodb"]["db"]]

# Get the LDAP server from DNS
ldap_server = resolver.resolve(f'_ldap._tcp.{domain_creds["fqdn"]}', 'SRV')[0].target.to_text()
ldap_base = domain_creds['ldap_base']
ldap_bind_dn = domain_creds['bind_dn']
ldap_pass = domain_creds['password']

# Connect to LDAP
ldap_conn = ldap.initialize(f"ldap://{ldap_server}")
ldap_conn.protocol_version = 3
ldap_conn.set_option(ldap.OPT_REFERRALS, 0)
ldap_conn.simple_bind_s(ldap_bind_dn, ldap_pass)

# Fill the Query Cache with the default groups
QUERY_CACHE = {"Domain Users": ["Domain Users"],
               "Domain Admins": ["Domain Admins"],
               "Domain Computers": ["Domain Computers"],
               "Domain Controllers": ["Domain Controllers"],
               "Domain Guests": ["Domain Guests"],
               "Enterprise Admins": ["Enterprise Admins"],
               "Power Users": ["Power Users"],
               "Print Operators": ["Print Operators"],
               "Remote Desktop Users": ["Remote Desktop Users"],
               "Replicator": ["Replicator"],
               "Protected Users": ["Protected Users"],
               "Schema Admins": ["Schema Admins"],
               "Server Operators": ["Server Operators"],
               "Users": ["Users"],
               "Backup Operators": ["Backup Operators"],
               "Cryptographic Operators": ["Cryptographic Operators"],
               "Distributed COM Users": ["Distributed COM Users"],
               "Event Log Readers": ["Event Log Readers"],
               "Guests": ["Guests"],
               "IIS_IUSRS": ["IIS Users"],
               "Network Configuration Operators": ["Network Configuration Operators"],
               "Performance Log Users": ["Performance Log Users"],
               "Performance Monitor Users": ["Performance Monitor Users"],
               "Everyone": ["Everyone"],
               domain_creds["admin_group"]: ["Administrators"]
               }


# Add user from config to the QUERY_CACHE

def get_users(identity: str) -> List[str]:
    ldap_filter = f"(&(objectClass=group)(cn={identity}))"
    if identity in QUERY_CACHE:
        return QUERY_CACHE[identity]

    try:
        msgid = ldap_conn.search(base=ldap_base,
                                 scope=ldap.SCOPE_SUBTREE,
                                 filterstr=ldap_filter,
                                 attrlist=['member'])

        result = ldap_conn.result(msgid)
    except ldap.LDAPError:
        # Search error means it's not a group
        QUERY_CACHE[identity] = [identity]
        return QUERY_CACHE[identity]

    if not result[1][0][0] or not result[1][0][1].get('member'):
        QUERY_CACHE[identity] = []
        return QUERY_CACHE[identity]

    # If we have results, loop through the members
    # If the member is a group, get the members of that group
    # If the member is a user, add it to the list
    members = []
    for member in result[1][0][1]['member']:
        group_member = member.decode('utf-8').split(',OU=')[0][3:]
        try:
            QUERY_CACHE[group_member] = get_users(group_member)
        except RecursionError:
            print(f"Recursion error with {group_member}")
            QUERY_CACHE[group_member] = [group_member]
        members.extend(QUERY_CACHE[group_member])

    QUERY_CACHE[identity] = members

    return QUERY_CACHE[identity]


# Current time
now_time = datetime.now()

# Upsert the data into the database
for share in output:
    for acl in output[share]:
        identities = [acl["IdentityReference"]]

        if f"{domain_creds['kerberos_domain']}\\" in acl["IdentityReference"]:
            user_name = acl["IdentityReference"].split(f"{domain_creds['kerberos_domain']}\\")[1]
            setrecursionlimit(15)  # Sometimes groups are pointing to each other, limit the recursion
            identities = get_users(user_name)
            setrecursionlimit(1000)  # Reset the recursion limit

        for user in identities:
            # Sometimes users have extra escape characters leftover, remove them
            user = user.replace("\\", "")
            db["permissions"].update_one({"share": share, "identity": user, "acl": acl},
                                         {"$set": {
                                             "share": share,
                                             "identity": user,
                                             "acl": acl,
                                             "active": True,
                                             "updated": now_time
                                         }},
                                         upsert=True)

# Update all documents with updated time as not now_time and active true and set active to false
db["permissions"].update_many({"updated": {"$ne": now_time}, "active": True}, {"$set": {"active": False}})
