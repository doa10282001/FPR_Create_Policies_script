import requests
import json
from requests.auth import HTTPBasicAuth

requests.packages.urllib3.disable_warnings()

def fmc_gen_token(username,passwd):
    global response, FMC_token, Domain_UUID, FMC_refresh_token
    token_api_path = "/api/fmc_platform/v1/auth/generatetoken"
    url = Server_url + token_api_path
    conn = r.post(url,
                  verify=False,
                  auth=HTTPBasicAuth(username, password))
    FMC_token = conn.headers["X-auth-access-token"]
    Domain_UUID = conn.headers["DOMAIN_UUID"]
    FMC_refresh_token = conn.headers["X-auth-refresh-token"]
    return FMC_token, Domain_UUID, FMC_refresh_token

def get_current_Policy_UUID():
    get_Policy_UUID_url = '/api/fmc_config/v1/domain/' + Domain_UUID + '/policy/accesspolicies'
    url = Server_url + get_Policy_UUID_url
    Policy_UUID = r.get(url, headers = headers, verify = False)
    Policy_UUID_json = json.loads(Policy_UUID.text)
    for i in Policy_UUID_json['items']:
        print('name :', i['name'])
        print('ID :', i['id'])

def get_version():
    version_api = "/api/fmc_platform/v1/info/serverversion"
    version_url = Server_url + version_api
    get_version = r.get(version_url,verify=False,headers = headers)
    test_json = json.loads(get_version.text)
    FMC_Version = test_json['items'][0]['serverVersion']
    return FMC_Version

def create_Policy(policy_name):
    policy_api_path = '/api/fmc_config/v1/domain/' + Domain_UUID + '/policy/accesspolicies'
    Policy_url = Server_url + policy_api_path
    post_data = {
        "type": "AccessPolicy",
        "name": policy_name,
        "description": "Enterprise Policy to Detect and Prevent Threats",
        "defaultAction": {
            "intrusionPolicy": {
                "name": "Security Over Connectivity",
                "id": "abba9b63-bb10-4729-b901-2e2aa0f4491c",
                "type": "IntrusionPolicy"
            },
            "variableSet": {
                "name": "Default Set",
                "id": "76fa83ea-c972-11e2-8be8-8e45bb1343c0",
                "type": "VariableSet"
            },
            "type": "AccessPolicyDefaultAction",
            "logBegin": False,
            "logEnd": True,
            "sendEventsToFMC": True
        }
    }
    create_r = r.post(Policy_url, data=json.dumps(post_data), headers=headers, verify=False)
    if ((create_r.status_code == 201) or (create_r.status_code == 202)):
        print('Success Create Policy')
        json_r = json.loads(r.text)
        policy_UUID = json_r['id']
    else:
        print('Failed to Create Policy')
    return policy_UUID

def create_network_object(name,ip_address, Description = None):
    url = 'https://192.168.95.240/api/fmc_config/v1/domain/' + Domain_UUID + '/object/networks'
    post_data = {
        "name": name,
        "value": ip_address,
        "overridable": False,
        "description": Description,
        "type": "Network"
        }
    Create_Network_object = r.post(url, data=json.dumps(post_data), headers=headers, verify=False)
    if ((Create_Network_object.status_code == 200) or (Create_Network_object.status_code == 201)):
        print('create network objeck OK')
    #json_Create_Network_object = json.loads(Create_Network_object.text)

def get_Network_object_ID(net_name) -> dict:
    api_path = '/api/fmc_config/v1/domain/' + Domain_UUID +'/object/networks'
    url = Server_url + api_path
    get_ID = r.get(url, headers = headers, verify = False)
    get_ID_json = json.loads(get_ID.text)
    for i in get_ID_json['items']:
        if net_name == i['name']:
            return { "type": i['type'],
                     "name": i['name'],
                     "id": i['id']}

def port_object(port_name):
    api_path = '/api/fmc_config/v1/domain/' + Domain_UUID + '/object/protocolportobjects'
    url = Server_url + api_path
    port_info = r.get(url, headers = headers, verify = False)
    port_info_json = json.loads(port_info.text)
    for i in port_info_json['items']:
        if port_name == i['name']:
            protocol_url = i['links']['self']
            port_info_d = r.get(url, headers = headers, verify = False)
            json_port_info_d = json.loads(json_port_info_d)
            return {
                'type':json_port_info_d['type'],
                'protocol':json_port_info_d['protocol']
                'name':json_port_info['name'],
                'id':json_port_info['id']
            }

def addACRule(policy_UUID,Policies_name,Source_name,Destination_name,port_name,action):
    api_path = '/api/fmc_config/v1/domain/' + Domain_UUID + '/policy/accesspolicies/' + policy_UUID + '/accessrules'
    url = Server_url + api_path
    SRC = get_Network_object_ID(Source_name)
    DES = get_Network_object_ID(Destination_name)
    Des_Port = port_info(port_name)
    post_data = {
        "sendEventsToFMC": True,
        "action": action,
        "enabled": True,
        "type": "AccessRule",
        "name": Policies_name,
        "logFiles": True,
        "logBegin": False,
        "logEnd": False,
        "variableSet": {
            "name": "Default Set",
            "id": "76fa83ea-c972-11e2-8be8-8e45bb1343c0",
            "type": "VariableSet"
        },
        "sourceNetworks": {
            "objects": [{
                "type": SRC['type'],
                "name": SRC['name'],
                "id": SRC['id']
            }]
        },
        "destinationNetworks": {
            "objects": [{
                "type": DES['type'],
                "name": DES['name'],
                "id": DES['id']
            }]
        },
        "destinationPorts": {
            "objects": [
                {
                "type": Des_Port['type'],
                "protocol": Des_Port['protocol'],
                "name": Des_Port['name'],
                "id": Des_Port['id']
                }]
            },
        }
    add_ACL = r.post(url, data=json.dumps(post_data), headers=headers, verify=False)
    if ((add_ACL.status_code == 200) or (add_ACL.status_code == 201)):
        print('Add_success')
    else:
        print(add_ACL.status_code,'\n')
        print(add_ACL.text)

FMC_Addr = '192.168.95.240'
Server_url = 'https://' + FMC_Addr
username = 'admin'
password = 'Admin123'
r = requests.session()
fmc_gen_token(username,password)

headers = {'Content-Type': 'application/json', 'X-auth-access-token': FMC_token}
print('FMC current Version :',get_version())
