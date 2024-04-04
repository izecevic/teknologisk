import requests,json,urllib3,uuid,sys
from time import sleep
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# region functions
# region function process_request
def process_request(url, method, user, password, headers, payload=None, secure=False, upload_binary=False, return_cookies=False, upload_files=None):
    """
    Processes a web request and handles result appropriately with retries.
    Returns the content of the web request if successfull.
    """
    if payload != None and (upload_binary == True or upload_files != None):
       payload = payload
    elif payload != None and upload_binary == False:
        payload = json.dumps(payload)

    #configuring web request behavior
    if upload_binary == True: 
        timeout = 9000 # 15 mins (usually for binary uploads)
    else:
        timeout = 30
    retries = 5
    sleep_between_retries = 5

    while retries > 0:
        try:
            if method == 'GET':
                response = requests.get(
                    url,
                    headers=headers,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout,
                )
            elif method == 'POST':
                response = requests.post(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout,
                    files=upload_files
                )
            elif method == 'PUT':
                response = requests.put(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PATCH':
                response = requests.patch(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout,
                )
            elif method == 'DELETE':
                response = requests.delete(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
        except requests.exceptions.HTTPError as error_code:
            print ("Http Error!")
            print("status code: {}".format(response.status_code))
            print("reason: {}".format(response.reason))
            print("text: {}".format(response.text))
            print("elapsed: {}".format(response.elapsed))
            print("headers: {}".format(response.headers))
            if payload is not None:
                print("payload: {}".format(payload))
            print(json.dumps(
                json.loads(response.content),
                indent=4
            ))
            exit(response.status_code)
        except requests.exceptions.ConnectionError as error_code:
            print ("Connection Error!")
            if retries == 1:
                print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
                exit(1)
            else:
                print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
                sleep(sleep_between_retries)
                retries -= 1
                print ("retries left: {}".format(retries))
                continue
            print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
            exit(1)
        except requests.exceptions.Timeout as error_code:
            print ("Timeout Error!")
            if retries == 1:
                print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
                exit(1)
            print('Error! Code: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
            sleep(sleep_between_retries)
            retries -= 1
            print ("retries left: {}".format(retries))
            continue
        except requests.exceptions.RequestException as error_code:
            print ("Error!")
            exit(response.status_code)
        break

    if response.ok and return_cookies == False:
        print("Request suceedded!")
        return json.loads(response.content)
    if response.ok and return_cookies == True:
        print("Request suceedded!")
        return response
    if response.status_code == 401:
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        return (response.status_code)
    elif response.status_code == 500:
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        print("text: {0}".format(response.text))
        exit(response.status_code)
    elif response.status_code == 404:
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        print("text: {0}".format(response.text))
        return (response.status_code)
    else:
        print("Request failed!")
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        print("text: {0}".format(response.text))
        print("raise_for_status: {0}".format(response.raise_for_status()))
        print("elapsed: {0}".format(response.elapsed))
        print("headers: {0}".format(response.headers))
        if payload is not None:
            print("payload: {0}".format(payload))
        print(json.dumps(
            json.loads(response.content),
            indent=4
        ))
        exit(response.status_code)    
# endregion

# region pc_get_projects
def pc_get_projects(api_server,username,secret,project_name=None):
    """
        Retrieve projects details on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_name: specific project details to retrieve.
        
    Returns:
        A list of project details (entities part of the json response).
    """
    
    # variables
    projects_list = []
    
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/projects/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'kind':'project'}
    # endregion

    # Making the call
    print("Retrieving project details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # processing
    if project_name == None:
        print("Return all projects..")
        projects_list.extend(resp['entities'])
    else: 
        for project in resp['entities']:
            if project['status']['name'] == project_name:
                print("Return single project")
                projects_list.append(project)
                break
    # return
    return projects_list

# endregion

# region get pc_get_projects_internal
def pc_get_projects_internal(api_server,username,secret,project_uuid):
    """
        Retrieve projects internal details on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_uuid: uuid of the project
        
    Returns:
        Project internal details (json response).
    """
        
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/projects_internal/{}".format(project_uuid)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # Making the call
    print("Retrieving project internal {} details on".format(project_uuid,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)

    # return
    return resp
# endregion

# region get pc_get_project_uuid
def pc_get_project_uuid(api_server,username,secret,project_name):
    """
        Retrieve project uuid on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_name: project details to retrieve.
        
    Returns:
        Project uuid (string).
    """
        
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/projects/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'kind':'project','filter': 'name=={}'.format(project_name)}
    # endregion

    # Making the call
    print("Retrieving project {} uuid on {}".format(project_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp['entities'][0]['metadata']['uuid']
# endregion

# region pc_get pc_get_account_uuid
def pc_get_account_uuid(api_server,username,secret,account_name="NTNX_LOCAL_AZ"):
    """
        Retrieve account uuid on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        account_name: account details to retrieve. (default PC)
        
    Returns:
        account uuid (string).
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/accounts/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'kind': 'account',"filter":"name=={}".format(account_name)}
    # endregion

    # Making the call
    print("Retrieving account {} uuid on {}".format(account_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # returning
    return resp['entities'][0]['metadata']['uuid']
# endregion

# region pc_create_project
def pc_create_project(api_server,username,secret,project_name):
    """
        Creates a project on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_name: Name of the project to create
        
    Returns:
        Project creation response (json response).
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/projects_internal"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'spec': {
            'project_detail': {
                'name': project_name,
                'resources': {}
            },
            'user_list': [],
            'user_group_list': [],
            'access_control_policy_list': []
        },
        'api_version': '3.0',
        'metadata': {'kind': 'project'}
    }
    # endregion

    # Making the call
    print("Creatint project {} on {}".format(project_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp
# endregion

# region get pc_get_directory_service_uuid
def pc_get_directory_service_uuid(api_server,username,secret,directory_service_name):
    """
        Retrieves directory service uuid on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        directory_service_name: Name of the directory service to retrieve
        
    Returns:
        Uuid of the directory service (string).
    """
        
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/directory_services/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'filter':'name=={}'.format(directory_service_name)}
    # endregion

    # Making the call
    print("Retrieving directory service uuid {} on {}".format(directory_service_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # return
    return resp['entities'][0]['metadata']['uuid']
# endregion

# region pc_calm_group_search
def pc_calm_search_users(api_server,username,secret,directory_service_uuid,search_name):
    """
        Retrieves distinguished_name group on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        directory_service_uuid: Uuid of the directory service
        group_name: group name to retrieve on the directory service
        
    Returns:
        distinguished_name group (string).
    """
    
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/calm/v3.0/calm_users/search"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'query':search_name,
        'provider_uuid': directory_service_uuid,
        'user_type':"ACTIVE_DIRECTORY",
        'is_wildcard_search':True
    }
    # endregion

    # Making the call
    print("Retrieving {} uuid".format(search_name))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # filterng
    for entity in resp['search_result_list']:
        if entity['type'] == "Group":
            for attribute in entity['attribute_list']:
                if attribute['name'] == "distinguishedName":
                    search_value = attribute['value_list'][0]
        elif entity['type'] == "Person":
            for attribute in entity['attribute_list']:
                if attribute['name'] == "userPrincipalName":
                    search_value = attribute['value_list'][0]
    
    # return
    return search_value
# endregion

# region pc_get_acp_user
def pc_get_acp_user_id(api_server,username,secret,acp_user):
    """
        Retrieves distinguished_name user entity_id on Calm

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        acp_user: Name of user to retrieve
        
    Returns:
        distinguished_name group id (string).
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/groups"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'entity_type':'abac_user_capability',
        'group_member_attributes':[{'attribute':'user_uuid'}],
        'query_name':'prism:BaseGroupModel',
        'filter_criteria':'username=={}'.format(acp_user)
    }
    # endregion

    # Making the call
    print("Retreiving user uuid {}".format(acp_user))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    print(resp)

    # return
    return resp['group_results'][0]['entity_results'][0]['entity_id'] 
# endregion

# region pc_get_acp_group
def pc_get_acp_group_id(api_server,username,secret,acp_group):
    """
        Retrieves distinguished_name group entity_id on Calm

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        dn_group: Name of the dn group to retrieve
        
    Returns:
        distinguished_name group id (string).
    """

    # variables
    # calculate acp_distinguished_name variable required for the payload
    # from CN=Developers,CN=Users,DC=ntnxlab,DC=loca to cn%3Ddevelopers%2Ccn%3Dusers%2Cdc%3Dntnxlab%2Cdc%3Dlocal
    count = 1
    acp_distinguished_name = ""
    for entity in acp_group.rsplit(","):
        entity_string = entity.lower().replace("=","%3D") # replace '=' with '%3D'
        if count < (len(acp_group.rsplit(","))):
            entity_string += ("%2C") #replace ',' with '%2C'  
        acp_distinguished_name += entity_string
        count += 1
    
    acp_distinguished_name.replace(" ","%20") #remove space (if any)

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/groups"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'entity_type': 'user_group',
        'group_member_attributes': [
            {
                'attribute': 'uuid'
            },
            {
                'attribute': 'distinguished_name'
            }
        ],
        'query_name': 'prism:BaseGroupModel',
        'filter_criteria': 'distinguished_name=={}'.format(acp_distinguished_name)
    }
    # endregion


    # Making the call
    print("Retreiving dn_group uuid {}".format(acp_group))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp['group_results'][0]['entity_results'][0]['entity_id'] 
# endregion

# region pc_set_project_acp_group
def pc_set_project_acp_group(api_server,username,secret,project_uuid,acp_group_id,group_role_uuid):
    """
        Set group and role on a given Calm project

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_uuid: Uuid of the project.
        acp_group_id: group entity id to add to the calm project.
        group_role_uuid: role uuid to add to the calm project.
        
    Returns:
        Task execution (json response).
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/projects_internal/{}".format(project_uuid)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # get project_json details first
    print("Retrieving project {} details on {}".format(project_uuid,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    project_json = resp

    # update existing access_control_policy_list
    for acccess_control_policy in project_json['spec']['access_control_policy_list']:
        operation = {'operation': "UPDATE"}
        acccess_control_policy.update(operation)

    # payload
    add_acp_group = {
        'operation': 'ADD',
        'acp': {
            'name': 'nuCalmAcp-'+str(uuid.uuid4()),
            'resources': {
                'role_reference': {
                    'uuid': group_role_uuid,
                    'kind': 'role'
                },
                'user_group_reference_list': [
                    {
                    'kind': 'user_group',
                    'uuid': acp_group_id
                    }
                ],
                'filter_list': {
                    'context_list': [{
                            'scope_filter_expression_list': [
                                {
                                    'operator': 'IN',
                                    'left_hand_side': 'PROJECT',
                                    'right_hand_side': {
                                        'uuid_list': [project_uuid]
                                    }
                                }
                            ],
                            'entity_filter_expression_list': [
                                {
                                    'operator': 'IN',
                                    'left_hand_side': {
                                        'entity_type': 'ALL'
                                    },
                                    'right_hand_side': {
                                        'collection': 'ALL'
                                    }
                                }
                            ]
                        }
                    ]
                }
            },
            'description': 'ACPDescription-'+str(uuid.uuid4())
        },
        'metadata': {
            'kind': 'access_control_policy'
        }
    }
        
    # push acp_group to payload
    project_json['spec']['access_control_policy_list'].append(add_acp_group)
    add_acp_group = {'kind': 'user_group','uuid': acp_group_id}
    project_json['spec']['project_detail']['resources']['external_user_group_reference_list'].append(add_acp_group)

    # update json
    project_json.pop('status', None) # don't need status for the update
    project_json['metadata'].pop('owner_reference', None)
    project_json['metadata'].pop('create_time', None)
    payload = project_json

    # updating the project
    method = "PUT"
    print("Updating project {} details on {}".format(project_uuid,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp
# endregion

# region pc_set_project_acp_user
def pc_set_project_acp_user(api_server,username,secret,project_uuid,acp_user_id,user_role_uuid):
    """
        Set group and role on a given Calm project

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_uuid: Uuid of the project.
        acp_user_id: user entity id to add to the calm project.
        user_role_uuid: role uuid to add to the calm project.
        
    Returns:
        Task execution (json response).
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/projects_internal/{}".format(project_uuid)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # get project_json details first
    print("Retrieving project {} details on {}".format(project_uuid,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    project_json = resp
    
    # update existing access_control_policy_list
    for acccess_control_policy in project_json['spec']['access_control_policy_list']:
        operation = {'operation': "UPDATE"}
        acccess_control_policy.update(operation)

    # payload
    add_acp_user = {
        'operation': 'ADD',
        'acp': {
            'name': 'nuCalmAcp-'+str(uuid.uuid4()),
            'resources': {
                'role_reference': {
                    'uuid': user_role_uuid,
                    'kind': 'role'
                },
                'user_reference_list': [
                    {
                        'kind': 'user',
                        'uuid': acp_user_id
                    }
                ],
                'filter_list': {
                    'context_list': [{
                            'scope_filter_expression_list': [
                                {
                                    'operator': 'IN',
                                    'left_hand_side': 'PROJECT',
                                    'right_hand_side': {
                                        'uuid_list': [project_uuid]
                                        }
                                }
                            ],
                            'entity_filter_expression_list': [
                                {
                                    'operator': 'IN',
                                    'left_hand_side': {
                                        'entity_type': 'ALL'
                                        },
                                    'right_hand_side': {
                                        'collection': 'ALL'
                                        }
                                }
                            ]
                        }
                    ]
                }
            },
            'description': 'ACPDescription-'+str(uuid.uuid4())
        },
        'metadata': {'kind': 'access_control_policy'}
    }

    # push acp_user to payload
    project_json['spec']['access_control_policy_list'].append(add_acp_user)
    add_acp_user = {'kind': 'user','uuid': acp_user_id}
    project_json['spec']['project_detail']['resources']['user_reference_list'].append(add_acp_user)

    # update json
    project_json.pop('status', None) # don't need status for the update
    project_json['metadata'].pop('owner_reference', None)
    project_json['metadata'].pop('create_time', None)
    payload = project_json

    # Making the call
    method = "PUT"
    print("Updating project {} details on {}".format(project_uuid,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp
# endregion

# region create pc_set_project_infrastructure
def pc_set_project_infrastructure(api_server,username,secret,project_uuid,account_uuid,subnet_uuid):
    """
        Set infrastructure resources for a given project on Calm

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_uuid: Uuid of the project.
        account_uuid: uuid of the account (default account_name is NTNX_LOCAL_AZ (PC))
        cluster_uuid: uuid of the cluster
        subnet_uuid: uuid of the subnet (Default subnet for the calm project)
        
    Returns:
        Task execution (json response).
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    method = "GET"
    api_server_endpoint = "/api/nutanix/v3/projects_internal/{}".format(project_uuid)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    # endregion

    # get project_json details first
    print("Retrieving project {} details on {}".format(project_uuid,api_server))
    print("Making a {} API call to {}".format(method, url))
    project_json = process_request(url,method,username,secret,headers)

    # region updating project payload
    # update existing access_control_policy_list
    for acccess_control_policy in project_json['spec']['access_control_policy_list']:
        operation = {'operation': "UPDATE"}
        acccess_control_policy.update(operation)

    # push account and default_subnet details
    if not project_json['spec']['project_detail']['resources']['account_reference_list']:
        account_payload = {'kind': 'account','uuid': account_uuid}
        project_json['spec']['project_detail']['resources']['account_reference_list'].append(account_payload)

    if not project_json['spec']['project_detail']['resources']['subnet_reference_list']:
        subnet_payload = {'kind': 'subnet','uuid': subnet_uuid}
        project_json['spec']['project_detail']['resources']['subnet_reference_list'].append(subnet_payload)

    # update json
    project_json.pop('status', None) # don't need status for the update
    payload = project_json
    # endregion

    # make the api call
    method = "PUT"
    print("Updating project {} details on {}".format(project_uuid,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp
# endregion

# endregion