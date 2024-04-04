# import functions
from calm_nutanix_functions import *

pc_api = "10.68.97.150"
pc_user = "iz@emeagso.lab"
pc_pwd = "nutanix/4u"
project_name = "igor"
directory_service_name="EMEAGSO"
user_name = "iz@emeagso.lab"
role_name = "Project Admin"

# retrieve the project uuid
project_uuid = pc_get_project_uuid(pc_api,pc_user,pc_pwd,project_name)
# pc_project_uuid = "3876b2c6-d8dc-4fae-9196-60375ea57619"

# retrieve the project uuid (internal)
pc_project_internal_details = pc_get_projects_internal(pc_api,pc_user,pc_pwd,pc_project_uuid)
# pc_project_uuid = "3876b2c6-d8dc-4fae-9196-60375ea57619"

# retrieve the directory yyid
pc_directory_uuid = pc_get_directory_service_uuid(pc_api,pc_user,pc_pwd,directory_service_name)
#pc_directory_uuid="050d8d36-0f22-5b22-b9cc-fc7c75e55082"

# retrieve user dn_name
pc_dn_user = pc_calm_search_users(pc_api,pc_user,pc_pwd,pc_directory_uuid,user_name)
#print(pc_dn_user)

# retrieve user user id within AD
pc_acp_user_id = pc_get_acp_user_id(pc_api,pc_user,pc_pwd,pc_dn_user)
#print(pc_acp_user_id)

# retrieve role_uuid
pc_user_role_uuid = pc_get_role_uuid(pc_api,pc_user,pc_pwd,role_name)
#print(pc_user_role_uuid)

# retrieve update_project
pc_set_project_acp_user_task = pc_set_project_acp_user(pc_api,pc_user,pc_pwd,pc_project_uuid,pc_acp_user_id,pc_user_role_uuid)
exit (0)