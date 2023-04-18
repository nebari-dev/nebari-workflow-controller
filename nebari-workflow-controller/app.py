import json
import logging
import os
from fastapi import Depends, FastAPI, HTTPException, Body
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field

from typing import Any, Dict, List
from keycloak import KeycloakAdmin


logger = logging.getLogger(__name__)

app = FastAPI()

def get_username_groups(request):
    # get user - Check if `workflows.argoproj.io/creator` shows up under ManagedFields with manager "argo".  If so, then we can trust the uid from there.  
    # workflow_submitter = request['request']['userInfo']['username']
    keycloak_uid = request['request']['object']['metadata']['labels']['workflows.argoproj.io/creator']
    kcadm = KeycloakAdmin(
        server_url="http://adam.nebari.dev/auth/",  # TODO: Don't hard code this address
        username=os.environ['KEYCLOAK_USERNAME'],
        password=os.environ['KEYCLOAK_PASSWORD'],
        user_realm_name="master",
        realm_name="nebari",
        client_id="admin-cli",
    )


    # Check if `workflows.argoproj.io/creator` shows up under ManagedFields with manager "argo".  If so, then we can trust the uid from there. 
    sent_by_argo = False
    if request['request']['userInfo']['username'].startswith('system:serviceaccount'):
        for managedField in request['request']['object']['metadata']['managedFields']:
            if managedField.get('manager', '') == 'argo' and 'f:workflows.argoproj.io/creator' in managedField['fieldsV1']['f:metadata']['f:labels']:
                sent_by_argo = True
                break

    if sent_by_argo:
        keycloak_uid = request['request']['object']['metadata']['labels']['workflows.argoproj.io/creator']
        keycloak_uid = 'a667b60d-caf8-4918-bdb0-0f6b9be03fcf'  # TODO: remove this line
        keycloak_username = kcadm.get_user(keycloak_uid)['username']
    else:
        # TODO: put try catch here if username is not found
        keycloak_username = request['request']['userInfo']['username']
        keycloak_uid = kcadm.get_user_id(keycloak_username)

    keycloak_uid = 'a667b60d-caf8-4918-bdb0-0f6b9be03fcf'  # TODO: remove this line
    groups = kcadm.get_user_groups(keycloak_uid)
    return keycloak_username, groups

# def validate(request, allowed_pvcs):
#     """Check whether the request is valid.

#     Returns:
#         bool: whether the request is valid
#     """

@app.post("/validate")
def admission_controller(request=Body(...)):

    def return_forbid_response(message):
        return {
            "apiVersion": request['apiVersion'],
            "kind": "AdmissionReview",
            "response": {
                "allowed": False,
                "uid": request['request']['uid'],
                "status": {
                    "message": message
                },
            },
        }
    
    allow_response = {
        "apiVersion": request['apiVersion'],
        "kind": "AdmissionReview",
        "response": {
            "uid": request['request']['uid'],
            "allowed": True
        }
    }

    keycloak_username, groups = get_username_groups(request)
    shared_filesystem_sub_paths = set(['shared' + group['path'] for group in groups] + ['home/' + keycloak_username])
    conda_store_sub_paths = set([group['path'].replace('/', '') for group in groups] + ['global', keycloak_username])
    print(groups)

    # verify only allowed volumes were mounted
    allowed_pvcs = {'jupyterhub-dev-share', 'conda-store-dev-share'}
    volume_name_allowed_pvc_map = {}
    for volume in request.get('request', {}).get('object', {}).get('spec', {}).get('volumes', {}):
        if 'persistentVolumeClaim' in volume:
            if volume['persistentVolumeClaim']['claimName'] not in allowed_pvcs:
                logger.info(f"Workflow attempts to mount disallowed PVC: {volume['persistentVolumeClaim']['claimName']}")
                denyReason = f"Workflow attempts to mount disallowed PVC: {volume['persistentVolumeClaim']['claimName']}. Allowed PVCs are: {allowed_pvcs}."
                return return_forbid_response(denyReason)
            else:
                volume_name_allowed_pvc_map[volume['name']] = volume['persistentVolumeClaim']['claimName']

    def _verify_volume_mounts(container):
        # verify only allowed volume_mounts were mounted
        for volume_mount in container.get('volumeMounts', {}):
            if volume_mount['name'] in volume_name_allowed_pvc_map:
                if volume_name_allowed_pvc_map[volume_mount['name']] == "jupyterhub-dev-share":
                    if volume_mount.get('subPath', '') not in shared_filesystem_sub_paths:
                        logger.info(f"Workflow attempts to mount disallowed subPath: {volume_mount['subPath']}")
                        denyReason = f"Workflow attempts to mount disallowed subPath: {volume_mount['subPath']}. Allowed subPaths are: {shared_filesystem_sub_paths}."
                        return return_forbid_response(denyReason)
                elif volume_name_allowed_pvc_map[volume_mount['name']] == "conda-store-dev-share":
                    if volume_mount.get('subPath', '') not in conda_store_sub_paths:
                        logger.info(f"Workflow attempts to mount disallowed subPath: {volume_mount['subPath']}")
                        denyReason = f"Workflow attempts to mount disallowed subPath: {volume_mount['subPath']}. Allowed subPaths are: {conda_store_sub_paths}."
                        return return_forbid_response(denyReason)

    for template in request['request']['object']['spec']['templates']:
        # verify container
        _verify_volume_mounts(template['container'])
        # verify initContainers
        for initContainer in template.get('initContainers', {}):
            _verify_volume_mounts(initContainer)

        # TODO: How to template all the different things to check and specify allowed values (assuming I make this a reusable package eventually)?

    logger.info(f"Allowing workflow to be created: {request['request']['object']['metadata']['name']}")
        
    return allow_response

