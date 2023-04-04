import json
import logging
from fastapi import Depends, FastAPI, HTTPException, Body
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field

from typing import Any, Dict, List
from keycloak import KeycloakAdmin


logger = logging.getLogger(__name__)

app = FastAPI()

@app.post("/validate")
def admission_controller(request=Body(...)):

    # get user
    # workflow_submitter = request['request']['userInfo']['username']
    # keycloak_uid = request['request']['object']['metadata']['labels']['workflows.argoproj.io/creator']
    # kcadm = KeycloakAdmin(server_url="http://nebari.adamdlewis.com/auth/",
    #                     username='root',
    #                     password='<insert-admin-password>',
    #                     realm_name="master",
    #                     client_id="admin-cli",
    #                     verify=False)
    # kcadm.realm_name = 'nebari'

    # groups = kcadm.get_user_groups(keycloak_uid)
    # group_names = [group['name'] for group in groups]

    print(request['request']['object'])
    forbid_response = {
        "apiVersion": request['apiVersion'],
        "kind": "AdmissionReview",
        "response": {
            "allowed": False,
            "uid": request['request']['uid'],
            "status": {
                "message": "Cuz I'm grumpy!"
            }
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
    response = forbid_response
    print('response', response)
    return response

