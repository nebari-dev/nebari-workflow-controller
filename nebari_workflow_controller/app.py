import logging
import os
from functools import partial

from fastapi import Body, FastAPI
from keycloak import KeycloakAdmin

from nebari_workflow_controller.models import KeycloakGroup, KeycloakUser

logger = logging.getLogger(__name__)

app = FastAPI()

allowed_pvcs = {"jupyterhub-dev-share", "conda-store-dev-share"}
conda_store_global_namespaces = ["global", "nebari-git"]


def sent_by_argo(request: dict):
    # Check if `workflows.argoproj.io/creator` shows up under ManagedFields with manager "argo".  If so, then we can trust the uid from there.
    sent_by_argo = False
    if request["request"]["userInfo"]["username"].startswith("system:serviceaccount"):
        for managedField in request["request"]["object"]["metadata"]["managedFields"]:
            if (
                managedField.get("manager", "") == "argo"
                and "f:workflows.argoproj.io/creator"
                in managedField["fieldsV1"]["f:metadata"]["f:labels"]
            ):
                sent_by_argo = True
                break
    return sent_by_argo


def get_keycloak_user_info(request: dict) -> KeycloakUser:
    # Check if `workflows.argoproj.io/creator` shows up under ManagedFields with manager "argo".  If so, then we can trust the uid from there.  If not, then we have to trust the username from the request.

    # TODO: put try catch here if can't connect to keycloak
    kcadm = KeycloakAdmin(
        server_url=os.environ["KEYCLOAK_URL"],
        username=os.environ["KEYCLOAK_USERNAME"],
        password=os.environ["KEYCLOAK_PASSWORD"],
        user_realm_name="master",
        realm_name="nebari",
        client_id="admin-cli",
    )

    if sent_by_argo(request):
        keycloak_uid = request["request"]["object"]["metadata"]["labels"][
            "workflows.argoproj.io/creator"
        ]
        keycloak_username = kcadm.get_user(keycloak_uid)["username"]
    else:
        # TODO: put try catch here if username is not found
        keycloak_username = request["request"]["userInfo"]["username"]
        keycloak_uid = kcadm.get_user_id(keycloak_username)

    groups = kcadm.get_user_groups(keycloak_uid)
    keycloak_user = KeycloakUser(
        username=keycloak_username,
        id=keycloak_uid,
        groups=[KeycloakGroup(**group) for group in groups],
    )
    return keycloak_user


def base_return_response(allowed, apiVersion, request_uid, message=None):
    response = {
        "apiVersion": apiVersion,
        "kind": "AdmissionReview",
        "response": {
            "allowed": allowed,
            "uid": request_uid,
        },
    }
    if not allowed:
        response["response"]["status"] = {"message": message}
    return response


def find_invalid_volume_mount(
    container, volume_name_pvc_name_map, allowed_pvc_sub_paths_iterable
):
    # verify only allowed volume_mounts were mounted
    for volume_mount in container.get("volumeMounts", {}):
        if volume_mount["name"] in volume_name_pvc_name_map:
            for allowed_pvc, allowed_sub_paths in allowed_pvc_sub_paths_iterable:
                if volume_name_pvc_name_map[volume_mount["name"]] == allowed_pvc:
                    if volume_mount.get("subPath", "") not in allowed_sub_paths:
                        denyReason = f"Workflow attempts to mount disallowed subPath: {volume_mount}. Allowed subPaths are: {allowed_sub_paths}."
                        logger.info(denyReason)
                        return denyReason


@app.post("/validate")
def admission_controller(request=Body(...)):
    keycloak_user = get_keycloak_user_info(request)

    return_response = partial(
        base_return_response,
        apiVersion=request["apiVersion"],
        request_uid=request["request"]["uid"],
    )
    shared_filesystem_sub_paths = set(
        ["shared" + group.path for group in keycloak_user.groups]
        + ["home/" + keycloak_user.username]
    )
    conda_store_sub_paths = set(
        [group.path.replace("/", "") for group in keycloak_user.groups]
        + conda_store_global_namespaces
        + [keycloak_user.username]
    )
    allowed_pvc_sub_paths_iterable = tuple(
        zip(
            ("jupyterhub-dev-share", "conda-store-dev-share"),
            (shared_filesystem_sub_paths, conda_store_sub_paths),
        )
    )

    # verify only allowed volumes were mounted
    volume_name_pvc_name_map = {}
    for volume in (
        request.get("request", {}).get("object", {}).get("spec", {}).get("volumes", {})
    ):
        if "persistentVolumeClaim" in volume:
            if volume["persistentVolumeClaim"]["claimName"] not in allowed_pvcs:
                logger.info(
                    f"Workflow attempts to mount disallowed PVC: {volume['persistentVolumeClaim']['claimName']}"
                )
                denyReason = f"Workflow attempts to mount disallowed PVC: {volume['persistentVolumeClaim']['claimName']}. Allowed PVCs are: {allowed_pvcs}."
                return return_response(False, message=denyReason)
            else:
                volume_name_pvc_name_map[volume["name"]] = volume[
                    "persistentVolumeClaim"
                ]["claimName"]

    for template in request["request"]["object"]["spec"]["templates"]:
        # verify container
        if denyReason := find_invalid_volume_mount(
            template["container"],
            volume_name_pvc_name_map,
            allowed_pvc_sub_paths_iterable,
        ):
            return return_response(False, message=denyReason)

        # verify initContainers
        for initContainer in template.get("initContainers", {}):
            if denyReason := find_invalid_volume_mount(
                initContainer, volume_name_pvc_name_map, allowed_pvc_sub_paths_iterable
            ):
                return return_response(False, message=denyReason)

    logger.info(
        f"Allowing workflow to be created: {request['request']['object']['metadata']['name']}"
    )
    return return_response(True)
