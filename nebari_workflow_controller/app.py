import base64
import copy
import logging
import os
from functools import partial

import jsonpatch
from fastapi import Body, FastAPI
from keycloak import KeycloakAdmin
from kubernetes import client, config

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
    volume_mounts, volume_name_pvc_name_map, allowed_pvc_sub_paths_iterable
):
    # verify only allowed volume_mounts were mounted
    for volume_mount in volume_mounts:
        if volume_mount["name"] in volume_name_pvc_name_map:
            for allowed_pvc, allowed_sub_paths in allowed_pvc_sub_paths_iterable:
                if volume_name_pvc_name_map[volume_mount["name"]] == allowed_pvc:
                    if (
                        sub_path := volume_mount.get("subPath", "")
                    ) not in allowed_sub_paths:
                        denyReason = f"Workflow attempts to mount disallowed subPath: {sub_path}. Allowed subPaths are: {allowed_sub_paths}."
                        logger.info(denyReason)
                        return denyReason


def check_for_invalid_volume_mounts(
    dict_or_list, volume_name_pvc_name_map, allowed_pvc_sub_paths_iterable
):
    """Recursively check for invalid volume mounts"""
    if isinstance(dict_or_list, dict):
        for key, value in dict_or_list.items():
            if key == "volumeMounts":
                if denyReason := find_invalid_volume_mount(
                    value,
                    volume_name_pvc_name_map,
                    allowed_pvc_sub_paths_iterable,
                ):
                    return denyReason
            elif isinstance(value, (list, dict)):
                if found_invalid_volume_mount := check_for_invalid_volume_mounts(
                    value, volume_name_pvc_name_map, allowed_pvc_sub_paths_iterable
                ):
                    return found_invalid_volume_mount
    elif isinstance(dict_or_list, list):
        for item in dict_or_list:
            if found_invalid_volume_mount := check_for_invalid_volume_mounts(
                item, volume_name_pvc_name_map, allowed_pvc_sub_paths_iterable
            ):
                return found_invalid_volume_mount


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

    # verify only allowed pvcs were attached as volumes
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

    # verify only allowed subPaths were mounted
    if denyReason := check_for_invalid_volume_mounts(
        request, volume_name_pvc_name_map, allowed_pvc_sub_paths_iterable
    ):
        return return_response(False, message=denyReason)

    logger.info(
        f"Allowing workflow to be created: {request['request']['object']['metadata']['name']}"
    )
    return return_response(True)


def get_user_pod_spec(keycloak_user):
    config.incluster_config.load_incluster_config()
    k8s_client = client.CoreV1Api()

    # TODO: Replace dev with an env variable
    jupyter_pod_list = k8s_client.list_namespaced_pod(
        "dev", label_selector=f"hub.jupyter.org/username={keycloak_user.username}"
    ).items

    if len(jupyter_pod_list) > 1:
        logger.warning(
            f"More than one pod found for user {keycloak_user.username}. Using first pod found."
        )
        # TODO: verify how this will work with CDSDashboards

    # throw error if no pods found
    if len(jupyter_pod_list) == 0:
        raise Exception(f"No pod found for user {keycloak_user.username}.")

    jupyter_pod_spec = jupyter_pod_list[0]
    return jupyter_pod_spec


keep_portions = [
    "spec.containers[0].image",
    "spec.containers[0].image.lifecycle",
    "spec.containers[0].name",
    "spec.containers[0].resources",
    "spec.containers[0].securityContext",
    "spec.containers[0].volume_mounts",
    "spec.init_containers",
    "spec.security_context",
    "spec.tolerations",
    "spec.volumes",
]

mutate_label = "jupyter-flow"


@app.post("/mutate")
def mutate(request=Body(...)):
    print(request)
    spec = request["request"]["object"]
    if spec.get("metadata", {}).get("labels", {}).get(mutate_label, "false") != "false":
        modified_spec = copy.deepcopy(spec)
        keycloak_user = get_keycloak_user_info(request)
        get_user_pod_spec(keycloak_user)
        breakpoint()
        # LEFT OFF
        patch = jsonpatch.JsonPatch.from_diff(spec, modified_spec)
        return {
            "response": {
                "allowed": True,
                "uid": request["request"]["uid"],
                "patch": base64.b64encode(str(patch).encode()).decode(),
                "patchtype": "JSONPatch",
            }
        }
    else:
        return {
            "apiVersion": request["apiVersion"],
            "kind": "AdmissionReview",
            "response": {
                "allowed": True,
                "uid": request["request"]["uid"],
            },
        }


"""
conda init && bash
conda activate default
pip install "kubernetes==26.1.0"
cd /opt/conda/envs/default/lib/python3.10/site-packages/nebari_workflow_controller/

python -m nebari_workflow_controller
"""
