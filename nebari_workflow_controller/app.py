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

jupythub_share_name = f"jupyterhub-{os.environ['NAMESPACE']}-share"
conda_store_share_name = f"conda-store-{os.environ['NAMESPACE']}-share"
allowed_pvcs = {jupythub_share_name, conda_store_share_name}
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
        # TODO: handle case if resubmitted from workflow
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


@app.post("/validate")
def validate(request=Body(...)):
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
            (jupythub_share_name, conda_store_share_name),
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

    for template in request["request"]["object"]["spec"]["templates"]:
        # check if any container or initContainer mounts disallowed subPath
        if "volumeMounts" in template.get("container", {}):
            if denyReason := find_invalid_volume_mount(
                template["container"]["volumeMounts"],
                volume_name_pvc_name_map,
                allowed_pvc_sub_paths_iterable,
            ):
                return return_response(False, message=denyReason)

        for initContainer in template.get("initContainers", []):
            if "volumeMounts" in initContainer:
                if denyReason := find_invalid_volume_mount(
                    initContainer["volumeMounts"],
                    volume_name_pvc_name_map,
                    allowed_pvc_sub_paths_iterable,
                ):
                    return return_response(False, message=denyReason)

    if request["request"]["object"]["metadata"].get("name"):
        log_msg = f"Allowing workflow to be created: {request['request']['object']['metadata']['name']}"
    else:
        log_msg = f"Allowing workflow to be created: {request['request']['object']['metadata']['generateName']}"
    logger.info(log_msg)

    return return_response(True)


def get_user_pod_spec(keycloak_user):
    config.incluster_config.load_incluster_config()
    k8s_client = client.CoreV1Api()

    jupyter_pod_list = k8s_client.list_namespaced_pod(
        os.environ["NAMESPACE"],
        label_selector=f"hub.jupyter.org/username={keycloak_user.username}",
    ).items

    if len(jupyter_pod_list) > 1:
        logger.warning(
            f"More than one pod found for user {keycloak_user.username}. Using last pod started."
        )
        jupyter_pod_list.sort(key=lambda pod: pod.status.start_time, reverse=True)

    # throw error if no pods found
    if len(jupyter_pod_list) == 0:
        raise Exception(f"No pod found for user {keycloak_user.username}.")

    jupyter_pod_spec = jupyter_pod_list[0]
    return jupyter_pod_spec


mutate_label = "jupyterflow-override"


@app.post("/mutate")
def mutate(request=Body(...)):
    spec = request["request"]["object"]
    if spec.get("metadata", {}).get("labels", {}).get(mutate_label, "false") != "false":
        modified_spec = copy.deepcopy(spec)
        keycloak_user = get_keycloak_user_info(request)
        user_pod_spec = get_user_pod_spec(keycloak_user)

        api = client.ApiClient()

        container_keep_portions = get_container_keep_portions(user_pod_spec, api)
        spec_keep_portions = get_spec_keep_portions(user_pod_spec, api)

        for template in modified_spec["spec"]["templates"]:
            mutate_template(container_keep_portions, spec_keep_portions, template)

        patch = jsonpatch.JsonPatch.from_diff(spec, modified_spec)
        return {
            "apiVersion": request["apiVersion"],
            "kind": "AdmissionReview",
            "response": {
                "allowed": True,
                "uid": request["request"]["uid"],
                "patch": base64.b64encode(str(patch).encode()).decode(),
                "patchType": "JSONPatch",
            },
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


def get_spec_keep_portions(user_pod_spec, api):
    return [
        (
            [
                api.sanitize_for_serialization(iC)
                for iC in user_pod_spec.spec.init_containers
            ],
            "initContainers",
        ),
        (
            api.sanitize_for_serialization(user_pod_spec.spec.security_context),
            "securityContext",
        ),
        (
            api.sanitize_for_serialization(user_pod_spec.spec.node_selector),
            "nodeSelector",
        ),
        (
            [api.sanitize_for_serialization(t) for t in user_pod_spec.spec.tolerations],
            "tolerations",
        ),
        (
            [
                api.sanitize_for_serialization(v)
                for v in user_pod_spec.spec.volumes
                if not v.name.startswith("kupe-api-access-")
            ],
            "volumes",
        ),
    ]


def get_container_keep_portions(user_pod_spec, api):
    return [
        (user_pod_spec.spec.containers[0].image, "image"),
        (
            [
                api.sanitize_for_serialization(var)
                for var in user_pod_spec.spec.containers[0].env
            ],
            "env",
        ),
        (
            api.sanitize_for_serialization(user_pod_spec.spec.containers[0].lifecycle),
            "lifecycle",
        ),
        (
            api.sanitize_for_serialization(
                user_pod_spec.spec.containers[0].security_context
            ),
            "securityContext",
        ),
        (
            [
                api.sanitize_for_serialization(v)
                for v in user_pod_spec.spec.containers[0].volume_mounts
            ],
            "volumeMounts",
        ),
        (user_pod_spec.spec.containers[0].working_dir, "workingDir"),
    ]


def mutate_template(container_keep_portions, spec_keep_portions, template):
    for value, key in container_keep_portions:
        if "container" not in template:
            continue

        if isinstance(value, dict):
            if key in template["container"]:
                template["container"][key] = {
                    **template["container"][key],
                    **value,
                }
            else:
                template["container"][key] = value
        elif isinstance(value, list):
            if key in template["container"]:
                template["container"][key].append(value)
            else:
                template["container"][key] = value
        else:
            template["container"][key] = value

    for value, key in spec_keep_portions:
        if isinstance(value, dict):
            if key in template:
                template[key] = {**template[key], **value}
            else:
                template[key] = value
        elif isinstance(value, list):
            if key in template:
                template[key].append(value)
            else:
                template[key] = value
        else:
            template[key] = value
