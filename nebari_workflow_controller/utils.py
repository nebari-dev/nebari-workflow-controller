import base64
import logging
import os

from keycloak import KeycloakAdmin
from kubernetes import client, config

from nebari_workflow_controller.exceptions import (
    NebariWorkflowControllerException as NWFCException,
)
from nebari_workflow_controller.models import KeycloakGroup, KeycloakUser

logger = logging.getLogger(__name__)


def process_unhandled_exception(e, return_response, logger):
    error_message = "An internal error occurred in nebari-workflow-controller while mutating the workflow.  Please open an issue at https://github.com/nebari-dev/nebari-workflow-controller/issues.  The error was: {e}"
    logger.exception(e)
    return return_response(False, message=error_message)


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


def base_return_response(
    allowed, apiVersion, request_uid, message=None, patch=None, patchType=None
):
    if (not patch) != (not patchType):
        raise Exception(
            f"patch and patchType must be specified together.  patch: {patch}, patchType: {patchType}"
        )
    if (allowed) != (message is None):
        raise Exception(
            "Failure message must be specified only when workflow not allowed"
        )

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

    if patch:
        response["response"]["patch"] = base64.b64encode(str(patch).encode()).decode()
        response["response"]["patchType"] = patchType

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
        raise NWFCException(
            f"A user pod instance for Jupyterhub user {keycloak_user.username} must be running when workflow starts. No pod found for user {keycloak_user.username}."
        )

    jupyter_pod_spec = jupyter_pod_list[0]
    return jupyter_pod_spec


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
