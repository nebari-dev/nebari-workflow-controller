import copy
import logging
import os
from functools import partial

import jsonpatch
from fastapi import Body, FastAPI
from kubernetes import client

from nebari_workflow_controller.exceptions import (
    NebariWorkflowControllerException as NWFCException,
)
from nebari_workflow_controller.utils import (
    base_return_response,
    find_invalid_volume_mount,
    get_container_keep_portions,
    get_keycloak_user_info,
    get_spec_keep_portions,
    get_user_pod_spec,
    mutate_template,
    process_unhandled_exception,
)

logger = logging.getLogger(__name__)

app = FastAPI()

jupythub_share_name = f"jupyterhub-{os.environ['NAMESPACE']}-share"
conda_store_share_name = f"conda-store-{os.environ['NAMESPACE']}-share"
allowed_pvcs = {jupythub_share_name, conda_store_share_name}
conda_store_global_namespaces = ["global", "nebari-git"]


@app.post("/validate")
def validate(request=Body(...)):
    logger.debug(f"Received request: \n\n{request}")
    return_response = partial(
        base_return_response,
        apiVersion=request["apiVersion"],
        request_uid=request["request"]["uid"],
    )
    try:
        keycloak_user = get_keycloak_user_info(request)

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
            request.get("request", {})
            .get("object", {})
            .get("spec", {})
            .get("volumes", {})
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
    except Exception as e:
        return process_unhandled_exception(e, return_response, logger)


mutate_label = "jupyterflow-override"


@app.post("/mutate")
def mutate(request=Body(...)):
    logger.debug(f"Received request: \n\n{request}")
    return_response = partial(
        base_return_response,
        apiVersion=request["apiVersion"],
        request_uid=request["request"]["uid"],
    )
    try:
        spec = request["request"]["object"]
        if (
            spec.get("metadata", {}).get("labels", {}).get(mutate_label, "false")
            != "false"
        ):
            modified_spec = copy.deepcopy(spec)
            keycloak_user = get_keycloak_user_info(request)
            try:
                user_pod_spec = get_user_pod_spec(keycloak_user)
            except NWFCException as e:
                return return_response(False, message=str(e))

            api = client.ApiClient()

            container_keep_portions = get_container_keep_portions(user_pod_spec, api)
            spec_keep_portions = get_spec_keep_portions(user_pod_spec, api)

            for template in modified_spec["spec"]["templates"]:
                mutate_template(container_keep_portions, spec_keep_portions, template)

            patch = jsonpatch.JsonPatch.from_diff(spec, modified_spec)
            return return_response(
                allowed=True,
                patch=patch,
                patchType="JSONPatch",
            )
        else:
            return return_response(True)
    except Exception as e:
        return process_unhandled_exception(e, return_response, logger)
