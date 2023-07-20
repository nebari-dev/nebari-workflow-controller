import base64

import jsonpatch
import pytest
import yaml
from kubernetes import client

from nebari_workflow_controller.app import mutate, validate
from nebari_workflow_controller.utils import (
    get_container_keep_portions,
    get_spec_keep_portions,
    mutate_template,
)

from .conftest import (
    _invalid_request_paths,
    _invalid_service_account_request_paths,
    _valid_request_paths,
    _valid_service_account_request_paths,
)


@pytest.mark.parametrize(
    "request_file,allowed",
    [(str(p), True) for p in _valid_request_paths()]
    + [(str(p), False) for p in _invalid_request_paths()],
)
def test_validate(request_file, allowed, mocked_get_keycloak_user):
    with open(request_file) as f:
        request = yaml.load(f, Loader=yaml.FullLoader)
    response = validate(request)

    assert response["response"]["allowed"] == allowed
    if not allowed:
        assert response["response"]["status"]["message"]


@pytest.mark.parametrize(
    "request_file,allowed",
    [(str(p), True) for p in _valid_service_account_request_paths()]
    + [(str(p), False) for p in _invalid_service_account_request_paths()],
)
def test_validate_with_service_account(request_file, allowed, mock_special_case):
    # The general case is where the user is directly validated against Keycloak.
    # This is the special case, where the user is validated against Keycloak via a service account.

    with open(request_file) as f:
        request = yaml.load(f, Loader=yaml.FullLoader)
    response = validate(request)

    assert response["response"]["allowed"] == allowed
    if not allowed:
        assert response["response"]["status"]["message"]


def test_mutate_template_doesnt_error(request_templates, jupyterlab_pod_spec):
    api = client.ApiClient()
    container_keep_portions = get_container_keep_portions(jupyterlab_pod_spec, api)
    spec_keep_portions = get_spec_keep_portions(jupyterlab_pod_spec, api)

    for template in request_templates:
        mutate_template(
            container_keep_portions=container_keep_portions,
            spec_keep_portions=spec_keep_portions,
            template=template,
        )


@pytest.mark.parametrize(
    "request_file", ["tests/test_data/requests/valid/jupyterflow-override-example.yaml"]
)
def test_mutate_check_content(
    request_file, mocked_get_keycloak_user, mocked_get_user_pod_spec
):
    with open(request_file) as f:
        request = yaml.load(f, Loader=yaml.FullLoader)
    response = mutate(request)
    patch_text = base64.b64decode(response["response"]["patch"]).decode()
    patch = jsonpatch.JsonPatch.from_string(patch_text)
    mutated_spec = patch.apply(request["request"]["object"])
    for volume in [
        {
            "name": "home",
            "persistentVolumeClaim": {"claimName": "jupyterhub-dev-share"},
        },
        {"configMap": {"defaultMode": 420, "name": "etc-skel"}, "name": "skel"},
        {
            "name": "conda-store",
            "persistentVolumeClaim": {"claimName": "conda-store-dev-share"},
        },
        {"configMap": {"defaultMode": 420, "name": "dask-etc"}, "name": "dask-etc"},
        {
            "configMap": {"defaultMode": 420, "name": "etc-ipython"},
            "name": "etc-ipython",
        },
        {
            "configMap": {"defaultMode": 420, "name": "etc-jupyter"},
            "name": "etc-jupyter",
        },
        {
            "configMap": {"defaultMode": 420, "name": "jupyterlab-settings"},
            "name": "jupyterlab-settings",
        },
    ]:
        assert volume in mutated_spec["spec"]["templates"][0]["volumes"]

    assert mutated_spec["spec"]["templates"][0]["nodeSelector"] == {
        "mylabel": "myValue",
        "cloud.google.com/gke-nodepool": "user",
    }

    assert mutated_spec["spec"]["templates"][0]["container"]["resources"] == {
        "requests": {"cpu": "1500m", "memory": "5368709120"},
        "limits": {"cpu": "3000m", "memory": "8589934592"},
    }
