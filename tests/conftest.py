import os
import pickle
from pathlib import Path

import pytest
import yaml

from nebari_workflow_controller.models import KeycloakGroup, KeycloakUser

os.environ["NAMESPACE"] = "default"


def _valid_request_paths():
    return sorted(
        [str(p) for p in Path("./tests/test_data/requests/valid").glob("*.yaml")]
    )


@pytest.fixture(scope="session")
def valid_request_paths():
    return _valid_request_paths()


def _invalid_request_paths():
    return sorted(
        [str(p) for p in Path("./tests/test_data/requests/invalid").glob("*.yaml")]
    )


@pytest.fixture(scope="session")
def invalid_request_paths():
    return _invalid_request_paths()


def _all_request_paths():
    return _valid_request_paths() + _invalid_request_paths()


@pytest.fixture(scope="session")
def all_request_paths(valid_request_paths, invalid_request_paths):
    return valid_request_paths + invalid_request_paths


def load_request(request_path):
    with open(request_path) as f:
        return yaml.load(f, Loader=yaml.FullLoader)


def get_request_templates(loaded_request):
    templates = loaded_request["request"]["object"]["spec"]["templates"]
    if not isinstance(templates, list):
        breakpoint()
    return templates


@pytest.fixture(
    scope="session",
    params=([get_request_templates(load_request(rp)) for rp in _all_request_paths()]),
)
def request_templates(request):
    return request.param


@pytest.fixture(scope="session")
def jupyterlab_pod_spec():
    with open("tests/test_data/jupyterlab_pod_spec.pkl", "rb") as f:
        jupyterlab_pod_spec = pickle.load(f)
        return jupyterlab_pod_spec


@pytest.fixture()  # (scope="session")
def mocked_get_keycloak_user_info(mocker):
    mocker.patch(
        "nebari_workflow_controller.app.get_keycloak_user_info",
        return_value=KeycloakUser(
            username="mocked_username",
            id="mocked_id",
            groups=[
                KeycloakGroup(**g)
                for g in [
                    {
                        "id": "3135c469-02a9-49bc-9245-f886e6317397",
                        "name": "admin",
                        "path": "/admin",
                    },
                    {
                        "id": "137d8913-e7eb-4d68-85a3-59a7a15e99fa",
                        "name": "analyst",
                        "path": "/analyst",
                    },
                ]
            ],
        ),
    )


@pytest.fixture()  # (scope="session")
def mocked_get_user_pod_spec(mocker):
    with open("tests/test_data/jupyterlab_pod_spec.pkl", "rb") as f:
        jupyterlab_pod_spec = pickle.load(f)
    mocker.patch(
        "nebari_workflow_controller.app.get_user_pod_spec",
        return_value=jupyterlab_pod_spec,
    )
