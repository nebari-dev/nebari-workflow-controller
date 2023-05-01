import os
import pickle
from pathlib import Path

import pytest
import yaml

os.environ["NAMESPACE"] = "default"


def _valid_request_paths():
    return sorted(
        [str(p) for p in Path("./tests/test_data/requests/pass").glob("*.yaml")]
    )


@pytest.fixture(scope="session")
def valid_request_paths():
    return _valid_request_paths()


def _invalid_request_paths():
    return sorted(
        [str(p) for p in Path("./tests/test_data/requests/fail").glob("*.yaml")]
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
