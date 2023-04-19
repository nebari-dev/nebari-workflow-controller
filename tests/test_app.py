import pytest
import yaml

from nebari_workflow_controller.app import admission_controller
from nebari_workflow_controller.models import KeycloakGroup, KeycloakUser


@pytest.mark.parametrize(
    "request_file,allowed",
    # [
    # 	(str(p), True) for p in Path('./tests/test_data/requests/pass').glob('*.yaml')
    # ] + [
    # 	(str(p), False) for p in Path('./tests/test_data/requests/fail').glob('*.yaml')
    # ]
    [
        ("tests/test_data/requests/pass/browser_hello_world.yaml", True),
        ("tests/test_data/requests/pass/argo_cli_hello_world.yaml", True),
        ("tests/test_data/requests/pass/jupyterlab_pod.yaml", True),
        ("tests/test_data/requests/pass/kubectl_malicious.yaml", True),
        ("tests/test_data/requests/fail/initContainer_empty_subPath.yaml", False),
        ("tests/test_data/requests/fail/container_empty_subPath.yaml", False),
        ("tests/test_data/requests/fail/disallowed_volume.yaml", False),
        ("tests/test_data/requests/fail/container_disallowed_file_mount.yaml", False),
        (
            "tests/test_data/requests/fail/initContainer_disallowed_conda_mount.yaml",
            False,
        ),
        ("tests/test_data/requests/fail/container_disallowed_conda_mount.yaml", False),
        (
            "tests/test_data/requests/fail/initContainer_disallowed_file_mount.yaml",
            False,
        ),
    ],
)
def test_admission_controller(mocker, request_file, allowed):
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
    with open(request_file) as f:
        request = yaml.load(f, Loader=yaml.FullLoader)
    response = admission_controller(request)
    print(response)
    assert response["response"]["allowed"] == allowed
