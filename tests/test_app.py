import yaml
import pytest
from pathlib import Path
from nebari_workflow_controller.app import admission_controller

[(str(p), True) for p in Path('./tests/test_data').glob('*.yaml')]

@pytest.mark.parametrize(
	"request_file,allowed",
	[
		# [(str(p), True) for p in Path('./tests/test_data').glob('*.yaml')]
		('tests/test_data/request_from_browser.yaml', True), 
		('tests/test_data/request_from_argo_cli.yaml', True), 
		('tests/test_data/request_from_kubectl_malicious.yaml', False), 
		('tests/test_data/request_container_volume_without_subPath.yaml', False), 
		('tests/test_data/request_like_jupyterlab_pod.yaml', True), 
		('tests/test_data/request_initContainer_volume_without_subPath.yaml', False)]
)
def test_admission_controller(mocker, request_file, allowed):
	mocker.patch('nebari_workflow_controller.app.get_username_groups', 
		return_value=(
			'mocked_username', 
			[
				{'id': '3135c469-02a9-49bc-9245-f886e6317397', 'name': 'admin', 'path': '/admin'}, 
				{'id': '137d8913-e7eb-4d68-85a3-59a7a15e99fa', 'name': 'analyst', 'path': '/analyst'}
			]
		)
	)
	with open(request_file) as f:
		request = yaml.load(f, Loader=yaml.FullLoader)
	response = admission_controller(request)
	print(response)
	assert response['response']['allowed'] == allowed