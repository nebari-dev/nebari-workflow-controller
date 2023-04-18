import yaml
import pytest
from app import get_username_groups


@pytest.mark.parametrize(
	"request_file",
	["./tests/test_data/request_from_browser.yaml",]
)
def test_admission_controller(request_file, mocker):
	mocker.patch('app.get_username_groups', lambda request: 'adam', ['nebari'])
	with open(request_file) as f:
		request = yaml.load(f, Loader=yaml.FullLoader)
	print(get_username_groups(request))