# Nebari Workflow Controller
A kubernetes admission controller to enable volumeMount permisions on Argo Workflows on Nebari and provide a convenience method for deploying jupyterlab-like workflows for users.

# Run project
- `pip install .`
- `python -m nebari_workflow_controller`

# Known Limitations
Resubmitting workflows is not supported by Nebari Workflow Controller.

# Developing on this project
Run `pip install -e .[dev]`
