# Nebari Workflow Controller

![PyPI](https://img.shields.io/pypi/v/nebari-workflow-controller)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/nebari-workflow-controller)


A [kubernetes admission controller](https://kubernetes.io/blog/2019/03/21/a-guide-to-kubernetes-admission-controllers/) to enable volumeMount permissions on Argo Workflows on Nebari and provide a convenience method for deploying jupyterlab-like workflows for users.

# Run project
- `pip install nebari-workflow-controller`
- `python -m nebari_workflow_controller`

# Known Limitations
Resubmitting workflows is not supported by Nebari Workflow Controller.

# Developing on this project
Run `pip install -e .[dev]`
