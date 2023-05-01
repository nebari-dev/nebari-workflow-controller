from pathlib import Path

import yaml

preamble = """
apiVersion: admission.k8s.io/v1
kind: AdmissionReview
request:
    dryRun: false
    kind:
        group: argoproj.io
        kind: Workflow
        version: v1alpha1
    name: hello-world
    namespace: dev
    operation: CREATE
    options:
        apiVersion: meta.k8s.io/v1
        kind: CreateOptions
    requestKind:
        group: argoproj.io
        kind: Workflow
        version: v1alpha1
    requestResource:
        group: argoproj.io
        resource: workflows
        version: v1alpha1
    resource:
        group: argoproj.io
        resource: workflows
        version: v1alpha1
    uid: c1bba5c6-2189-41ff-9487-be504c04487b
    userInfo:
        groups:
        - system:serviceaccounts
        - system:serviceaccounts:dev
        - system:authenticated
        uid: eac0d7ab-af84-4c3f-a5fd-71845ff9e8c9
        username: system:serviceaccount:dev:argo-admin
"""

new_request = yaml.load(preamble, Loader=yaml.FullLoader)
files = Path("./requests/valid").glob("*.yaml")

for request_file in files:
    with open(request_file, "r") as f:
        try:
            request = yaml.load(f, Loader=yaml.FullLoader)
        except Exception:
            print(str(request_file))
            breakpoint()
    if request["kind"] == "Workflow":
        if value := request["metadata"].get("generateName"):
            request["metadata"]["name"] = value
            request["metadata"].pop("generateName")
        new_request["request"]["object"] = request
        with open(request_file, "w") as f:
            yaml.dump(new_request, f)
