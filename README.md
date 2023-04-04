Argo Workflows Admission Controller
===================================

This repo holds some proof of concept work for an Argo Workflows Admission Controller to limit the volumes that a workflow can mount.  It is mostly a storage of some WIP code, and will not run without some modification.

Steps to use
============
- You need to build the argowf_admission_controller/Dockerfile and push it to a registry that your kubernetes cluster can access.
- You need to kubectl apply the files in the manifests directory.

The argowf_admission_controller folder contains the source code for the Fastapi admission controller.