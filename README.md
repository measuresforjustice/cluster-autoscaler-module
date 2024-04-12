# Archived
Please use the official helm chart
https://github.com/kubernetes/autoscaler/tree/master/charts/cluster-autoscaler
https://artifacthub.io/packages/helm/cluster-autoscaler/cluster-autoscaler


# cluster-autoscaler terraform module

Terraform module for creating cluster-autoscaler in kubernetes with an IAM user

Creates both the IAM user with permissions for cluster-autoscaler and the k8 deployment with necessary roles.

The latest version of the cluster-autoscaler image for your k8 version can be found at https://github.com/kubernetes/autoscaler/tree/master/cluster-autoscaler

## Important install steps

All auto scaling groups to be scaled need to be tagged with `k8s.io/cluster-autoscaler/enabled` = `1` and `kubernetes.io/cluster/CLUSTER_NAME` = `1`.

## Legal stuff

This terraform module is released under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

Copyright 2019 Measures for Justice Institute.
