/*
Copyright 2019 Measures for Justice Institute.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

variable "aws_region" {
  default     = "us-east-1"
  description = "aws region to use"
}

variable "autoscaler_version" {
  description = "Version of cluster-autoscaler to use"
}

variable "scale_down_threshold"{
  description = "Sum of requested resources divided by capacity, below which a node can be considered for scale down"
  default = ".5"
}

variable "cluster_name" {
  description = "Name of your k8 cluster"
}

variable "openid_url" {
  description = "OpenID url of your k8 cluster"
}

variable "openid_arn" {
  description = "OpenID ARN of your k8 cluster"
}
