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
resource "aws_iam_user" "cluster-autoscaler-user" {
  name = "cluster-autoscaler"
}

resource "aws_iam_policy" "cluster-autoscaler-policy" {
  name = "cluster-autoscaler"
  path = "/"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:DescribeAutoScalingInstances",
        "autoscaling:DescribeLaunchConfigurations",
        "autoscaling:DescribeTags",
        "autoscaling:SetDesiredCapacity",
        "autoscaling:TerminateInstanceInAutoScalingGroup",
        "ec2:DescribeLaunchTemplateVersions"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_user_policy_attachment" "cluster-autoscaler-attach" {
  user       = "${aws_iam_user.cluster-autoscaler-user.name}"
  policy_arn = "${aws_iam_policy.cluster-autoscaler-policy.arn}"
}

resource "aws_iam_access_key" "cluster-autoscaler-key" {
  user = "${aws_iam_user.cluster-autoscaler-user.name}"
}

resource "kubernetes_secret" "aws_key" {
  metadata {
    name      = "cluster-autoscaler-aws"
    namespace = "kube-system"
  }

  data {
    "key_id" = "${aws_iam_access_key.cluster-autoscaler-key.id}"
    "key"    = "${aws_iam_access_key.cluster-autoscaler-key.secret}"
  }
}

resource "kubernetes_service_account" "cluster-autoscaler-sa" {
  metadata {
    name      = "cluster-autoscaler"
    namespace = "kube-system"
    labels {
      "k8s-addon" = "cluster-autoscaler.addons.k8s.io"
      "k8s-app" = "cluster-autoscaler"
    }
  }

  secret {
    name = "${kubernetes_secret.aws_key.metadata.0.name}"
  }
  automount_service_account_token = "true"
}

resource "kubernetes_cluster_role" "cluster_role" {
  metadata {
    name      = "cluster-autoscaler"
    labels {
      "k8s-addon" = "cluster-autoscaler.addons.k8s.io"
      "k8s-app" = "cluster-autoscaler"
    }
  }

  rule {
    api_groups = ["",]
    resources = ["events","endpoints"]
    verbs = ["create", "patch"]
  }
  rule {
    api_groups = [""]
    resources = ["pods/eviction"]
    verbs = ["create"]
  }
  rule {
    api_groups = [""]
    resources = ["pods/status"]
    verbs = ["update"]
  }
  rule {
    api_groups = [""]
    resources = ["endpoints"]
    resource_names = ["cluster-autoscaler"]
    verbs = ["get","update"]
  }
  rule {
    api_groups = [""]
    resources = ["nodes"]
    verbs = ["watch","list","get","update"]
  }
  rule {
    api_groups = [""]
    resources = ["pods","services","replicationcontrollers",
      "persistentvolumeclaims","persistentvolumes"]
    verbs = ["watch","list","get"]
  }
  rule {
    api_groups = ["extensions"]
    resources = ["replicasets","daemonsets"]
    verbs = ["watch","list","get"]
  }
  rule {
    api_groups = ["policy"]
    resources = ["poddisruptionbudgets"]
    verbs = ["watch","list"]
  }
  rule {
    api_groups = ["apps"]
    resources = ["statefulsets"]
    verbs = ["watch","list","get"]
  }
  rule {
    api_groups = ["storage.k8s.io"]
    resources = ["storageclasses"]
    verbs = ["watch","list","get"]
  }
}

resource "kubernetes_cluster_role_binding" "cluster_role_bind" {
  metadata {
    name = "cluster-autoscaler"
    labels {
      "k8s-addon" = "cluster-autoscaler.addons.k8s.io"
      "k8s-app" = "cluster-autoscaler"
    }
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    name = "${kubernetes_cluster_role.cluster_role.metadata.0.name}"
    kind = "ClusterRole"
  }

  subject {
    api_group = ""
    kind = "ServiceAccount"
    name = "${kubernetes_service_account.cluster-autoscaler-sa.metadata.0.name}"
    namespace = "kube-system"
  }
}

resource "kubernetes_role" "cluster-autoscaler-role" {
  metadata {
    name = "cluster-autoscaler"
    namespace = "kube-system"
    labels {
      "k8s-addon" = "cluster-autoscaler.addons.k8s.io"
      "k8s-app" = "cluster-autoscaler"
    }
  }

  rule {
    api_groups = [
      "",
    ]

    resources = [
      "configmaps",
    ]

    verbs = [
      "create",
    ]
  }
  rule {
    api_groups = [
      "",
    ]

    resources = [
      "configmaps",
    ]

    resource_names = [
      "cluster-autoscaler-status"
    ]

    verbs = [
      "delete",
      "get",
      "update"
    ]
  }
}

resource "kubernetes_role_binding" "role_bind" {
  metadata {
    name = "cluster-autoscaler"
    namespace = "kube-system"
    labels {
      "k8s-addon" = "cluster-autoscaler.addons.k8s.io"
      "k8s-app" = "cluster-autoscaler"
    }
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    name = "${kubernetes_role.cluster-autoscaler-role.metadata.0.name}"
    kind = "Role"
  }

  subject {
    api_group = ""
    kind = "ServiceAccount"
    name = "${kubernetes_service_account.cluster-autoscaler-sa.metadata.0.name}"
    namespace = "kube-system"
  }
}

resource "kubernetes_deployment" "deployment" {
  metadata {
    name      = "cluster-autoscaler"
    namespace = "kube-system"

    labels {
      "app" = "cluster-autoscaler"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels {
        app = "cluster-autoscaler"
      }
    }

    template {
      metadata {
        labels {
          app = "cluster-autoscaler"
        }
      }

      spec {
        #!!!!set manually: automount_service_account_token = "true"  ### automountServiceAccountToken: true
        service_account_name = "${kubernetes_service_account.cluster-autoscaler-sa.metadata.0.name}"

        container {
          command = [
            "./cluster-autoscaler",
            "--v=2",
            "--cloud-provider=aws",
            "--skip-nodes-with-local-storage=false",
            "--expander=least-waste",
            "--node-group-auto-discovery=asg:tag=k8s.io/cluster-autoscaler/enabled,kubernetes.io/cluster/${var.cluster_name}"
          ]

          security_context {
            allow_privilege_escalation = "false"
            privileged                 = "false"
            run_as_user                = "999"
            run_as_non_root            = "true"
          }

          resources {
            limits {
              cpu = "100m"
              memory = "300Mi"
            }
            requests {
              cpu = "100m"
              memory = "300Mi"
            }
          }

          env {
            name = "AWS_ACCESS_KEY_ID"

            value_from {
              secret_key_ref {
                name = "${kubernetes_secret.aws_key.metadata.0.name}"
                key  = "key_id"
              }
            }
          }

          env {
            name = "AWS_SECRET_ACCESS_KEY"

            value_from {
              secret_key_ref {
                name = "${kubernetes_secret.aws_key.metadata.0.name}"
                key  = "key"
              }
            }
          }

          env {
            name  = "AWS_DEFAULT_REGION"
            value = "${var.aws_region}"
          }

          image             = "gcr.io/google-containers/cluster-autoscaler:v${var.autoscaler_version}"
          image_pull_policy = "Always"

          name = "cluster-autoscaler"

          volume_mount {
            name = "ssl-certs"
            mount_path = "/etc/ssl/certs/ca-certificates.crt"
            read_only = "true"
          }

        }
        volume {
          name = "ssl-certs"
          host_path {
            path = "/etc/ssl/certs/ca-bundle.crt"
          }
        }
      }
    }
  }
}
