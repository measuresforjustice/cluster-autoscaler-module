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

locals {
  sa_name = "cluster-autoscaler"
}

data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(var.openid_url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:${local.sa_name}"]
    }

    principals {
      identifiers = [var.openid_arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "role" {
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json
  name               = "cluster-autoscaler"
}

resource "aws_iam_role_policy_attachment" "role-policy-attach" {
  role       = aws_iam_role.role.name
  policy_arn = aws_iam_policy.cluster-autoscaler-policy.arn
}

resource "kubernetes_service_account" "cluster-autoscaler-sa" {
  metadata {
    name      = local.sa_name
    namespace = "kube-system"
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.role.arn
    }
    labels = {
      "k8s-addon"              = "cluster-autoscaler.addons.k8s.io"
      "k8s-app"                = "cluster-autoscaler"
      "app.kubernetes.io/name" = "cluster-autoscaler"
    }
  }

  automount_service_account_token = "true"
}

resource "kubernetes_cluster_role" "cluster_role" {
  metadata {
    name = "cluster-autoscaler"
    labels = {
      "k8s-addon"              = "cluster-autoscaler.addons.k8s.io"
      "k8s-app"                = "cluster-autoscaler"
      "app.kubernetes.io/name" = "cluster-autoscaler"
    }
  }

  rule {
    api_groups = [""]
    resources  = ["events", "endpoints"]
    verbs      = ["create", "patch"]
  }
  rule {
    api_groups = [""]
    resources  = ["pods/eviction"]
    verbs      = ["create"]
  }
  rule {
    api_groups = [""]
    resources  = ["pods/status"]
    verbs      = ["update"]
  }
  rule {
    api_groups     = [""]
    resources      = ["endpoints"]
    resource_names = ["cluster-autoscaler"]
    verbs          = ["get", "update"]
  }
  rule {
    api_groups = [""]
    resources  = ["nodes"]
    verbs      = ["watch", "list", "get", "update"]
  }
  rule {
    api_groups = [""]
    resources = [
      "pods",
      "services",
      "replicationcontrollers",
      "persistentvolumeclaims",
      "persistentvolumes",
    ]
    verbs = ["watch", "list", "get"]
  }
  rule {
    api_groups = ["policy"]
    resources  = ["poddisruptionbudgets"]
    verbs      = ["watch", "list"]
  }
  rule {
    api_groups = ["apps"]
    resources  = ["replicasets", "statefulsets", "daemonsets"]
    verbs      = ["watch", "list", "get"]
  }
  rule {
    api_groups = ["batch"]
    resources  = ["jobs", "cronjobs"]
    verbs      = ["watch", "list", "get"]
  }
  rule {
    api_groups = ["storage.k8s.io"]
    resources  = ["storageclasses", "csinodes"]
    verbs      = ["watch", "list", "get"]
  }
  rule {
    api_groups = ["coordination.k8s.io"]
    resources  = ["leases"]
    verbs      = ["create"]
  }
  rule {
    api_groups     = ["coordination.k8s.io"]
    resource_names = ["cluster-autoscaler"]
    resources      = ["leases"]
    verbs          = ["get", "update"]
  }
}

resource "kubernetes_cluster_role_binding" "cluster_role_bind" {
  metadata {
    name = "cluster-autoscaler"
    labels = {
      "k8s-addon"              = "cluster-autoscaler.addons.k8s.io"
      "k8s-app"                = "cluster-autoscaler"
      "app.kubernetes.io/name" = "cluster-autoscaler"
    }
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    name      = kubernetes_cluster_role.cluster_role.metadata[0].name
    kind      = "ClusterRole"
  }

  subject {
    api_group = ""
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.cluster-autoscaler-sa.metadata[0].name
    namespace = "kube-system"
  }
}

resource "kubernetes_role" "cluster-autoscaler-role" {
  metadata {
    name      = "cluster-autoscaler"
    namespace = "kube-system"
    labels = {
      "k8s-addon"              = "cluster-autoscaler.addons.k8s.io"
      "k8s-app"                = "cluster-autoscaler"
      "app.kubernetes.io/name" = "cluster-autoscaler"
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
      "list",
      "watch"
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
      "cluster-autoscaler-status", "cluster-autoscaler-priority-expander"
    ]

    verbs = [
      "delete",
      "get",
      "update",
      "watch"
    ]
  }
}

resource "kubernetes_role_binding" "role_bind" {
  metadata {
    name      = "cluster-autoscaler"
    namespace = "kube-system"
    labels = {
      "k8s-addon"              = "cluster-autoscaler.addons.k8s.io"
      "k8s-app"                = "cluster-autoscaler"
      "app.kubernetes.io/name" = "cluster-autoscaler"
    }
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    name      = kubernetes_role.cluster-autoscaler-role.metadata[0].name
    kind      = "Role"
  }

  subject {
    api_group = ""
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.cluster-autoscaler-sa.metadata[0].name
    namespace = "kube-system"
  }
}

resource "kubernetes_deployment" "deployment" {
  metadata {
    name      = "cluster-autoscaler"
    namespace = "kube-system"

    labels = {
      "app.kubernetes.io/name" = "cluster-autoscaler"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        "app.kubernetes.io/name" = "cluster-autoscaler"
      }
    }

    template {
      metadata {
        labels = {
          "app.kubernetes.io/name" = "cluster-autoscaler"
        }
      }

      spec {
        automount_service_account_token = true
        service_account_name            = kubernetes_service_account.cluster-autoscaler-sa.metadata[0].name
        priority_class_name             = "system-cluster-critical"
        security_context {
          fs_group = "1001"
        }
        container {
          command = [
            "./cluster-autoscaler",
            "--v=4",
            "--stderrthreshold=info",
            "--cloud-provider=aws",
            "--skip-nodes-with-local-storage=false",
            "--expander=least-waste",
            "--node-group-auto-discovery=asg:tag=k8s.io/cluster-autoscaler/enabled,kubernetes.io/cluster/${var.cluster_name}",
            "--balance-similar-node-groups",
            "--skip-nodes-with-system-pods=false"
          ]

          security_context {
            allow_privilege_escalation = "false"
            privileged                 = "false"
            capabilities {
              drop = ["all"]
            }
            run_as_user     = "1001"
            run_as_group    = "1001"
            run_as_non_root = "true"
          }

          resources {
            # limits = {
            #   cpu    = "100m"
            #   memory = "300Mi"
            # }
            requests = {
              cpu    = "100m"
              memory = "300Mi"
            }
          }

          port {
            name           = "prometheus"
            container_port = 8085
          }

          image             = "us.gcr.io/k8s-artifacts-prod/autoscaling/cluster-autoscaler:v${var.autoscaler_version}"
          image_pull_policy = "Always"

          name = "cluster-autoscaler"

          volume_mount {
            name       = "ssl-certs"
            mount_path = "/etc/ssl/certs/ca-certificates.crt"
            read_only  = "true"
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

resource "kubernetes_service" "cluster-autoscaler" {
  metadata {
    name      = "cluster-autoscaler-prometheus"
    namespace = "kube-system"
    labels = {
      "app.kubernetes.io/name" = "cluster-autoscaler"
    }
  }
  spec {
    cluster_ip = "None"
    selector = {
      "app.kubernetes.io/name" = "cluster-autoscaler"
    }
    port {
      name        = "prometheus"
      port        = 8085
      target_port = 8085
    }
  }

}
