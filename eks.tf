################################################################################
### Provider
################################################################################

provider "kubernetes" {   # Terraform에서 k8s에 접근할 수 있도록 인증 정보를 제공한다.
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  token                  = data.aws_eks_cluster_auth.eks.token
}

provider "helm" {   # Terraform에서 helm을 통해 k8s 내 Add-on를 설치할 수 있도록 인증 정보를 제공한다.
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    token                  = data.aws_eks_cluster_auth.eks.token
  }
}

################################################################################
### Data Sources
################################################################################
data "aws_availability_zones" "available" {}  # 사용가능한 가용영역 체크
data "aws_caller_identity" "current" {}  # Terraform에서 AWS의 계정 ID를 참조하기 위해 정의
data "aws_eks_cluster_auth" "eks" {name = module.eks.cluster_name}  # EKS 클러스터와 통신하기 위한 인증 토큰을 가져온다.
# data "terraform_remote_state" "remote" { # VPC State를 가져온다.
#   backend = "s3"
#   config = {
#     profile        = "thm-eks"
#     bucket         = "thm-eks-s3-tfstate"
#     key            = "thm-eks/terraform.tfstate"
#     dynamodb_table = "thm-eks-table-tfstate"
#     region         = "ap-northeast-2"
#   }

#   depends_on = [module.vpc]
# }

################################################################################
### EKS Module
################################################################################
module "eks" {
  source  = "terraform-aws-modules/eks/aws"

  cluster_name                   = "${local.name}-eks-cluster"
  cluster_version                = 1.24
  cluster_endpoint_public_access = true
  cluster_endpoint_private_access = true

  iam_role_name = "${local.name}-eks-cluster-role"
  iam_role_use_name_prefix = false
  cluster_encryption_policy_name = "${local.name}-eks-cluster-encryption-policy"
  cluster_encryption_policy_use_name_prefix = false
  cluster_security_group_name    = "${local.name}-eks-cluster-sg"
  cluster_security_group_use_name_prefix = false
  cluster_security_group_tags    = {"Name" = "${local.name}-eks-cluster-sg"}
  node_security_group_name			 = "${local.name}-eks-node-sg"
  node_security_group_use_name_prefix = false
  node_security_group_tags       = {"Name" = "${local.name}-eks-node-sg"}

  tags = local.tags

  # EKS Add-On
  cluster_addons = {
    coredns = {
      #most_recent       = true
      resolve_conflicts = "OVERWRITE"
    }
    kube-proxy = {
      #most_recent = true
    }
    vpc-cni = {
      #most_recent              = true
      before_compute           = true  # 워커 노드가 프로비저닝되기 전 vpc-cni가 배포되어야한다. 배포 전 워커 노드가 프로비저닝될 경우 파드 IP 할당 이슈(pending) 발생
      resolve_conflicts        = "OVERWRITE"
      service_account_role_arn = module.vpc_cni_irsa_role.iam_role_arn  # IRSA
      configuration_values     = jsonencode({
        env = {
          ENABLE_PREFIX_DELEGATION = "true"  # prefix assignment mode 활성화
          WARM_PREFIX_TARGET       = "1"  # 기본 권장 값
        }
      })
    }
    aws-ebs-csi-driver = {
      #most_recent = true
      service_account_role_arn = module.ebs_csi_driver_irsa_role.iam_role_arn
    }
    aws-efs-csi-driver = {
      #most_recent = true
      service_account_role_arn = module.efs_csi_driver_irsa_role.iam_role_arn
    }        
  }

  vpc_id     = local.vpc_id
  subnet_ids = local.subnet_ids

  # aws-auth configmap
  manage_aws_auth_configmap = true  # AWS -> EKS 접근을 위한 configmap 자동 생성

  ################################################################################
  ### EKS Managed Node Group 정의
  ################################################################################  
  eks_managed_node_group_defaults = {
    ami_type                   = "AL2_x86_64"
    capacity_type              = "SPOT"

    create_iam_role            = false
    iam_role_name              = "${local.name}-eks-node-role"
    iam_role_arn               = module.iam_assumable_role_custom.iam_role_arn
    iam_role_use_name_prefix   = false
    iam_role_attach_cni_policy = true
    iam_role_additional_policies = {
      AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"  # ssm 접속 권한
    }   
    use_name_prefix            = false  # false 하지 않으면 리소스 이름 뒤 임의의 난수값이 추가되어 생성됨
    
    create_launch_template          = false
    use_custom_launch_template      = true  # false : AWS EKS 관리 노드 그룹에서 제공하는 기본 템플릿을 사용
    enable_bootstrap_user_data      = true  # 사용자 지정 템플릿을 노드그룹에 지정하는 경우 노드가 클러스터에 join 하기위한 부트스트랩이 자동 적용되지 않음. 따라서 해당 옵션 true 설정 필요
  }

  # app
  eks_managed_node_groups = {
    app-ng = {
      name         = "${local.name}-app-ng"
      launch_template_id = aws_launch_template.app_launch_template.id
      labels = {
        nodegroup = "app"
      }
      desired_size = 1
      min_size     = 1
      max_size     = 5
    }

  # batch
    batch-ng = {
      name         = "${local.name}-batch-ng"
      launch_template_id = aws_launch_template.batch_launch_template.id
      labels = {
        nodegroup = "batch"
      }
      desired_size = 1
      min_size     = 1
      max_size     = 5
    }

  # front
    front-ng = {
      name         = "${local.name}-front-ng"
      launch_template_id = aws_launch_template.front_launch_template.id
      labels = {
        nodegroup = "front"
      }
      desired_size = 1
      min_size     = 1
      max_size     = 5
    }

  # mgmt
    mgmt-ng = {
      name         = "${local.name}-mgmt-ng"
      launch_template_id = aws_launch_template.mgmt_launch_template.id      
      labels = {
        nodegroup = "mgmt"
      }      
      desired_size = 1
      min_size     = 1
      max_size     = 5
    } 
  }
}

################################################################################
### Custom Launch Template 정의
################################################################################
resource "aws_launch_template" "app_launch_template" {
  name     = "${local.name}-eks-app-lt"
  instance_type = "t3.medium"
  key_name = module.key_pair.key_pair_name
  vpc_security_group_ids = [module.eks.cluster_primary_security_group_id]#, aws_security_group.remote_access.id]

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 30
      volume_type           = "gp3"
      delete_on_termination = true
    }
  }  

  dynamic "tag_specifications" {
    for_each = var.lt_resource_tags
    content {
      resource_type = tag_specifications.key
      tags = {
        Name = "${local.name}-eks-app-node"
      }
    }
  }

  tags = local.tags # LT Tag
}

resource "aws_launch_template" "batch_launch_template" {
  name     = "${local.name}-eks-batch-lt"
  instance_type = "t3.medium"
  key_name = module.key_pair.key_pair_name
  vpc_security_group_ids = [module.eks.cluster_primary_security_group_id]#, aws_security_group.remote_access.id]

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 30
      volume_type           = "gp3"
      delete_on_termination = true
    }
  }  

  dynamic "tag_specifications" {
    for_each = var.lt_resource_tags
    content {
      resource_type = tag_specifications.key
      tags = {
        Name = "${local.name}-eks-batch-node"
      }
    }
  }

  tags = local.tags # LT Tag
}

resource "aws_launch_template" "front_launch_template" {
  name     = "${local.name}-eks-front-lt"
  instance_type = "t3.medium"
  key_name = module.key_pair.key_pair_name
  vpc_security_group_ids = [module.eks.cluster_primary_security_group_id]#, aws_security_group.remote_access.id]

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 30
      volume_type           = "gp3"
      delete_on_termination = true
    }
  }  

  dynamic "tag_specifications" {
    for_each = var.lt_resource_tags
    content {
      resource_type = tag_specifications.key
      tags = {
        Name = "${local.name}-eks-front-node"
      }
    }
  }

  tags = local.tags # LT Tag
}

resource "aws_launch_template" "mgmt_launch_template" {
  name     = "${local.name}-eks-mgmt-lt"
  instance_type = "t3.medium"
  key_name = module.key_pair.key_pair_name
  vpc_security_group_ids = [module.eks.cluster_primary_security_group_id]#, aws_security_group.remote_access.id]

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 30
      volume_type           = "gp3"
      delete_on_termination = true
    }
  }  

  dynamic "tag_specifications" {
    for_each = var.lt_resource_tags
    content {
      resource_type = tag_specifications.key
      tags = {
        Name = "${local.name}-eks-mgmt-node"
      }
    }
  }

  tags = local.tags # LT Tag
}


################################################################################
### IRSA Module
################################################################################
module "vpc_cni_irsa_role" { 
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = "${local.name}-eks-vpc_cni-role"
  policy_name_prefix    = "${local.name}-eks-"
  attach_vpc_cni_policy = true
  vpc_cni_enable_ipv4   = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-node"]
    }
  }

  tags = local.tags
}

module "load_balancer_controller_irsa_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = "${local.name}-eks-lb_controller-role"
  policy_name_prefix    = "${local.name}-eks-"  
  attach_load_balancer_controller_policy = true
  
  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }

  tags = local.tags
}

module "load_balancer_controller_targetgroup_binding_only_irsa_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name = "${local.name}-eks-lb_controller_tg-role"
  policy_name_prefix    = "${local.name}-eks-"  
  attach_load_balancer_controller_targetgroup_binding_only_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }

  tags = local.tags
}

module "external_dns_irsa_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                     = "${local.name}-eks-external_dns-role"
  policy_name_prefix            = "${local.name}-eks-"  
  attach_external_dns_policy    = true
  external_dns_hosted_zone_arns = [local.external_dns_arn]

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:external-dns"]
    }
  }

  tags = local.tags
}

module "ebs_csi_driver_irsa_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                     = "${local.name}-eks-ebs_csi-role"
  policy_name_prefix            = "${local.name}-eks-"  
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }

  tags = local.tags
}

module "efs_csi_driver_irsa_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                     = "${local.name}-eks-efs_csi-role"
  policy_name_prefix            = "${local.name}-eks-"  
  attach_efs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:efs-csi-controller-sa"]
    }
  }

  tags = local.tags
}


################################################################################
### IAM
################################################################################

# node용 IAM Role 추가
module "iam_assumable_role_custom" {
  source = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"

  trusted_role_services = [
    "ec2.amazonaws.com"
  ]

  create_role             = true
  role_name               = "${local.name}-eks-node-role"
  role_requires_mfa       = false
  custom_role_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
  ]

  tags = local.tags
}

module "key_pair" {
  source  = "terraform-aws-modules/key-pair/aws"
  version = "~> 2.0"
  key_name           = "${local.name}-ssh-keypair"
  create_private_key = true

  tags = local.tags
}

# resource "aws_security_group" "remote_access" {
#   name = "${local.name}-eks-remote_access-sg"
#   description = "Allow remote SSH access"
#   vpc_id      = local.vpc_id

#   ingress {
#     description = "SSH access"
#     from_port   = 22
#     to_port     = 22
#     protocol    = "tcp"
#     cidr_blocks = ["0.0.0.0/0"]
#   }
#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = "-1"
#     cidr_blocks = ["0.0.0.0/0"]
#   }

#   tags = local.tags
# }



################################################################################
### k8s Service Account
################################################################################
resource "kubernetes_service_account" "aws-load-balancer-controller" {
  metadata {
    name        = "aws-load-balancer-controller"
    namespace   = "kube-system"
    annotations = {
      "eks.amazonaws.com/role-arn" = module.load_balancer_controller_irsa_role.iam_role_arn  # irsa 생성 모듈에서 output으로 iam_role_arn을 제공한다.
    }

    labels = {
      "app.kubernetes.io/component" = "controller"
      "app.kubernetes.io/name" = "aws-load-balancer-controller"
    }

  }
  depends_on = [module.load_balancer_controller_irsa_role]
}

resource "kubernetes_service_account" "external-dns" {
  metadata {
    name        = "external-dns"
    namespace   = "kube-system"
    annotations = {
      "eks.amazonaws.com/role-arn" = module.external_dns_irsa_role.iam_role_arn
    }
  }
  depends_on = [module.external_dns_irsa_role]
}

################################################################################
### Helm
################################################################################
# https://github.com/GSA/terraform-kubernetes-aws-load-balancer-controller/blob/main/main.tf
# https://registry.terraform.io/providers/hashicorp/helm/latest/docs/resources/release
# https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.5/
resource "helm_release" "aws-load-balancer-controller" {
  name       = "aws-load-balancer-controller"
  namespace  = "kube-system"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"

  set {
    name = "clusterName"
    value = module.eks.cluster_name
  }
  set {
    name = "serviceAccount.create"
    value = false
  }
  set {
    name = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  ## no endpoints available for service "aws-load-balancer-webhook-service" 이슈 해결을 위한 옵션 추가
  set {
    name = "region"
    value = "ap-northeast-2"
  }
  set {
    name = "vpcid"
    value = local.vpc_id
  }  
}

# https://tech.polyconseil.fr/external-dns-helm-terraform.html
# parameter https://github.com/kubernetes-sigs/external-dns/tree/master/charts/external-dns
resource "helm_release" "external_dns" {
  name       = "external-dns"
  namespace  = "kube-system"
  repository = "https://charts.bitnami.com/bitnami"
  chart      = "external-dns"
  wait       = false  ## 서비스가 완전히 올라올때 까지 대기
  set {
    name = "provider"
    value = "aws"
  }
  set {
    name = "serviceAccount.create"
    value = false
  }
  set {
    name = "serviceAccount.name"
    value = "external-dns"
  }
  set {
    name  = "policy"
    value = "sync"
  }     
}
