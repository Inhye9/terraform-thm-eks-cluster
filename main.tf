terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
  }
}

provider "aws" {
  profile = "devops"
  region = "ap-northeast-2"
}

################################################################################
### Local Variable
################################################################################
locals {
  name              = "thm"
  region            = "ap-northeast-2"

  # vpc부터 자동 생성(vpc.tf)
   vpc_id            = module.vpc.vpc_id
   subnet_ids        = module.vpc.public_subnets

  # 기 생성된 vpc에 클러스터 생성 시 아래 사용
  #vpc_id            = "vpc-0ea3ad043f6e004f2"
  #subnet_ids        = ["subnet-01c0fc672eaf257dc", "subnet-0f793265ffeac0b8c", "subnet-0438504338da74082", "subnet-0c441face26a9764c", "subnet-07eaef7db4903ccae", "subnet-0ad869e732acab4ea"]

  #external_dns_arn  = "arn:aws:route53:::hostedzone/Z0519242ZREPXM4WQPAJ"  # ap-northeast-2 개인용 Route53 HostingZone 
  external_dns_arn  = "arn:aws:route53:::hostedzone/Z0171354247GPRHXLFIR8"  # ap-northeast-2 개인용 Route53 HostingZone 
  external_cert_arn = "arn:aws:acm:ap-northeast-2:719688951936:certificate/1d4ec646-4332-47e9-9b52-5a0b0bd36fae" # ap-northeast-2
  eks_oidc_provider     = module.eks.oidc_provider
  eks_oidc_provider_arn = module.eks.oidc_provider_arn
  tags = {
    CreatedBy = "Terraform"
  }
}

variable "lt_resource_tags" {  # LT 리소스 태깅을 위한 변수
  type    = set(string)
  default = ["instance", "volume", "spot-instances-request"]
}
