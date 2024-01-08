# ###############################################################################
# ## VPC
# ###############################################################################
 module "vpc" {
   source = "terraform-aws-modules/vpc/aws"

   name = "${local.name}-vpc"
   cidr = "192.168.0.0/16"

   azs                 = ["${local.region}a", "${local.region}c"]
   public_subnets      = ["192.168.0.0/20", "192.168.16.0/20"]
   public_subnet_names = ["${local.name}-pub-a-sn", "${local.name}-pub-c-sn"]
  
   public_subnet_tags       = {"kubernetes.io/role/elb" = 1}
   public_route_table_tags  = {"Name" = "${local.name}-vpc-public-rt"}
   default_route_table_tags = {"Name" = "${local.name}-vpc-default-rt"}
   igw_tags                 = {"Name" = "${local.name}-vpc-public-igw"}
  
   enable_nat_gateway       = false
   enable_dns_hostnames     = true
   enable_dns_support       = true
   map_public_ip_on_launch  = true

   tags = local.tags
 }

