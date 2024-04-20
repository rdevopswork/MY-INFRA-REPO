

# module "eks" {
#   source = "../../infrastructure-modules/eks"

#   env = "dev"
#   eks_version = "1.27"
#   eks_name    = "demo"
#   subnet_ids = data.aws_subnets.selected.ids
    
#   node_groups = {
#     general = {
#       capacity_type  = "ON_DEMAND"
#       instance_types = ["t3.medium"]
#       scaling_config = {
#         desired_size = 1
#         max_size     = 10
#         min_size     = 0
#       }
#     }
#   }
  

# }

module "eks" {
  source  = "../../infrastructure-modules/terraform-aws-eks"


  cluster_name    = "dev-demo"
  cluster_version = "1.27"

  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = true

  vpc_id     = data.aws_vpc.selected.id
  subnet_ids = data.aws_subnets.selected.ids

  enable_irsa = true

  # eks_managed_node_group_defaults = {
  #   disk_size = 30
  # }

  eks_managed_node_groups = {
    general = {
      desired_size = 2
      min_size     = 1
      max_size     = 10

      labels = {
        role = "general"
      }

      instance_types = ["t3.medium"]
      capacity_type  = "ON_DEMAND"
    }

    # spot = {
    #   desired_size = 1
    #   min_size     = 1
    #   max_size     = 10

    #   labels = {
    #     role = "spot"
    #   }

    #   taints = [{
    #     key    = "market"
    #     value  = "spot"
    #     effect = "NO_SCHEDULE"
    #   }]

    #   instance_types = ["t3.micro"]
    #   capacity_type  = "SPOT"
    # }
  }

  tags = {
    Environment = "staging"
  }
}
