# terraform {
#   backend "s3" {
#     encrypt        = true
#     bucket         = "my-s3-bucket"
#     dynamodb_table = "my-dynamodb-table"
#     key            = "terraform/vpc/vpc.tfstate"
#     region         = "us-east-1"
#     profile        = "default"
#   }
# }