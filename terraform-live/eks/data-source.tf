data "aws_vpc" "selected" {
  filter {
    name   = "tag:Name"
    values = ["staging-main"]
  }
}

data "aws_subnets" "selected" {
  tags = {
    Name = "*private*"
  }
}