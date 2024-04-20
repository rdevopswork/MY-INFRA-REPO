## MY-INFRA-REPO

aws configure
aws eks update-kubeconfig --name dev-demo --region us-east-1

curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.22.17/2023-05-11/bin/linux/amd64/kubectl
chmod +x ./kubectl
mkdir -p $HOME/bin && cp ./kubectl $HOME/bin/kubectl && export PATH=$HOME/bin:$PATH
echo 'export PATH=$HOME/bin:$PATH' >> ~/.bashrc

./kubectl get nodes\
