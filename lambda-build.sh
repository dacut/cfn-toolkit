#!/bin/bash -ex
docker build -t cfn-toolkit .
docker run --rm cfn-toolkit cat /lambda.zip > lambda.zip

for region in $(aws --output text ec2 describe-regions | awk '{print $3}'); do
  aws --profile iono --region $region s3 cp lambda.zip \
    s3://ionosphere-cfn-${region}/ionosphere-cfn-toolkit.zip --acl public-read
done
