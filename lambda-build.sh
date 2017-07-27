#!/bin/bash -ex
if [[ ! -d lambda-build-venv ]]; then
  virtualenv --python python3.6 lambda-build-venv
fi;

source lambda-build-venv/bin/activate

rm -f lambda.zip
pip install -r requirements.txt
python -m py_compile handler.py hashparams.py

rm -f lambda.zip
zip -r lambda.zip handler.py hashparams.py __pycache__
cd lambda-build-venv/lib/python3.6/site-packages
zip -r ../../../../lambda.zip . --exclude "*.dist-info/*" "*.so" "*.dylib" \
  "boto3/*" "botocore/*" "coverage/*" "docutils/*" "markupsafe/*" "mock/*" \
  "moto/*" "nose/*" "pbr/*" "pip/*" "setuptools/*" "wheel/*"
cd ../../../..

for region in $(aws --output text ec2 describe-regions | awk '{print $3}'); do
  if [[ "$region" = "eu-west-1" || "$region" = "sa-east-1" || "$region" = "ap-northeast-1" || "$region" = "ap-southeast-1" ]]; then
    continue;
  fi;

  aws --profile iono --region $region s3 cp lambda.zip \
    s3://ionosphere-cfn-${region}/ionosphere-cfn-utils.zip --acl public-read
done;
