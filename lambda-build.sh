#!/bin/bash -ex
docker build -t cfn-toolkit .
docker run --rm cfn-toolkit cat /lambda.zip > lambda.zip
