# cfn-generator
This is a collection of custom CloudFormation resources intended to make it
easier for dynamic deployments.

# Setting up
Before using this, you will need to deploy this as a Lambda function in your
own template. (We don't provide a centralised source for this, and you should
not use one; you are opening your AWS account for potential abuse and misuse
by doing so.) For example:

    Resources:
      CFNGenerator:
        Type: AWS::Lambda::Function
        Properties:
          Code:
            S3Bucket: kanga-cfn
            S3Key: cfn-generator.zip
            S3ObjectVersion: 1
          Description: CloudFormation custom properties
          Handler: handler.lambda_handler
          MemorySize: 128
          Role: (IAM role in your account)
          Runtime: python3.6
          Timeout: 10

# Using custom resources provided by cfn-generator
To use a custom resource in your CloudFormation template, specify one of the
types given below and point `ServiceToken` at your Lambda function. For
example:

    Resources:
      AdminPasswordGen:
        Type: Custom::GeneratePassword
        Properties:
          ServiceToken: !GetAtt CFNGenerator.Arn

# Available resources

## Custom::GeneratePassword
Generate a password using passlib.
