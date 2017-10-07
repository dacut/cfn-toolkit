#!/usr/bin/env python3.6
"""
Test Custom::S3BucketNotification resource.
"""
# pylint: disable=C0103
from logging import getLogger
from unittest import skip
import boto3
import cfntoolkit.s3
from moto import mock_s3
from .base import CFNToolkitTestBase

log = getLogger("tests.test_s3")

class TestS3(CFNToolkitTestBase):
    """
    Test Custom::S3BucketNotification resource.
    """
    def test_function_regex(self):
        """
        Test the Lambda function regular expression matcher.
        """
        cfntoolkit.s3.validate_function_arn(
            "arn:aws:lambda:us-west-2:021973571807:function:CopyLambdaRuntime")
        try:
            cfntoolkit.s3.validate_function_arn("")
            self.fail("Expected ValueError")
        except ValueError:
            pass

    @skip("mock_s3 breaks the response handler -- https://github.com/spulec/moto/issues/1026")
    def test_setup_lambda_notifications(self):
        """
        Create a notification.
        """
        with mock_s3():
            s3 = boto3.client("s3")
            s3.create_bucket(Bucket="test")
            try:
                self.invoke(
                    ResourceType="Custom::S3BucketNotification",
                    BucketName="test",
                    NotificationConfiguration={
                        "LambdaConfigurations": [{
                            "Event": ["s3:ObjectCreated:*"],
                            "Function": "arn:aws:lambda:us-west-2:123456789012:function:Foo",
                        }]
                    })
            finally:
                s3.delete_bucket(Bucket="test")
