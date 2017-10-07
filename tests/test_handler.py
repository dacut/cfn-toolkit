#!/usr/bin/env python3.6
"""
Test the Lambda handler.
"""
# pylint: disable=C0103,C0111,R0904
from unittest import skip
import boto3
from moto import mock_apigateway
from .base import CFNToolkitTestBase

class TestHandler(CFNToolkitTestBase):
    """
    Test the Lambda handler functionality.
    """
    def test_unknown_type(self):
        result = self.invoke(ResourceType="Custom::Unknown")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"], "Unknown resource type Custom::Unknown")

    @skip("Moto doesn't support update_rest_api yet")
    def test_apigw_binary(self):
        with mock_apigateway():
            apigw = boto3.client("apigateway")
            result = apigw.create_rest_api(name="test")
            rest_api_id = result["id"]

            result = self.invoke(
                ResourceType="Custom::ApiGatewayBinary",
                RestApiId=rest_api_id)

            self.assertEqual(result["Status"], "SUCCESS")

            result = apigw.get_rest_api(restApiId=rest_api_id)
            self.assertIn("*/*", result["binaryMediaTypes"])
