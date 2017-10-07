#!/usr/bin/env python3
"""
CloudFormation Custom::APIGatewayBinary resource handler.
"""
from typing import Any, Dict
import boto3

def api_gateway_binary(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Custom::ApiGatewayBinary resource
    Enable binary support on an API Gateway REST API.
    """
    apigw = boto3.client("apigateway")
    request_type = event["RequestType"]
    rest_api_id = event["ResourceProperties"]["RestApiId"]

    # Do we already have binary support enabled?
    rest_api_info = apigw.get_rest_api(restApiId=rest_api_id)
    binary_enabled = ("binaryMediaTypes" in rest_api_info and
                      "*/*" in rest_api_info["binaryMediaTypes"])

    if request_type in ("Create", "Update"):
        if not binary_enabled:
            apigw.update_rest_api(restApiId=rest_api_id, patchOperations=[
                {"op": "add", "path": "/binaryMediaTypes/*~1*"}
            ])
    elif request_type == "Delete":
        if binary_enabled:
            apigw.update_rest_api(restApiId=rest_api_id, patchOperations=[
                {"op": "remove", "path": "/binaryMediaTypes/*~1*"}
            ])

    return {}
