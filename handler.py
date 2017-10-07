#!/usr/bin/env python3
"""
This is a set of custom CloudFormation resources to help make deployments
easier.
"""
# pylint: disable=C0103
from json import dumps as json_dumps
from logging import getLogger, DEBUG
from typing import Any, Dict
from uuid import uuid4

from cfntoolkit import apigateway, crypto, ec2, s3
import requests

log = getLogger()
log.setLevel(DEBUG)

def listify(value: Any):
    """
    Encapsulate value in a list if it isn't already.
    """
    if isinstance(value, list):
        return value

    return [value]

def lambda_handler(event: Dict[str, Any], _) -> None:
    """
    Main entrypoint for the Lambda function.
    """
    log.debug("event=%s", event)

    body = {
        "Status": "FAILED",
        "Reason": "Unknown error",
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
    }

    if "PhysicalResourceId" in event:
        body["PhysicalResourceId"] = event["PhysicalResourceId"]

    handler = handlers.get(event["ResourceType"])
    if handler is None:
        body["Reason"] = "Unknown resource type %s" % event["ResourceType"]
    else:
        try:
            data = handler(event)
            if data is None:
                data = {}
            if "PhysicalResourceId" in data: # pragma: nocover
                body["PhysicalResourceId"] = data.pop("PhysicalResourceId")
            body["Status"] = "SUCCESS"
            del body["Reason"]
            body["Data"] = data
        except Exception as e:              # pylint: disable=W0703
            log.error("Failed", exc_info=True)
            body["Reason"] = str(e)

    if "PhysicalResourceId" not in body:
        body["PhysicalResourceId"] = str(uuid4())

    log.debug("body=%s", body)
    body_str = json_dumps(body).encode("utf-8")
    headers = {
        "Content-Type": "",
        "Content-Length": str(len(body_str)),
    }
    r = requests.put(event["ResponseURL"], headers=headers, data=body_str)
    print("Result: %d %s" % (r.status_code, r.reason))
    return


handlers = {
    "Custom::ApiGatewayBinary": apigateway.api_gateway_binary,
    "Custom::FindImage": ec2.find_image,
    # "Custom::DynamoDB::Item": dynamodb_item,
    "Custom::GeneratePassword": crypto.generate_password,
    "Custom::HashPassword": crypto.hash_password,
    "Custom::S3BucketNotification": s3.s3_bucket_notification,
    "Custom::SecureRandom": crypto.secure_random,
}
