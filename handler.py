#!/usr/bin/env python3
"""
This is a set of custom CloudFormation resources to help make deployments
easier.
"""
from base64 import b64decode, b64encode
from distutils.util import strtobool
from json import dumps as json_dumps
from logging import getLogger, DEBUG
from os import environ
from uuid import uuid4

import boto3
from passlib.hash import pbkdf2_sha256
from passlib.pwd import genphrase
import requests
from .hashparams import HashAlgorithm

log = getLogger()
log.setLevel(DEBUG)

def lambda_handler(event, context):
    global handlers

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
            if "PhysicalResourceId" in data:
                body["PhysicalResourceId"] = data.pop("PhysicalResourceId")
            body["Status"] = "SUCCESS"
            del body["Reason"]
            body["Data"] = data
        except Exception as e:
            body["Reason"] = str(e)

    if "PhysicalResourceId" not in body:
        body["PhysicalResourceId"] = str(uuid4())

    log.debug("body=%s", body)
    body = json_dumps(body)
    headers = {
        "Content-Type": "",
        "Content-Length": str(len(body)),
    }
    r = requests.put(event["ResponseURL"], headers=headers, data=body)
    print("Result: %d %s" % (r.status_code, r.reason))
    return


def api_gateway_binary(event):
    """
    Custom::ApiGatewayBinary resource

    This enables binary support on an API Gateway REST API.

    Usage:
    Resources:
      RestApi:
        Type: AWS::
    """
    if event["RequestType"] not in ("Create", "Update"):
        return

    apigw = boto3.client("apigateway")
    rest_api_id = event["ResourceProperties"]["RestApiId"]

    # Do we already have binary support enabled?
    rest_api_info = apigw.get_rest_api(restApiId=rest_api_id)

    if ("binaryMediaTypes" not in rest_api_info or
        "*/*" not in rest_api_info["binaryMediaTypes"]):
        apigw.update_rest_api(restApiId=rest_api_id, patchOperations=[
            {"op": "add", "path": "/binaryMediaTypes/*~1*"}
        ])

    return


def generate_password(event):
    if event["RequestType"] not in ("Create", "Update"):
        return

    parameter_name = event["ResourceProperties"]["ParameterName"]

    ddb_table_prefix = environ.get("DYNAMODB_TABLE_PREFIX", "Rolemaker.")
    ddb = boto3.resource("dynamodb")
    ddb_parameters = ddb.Table(ddb_table_prefix + "Parameters")

    password = genphrase(entropy="secure", wordset="bip39")

    # Write this to DynamoDB, hashed.
    hashed_password = pbkdf2_sha256.hash(password)

    ddb_parameters.update_item(
        Key={"Name": parameter_name},
        UpdateExpression="SET #V = :hash",
        ExpressionAttributeNames={"#V": "Value"},
        ExpressionAttributeValues={":hash": hashed_password}
    )
    return {"Password": password}


def hash_password(event):
    if event["RequestType"] not in ("Create", "Update"):
        return

    rp = dict(event["ResourceProperties"])

    allow_insecure = rp.pop("AllowInsecure", False)
    if isinstance(allow_insecure, str):
        allow_insecure = strtobool(allow_insecure)
    elif isinstance(allow_insecure, (list, tuple, dict)):
        raise TypeError("AllowInsecure must be true or false")
    else:
        allow_insecure = bool(allow_insecure)

    ciphertext_b64_password = rp.pop("CiphertextBase64Password", None)
    encryption_context = rp.pop("EncryptionContext", None)
    plaintext_password = rp.pop("PlaintextPassword", None)
    scheme = rp.pop("Scheme", None)

    if plaintext_password is None:
        if ciphertext_b64_password is None:
            raise ValueError(
                "Either PlaintextPassword or CiphertextBase64Password must be "
                "specified")

        if not isinstance(ciphertext_b64_password, str):
            raise TypeError(
                "CiphertextBase64Password must be a string")

        if encryption_context is None:
            encryption_context = {}
        elif not isinstance(encryption_context, dict):
            raise TypeError("EncryptionContext must be a mapping")

        try:
            ciphertext = b64decode(ciphertext_b64_password)
        except ValueError:
            raise ValueError(
                "Invalid base64 encoding in CiphertextBase64Password")

        try:
            result = boto3.client("kms").decrypt(
                CiphertextBlob=ciphertext,
                EncryptionContext=encryption_context
        except Exception as e:
            raise ValueError(
                "Unable to decrypt CiphertextBase64Password")

        plaintext_password = result["Plaintext"]
    else:
        if ciphertext_b64_password:
            raise ValueError(
                "PlaintextPassword and CiphertextBase64Password are mutually "
                "exclusive")

        if not isinstance(plaintext_password, str):
            raise TypeError("PlaintextPassword must be a string")

    if scheme is None:
        raise ValueError("Scheme must be specified")
    elif not isinstance(scheme, str):
        raise TypeError("Scheme must be a string")
    elif not scheme:
        raise ValueError("Scheme cannot be empty")

    if scheme not in HashAlgorithm.algorithms:
        raise ValueError("Unknown scheme %r" % scheme)

    algorithm = scheme.algorithms[scheme]

def secure_random(event):
    if event["RequestType"] not in ("Create", "Update"):
        return

    size = event["ResourceProperties"]["Size"]
    try:
        size = int(size)
        if size <= 0:
            raise ValueError()
    except ValueError:
        raise ValueError("Invalid size parameter: %r" % (size,))

    result = b64encode(urandom(size))
    return {"Base64": result}


handlers = {
    "Custom::ApiGatewayBinary": api_gateway_binary,
    "Custom::FindAMI": find_ami,
    "Custom::DynamoDB::Item": dynamodb_item,
    "Custom::GeneratePassword": generate_password,
    "Custom::HashPassword": hash_password,
    "Custom::SecureRandom": secure_random,
}
