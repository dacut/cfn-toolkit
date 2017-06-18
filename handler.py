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
import re
from uuid import uuid4

import boto3
from passlib.pwd import genphrase, genword
from iso8601 import parse_date
import requests
from hashparams import HashAlgorithm

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
        Type: AWS::Gateway::RestApi
      EnableBinary:
        Type: Custom::APIGatewayBinary
        Properties:
          RestApiId: !Ref RestApi
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


def find_image(event):
    """
    Custom::FindImage resource

    This locates the latest version of an AMI/AKI/ARI.

    Usage:
    Resources:
      OS:
        Type: Custom::FindAMI
        Properties:
          Architecture: i386|x86_64
          EnaSupport: true|false
          ExcludedDescriptions: list of regular expressions to test against the
            description field; matching AMIs are excluded.
          IncludedDescriptions: list of regular expressions to test against the
            description field; non-matching AMIs are excluded.
          InstanceType: Restricts AMIs to those capable of running on the given
            instance type.
          Owner: The owner of the AMI to return. Either a 12-digit AWS account number,
            "amazon", "aws-marketplace", "microsoft", or "self".
          Platform: Either "windows" or not specified.
          PreferredRootDeviceType: If specified, prefers (but does not require) images
            using the specified root device type, either "ebs" or "instance-store".
          PreferredVirtualizationType: If specified, prefers (but does not require)
            images using the specified virtualization type, either "hvm" or
            "paravirtual".
          RootDeviceType: If specified, filters images to the specified root device
            type, either "ebs" or "instance-store".
          VirtualizationType: If specified, filters images to the specified
            virtualization type, either "hvm" or "paravirtual".
      Instance:
        Type: AWS::EC2::Instance
        Properties:
          ImageId: !GetAtt OS.AmiId
    """
    if event["RequestType"] not in ("Create", "Update"):
        return

    rp = dict(event["ResourceProperties"])
    filters = []

    try:
        owner = rp["Owner"]
    except KeyError:
        raise ValueError("Owner must be specified")


    architecture = rp.get("Architecture")
    if architecture is not None:
        filters.append[{"Name": "architecture", "Values": [architecture]}]

    ena_support = rp.get("EnaSupport")
    if ena_support is not None:
        filters.append({"Name": "ena-support", "Values": [ena_support]})

    platform = rp.get("Platform")
    if platform is not None:
        filters.append({"Name": "platform", "Values": [platform]})

    instance_type = rp.get("InstanceType")
    if instance_type is not None:
        if "." in instance_type:
            instance_family = instance_type[:instance_type.find(".")]
        else:
            instance_family = instance_type

        if instance_family in {"c3", "hi1", "hs1", "m3"}:
            # Switch hitting instance types; don't set virtualization type
            pass
        elif instance_family in {"c1", "m1", "m2", "t1"}:
            # PV-only instance types
            if ("VirtualizationType" in rp and
                rp.pop("VirtualizationType") != "paravirtual"):
                raise ValueError(
                    "VirtualizationType must be paravritual for %s instance types" %
                    instance_type)
            filters.append({"Name": "virtualization-type",
                            "Values": ["paravirtual"]})
        else:
            if ("VirtualizationType" in rp and
                rp.pop("VirtualizationType") != "hvm"):
                raise ValueError(
                    "VirtualizationType must be hvm for %s instance types" %
                    instance_type)
            filters.append({"Name": "virtualization-type",
                            "Values": ["hvm"]})

        if instance_family in {"c4", "m4", "p2", "r4", "t1", "t2"}:
            # EBS-only root volume types.
            if ("RootDeviceType" in rp and
                rp.pop("RootDeviceType") != "ebs"):
                raise ValueError(
                    "RootDeviceType must be ebs for %s instance types" %
                    instance_type)
            filters.append({"Name": "root-device-type",
                            "Values": ["ebs"]})

    root_device_type = rp.get("RootDeviceType")
    if root_device_type is not None:
        filters.append({"Name": "root-device-type", "Values": [root_device_type]})

    virtualization_type = rp.get("VirtualizationType")
    if virtualization_type is not None:
        filters.append({"Name": "virtualization-type",
                        "Values": [virtualization_type]})

    excluded_descriptions = rp.get("ExcludedDescriptions")
    excluded_names = rp.get("ExcludedNames")
    included_descriptions = rp.get("IncludedDescriptions")
    included_names = rp.get("IncludedNames")

    if isinstance(excluded_descriptions, str):
        excluded_descriptions = [excluded_descriptions]

    if isinstance(excluded_names, str):
        excluded_names = [excluded_names]

    if isinstance(included_descriptions, str):
        included_descriptions = [included_descriptions]

    if isinstance(included_names, str):
        included_names = [included_names]

    ec2 = boto3.client("ec2")
    result = ec2.describe_images(Owners=[owner], Filters=filters)
    images = result.get("Images")

    if not images:
        raise ValueError("No AMIs found that match the filters applied.")

    if excluded_descriptions is not None:
        regex = re.compile(
            "|".join(["(?:%s)" % desc for desc in excluded_descriptions]))

        images = [im for im in images if not regex.search(im["Description"])]

    if not images:
        raise ValueError("No AMIs found; all AMIs matched ExcludedDescriptions")

    if excluded_names is not None:
        regex = re.compile(
            "|".join(["(?:%s)" % desc for desc in excluded_names]))

        images = [im for im in images if not regex.search(im["Name"])]

    if not images:
        raise ValueError("No AMIs found; all AMIs matched ExcludedNames")

    if included_descriptions is not None:
        regex = re.compile(
            "|".join(["(?:%s)" % desc for desc in excluded_descriptions]))

        images = [im for im in images if regex.search(im["Description"])]

    if not images:
        raise ValueError("No AMIs found; no AMIs matched IncludedDescriptions")

    if included_names is not None:
        regex = re.compile(
            "|".join(["(?:%s)" % desc for desc in excluded_names]))

        images = [im for im in images if regex.search(im["Name"])]

    if not images:
        raise ValueError("No AMIs found; no AMIs matched IncludedNames")

    preferred_virtualization_type = rp.get("PreferredVirtualizationType")
    preferred_root_device_type = rp.get("PreferredRootDeviceType")

    def sort_key(image):
        date = parse_date(image["CreationDate"])
        is_preferred_virtualization_type = (
            preferred_virtualization_type is None or
            image["VirtualizationType"] == preferred_virtualization_Type)
        is_preferred_root_device_type = (
            preferred_root_device_type is None or
            image["RootDeviceType"] == preferred_root_device_type)

        return (is_preferred_virtualization_type,
                is_preferred_root_device_type,
                date)

    images.sort(key=sort_key, reverse=True)
    image_ids = [image["ImageId"] for image in images]
    return {
        "ImageId": images_ids[0],
        "MatchingImageIds": image_ids,
    }


def generate_password(event):
    if event["RequestType"] not in ("Create", "Update"):
        return

    rp = dict(event["ResourceProperties"])

    password_type = rp.get("PasswordType", "word")
    kw = {}

    if password_type == "phrase":
        generator = genphrase

        if "Chars" in rp:
            raise ValueError(
                'Chars cannot be specified when PasswordType is "phrase"')

        if "Charset" in rp:
            raise ValueError(
                'Charset cannot be specified when PasswordType is "phrase"')

        if "Wordset" in rp:
            if "Words" in rp:
                raise ValueError(
                    'Words and Wordset are mutually exclusive')
            kw["wordset"] = rp["Wordset"]
        elif "Words" in rp:
            kw["words"] = rp["Words"]

        if "Separator" in rp:
            kw["separator"] = rp["Separator"]
    elif password_type == "word":
        generator = genword

        if "Words" in rp:
            raise ValueError(
                'Words cannot be specified when PasswordType is "word"')

        if "Wordset" in rp:
            raise ValueError(
                'Wordset cannot be specified when PasswordType is "word"')

        if "Charset" in rp:
            if "Chars" in rp:
                raise ValueError(
                    'Chars and Charset are mutually exclusive')
            kw["charset"] = rp["Charset"]
        elif "Chars" in rp:
            kw["chars"] = rp["Chars"]

        if "Separator" in rp:
            raise ValueError(
                'Separator cannot be specified when PasswordType is "word"')
    else:
        raise ValueError(
            'PasswordType must be "word" or "phrase": %r' % password_type)

    entropy = rp.get("Entropy")
    if entropy is not None:
        if not isinstance(entropy, int):
            raise ValueError('Entropy must be an integer: %r' % entropy)
        kw["entropy"] = entropy

    password = generator(**kw)

    encryption_key = rp.get("EncryptionKey")
    if encryption_key is not None:
        encryption_context = rp.get("EncryptionContext", {})

        kms = boto3.client("kms")
        result = kms.encrypt(
            KeyId=encryption_key, EncryptionContext=encryption_context,
            Plaintext=password.encode("utf-8"))

        blob = result["CiphertextBlob"]
        return {"CiphertextBase64Password": b64encode(blob).decode("utf-8")}
    else:
        return {"PlaintextPassword": password}


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

    # Make sure we have exactly one of plaintext_password or ciphertext_b64_password
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
                EncryptionContext=encryption_context)
        except Exception:
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

    # Make sure Scheme was specified and is valid.
    if scheme is None:
        raise ValueError("Scheme must be specified")
    elif not isinstance(scheme, str):
        raise TypeError("Scheme must be a string")
    elif not scheme:
        raise ValueError("Scheme cannot be empty")

    if scheme.replace("-", "_") not in HashAlgorithm.algorithms:
        raise ValueError("Unknown scheme %r" % scheme)

    algorithm = HashAlgorithm.algorithms[scheme.replace("-", "_")]

    # Don't allow insecure algorithms if AllowInsecure wasn't specified.
    if not algorithm.is_secure and not allow_insecure:
        raise ValueError(
            "Scheme %s is insecure and AllowInsecure was not specified" % scheme)

    # Parse algorithm-specific parameters
    builder = algorithm.algorithm
    builder_kw = {}

    for parameter_name, parameter in algorithm.parameters.items():
        if parameter_name not in rp:
            continue

        parameter_value = rp.pop(parameter_name)
        try:
            parameter_value = parameter.type(parameter_value)
        except (TypeError, ValueError):
            raise ValueError("Invalid value for parameter %s: %r" %
                (parameter_name, parameter_value))

        if parameter.validator is not None:
            parameter.validator(parameter_value)

        if (parameter.min_length is not None and
            len(parameter_value) < parameter.min_length):
            raise ValueError("Length of parameter %s cannot be less than %s: %r" %
                (parameter_name, parameter.min_length, parameter_value))

        if (parameter.max_length is not None and
            len(parameter_value) > parameter.max_length):
            raise ValueError("Length of parameter %s cannot be greater than %s: %r" %
                (parameter_name, parameter.max_length, parameter_value))

        if (parameter.min_value is not None and
            parameter_value < parameter.min_value):
            raise ValueError("Value of parameter %s cannot be less than %s: %r" %
                (parameter_name, parameter.min_value, parameter_value))

        if (parameter.max_value is not None and
            parameter_value > parameter.max_value):
            raise ValueError("Value of parameter %s cannot be greater than %s: %r" %
                (parameter_name, parameter.max_value, parameter_value))

        builder_kw[parameter.algorithm_parameter] = parameter_value

    if rp:
        raise ValueError("Unknown parameters: %s" %
                         ", ".join(sorted(rp.keys())))

    builder = builder.using(**builder_kw)
    result = builder.hash(plaintext_password)

    return {"Hash": result}

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
    "Custom::FindImage": find_image,
    # "Custom::DynamoDB::Item": dynamodb_item,
    "Custom::GeneratePassword": generate_password,
    "Custom::HashPassword": hash_password,
    "Custom::SecureRandom": secure_random,
}
