#!/usr/bin/env python3
"""
CloudFormation Custom::S3BucketNotification resource.
"""
# pylint: disable=C0103
from re import compile as re_compile
from typing import Any, Dict, List
import boto3

def s3_bucket_notification(event):
    """
    Custom::S3BucketNotification
    Add or remove bucket notification events. This allows you to avoid a
    circular dependency problem with CloudFormation.
    """
    request_type = event["RequestType"]
    bucket_name = event["ResourceProperties"].get("BucketName")
    nc = event["ResourceProperties"].get("NotificationConfiguration")

    if not isinstance(bucket_name, str):
        raise TypeError("BucketName must be a string")

    s3 = boto3.client("s3")
    if request_type == "Delete":
        s3.put_bucket_notification_configuration(
            Bucket=bucket_name, NotificationConfiguration={})
        return

    if not isinstance(nc, dict):
        raise TypeError("NotificationConfiguration must be a mapping")

    boto_nc = {
        "TopicConfigurations": get_boto_topic_configs(
            nc.get("TopicConfigurations", [])),
        "QueueConfigurations": get_boto_queue_configs(
            nc.get("QueueConfigurations", [])),
        "LambdaFunctionConfigurations": get_boto_lambda_configs(
            nc.get("LambdaConfigurations", [])),
    }
    s3.put_bucket_notification_configuration(
        Bucket=bucket_name, NotificationConfiguration=boto_nc)
    return

LC_TYPE_MSG = "LambdaConfigurations must be a list of mappings"
def get_boto_lambda_configs(lambda_configs: List[Dict[str, Any]]) \
    -> List[Dict[str, Any]]:
    """
    get_boto_lambda_configs(lambda_configs: List[Dict[str, Any]]) \
        -> List[Dict[str, Any]]
    Convert a CloudFormation LambdaConfigurations shape into the corresponding
    Boto types, performing validation in the process.
    """
    result = []

    for lc in lambda_configs:
        if not isinstance(lc, dict):
            raise TypeError(LC_TYPE_MSG)

        boto_lc = {
            "Event": validate_lambda_config_event(lc.get("Event")),
            "Function": validate_lambda_config_function(lc.get("Function")),
        }

        lc_filter = lc.get("Filter")

        if lc_filter:
            boto_lc["Filter"] = validate_lambda_config_filter(lc_filter)

        result.append(boto_lc)
    return result

LC_EVENT_MISSING_MSG = "LambdaConfiguration must contain an Event property"
LC_EVENT_TYPE_MSG = """\
LambdaConfiguration Event must be a string or list of strings"""
def validate_lambda_config_event(event: Any) -> List[str]:
    """
    validate_lambda_config_event(event: Any) -> List[str]
    Ensure the Event field of a LambdaConfiguration shape is correct.
    """
    if not event:
        raise TypeError(LC_EVENT_MISSING_MSG)
    if isinstance(event, str):
        return [event]
    elif isinstance(event, list):
        for el in event:
            if not isinstance(el, str):
                raise TypeError(LC_EVENT_TYPE_MSG)
        return event

    raise TypeError(LC_EVENT_TYPE_MSG)

LC_FUNCTION_MSG = """\
LambdaConfiguration Function must be a string in the form
"arn:aws.*:lambda:<region>:<account-id>:function:<name>"
"""
LAMBDA_FUNCTION_ARN_REGEX = re_compile(
    r"arn:aws[^:]*:lambda:[^:]+:[0-9]{12}:function:.*")
def validate_lambda_config_function(function: Any) -> str:
    """
    validate_lambda_config_function(function: Any) -> str
    Ensure the Function field of a LambdaConfiguration shape is a function ARN.
    """
    if not isinstance(function, str):
        raise TypeError(LC_FUNCTION_MSG)

    if not LAMBDA_FUNCTION_ARN_REGEX.match(function):
        raise ValueError(LC_FUNCTION_MSG)

    return function

LC_FILTER_MSG = """\
LambdaConfiguration filter must be a mapping of the form \
{"S3Key": {"Rules": [{"Name": String, "Value": String ...}]}}"""
LC_FILTER_S3KEY_MSG = """\
LambdaConfiguration S3Key must be a mapping of the form \
{"Rules": [{"Name": String, "Value": String ...}]}"""
LC_FILTER_RULES_MSG = """\
LambdaConfiguration Rules must be a list of the form \
[{"Name": String, "Value": String ...}]"""
def validate_lambda_config_filter(lc_filter: Any) \
    -> Dict[str, List[Dict[str, str]]]:
    """
    validate_lambda_config_filter(filter: Any)
        -> Dict[str, Dict[str, List[Dict[str, str]]]]
    Ensure the Filter field of a LambdaConfiguration shape is correct.
    """
    if not isinstance(lc_filter, dict):
        raise TypeError(LC_FILTER_MSG)
    if len(filter) != 1 or "S3Key" not in lc_filter:
        raise ValueError(LC_FILTER_MSG)

    s3_key = lc_filter["S3Key"]
    if not isinstance(s3_key, dict):
        raise TypeError(LC_FILTER_S3KEY_MSG)
    if len(s3_key) != 1 or "Rules" not in s3_key:
        raise ValueError(LC_FILTER_S3KEY_MSG)

    rules = s3_key["Rules"]
    if not isinstance(rules, (list, tuple)):
        raise TypeError(LC_FILTER_RULES_MSG)

    for rule in rules:
        if not isinstance(rule, dict):
            raise TypeError(LC_FILTER_RULES_MSG)

        if len(rule) != 2 or "Name" not in rule or "Value" not in rule:
            raise ValueError(LC_FILTER_RULES_MSG)

    return {"Key": {"FilterRules": rules}}
