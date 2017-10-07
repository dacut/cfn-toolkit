#!/usr/bin/env python3
"""
CloudFormation Custom::S3BucketNotification resource.
"""
# pylint: disable=C0103
from logging import getLogger
from re import compile as re_compile
from typing import Any, Dict, List
import boto3

log = getLogger("cfntoolkit.s3")

def s3_bucket_notification(event: Dict[str, Any]) -> None:
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
        log.debug("Deleting bucket notifications for %s", bucket_name)
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
            "Events": validate_event("LambdaConfigurations", lc.get("Event")),
            "LambdaFunctionArn": validate_function_arn(lc.get("Function")),
        }

        lc_filter = lc.get("Filter")

        if lc_filter:
            boto_lc["Filter"] = validate_filter(
                "LambdaConfigurations", lc_filter)

        result.append(boto_lc)
    return result

TC_TYPE_MSG = "QueueConfigurations must be a list of mappings"
def get_boto_queue_configs(queue_configs: List[Dict[str, Any]]) \
    -> List[Dict[str, Any]]:
    """
    get_boto_queue_configs(queue_configs: List[Dict[str, Any]]) \
        -> List[Dict[str, Any]]
    Convert a CloudFormation QueueConfigurations shape into the corresponding
    Boto types, performing validation in the process.
    """
    result = []

    for qc in queue_configs:
        if not isinstance(qc, dict):
            raise TypeError(TC_TYPE_MSG)

        boto_qc = {
            "Events": validate_event("TopicConfigurations", qc.get("Event")),
            "QueueArn": validate_queue_arn(qc.get("Queue")),
        }

        qc_filter = qc.get("Filter")

        if qc_filter:
            boto_qc["Filter"] = validate_filter(
                "QueueConfigurations", qc_filter)

        result.append(boto_qc)
    return result

TC_TYPE_MSG = "TopicConfigurations must be a list of mappings"
def get_boto_topic_configs(topic_configs: List[Dict[str, Any]]) \
    -> List[Dict[str, Any]]:
    """
    get_boto_topic_configs(topic_configs: List[Dict[str, Any]]) \
        -> List[Dict[str, Any]]
    Convert a CloudFormation TopicConfigurations shape into the corresponding
    Boto types, performing validation in the process.
    """
    result = []

    for tc in topic_configs:
        if not isinstance(tc, dict):
            raise TypeError(TC_TYPE_MSG)

        boto_tc = {
            "Event": validate_event("TopicConfigurations", tc.get("Event")),
            "TopicArn": validate_topic_arn(tc.get("Topic")),
        }

        tc_filter = tc.get("Filter")

        if tc_filter:
            boto_tc["Filter"] = validate_filter(
                "TopicConfigurations", tc_filter)

        result.append(boto_tc)
    return result


EVENT_MISSING_MSG = "%s must contain an Event property"
EVENT_TYPE_MSG = """\
LambdaConfiguration Event must be a string or list of strings"""
def validate_event(parent: str, event: Any) -> List[str]:
    """
    validate_event(parent: str, event: Any) -> List[str]
    Ensure the Event field of a configuration shape is correct.
    """
    if not event:
        raise TypeError(EVENT_MISSING_MSG % parent)
    if isinstance(event, str):
        return [event]
    elif isinstance(event, list):
        for el in event:
            if not isinstance(el, str):
                raise TypeError(EVENT_TYPE_MSG)
        return event

    raise TypeError(EVENT_TYPE_MSG)

FILTER_MSG = """\
%s Filter must be a mapping of the form \
{"S3Key": {"Rules": [{"Name": String, "Value": String ...}]}}"""
FILTER_S3KEY_MSG = """\
%s Filter.S3Key must be a mapping of the form \
{"Rules": [{"Name": String, "Value": String ...}]}"""
FILTER_RULES_MSG = """\
%s Filter.S3Key.Rules must be a list of the form \
[{"Name": String, "Value": String ...}]"""
def validate_filter(parent: str, c_filter: Any) \
    -> Dict[str, List[Dict[str, str]]]:
    """
    validate_filter(parent: str, c_filter: Any)
        -> Dict[str, Dict[str, List[Dict[str, str]]]]
    Ensure the Filter field of a configuration shape is correct.
    """
    if not isinstance(c_filter, dict):
        raise TypeError(FILTER_MSG % parent)
    if len(filter) != 1 or "S3Key" not in c_filter:
        raise ValueError(FILTER_MSG % parent)

    s3_key = c_filter["S3Key"]
    if not isinstance(s3_key, dict):
        raise TypeError(FILTER_S3KEY_MSG % parent)
    if len(s3_key) != 1 or "Rules" not in s3_key:
        raise ValueError(FILTER_S3KEY_MSG % parent)

    rules = s3_key["Rules"]
    if not isinstance(rules, (list, tuple)):
        raise TypeError(FILTER_RULES_MSG % parent)

    for rule in rules:
        if not isinstance(rule, dict):
            raise TypeError(FILTER_RULES_MSG % parent)

        if len(rule) != 2 or "Name" not in rule or "Value" not in rule:
            raise ValueError(FILTER_RULES_MSG % parent)

    return {"Key": {"FilterRules": rules}}

LC_FUNCTION_MSG = """\
LambdaConfiguration Function must be a string in the form
"arn:aws.*:lambda:<region>:<account-id>:function:<name>"
"""
LAMBDA_FUNCTION_ARN_REGEX = re_compile(
    r"arn:aws[^:]*:lambda:[^:]+:[0-9]{12}:function:.*")
def validate_function_arn(function: Any) -> str:
    """
    validate_function_arn(function: Any) -> str
    Ensure the Function field of a LambdaConfiguration shape is a function ARN.
    """
    if not isinstance(function, str):
        raise TypeError(LC_FUNCTION_MSG)

    if not LAMBDA_FUNCTION_ARN_REGEX.match(function):
        raise ValueError(LC_FUNCTION_MSG)

    return function

QUEUE_ARN_MSG = """\
QueueConfiguration Queue must be a string in the form
"arn:aws.*:sqs:<region>:<account-id>:<queue>"
"""
QUEUE_ARN_REGEX = re_compile(
    r"arn:aws[^:]*:sqs:[^:]+:[0-9]{12}:.*")
def validate_queue_arn(queue_arn: Any) -> str:
    """
    validate_queue_arn(queue_arn: Any) -> str
    Ensure the Topic field of a TopicConfiguration shape is a function ARN.
    """
    if not isinstance(queue_arn, str):
        raise TypeError(QUEUE_ARN_MSG)

    if not QUEUE_ARN_REGEX.match(queue_arn):
        raise ValueError(QUEUE_ARN_MSG)

    return queue_arn

TOPIC_ARN_MSG = """\
TopicConfiguration Topic must be a string in the form
"arn:aws.*:sns:<region>:<account-id>:<topic>"
"""
TOPIC_ARN_REGEX = re_compile(
    r"arn:aws[^:]*:sns:[^:]+:[0-9]{12}:.*")
def validate_topic_arn(topic_arn: Any) -> str:
    """
    validate_topic_arn(topic_arn: Any) -> str
    Ensure the Topic field of a TopicConfiguration shape is a function ARN.
    """
    if not isinstance(topic_arn, str):
        raise TypeError(TOPIC_ARN_MSG)

    if not TOPIC_ARN_REGEX.match(topic_arn):
        raise ValueError(TOPIC_ARN_MSG)

    return topic_arn
