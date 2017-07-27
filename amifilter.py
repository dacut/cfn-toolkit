#!/usr/bin/env python3
"""
Provide filters for the Custom::FindImage resource.
"""
# pylint: disable=C0103
import re
from typing import Any, Dict, List

# EC2 instance families that only support paravirtualization.
PV_ONLY_INSTANCE_FAMILIES = {"c1", "m1", "m2", "t1",}

# EC2 instance families that support either paravirtualization or HVM.
PV_HVM_INSTANCE_FAMILIES = {"c3", "hi1", "hs1", "m3",}

# EC2 instance families that have instance storage.
INSTANCE_STORE_FAMILIES = {
    "c1", "c3", "cc2", "cg1", "cr1", "d2", "g2", "f1", "hi1", "hs1", "i2",
    "i3", "m1", "m2", "m3", "r3", "x1",
}


# These request properties are embedded in the filter directly (though
# renamed), with the value encapsulated as a list.
DIRECT_FILTERS = {
    "Architecture": "architecture",
    "EnaSupport": "ena-support",
    "Platform": "platform",
    "RootDeviceType": "root-device-type",
    "VirtualizationType": "virtualization-type",
}


def add_filters(
        request_properties: Dict[str, Any],
        filters: Dict[str, List]) -> None:
    """
    add_filters(request_properties: Dict[Str, Any],
        filters: Dict[str, Any]) -> None:
    Examine request_properties for appropriate values and apply them to the
    filters list.
    """
    for key in DIRECT_FILTERS:
        if key in request_properties:
            value = request_properties.pop(key)
            filter_key = DIRECT_FILTERS.get(key)
            filters[filter_key] = listify(value)

    add_instance_type_filter(request_properties, filters)

    return

def add_instance_type_filter(
        request_properties: Dict[str, Any], filters: Dict[str, List]) -> None:
    """
    add_instance_type_filter(
        request_properties: Dict[str, Any], filters: List) -> None
    Examine request_properties for an instance_type filter
    """
    instance_type = request_properties.pop("InstanceType", None)
    if instance_type is None:
        return

    if "." in instance_type:
        instance_family = instance_type[:instance_type.find(".")]
    else:
        instance_family = instance_type

    if instance_family in PV_ONLY_INSTANCE_FAMILIES:
        # PV-only instance types
        if (filters.get("virutalization-type", ["paravirtual"]) !=
                ["paravirtual"]):
            raise ValueError(
                "VirtualizationType must be paravirtual for %s instance "
                "types" % (instance_type,))

        filters["virtualization-type"] = ["paravirtual"]
    # Ignore Switch hitting instance types (c3, etc.); assume all newer
    # instance families are HVM-only.
    elif instance_family not in PV_HVM_INSTANCE_FAMILIES:
        if filters.get("virtualization-type", ["hvm"]) != ["hvm"]:
            raise ValueError(
                "VirtualizationType must be hvm for %s instance types" %
                (instance_type,))
        filters["virtualization-type"] = ["hvm"]

    if instance_family not in INSTANCE_STORE_FAMILIES:
        # EBS-only root volume types.
        if filters.get("root-device-type", ["ebs"]) != ["ebs"]:
            raise ValueError(
                "RootDeviceType must be ebs for %s instance types" %
                (instance_type,))
        filters["root-device-type"] = ["ebs"]

    return

def filter_names_and_descriptions(
        images: List, request_properties: Dict[str, Any]) -> List:
    """
    filter_names_and_descriptions(
            images: List, request_properties: Dict[str, Any]) -> List:
    Filter image names and descriptions according to the rules given in
    request_properties.
    """
    for include_exclude in ["Included", "Excluded"]:
        for param in ["Description", "Name"]:
            key = "%s%ss" % (include_exclude, param)
            value = request_properties.get(key)

            if not value:
                continue

            regex = regex_string_list(listify(value))

            # maybe_not is a passthrough when including, reverses the logic
            # test when excluding.
            if include_exclude == "Included":
                maybe_not = lambda x: x
            else:
                maybe_not = lambda x: not x

            images = [im for im in images
                      if maybe_not(regex.search(im[param]))]

            if not images:
                raise ValueError(
                    "No AMIs found that passed the %s filter" % key)

    return images

def listify(value):
    """
    Encapsulate value in a list if it isn't already.
    """
    if isinstance(value, list):
        return value

    return [value]

def regex_string_list(sl: List[str]):
    """
    Compile a list of strings into a regular expression.
    """
    return re.compile("|".join(["(?:%s)" % el for el in sl]))
