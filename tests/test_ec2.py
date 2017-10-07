#!/usr/bin/env python3.6
"""
Test EC2-related functionality.
"""
# pylint: disable=C0103,C0111,R0904
from .base import CFNToolkitTestBase

class TestEC2(CFNToolkitTestBase):
    """
    Test EC2-related functionality.
    """
    def test_find_image(self):
        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="966028770618",
            IncludedNames=["RAM Linux.*"],
            InstanceType="m4.xlarge")

        self.assertEqual(result["Status"], "SUCCESS")
        self.assertIn("Data", result)
        self.assertIn("ImageId", result["Data"])
        self.assertEqual(result["Data"]["ImageId"], "ami-ebe4fe92")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="966028770618",
            IncludedNames="RAM Linux.*",
            InstanceType="m4.xlarge")

        self.assertEqual(result["Status"], "SUCCESS")
        self.assertIn("Data", result)
        self.assertIn("ImageId", result["Data"])
        self.assertEqual(result["Data"]["ImageId"], "ami-ebe4fe92")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="966028770618",
            IncludedDescriptions=["RAM Linux.*"],
            InstanceType="m4.xlarge")

        self.assertEqual(result["Status"], "SUCCESS")
        self.assertIn("Data", result)
        self.assertIn("ImageId", result["Data"])
        self.assertEqual(result["Data"]["ImageId"], "ami-ebe4fe92")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="966028770618",
            IncludedDescriptions="RAM Linux.*",
            VirtualizationType="hvm")

        self.assertEqual(result["Status"], "SUCCESS")
        self.assertIn("Data", result)
        self.assertIn("ImageId", result["Data"])
        self.assertEqual(result["Data"]["ImageId"], "ami-ebe4fe92")

    def test_find_image_too_narrow_filter(self):
        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="966028770618",
            ImageId="ami-ebe4fe92",
            Platform="windows",
            EnaSupport="true",
            RootDeviceType="instance-store")

        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"], "No AMIs found that match the filters applied.")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="966028770618",
            Architecture="x86-64",
            InstanceType="m1.small")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"], "No AMIs found that match the filters applied.")

    def test_find_image_conflicting_descriptions(self):
        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="966028770618",
            ImageId="ami-ebe4fe92",
            ExcludedDescriptions=[".*"],
            InstanceType="m4.xlarge")

        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            "No AMIs found that passed the ExcludedDescriptions filter")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="966028770618",
            ImageId="ami-ebe4fe92",
            ExcludedDescriptions=".*",
            InstanceType="m4.xlarge")

        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            "No AMIs found that passed the ExcludedDescriptions filter")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="966028770618",
            IncludedDescriptions=["Zorro"],
            InstanceType="m4.xlarge")

        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            "No AMIs found that passed the IncludedDescriptions filter")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="966028770618",
            IncludedDescriptions="Zorro",
            InstanceType="m4.xlarge")

        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            "No AMIs found that passed the IncludedDescriptions filter")

    def test_find_image_conflicting_names(self):
        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="966028770618",
            ImageId="ami-ebe4fe92",
            ExcludedNames=[".*"],
            InstanceType="m4.xlarge")

        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            "No AMIs found that passed the ExcludedNames filter")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="966028770618",
            ImageId="ami-ebe4fe92",
            ExcludedNames=".*",
            InstanceType="m4.xlarge")

        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            "No AMIs found that passed the ExcludedNames filter")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="966028770618",
            IncludedNames=["Zorro"],
            InstanceType="m4.xlarge")

        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            "No AMIs found that passed the IncludedNames filter")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="966028770618",
            IncludedNames="Zorro",
            InstanceType="m4.xlarge")

        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            "No AMIs found that passed the IncludedNames filter")

    def test_find_image_owner_missing(self):
        result = self.invoke(ResourceType="Custom::FindImage")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(result["Reason"], "Owner must be specified")

    def test_find_image_root_device_conflict(self):
        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="966028770618",
            InstanceType="m4",
            RootDeviceType="instance-store")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            "RootDeviceType must be ebs for m4 instance types")

    def test_find_image_virtualization_conflict(self):
        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="966028770618",
            InstanceType="m4",
            VirtualizationType="paravirtual")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            "VirtualizationType must be hvm for m4 instance types")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="966028770618",
            InstanceType="m1",
            VirtualizationType="hvm")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            "VirtualizationType must be paravirtual for m1 instance types")

    def test_find_image_ignore_delete(self):
        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="966028770618",
            InstanceType="m1",
            VirtualizationType="hvm",
            PhysicalResourceId="abcd-zxcv",
            RequestType="Delete")

        self.assertEqual(result["Status"], "SUCCESS")
        self.assertEqual(result["PhysicalResourceId"], "abcd-zxcv")
