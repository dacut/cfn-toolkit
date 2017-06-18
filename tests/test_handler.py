from base64 import b64encode
from http.client import HTTPMessage, HTTPResponse
from http.server import BaseHTTPRequestHandler, HTTPServer
from json import loads as json_loads
from io import BytesIO
from sys import stderr
from threading import Thread
from unittest import TestCase

import boto3


class ResponseHandler(BaseHTTPRequestHandler):
    responses = []

    def do_PUT(self):
        content_length = self.headers.get("Content-Length")
        if content_length is not None:
            content_length = int(content_length)

        data = self.rfile.read(content_length)
        self.responses.append(data)

        self.send_response(200, "")
        self.send_header("Content-Length", "0")
        self.send_header("Server", "AmazonS3")
        self.end_headers()

        return


class TestHandler(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), ResponseHandler)
        cls.thread = Thread(target=cls.server.serve_forever)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        return


    def setUp(self):
        ResponseHandler.responses = []
        return

    def invoke(self, ResourceType, RequestType="Create",
               LogicalResourceId="LogicalResourceId", **kw):
        sockname = self.server.socket.getsockname()

        event = {
            "StackId": "stack-1234",
            "RequestId": "req-1234",
            "LogicalResourceId": LogicalResourceId,
            "RequestType": RequestType,
            "ResourceType": ResourceType,
            "ResponseURL": "http://%s:%s/" % (sockname[0], sockname[1])
        }

        if "PhysicalResourceId" in kw:
            event["PhysicalResourceId"] = kw.pop("PhysicalResourceId")

        event["ResourceProperties"] = kw

        import handler
        handler.lambda_handler(event, None)
        return json_loads(ResponseHandler.responses.pop())

    def test_unknown_type(self):
        result = self.invoke(ResourceType="Custom::Unknown")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "Unknown resource type Custom::Unknown")

    def test_pwgen(self):
        result = self.invoke(ResourceType="Custom::GeneratePassword")
        self.assertIn("Data", result)
        self.assertIn("PlaintextPassword", result["Data"])
        return

    def test_hash_password_ok(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            PlaintextPassword="Hello")
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertIn("Data", result)
        self.assertIn("Hash", result["Data"])
        self.assertTrue(result["Data"]["Hash"].startswith("$pbkdf2-sha256$"))

    def test_hash_password_rounds(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            Rounds=1000,
            PlaintextPassword="Hello")
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertIn("Data", result)
        self.assertIn("Hash", result["Data"])
        self.assertTrue(result["Data"]["Hash"].startswith("$pbkdf2-sha256$"))

    def test_hash_password_bad_rounds_value(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            Rounds=-1000,
            PlaintextPassword="Hello")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "Value of parameter Rounds cannot be less than "
            "1: -1000")

    def test_hash_password_bad_rounds_type(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            Rounds="foo",
            PlaintextPassword="Hello")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "Invalid value for parameter Rounds: 'foo'")

    def test_hash_password_dash(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2-sha512",
            PlaintextPassword="Hello")
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertIn("Data", result)
        self.assertIn("Hash", result["Data"])
        self.assertTrue(result["Data"]["Hash"].startswith("$pbkdf2-sha512$"))

    def test_hash_password_missing_scheme(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            PlaintextPassword="Hello")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(result["Reason"], "Scheme must be specified")

    def test_hash_password_bad_scheme_type(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme=3,
            PlaintextPassword="Hello")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(result["Reason"], "Scheme must be a string")

    def test_hash_password_empty_scheme(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="",
            PlaintextPassword="Hello")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(result["Reason"], "Scheme cannot be empty")

    def test_hash_password_unknown_scheme(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="zapf-foo",
            PlaintextPassword="Hello")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(result["Reason"], "Unknown scheme 'zapf-foo'")

    def test_hash_password_bad_plaintext(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha512",
            PlaintextPassword=3)
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "PlaintextPassword must be a string")

    def test_hash_password_plaintext_ciphertext_conflict(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha512",
            PlaintextPassword="Hello",
            CiphertextBase64Password="abcde=")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "PlaintextPassword and CiphertextBase64Password"
            " are mutually exclusive")

    def test_hash_password_bad_ciphertext(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha512",
            CiphertextBase64Password=3)
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "CiphertextBase64Password must be a string")

    def test_hash_password_ciphertext(self):
        kms = boto3.client("kms")
        key_id = "alias/testing-only"
        ec = {"foo": "bar"}
        ciphertext = b64encode(kms.encrypt(
            Plaintext="Hello", KeyId=key_id, EncryptionContext=ec)
            ["CiphertextBlob"]).decode("ascii")

        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha512",
            CiphertextBase64Password=ciphertext,
            EncryptionContext=ec)
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertTrue(result["Data"]["Hash"].startswith("$pbkdf2-sha512$"))


    def test_hash_password_disallow_insecure(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="bigcrypt",
            PlaintextPassword="Hello")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "Scheme bigcrypt is insecure and AllowInsecure "
            "was not specified")

    def test_hash_password_insecure_ok(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="md5_crypt",
            PlaintextPassword="Hello",
            AllowInsecure=True)
        self.assertEquals(result["Status"], "SUCCESS")

    def test_hash_password_wrong_length(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="md5_crypt",
            Salt="abcdefghijkl",
            PlaintextPassword="Hello",
            AllowInsecure=True)
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "Length of parameter Salt cannot be greater "
            "than 8: 'abcdefghijkl'")

        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="des_crypt",
            Salt="a",
            PlaintextPassword="Hello",
            AllowInsecure=True)
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "Length of parameter Salt cannot be less "
            "than 2: 'a'")

    def test_hash_password_too_big(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="sha1_crypt",
            SaltSize=100,
            PlaintextPassword="Hello",
            AllowInsecure=True)
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "Value of parameter SaltSize cannot be greater "
            "than 64: 100")

    def test_hash_password_unknown_parameter(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            Foo="Bar",
            Baz="Boo",
            PlaintextPassword="Hello",
            AllowInsecure=True)
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "Unknown parameters: Baz, Foo")

    def test_secure_random_ok(self):
        result = self.invoke(
            ResourceType="Custom::SecureRandom",
            Size=10)
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertIn("Base64", result["Data"])

    def test_secure_random_bad_size(self):
        result = self.invoke(
            ResourceType="Custom::SecureRandom",
            Size=0)
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(result["Reason"], "Invalid size parameter: 0")

    def test_secure_random_ignore_delete(self):
        result = self.invoke(
            ResourceType="Custom::SecureRandom",
            PhysicalResourceId="abcd-efgh",
            RequestType="Delete",
            Size=0)
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertEquals(result["PhysicalResourceId"], "abcd-efgh")

    def test_find_image(self):
        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="021973571807",
            IncludedNames=["RAMLinux.*"],
            InstanceType="m4.xlarge")

        self.assertEquals(result["Status"], "SUCCESS")
        self.assertIn("Data", result)
        self.assertIn("ImageId", result["Data"])
        self.assertEquals(result["Data"]["ImageId"], "ami-d80ff3b8")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="021973571807",
            IncludedNames="RAMLinux.*",
            InstanceType="m4.xlarge")

        self.assertEquals(result["Status"], "SUCCESS")
        self.assertIn("Data", result)
        self.assertIn("ImageId", result["Data"])
        self.assertEquals(result["Data"]["ImageId"], "ami-d80ff3b8")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="021973571807",
            IncludedDescriptions=["RAMLinux.*"],
            InstanceType="m4.xlarge")

        self.assertEquals(result["Status"], "SUCCESS")
        self.assertIn("Data", result)
        self.assertIn("ImageId", result["Data"])
        self.assertEquals(result["Data"]["ImageId"], "ami-d80ff3b8")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="021973571807",
            IncludedDescriptions="RAMLinux.*",
            VirtualizationType="hvm")

        self.assertEquals(result["Status"], "SUCCESS")
        self.assertIn("Data", result)
        self.assertIn("ImageId", result["Data"])
        self.assertEquals(result["Data"]["ImageId"], "ami-d80ff3b8")

    def test_find_image_too_narrow_filter(self):
        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="021973571807",
            ImageId="ami-d80ff3b8",
            Platform="windows",
            EnaSupport="true",
            RootDeviceType="instance-store")

        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "No AMIs found that match the filters applied.")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="021973571807",
            Architecture="x86-64",
            InstanceType="m1.small")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "No AMIs found that match the filters applied.")

    def test_find_image_conflicting_descriptions(self):
        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="021973571807",
            ImageId="ami-d80ff3b8",
            ExcludedDescriptions=[".*"],
            InstanceType="m4.xlarge")

        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "No AMIs found; all AMIs matched "
            "ExcludedDescriptions")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="021973571807",
            ImageId="ami-d80ff3b8",
            ExcludedDescriptions=".*",
            InstanceType="m4.xlarge")

        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "No AMIs found; all AMIs matched "
            "ExcludedDescriptions")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="021973571807",
            IncludedDescriptions=["Zorro"],
            InstanceType="m4.xlarge")

        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "No AMIs found; no AMIs matched "
            "IncludedDescriptions")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="021973571807",
            IncludedDescriptions="Zorro",
            InstanceType="m4.xlarge")

        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "No AMIs found; no AMIs matched "
            "IncludedDescriptions")

    def test_find_image_conflicting_names(self):
        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="021973571807",
            ImageId="ami-d80ff3b8",
            ExcludedNames=[".*"],
            InstanceType="m4.xlarge")

        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "No AMIs found; all AMIs matched "
            "ExcludedNames")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="021973571807",
            ImageId="ami-d80ff3b8",
            ExcludedNames=".*",
            InstanceType="m4.xlarge")

        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "No AMIs found; all AMIs matched "
            "ExcludedNames")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="021973571807",
            IncludedNames=["Zorro"],
            InstanceType="m4.xlarge")

        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "No AMIs found; no AMIs matched "
            "IncludedNames")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="021973571807",
            IncludedNames="Zorro",
            InstanceType="m4.xlarge")

        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "No AMIs found; no AMIs matched "
            "IncludedNames")

    def test_find_image_owner_missing(self):
        result = self.invoke(ResourceType="Custom::FindImage")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(result["Reason"], "Owner must be specified")

    def test_find_image_root_device_conflict(self):
        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="021973571807",
            InstanceType="m4",
            RootDeviceType="instance-store")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "RootDeviceType must be ebs for m4 instance "
            "types")

    def test_find_image_virtualization_conflict(self):
        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="021973571807",
            InstanceType="m4",
            VirtualizationType="paravirtual")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "VirtualizationType must be hvm for m4 instance "
            "types")

        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="021973571807",
            InstanceType="m1",
            VirtualizationType="hvm")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "VirtualizationType must be paravirtual for m1 "
            "instance types")

    def test_find_image_ignore_delete(self):
        result = self.invoke(
            ResourceType="Custom::FindImage",
            Owner="021973571807",
            InstanceType="m1",
            VirtualizationType="hvm",
            PhysicalResourceId="abcd-zxcv",
            RequestType="Delete")

        self.assertEquals(result["Status"], "SUCCESS")
        self.assertEquals(result["PhysicalResourceId"], "abcd-zxcv")
