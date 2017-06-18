from base64 import b64decode, b64encode
from http.client import HTTPMessage, HTTPResponse
from http.server import BaseHTTPRequestHandler, HTTPServer
from json import loads as json_loads
from io import BytesIO
from sys import stderr
from threading import Thread
from unittest import skip, TestCase

import boto3
from moto import mock_apigateway

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
        print("Handler is listening on %s:%s" % tuple(self.server.socket.getsockname()), file=stderr)
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
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertIn("PlaintextPassword", result["Data"])

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="phrase")
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertIn("PlaintextPassword", result["Data"])

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="phrase",
            Wordset="eff_short")
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertIn("PlaintextPassword", result["Data"])

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="phrase",
            Words=["hello", "world"],
            Separator=",")
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertIn("PlaintextPassword", result["Data"])
        for item in result["Data"]["PlaintextPassword"].split(","):
            self.assertIn(item, ["hello", "world"])

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="word",
            Chars="abcd",
            Entropy=20)
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertIn("PlaintextPassword", result["Data"])
        for c in result["Data"]["PlaintextPassword"]:
            self.assertIn(c, "abcd")

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="word",
            Charset="hex",
            Entropy=20)
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertIn("PlaintextPassword", result["Data"])
        for c in result["Data"]["PlaintextPassword"]:
            self.assertIn(c, "0123456789abcdef")

        return

    def test_pwgen_encryption(self):
        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            EncryptionKey="alias/testing-only")
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertNotIn("PlaintextPassword", result["Data"])
        self.assertIn("CiphertextBase64Password", result["Data"])

        kms = boto3.client("kms")
        result = kms.decrypt(CiphertextBlob=b64decode(
            result["Data"]["CiphertextBase64Password"]))

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            EncryptionKey="alias/testing-only",
            EncryptionContext={"Usage": "testing"})
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertNotIn("PlaintextPassword", result["Data"])
        self.assertIn("CiphertextBase64Password", result["Data"])

        kms = boto3.client("kms")
        result = kms.decrypt(CiphertextBlob=b64decode(
            result["Data"]["CiphertextBase64Password"]),
            EncryptionContext={"Usage": "testing"})
        return

    def test_pwgen_conflicts(self):
        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="phrase",
            Chars="abcd")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"],
            'Chars cannot be specified when PasswordType is "phrase"')

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="phrase",
            Charset="ascii_62")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"],
            'Charset cannot be specified when PasswordType is "phrase"')

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="phrase",
            Words=["hello", "world"],
            Wordset="eff_short")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"],
            'Words and Wordset are mutually exclusive')

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="word",
            Words=["hello", "world"])
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"],
            'Words cannot be specified when PasswordType is "word"')

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="word",
            Wordset="eff_short")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"],
            'Wordset cannot be specified when PasswordType is "word"')

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="word",
            Separator=":")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"],
            'Separator cannot be specified when PasswordType is "word"')

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="word",
            Chars="abcd",
            Charset="ascii_62")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"],
            'Chars and Charset are mutually exclusive')

    def test_pwgen_bad_type(self):
        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="cars")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"],
            'PasswordType must be "word" or "phrase": \'cars\'')

    def test_pwgen_bad_entropy(self):
        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            Entropy="cars")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"],
            "Entropy must be an integer: 'cars'")

    def test_pwgen_skip_delete(self):
        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            RequestType="Delete",
            PhysicalResourceId="qwer-ty")
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertEquals(result["PhysicalResourceId"], "qwer-ty")

    def test_hash_password_ok(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            PlaintextPassword="Hello")
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertTrue(result["Data"]["Hash"].startswith("$pbkdf2-sha256$"))

    def test_hash_password_encrypted(self):
        kms = boto3.client("kms")
        result = kms.encrypt(KeyId="alias/testing-only", Plaintext="Hello")
        ciphertext = b64encode(result["CiphertextBlob"]).decode("ascii")
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            CiphertextBase64Password=ciphertext)
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertTrue(result["Data"]["Hash"].startswith("$pbkdf2-sha256$"))

        result = kms.encrypt(
            KeyId="alias/testing-only", Plaintext="Hello",
            EncryptionContext={"Usage": "testing"})
        ciphertext = b64encode(result["CiphertextBlob"]).decode("ascii")
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            CiphertextBase64Password=ciphertext,
            EncryptionContext={"Usage": "testing"})
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertTrue(result["Data"]["Hash"].startswith("$pbkdf2-sha256$"))

        return

    def test_hash_password_no_password(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"],
            "Either PlaintextPassword or CiphertextBase64Password must be "
            "specified")

    def test_hash_password_bad_encryption_context(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            CiphertextBase64Password="abcd==",
            EncryptionContext=[1])
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "EncryptionContext must be a mapping")

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

        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            CiphertextBase64Password="abcde=====")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"],
            "Invalid base64 encoding in CiphertextBase64Password")

        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            CiphertextBase64Password="abcd==")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"],
            "Unable to decrypt CiphertextBase64Password")


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

        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="bigcrypt",
            PlaintextPassword="Hello",
            AllowInsecure=[1])
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "AllowInsecure must be true or false")

    def test_hash_password_insecure_ok(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="md5_crypt",
            PlaintextPassword="Hello",
            AllowInsecure=True)
        self.assertEquals(result["Status"], "SUCCESS")

        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="md5_crypt",
            PlaintextPassword="Hello",
            AllowInsecure="yes")
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

    def test_hash_password_scram(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="scram",
            Algs=["sha-1"],
            PlaintextPassword="Hello")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "Alg must contain sha-256 or sha-512")

        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="scram",
            Algs=["foo", "sha-256", "sha-512"],
            PlaintextPassword="Hello")
        self.assertEquals(result["Status"], "FAILED")
        self.assertEquals(
            result["Reason"], "Invalid Alg value: 'foo'")

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

    def test_hash_password_ignore_delete(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            RequestType="Delete",
            PhysicalResourceId="password")
        self.assertEquals(result["Status"], "SUCCESS")
        self.assertEquals(result["PhysicalResourceId"], "password")

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

    @skip("Moto doesn't support update_rest_api yet")
    def test_apigw_binary(self):
        with mock_apigateway():
            apigw = boto3.client("apigateway")
            result = apigw.create_rest_api(name="test")
            rest_api_id = result["id"]

            result = self.invoke(
                ResourceType="Custom::ApiGatewayBinary",
                RestApiId=rest_api_id)

            self.assertEquals(result["Status"], "SUCCESS")

            result = apigw.get_rest_api(restApiId=rest_api_id)
            self.assertIn("*/*", result["binaryMediaTypes"])
