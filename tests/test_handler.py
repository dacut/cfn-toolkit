from http.client import HTTPMessage, HTTPResponse
from http.server import BaseHTTPRequestHandler, HTTPServer
from json import loads as json_loads
from io import BytesIO
from sys import stderr
from threading import Thread
from unittest import TestCase


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
            "ResponseURL": "http://%s:%s/" % (sockname[0], sockname[1]),
            "ResourceProperties": kw,
        }

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
