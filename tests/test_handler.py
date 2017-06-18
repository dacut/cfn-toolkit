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


    def test_pwgen(self):
        result = self.invoke(ResourceType="Custom::GeneratePassword")
        self.assertIn("Data", result)
        self.assertIn("PlaintextPassword", result["Data"])
        return

    def test_hash_password(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            PlaintextPassword="Hello")
        self.assertIn("Data", result)
        self.assertIn("Hash", result["Data"])
        self.assertTrue(result["Data"]["Hash"].startswith("$pbkdf2-sha256$"))
