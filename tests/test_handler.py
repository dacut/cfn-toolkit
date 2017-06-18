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
    def setUp(self):
        self.server = HTTPServer(("127.0.0.1", 13438), ResponseHandler)
        self.thread = Thread(target=self.server.serve_forever)
        self.thread.start()
        return

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        return

    def test_pwgen(self):
        import handler
        handler.lambda_handler({
            "StackId": "stack-1234",
            "RequestId": "req-1234",
            "LogicalResourceId": "password",
            "RequestType": "Create",
            "ResourceType": "Custom::GeneratePassword",
            "ResponseURL": "http://127.0.0.1:13438/",
            "ResourceProperties": {},
        }, None)

        response = ResponseHandler.responses.pop()
        result = json_loads(response)

        self.assertIn("Data", result)
        self.assertIn("PlaintextPassword", result["Data"])
        return
