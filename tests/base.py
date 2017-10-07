#!/usr/bin/env python3.6
"""
Base classes for all tests.
"""
# pylint: disable=C0103,C0111,R0904
from http.server import BaseHTTPRequestHandler, HTTPServer
from json import loads as json_loads
from threading import Thread
from unittest import TestCase

class ResponseHandler(BaseHTTPRequestHandler):
    """
    Handles S3 POSTs that the Lambda handler sends its results to.
    """
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

class CFNToolkitTestBase(TestCase):
    """
    Setup the handler for testing and provide a way to invoke the mock Lambda
    function.
    """
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
        """
        Invoke a mock lambda function.
        """
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
