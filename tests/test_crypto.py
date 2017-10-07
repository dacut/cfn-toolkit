#!/usr/bin/env python3.6
"""
Test the Lambda handler.
"""
# pylint: disable=C0103,C0111,R0904
from base64 import b64decode, b64encode
import boto3
from .base import CFNToolkitTestBase

class TestCrypto(CFNToolkitTestBase):
    def test_unknown_type(self):
        result = self.invoke(ResourceType="Custom::Unknown")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"], "Unknown resource type Custom::Unknown")

    def test_pwgen(self):
        result = self.invoke(ResourceType="Custom::GeneratePassword")
        self.assertEqual(result["Status"], "SUCCESS")
        self.assertIn("PlaintextPassword", result["Data"])

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="phrase")
        self.assertEqual(result["Status"], "SUCCESS")
        self.assertIn("PlaintextPassword", result["Data"])

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="phrase",
            Wordset="eff_short")
        self.assertEqual(result["Status"], "SUCCESS")
        self.assertIn("PlaintextPassword", result["Data"])

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="phrase",
            Words=["hello", "world"],
            Separator=",")
        self.assertEqual(result["Status"], "SUCCESS")
        self.assertIn("PlaintextPassword", result["Data"])
        for item in result["Data"]["PlaintextPassword"].split(","):
            self.assertIn(item, ["hello", "world"])

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="word",
            Chars="abcd",
            Entropy=20)
        self.assertEqual(result["Status"], "SUCCESS")
        self.assertIn("PlaintextPassword", result["Data"])
        for c in result["Data"]["PlaintextPassword"]:
            self.assertIn(c, "abcd")

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="word",
            Charset="hex",
            Entropy=20)
        self.assertEqual(result["Status"], "SUCCESS")
        self.assertIn("PlaintextPassword", result["Data"])
        for c in result["Data"]["PlaintextPassword"]:
            self.assertIn(c, "0123456789abcdef")

        return

    def test_pwgen_encryption(self):
        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            EncryptionKey="alias/testing-only")
        self.assertEqual(result["Status"], "SUCCESS")
        self.assertNotIn("PlaintextPassword", result["Data"])
        self.assertIn("CiphertextBase64Password", result["Data"])

        kms = boto3.client("kms")
        result = kms.decrypt(CiphertextBlob=b64decode(
            result["Data"]["CiphertextBase64Password"]))

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            EncryptionKey="alias/testing-only",
            EncryptionContext={"Usage": "testing"})
        self.assertEqual(result["Status"], "SUCCESS")
        self.assertNotIn("PlaintextPassword", result["Data"])
        self.assertIn("CiphertextBase64Password", result["Data"])

        kms = boto3.client("kms")
        result = kms.decrypt(
            CiphertextBlob=b64decode(
                result["Data"]["CiphertextBase64Password"]),
            EncryptionContext={"Usage": "testing"})
        return

    def test_pwgen_conflicts(self):
        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="phrase",
            Chars="abcd")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            'Chars cannot be specified when PasswordType is "phrase"')

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="phrase",
            Charset="ascii_62")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            'Charset cannot be specified when PasswordType is "phrase"')

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="phrase",
            Words=["hello", "world"],
            Wordset="eff_short")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            'Words and Wordset are mutually exclusive')

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="word",
            Words=["hello", "world"])
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            'Words cannot be specified when PasswordType is "word"')

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="word",
            Wordset="eff_short")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            'Wordset cannot be specified when PasswordType is "word"')

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="word",
            Separator=":")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            'Separator cannot be specified when PasswordType is "word"')

        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="word",
            Chars="abcd",
            Charset="ascii_62")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            'Chars and Charset are mutually exclusive')

    def test_pwgen_bad_type(self):
        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            PasswordType="cars")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            'PasswordType must be "word" or "phrase": \'cars\'')

    def test_pwgen_bad_entropy(self):
        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            Entropy="cars")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            "Entropy must be an integer: 'cars'")

    def test_pwgen_skip_delete(self):
        result = self.invoke(
            ResourceType="Custom::GeneratePassword",
            RequestType="Delete",
            PhysicalResourceId="qwer-ty")
        self.assertEqual(result["Status"], "SUCCESS")
        self.assertEqual(result["PhysicalResourceId"], "qwer-ty")

    def test_hash_password_ok(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            PlaintextPassword="Hello")
        self.assertEqual(result["Status"], "SUCCESS")
        self.assertTrue(result["Data"]["Hash"].startswith("$pbkdf2-sha256$"))

    def test_hash_password_encrypted(self):
        kms = boto3.client("kms")
        result = kms.encrypt(KeyId="alias/testing-only", Plaintext="Hello")
        ciphertext = b64encode(result["CiphertextBlob"]).decode("ascii")
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            CiphertextBase64Password=ciphertext)
        self.assertEqual(result["Status"], "SUCCESS")
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
        self.assertEqual(result["Status"], "SUCCESS")
        self.assertTrue(result["Data"]["Hash"].startswith("$pbkdf2-sha256$"))

        return

    def test_hash_password_no_password(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            "Either PlaintextPassword or CiphertextBase64Password must be "
            "specified")

    def test_hash_password_bad_encryption_context(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            CiphertextBase64Password="abcd==",
            EncryptionContext=[1])
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"], "EncryptionContext must be a mapping")

    def test_hash_password_rounds(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            Rounds=1000,
            PlaintextPassword="Hello")
        self.assertEqual(result["Status"], "SUCCESS")
        self.assertIn("Data", result)
        self.assertIn("Hash", result["Data"])
        self.assertTrue(result["Data"]["Hash"].startswith("$pbkdf2-sha256$"))

    def test_hash_password_bad_rounds_value(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            Rounds=-1000,
            PlaintextPassword="Hello")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"], "Value of parameter Rounds cannot be less than "
            "1: -1000")

    def test_hash_password_bad_rounds_type(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            Rounds="foo",
            PlaintextPassword="Hello")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"], "Invalid value for parameter Rounds: 'foo'")

    def test_hash_password_dash(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2-sha512",
            PlaintextPassword="Hello")
        self.assertEqual(result["Status"], "SUCCESS")
        self.assertIn("Data", result)
        self.assertIn("Hash", result["Data"])
        self.assertTrue(result["Data"]["Hash"].startswith("$pbkdf2-sha512$"))

    def test_hash_password_missing_scheme(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            PlaintextPassword="Hello")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(result["Reason"], "Scheme must be specified")

    def test_hash_password_bad_scheme_type(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme=3,
            PlaintextPassword="Hello")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(result["Reason"], "Scheme must be a string")

    def test_hash_password_empty_scheme(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="",
            PlaintextPassword="Hello")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(result["Reason"], "Scheme cannot be empty")

    def test_hash_password_unknown_scheme(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="zapf-foo",
            PlaintextPassword="Hello")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(result["Reason"], "Unknown scheme 'zapf-foo'")

    def test_hash_password_bad_plaintext(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha512",
            PlaintextPassword=3)
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"], "PlaintextPassword must be a string")

    def test_hash_password_plaintext_ciphertext_conflict(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha512",
            PlaintextPassword="Hello",
            CiphertextBase64Password="abcde=")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"], "PlaintextPassword and CiphertextBase64Password"
            " are mutually exclusive")

    def test_hash_password_bad_ciphertext(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha512",
            CiphertextBase64Password=3)
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"], "CiphertextBase64Password must be a string")

        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            CiphertextBase64Password="abcde=====")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            "Invalid base64 encoding in CiphertextBase64Password")

        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            CiphertextBase64Password="abcd==")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            "Unable to decrypt CiphertextBase64Password")


    def test_hash_password_ciphertext(self):
        kms = boto3.client("kms")
        key_id = "alias/testing-only"
        ec = {"foo": "bar"}
        ciphertext_blob = (
            kms.encrypt(Plaintext="Hello", KeyId=key_id, EncryptionContext=ec)
            ["CiphertextBlob"])
        ciphertext = b64encode(ciphertext_blob).decode("ascii")

        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha512",
            CiphertextBase64Password=ciphertext,
            EncryptionContext=ec)
        self.assertEqual(result["Status"], "SUCCESS")
        self.assertTrue(result["Data"]["Hash"].startswith("$pbkdf2-sha512$"))


    def test_hash_password_disallow_insecure(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="bigcrypt",
            PlaintextPassword="Hello")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"], "Scheme bigcrypt is insecure and AllowInsecure "
            "was not specified")

        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="bigcrypt",
            PlaintextPassword="Hello",
            AllowInsecure=[1])
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"], "AllowInsecure must be true or false")

    def test_hash_password_insecure_ok(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="md5_crypt",
            PlaintextPassword="Hello",
            AllowInsecure=True)
        self.assertEqual(result["Status"], "SUCCESS")

        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="md5_crypt",
            PlaintextPassword="Hello",
            AllowInsecure="yes")
        self.assertEqual(result["Status"], "SUCCESS")

    def test_hash_password_wrong_length(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="md5_crypt",
            Salt="abcdefghijkl",
            PlaintextPassword="Hello",
            AllowInsecure=True)
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"], "Length of parameter Salt cannot be greater "
            "than 8: 'abcdefghijkl'")

        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="des_crypt",
            Salt="a",
            PlaintextPassword="Hello",
            AllowInsecure=True)
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"], "Length of parameter Salt cannot be less "
            "than 2: 'a'")

    def test_hash_password_too_big(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="sha1_crypt",
            SaltSize=100,
            PlaintextPassword="Hello",
            AllowInsecure=True)
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"], "Value of parameter SaltSize cannot be greater "
            "than 64: 100")

    def test_hash_password_scram(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="scram",
            Algs=["sha-1"],
            PlaintextPassword="Hello")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"], "Alg must contain sha-256 or sha-512")

        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="scram",
            Algs=["foo", "sha-256", "sha-512"],
            PlaintextPassword="Hello")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"], "Invalid Alg value: 'foo'")

    def test_hash_password_unknown_parameter(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            Scheme="pbkdf2_sha256",
            Foo="Bar",
            Baz="Boo",
            PlaintextPassword="Hello",
            AllowInsecure=True)
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"], "Unknown parameters: Baz, Foo")

    def test_hash_password_ignore_delete(self):
        result = self.invoke(
            ResourceType="Custom::HashPassword",
            RequestType="Delete",
            PhysicalResourceId="password")
        self.assertEqual(result["Status"], "SUCCESS")
        self.assertEqual(result["PhysicalResourceId"], "password")

    def test_secure_random_ok(self):
        result = self.invoke(
            ResourceType="Custom::SecureRandom",
            Size=10)
        self.assertEqual(result["Status"], "SUCCESS")
        self.assertIn("Base64", result["Data"])

    def test_secure_random_bad_size(self):
        result = self.invoke(
            ResourceType="Custom::SecureRandom",
            Size=0)
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(result["Reason"], "Invalid size parameter: 0")

    def test_secure_random_ignore_delete(self):
        result = self.invoke(
            ResourceType="Custom::SecureRandom",
            PhysicalResourceId="abcd-efgh",
            RequestType="Delete",
            Size=0)
        self.assertEqual(result["Status"], "SUCCESS")
        self.assertEqual(result["PhysicalResourceId"], "abcd-efgh")
