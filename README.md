# cfn-generator
This is a collection of custom CloudFormation resources intended to make it
easier for dynamic deployments.

# Setting up
Before using this, you will need to deploy this as a Lambda function in your
own template. (We don't provide a centralised source for this, and you should
not use one; you are opening your AWS account for potential abuse and misuse
by doing so.) For example:

```yaml
  Resources:
    CFNGenerator:
      Type: AWS::Lambda::Function
      Properties:
        Code:
          S3Bucket: kanga-cfn
          S3Key: cfn-generator.zip
          S3ObjectVersion: 1
        Description: CloudFormation custom properties
        Handler: handler.lambda_handler
        MemorySize: 128
        Role: # IAM role in your account
        Runtime: python3.6
        Timeout: 10
```

# Using custom resources provided by cfn-generator
To use a custom resource in your CloudFormation template, specify one of the
types given below and point `ServiceToken` at your Lambda function. For
example:

```yaml
  Resources:
    AdminPasswordGen:
      Type: Custom::GeneratePassword
      Properties:
        ServiceToken: !GetAtt CFNGenerator.Arn
```

# Available resources

## Custom::GeneratePassword
Generate a password using passlib. See the [passlib documentation](https://passlib.readthedocs.io/en/stable/lib/passlib.pwd.html) for more details.

### Properties
* `Chars`: The characters to draw from when generating a password. This cannot be combined with `Charset` and is valid only when `PasswordType` is `"word"`.
* `Charset`: The predefined character set to draw from. This can be one of `"ascii_62"` (default; all digits, upper, and lower-case characters); `"ascii_50"` (subset of `"ascii_62"` that excludes visually similar characters); `"ascii_72"` (`"ascii_62"` plus some punctuation); or `"hex"` (lowercase hexadecimal). This cannot be combined with `Chars` and is valid only when `PasswordType` is `"word"`.
* `EncryptionContext`: If the password/passphrase is to be encrypted, the [encryption context to use](http://docs.aws.amazon.com/kms/latest/developerguide/encryption-context.html). This must be a mapping (JSON object, key/value dictionary).
* `EncryptionKey`: The KMS key ARN or alias (in the form `alias/keyname`) to use to encrypt the password.
* `Entropy`: The number of bits of entropy to include. This can be a numeric value greater than 48 or the strings `"strong"` (currently equal to 48) or `"secure"` (56). The default is `"secure"`.
* `PasswordType`: The type of password to generate. This can be either `"word"` or `"phrase"`. The default is `"word"`.
* `Separator`: The separator to use when separating words in a passphrase. This defaults to a space (`" "`) and is valid only when `PasswordType` is `"phrase"`.
* `Words`: The words to draw from when generating a passphrase. This cannot be combined with `Wordset` and is valid only when `PasswordType` is `"phrase"`.
* `Wordset`: The predefined word set to draw from. This can be one of `"eff_long"` (default; 7776 English words of ~7 letters); `"eff_short"` (1296 English words of ~4.5 characters); `"eff_prefixed"` (1296 English words of ~8 letters, each with a unique 3-character prefix); and `"bip39"` (2048 English words of ~5 letters, each with a unique 4-character prefix).  This cannot be combined with `Words` and is valid only when `PasswordType` is `"phrase"`.

### Returned Attributes
* `Password`: The generated password or passphrase. This is available only if the password is not encrypted.
* `CiphertextBase64`: The encrypted password or passphrase as a KMS ciphertext blob, base-64 encoded. This is available only if the password is encrypted.

### Example
```yaml
  Resources:
    DatabasePassphrase:
      Type: Custom::GeneratePassword
      Properties:
        ServiceToken: !GetAtt CFNGenerator.Arn
        EncryptionContext:
          Database: Test
          Purpose: One-time automated setup usage
        EncryptionKey: alias/test-db
        Entropy: secure
        PasswordType: pharse
        Wordset: bip39
    DatabaseSetup:
      Type: ...
      Properties:
        EncryptedPassword: !GetAtt DatabasePassphrase.CiphertextBase64
```
