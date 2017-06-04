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
* `Chars`: The characters to draw from when generating a password. This cannot be combined with `Charset` and is valid only when `PasswordType` is `word`.
* `Charset`: The predefined character set to draw from. This can be one of `ascii_62` (default; all digits, upper, and lower-case characters); `ascii_50` (subset of `ascii_62` that excludes visually similar characters); `ascii_72` (`ascii_62` plus some punctuation); or `hex` (lowercase hexadecimal). This cannot be combined with `Chars` and is valid only when `PasswordType` is `"word"`.
* `EncryptionContext`: If the password/passphrase is to be encrypted, the [encryption context to use](http://docs.aws.amazon.com/kms/latest/developerguide/encryption-context.html). This must be a mapping (JSON object, key/value dictionary).
* `EncryptionKey`: The KMS key ARN or alias (in the form `alias/keyname`) to use to encrypt the password.
* `Entropy`: The number of bits of entropy to include. This can be a numeric value greater than 48 or the strings `strong` (currently equal to 48) or `secure` (56). The default is `secure`.
* `PasswordType`: The type of password to generate. This can be either `word` or `phrase`. The default is `word`.
* `Separator`: The separator to use when separating words in a passphrase. This defaults to a space (`" "`) and is valid only when `PasswordType` is `phrase`.
* `Words`: The words to draw from when generating a passphrase. This cannot be combined with `Wordset` and is valid only when `PasswordType` is `phrase`.
* `Wordset`: The predefined word set to draw from. This can be one of `eff_long` (default; 7776 English words of ~7 letters); `eff_short` (1296 English words of ~4.5 characters); `eff_prefixed` (1296 English words of ~8 letters, each with a unique 3-character prefix); and `bip39` (2048 English words of ~5 letters, each with a unique 4-character prefix).  This cannot be combined with `Words` and is valid only when `PasswordType` is `phrase`.

### Returned Attributes
* `PlaintextPassword`: The generated password or passphrase. This is available only if the password is not encrypted.
* `CiphertextBase64Password`: The encrypted password or passphrase as a KMS ciphertext blob, base-64 encoded. This is available only if the password is encrypted.

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
        EncryptedPassword: !GetAtt DatabasePassphrase.CiphertextBase64Password
```

## Custom::HashPassword
Hash a password. See the [passlib documentation](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.html) for more details.

Note: Some of the hashing schemes are now considered insecure, but are included because various legacy products require them. To use an insecure hashing mechanism, the `AllowInsecure` property must be set to `true`.

### Properties
* `AllowInsecure`: This must be `true` to allow insecure hashing schemes to be used. The default is `false`.
* `Rounds`: The number of rounds to use (most secure algorithms). The meaning of this is scheme-specific (bcrypt is logarithmic, for example) and is applicable only to hashing schemes that use a variable number of rounds.
* `CiphertextBase64Password`: The encrypted password to hash. Either this or `PlaintextPassword` must be specified.
* `EncryptionContext`: The encryption context needed to decrypt `CiphertextBase64Password`.
* `PlaintextPassword`: The plaintext password to hash. Either this or `CiphertextBase64Password` must be specified.
* `Salt`: The salt string to use (most algorithms). This should be left unspecified unless necessary, and is only applicable to hashing schemes that use a salt.
* `SaltSize`: The number of bytes ot use when autogenerating a salt. This is optional, and is only applicable to hashing schemes that use a variable-length salt.
* `Scheme`: The password hashing scheme to use.
    * The following [secure schemes](https://passlib.readthedocs.io/en/stable/narr/quickstart.html) are supported: `argon2`, `bcrypt`, `bcrypt_sha256`, `pbkdf2_sha256`, `pbkdf2_sha512`, `scram`, `scrypt`, `sha256_crypt`, `sha512_crypt`.
    * The following application-specific secure schemes are supported: `django_argon2`, `django_bcrypt`, `django_bcrypt_sha256`, `django_pbkdf2_sha256`, `grub_pbkdf2_sha512`.
    * The following insecure schemes are supported only when `AllowInsecure` is set to `true`: `apr_md5_crypt`, `atlassian_pbkdf2_sha1`, `bigcrypt`, `bsdi_crypt`, `bsd_nthash`, `cisco_asa`, `cisco_pix`, `cisco_type7`, `crypt16`, `cta_pbkdf2_sha1`, `des_crypt`, `django_des_crypt`, `django_pbkdf2_sha1`, `django_salted_sha1`, `django_salted_sha256`, `dlitz_pbkdf2_sha`, `fshp`, `hex_md4`, `hex_md5`, `hex_sha1`, `hex_sha256`, `hex_sha512`, `ldap_md5`, `ldap_sha1`, `ldap_salted_md5`, `ldap_salted_sha1`, `lmhash`, `md5_crypt`, `msdcc`, `msdcc2`, `mssql2000`, `mssql2005`, `mysql323`, `mysql41`, `nthash`, `oracle10`, `oracle11`, `phpass`, `postgres_md5`, `sha1_crypt`, `sun_md5_crypt`.

The following properties are applicable to the `argon2` hash:
* `DigestSize`: Optional: length of the digest in bytes.
* `MemoryCost`: Optional: memory usage in kibibytes.
* `Parallelism`: Optional: parallelisation factor.

The following property is applicable to the `fshp` hash:
* `Variant`: The variant of FSHP to use. `0` uses the SHA-1 digest; `1` uses the SHA-2/256 digest (default); `2` uses the SHA-2/384 digest; `3` uses the SHA-2/512 digest.

The following property is applicable to the `scram` hash:
* `Algs`: The hashing algorithms to output. This is a list of one or more of the following values: `sha-1`, `sha-256`, and `sha-512`. The default is to return all three. **Specifying only `sha-1` is not allowed.**

The following properties are applicable to the `scrypt` hash:
* `BlockSize`: Optional: block size to pass to the scrypt hash function (scrypt `r` parameter).
* `Parallelism`: Optional: parallelisation factor (scrypt `p` parameter). 

The following property is applicable to the `sun_md5_crypt` hash:
* `BareSalt`: Defaults to `false`. See the [passlib documentation for details](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.sun_md5_crypt.html#smc-bare-salt).

The following property is applicable to the `cisco_asa`, `cisco_pix`, `msdcc`, `msdcc2`, `postgres_md5` and `oracle10` hashes:
* `User`: Required: the username associated with the password. These algorithms use the username as a salt.

### Returned Attributes
* `Hash`: The hashed password.

### Example
```yaml
  Resources:
    HashedPassword:
      Type: Custom::HashPassword
      Properties:
        ServiceToken: !GetAtt CFNGenerator.Arn
        CiphertextBase64Password: !GetAtt PasswordGenerator.CiphertextBase64Password
        EncryptionContext:
          Database: Test
          Purpose: One-time automated setup usage
        Scheme: bcrypt
    DatabaseSetup:
      Type: ...
      Properties:
        PasswordHash: !GetAtt HashedPassword.Hash
```
