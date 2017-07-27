"""
Information about hash algorithms.
"""
# pylint: disable=C0103,R0903

from warnings import catch_warnings, filterwarnings
from passlib.exc import PasslibSecurityWarning

with catch_warnings():
    filterwarnings("ignore", category=PasslibSecurityWarning)
    from passlib.hash import (                      # pylint: disable=E0611
        apr_md5_crypt, argon2, bcrypt, bcrypt_sha256, bigcrypt, bsdi_crypt,
        bsd_nthash, crypt16, cta_pbkdf2_sha1, des_crypt, dlitz_pbkdf2_sha1,
        django_argon2, django_bcrypt, django_bcrypt_sha256, django_des_crypt,
        django_pbkdf2_sha256, django_salted_md5, django_salted_sha1, fshp,
        grub_pbkdf2_sha512, hex_md4, hex_md5, hex_sha1, hex_sha256, hex_sha512,
        ldap_md5, ldap_sha1, ldap_salted_md5, ldap_salted_sha1, lmhash,
        md5_crypt, msdcc, msdcc2, mssql2000, mssql2005, mysql323, mysql41,
        nthash, oracle10, oracle11, pbkdf2_sha1, pbkdf2_sha256, pbkdf2_sha512,
        phpass, postgres_md5, scram, scrypt, sha1_crypt, sha256_crypt,
        sha512_crypt, sun_md5_crypt,
    )

class HashAlgorithm(object):
    """
    Information about a given hash algorithm.
    """
    algorithms = {}

    def __init__(self, name, algorithm, is_secure, parameters=None):
        super(HashAlgorithm, self).__init__()
        HashAlgorithm.algorithms[name] = self
        self.name = name
        self.is_secure = is_secure
        self.parameters = parameters if parameters is not None else {}
        self.algorithm = algorithm
        return

class HashParameter(object):
    """
    Information about a hash algorithm parameter, including its type, min/max
    values, min/max length, and an optional custom validator.
    """
    def __init__(self, algorithm_parameter, type, # pylint: disable=R0913,W0622
                 min_value=None, max_value=None,
                 min_length=None, max_length=None,
                 validator=None):
        super(HashParameter, self).__init__()
        self.algorithm_parameter = algorithm_parameter
        self.type = type
        self.min_value = min_value
        self.max_value = max_value
        self.min_length = min_length
        self.max_length = max_length
        self.validator = validator
        return

def validate_scram_algs(value):
    """
    validate_scram_algs(value)
    Make sure scram's underlying hash algorithms are valid and includes
    an algorithm besides SHA-1.
    """

    if not value:
        raise ValueError("Algs cannot be empty")

    for el in value:
        if not el in ("sha-1", "sha-256", "sha-512"):
            raise ValueError("Invalid Alg value: %r" % el)

    if value == ["sha-1"]:
        raise ValueError("Alg must contain sha-256 or sha-512")

    return

block_size = HashParameter("block_size", int, min_value=1)
ident = HashParameter("ident", str, min_length=1, max_length=1)
parallelism = HashParameter("parallelism", int, min_value=1)
rounds = HashParameter("rounds", int, min_value=1)
rounds_1_32 = HashParameter("rounds", int, min_value=1, max_value=32)
rounds_1_16777215 = HashParameter("rounds", int, min_value=1, max_value=16777215)
rounds_1_4294963199 = HashParameter("rounds", int, min_value=1, max_value=4294963199)
rounds_1_4294967295 = HashParameter("rounds", int, min_value=1, max_value=4294967295)
rounds_1_4294967296 = HashParameter("rounds", int, min_value=1, max_value=4294967296)
rounds_4_31 = HashParameter("rounds", int, min_value=4, max_value=31)
rounds_7_30 = HashParameter("rounds", int, min_value=7, max_value=30)
rounds_1000_999999999 = HashParameter("rounds", int, min_value=1000,
                                      max_value=999999999)
salt = HashParameter("salt", str, min_length=0)
salt_0_8 = HashParameter("salt", str, min_length=0, max_length=8)
salt_0_16 = HashParameter("salt", str, min_length=0, max_length=16)
salt_0_64 = HashParameter("salt", str, min_length=0, max_length=64)
salt_0_1024 = HashParameter("salt", str, min_length=0, max_length=1024)
salt_2 = HashParameter("salt", str, min_length=2, max_length=2)
salt_4 = HashParameter("salt", str, min_length=4, max_length=4)
salt_4_16 = HashParameter("salt", str, min_length=4, max_length=16)
salt_8 = HashParameter("salt", str, min_length=8, max_length=8)
salt_20 = HashParameter("salt", str, min_length=20, max_length=20)
salt_22 = HashParameter("salt", str, min_length=22, max_length=22)
salt_size = HashParameter("salt_size", int, min_value=0)
salt_size_0_8 = HashParameter("salt_size", int, min_value=0, max_value=8)
salt_size_0_64 = HashParameter("salt_size", int, min_value=0, max_value=64)
salt_size_0_1024 = HashParameter("salt_size", int, min_value=0, max_value=1024)
salt_size_1 = HashParameter("salt_size", int, min_value=1)
salt_size_4_16 = HashParameter("salt_size", int, min_value=4, max_value=16)

memory_cost = HashParameter("memory_cost", int, min_value=0)
digest_size = HashParameter("digest_size", int, min_value=1)
bcrypt_ident = HashParameter("ident", str)
lmhash_encoding = HashParameter("encoding", str)
user = HashParameter("user", str)
scram_algs = HashParameter("algs", list, validator=validate_scram_algs)
sun_md5_crypt_bare_salt = HashParameter("bare_salt", bool)
variant = HashParameter("variant", int, min_value=0, max_value=3)

#### Secure algorithms

HashAlgorithm(
    "argon2", algorithm=argon2, is_secure=True,
    parameters={
        "Salt": salt_0_1024,
        "SaltSize": salt_size,
        "Rounds": rounds,
        "MemoryCost": memory_cost,
        "Parallelism": parallelism,
        "DigestSize": digest_size,
    })

HashAlgorithm(
    "bcrypt", algorithm=bcrypt, is_secure=True,
    parameters={
        "Salt": salt_22,
        "Rounds": rounds_4_31,
        "Ident": ident,
    })

HashAlgorithm(
    "bcrypt_sha256", algorithm=bcrypt_sha256, is_secure=True,
    parameters=HashAlgorithm.algorithms["bcrypt"].parameters)

HashAlgorithm(
    "pbkdf2_sha256", algorithm=pbkdf2_sha256, is_secure=True,
    parameters={
        "Salt": salt_0_1024,
        "SaltSize": salt_size_0_1024,
        "Rounds": rounds_1_4294967296,
    })

HashAlgorithm(
    "pbkdf2_sha512", algorithm=pbkdf2_sha512, is_secure=True,
    parameters={
        "Salt": salt_0_1024,
        "SaltSize": salt_size_0_1024,
        "Rounds": rounds_1_4294967296,
    })

HashAlgorithm(
    "scram", algorithm=scram, is_secure=True,
    parameters={
        "Salt": salt_0_1024,
        "SaltSize": salt_size_0_1024,
        "Rounds": rounds_1_4294967296,
        "Algs": scram_algs,
    })

HashAlgorithm(
    "scrypt", algorithm=scrypt, is_secure=True,
    parameters={
        "Salt": salt_0_1024,
        "SaltSize": salt_size_0_1024,
        "Rounds": rounds_1_32,
        "BlockSize": block_size,
    })

HashAlgorithm(
    "sha256_crypt", algorithm=sha256_crypt, is_secure=True,
    parameters={
        "Salt": salt_0_16,
        "Rounds": rounds_1000_999999999,
    })

HashAlgorithm(
    "sha512_crypt", algorithm=sha512_crypt, is_secure=True,
    parameters={
        "Salt": salt_0_16,
        "Rounds": rounds_1000_999999999,
    })


#### Secure application-specific algorithms

HashAlgorithm(
    "django_argon2", algorithm=django_argon2, is_secure=True,
    parameters=HashAlgorithm.algorithms["argon2"].parameters)

HashAlgorithm(
    "django_bcrypt", algorithm=django_bcrypt, is_secure=True,
    parameters=HashAlgorithm.algorithms["bcrypt"].parameters)

HashAlgorithm(
    "django_bcrypt_sha256", algorithm=django_bcrypt_sha256, is_secure=True,
    parameters=HashAlgorithm.algorithms["bcrypt_sha256"].parameters)

HashAlgorithm(
    "django_pbkdf2_sha256", algorithm=django_pbkdf2_sha256, is_secure=True,
    parameters=HashAlgorithm.algorithms["pbkdf2_sha256"].parameters)

HashAlgorithm(
    "grub_pbkdf2_sha512", algorithm=grub_pbkdf2_sha512, is_secure=True,
    parameters=HashAlgorithm.algorithms["pbkdf2_sha512"].parameters)


#### Insecure algorithms

HashAlgorithm(
    "apr_md5_crypt", algorithm=apr_md5_crypt, is_secure=False,
    parameters={
        "Salt": salt_0_8,
    })

HashAlgorithm(
    "bigcrypt", algorithm=bigcrypt, is_secure=False,
    parameters={
        "Salt": salt_22,
    })

HashAlgorithm(
    "bsdi_crypt", algorithm=bsdi_crypt, is_secure=False,
    parameters={
        "Salt": salt_4,
        "Rounds": rounds_1_16777215,
    })

HashAlgorithm("bsd_nthash", algorithm=bsd_nthash, is_secure=False)

HashAlgorithm(
    "crypt16", algorithm=crypt16, is_secure=False,
    parameters={
        "Salt": salt_2,
    })

HashAlgorithm(
    "cta_pbkdf2_sha1", algorithm=cta_pbkdf2_sha1, is_secure=False,
    parameters={
        "Salt": salt,
        "SaltSize": salt_size_0_1024,
        "Rounds": rounds_1_4294967296,
    })

HashAlgorithm(
    "des_crypt", algorithm=des_crypt, is_secure=False,
    parameters={
        "Salt": salt_2,
    })

HashAlgorithm(
    "django_des_crypt", algorithm=django_des_crypt, is_secure=False,
    parameters=HashAlgorithm.algorithms["des_crypt"].parameters)

HashAlgorithm(
    "django_salted_md5", algorithm=django_salted_md5, is_secure=False,
    parameters={
        "Salt": salt,
        "SaltSize": salt_size_1,
    })

HashAlgorithm(
    "django_salted_sha1", algorithm=django_salted_sha1, is_secure=False,
    parameters={
        "Salt": salt,
        "SaltSize": salt_size_1,
    })

HashAlgorithm(
    "dlitz_pbkdf2_sha1", algorithm=dlitz_pbkdf2_sha1, is_secure=False,
    parameters={
        "Salt": salt,
        "SaltSize": salt_size_0_1024,
        "Rounds": rounds_1_4294967296,
    })

HashAlgorithm(
    "fhsp", algorithm=fshp, is_secure=False,
    parameters={
        "Salt": salt,
        "SaltSize": salt_size_1,
        "Rounds": rounds_1_4294967295,
        "Variant": variant,
    })

HashAlgorithm("hex_md4", algorithm=hex_md4, is_secure=False)

HashAlgorithm("hex_md5", algorithm=hex_md5, is_secure=False)

HashAlgorithm("hex_sha1", algorithm=hex_sha1, is_secure=False)

HashAlgorithm("hex_sha256", algorithm=hex_sha256, is_secure=False)

HashAlgorithm("hex_sha512", algorithm=hex_sha512, is_secure=False)

HashAlgorithm("ldap_md5", algorithm=ldap_md5, is_secure=False)

HashAlgorithm("ldap_sha1", algorithm=ldap_sha1, is_secure=False)

HashAlgorithm(
    "ldap_salted_md5", algorithm=ldap_salted_md5, is_secure=False,
    parameters={
        "Salt": salt_4_16,
        "SaltSize": salt_size_4_16,
    })

HashAlgorithm(
    "ldap_salted_sha1", algorithm=ldap_salted_sha1, is_secure=False,
    parameters={
        "Salt": salt_4_16,
        "SaltSize": salt_size_4_16,
    })

HashAlgorithm(
    "lmhash", algorithm=lmhash, is_secure=False, parameters={
        "Encoding": lmhash_encoding,
    })

HashAlgorithm(
    "md5_crypt", algorithm=md5_crypt, is_secure=False,
    parameters={
        "Salt": salt_0_8,
        "SaltSize": salt_size_0_8,
    })

HashAlgorithm(
    "msdcc", algorithm=msdcc, is_secure=False,
    parameters={
        "User": user,
    })

HashAlgorithm(
    "msdcc2", algorithm=msdcc2, is_secure=False,
    parameters={
        "User": user,
    })

HashAlgorithm(
    "mssql2000", algorithm=mssql2000, is_secure=False,
    parameters={
        "Salt": salt_4,
    })

HashAlgorithm(
    "mssql2005", algorithm=mssql2005, is_secure=False,
    parameters={
        "Salt": salt_4,
    })

HashAlgorithm("mysql323", algorithm=mysql323, is_secure=False)

HashAlgorithm("mysql41", algorithm=mysql41, is_secure=False)

HashAlgorithm("nthash", algorithm=nthash, is_secure=False)

HashAlgorithm(
    "oracle10", algorithm=oracle10, is_secure=False,
    parameters={
        "User": user,
    })

HashAlgorithm(
    "oracle11", algorithm=oracle11, is_secure=False,
    parameters={
        "Salt": salt_20,
    })

HashAlgorithm(
    "pbkdf2_sha1", algorithm=pbkdf2_sha1, is_secure=False,
    parameters={
        "Salt": salt_0_1024,
        "SaltSize": salt_size_0_1024,
        "Rounds": rounds_1_4294967296,
        "Parallelism": parallelism,
    })

HashAlgorithm(
    "phpass", algorithm=phpass, is_secure=False,
    parameters={
        "Salt": salt_8,
        "Rounds": rounds_7_30,
        "Ident": ident,
    }
)

HashAlgorithm(
    "postgres_md5", algorithm=postgres_md5, is_secure=False,
    parameters={
        "User": user,
    })

HashAlgorithm(
    "sha1_crypt", algorithm=sha1_crypt, is_secure=False,
    parameters={
        "Salt": salt_0_64,
        "SaltSize": salt_size_0_64,
        "Rounds": rounds_1_4294967295,
    })

HashAlgorithm(
    "sun_md5_crypt", algorithm=sun_md5_crypt, is_secure=False,
    parameters={
        "BareSalt": sun_md5_crypt_bare_salt,
        "Salt": salt,
        "SaltSize": salt_size,
        "Rounds": rounds_1_4294963199,
    })
