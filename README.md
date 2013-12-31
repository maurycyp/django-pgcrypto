django-pgcrypto
===============

django-pgcrypto is a Django plugin for encrypting supported model fields. It
transparently encrypts and decrypts column data using a provided key.


Installation
------------

    pip install django-pgcrypto


Generating a key
----------------

If you don't already have an encryption key for use with django-pgcrypto, you
can create a 256-bit AES key using `openssl`:

    $ openssl enc -aes256 -P
    enter aes-256-cbc encryption password:
    Verifying - enter aes-256-cbc encryption password:
    salt=81DE80EFA1A3354A
    key=9C3E6A5754BFD1326EB116BF54A32A423D6D1F255AF0B400A573D3D01E86F39A
    iv =D1B895B8F254041C5F0D921383851A94

Enter a password when prompted. Save the password in a safe place and take note
of the `key` value--your new key.


Configuration
-------------

Add your key to the project's `settings.py`:

    PGCRYPTO_DEFAULT_KEY = '9C3E6A5754BFD1326EB116BF54A32A423D6D1F255AF0B400A573D3D01E86F39A'

You can also set two optional settings.

    PGCRYPTO_VALID_CIPHERS = ('AES', 'Blowfish')
    PGCRYPTO_DEFAULT_CIPHER = 'AES'


Valid ciphers are those supported by `pycrypto`.


Supported fields
----------------

* `EncryptedCharField`
* `EncryptedDateField`
* `EncryptedDateTimeField`
* `EncryptedDecimalField`
* `EncryptedEmailField`
* `EncryptedTextField`


Example
-------

    from django.db import models
    import pgcrypto

    class Employee(models.Model):
        first_name = models.CharField(max_length=30)
        last_name = models.CharField(max_length=30)
        ssn = pgcrypto.EncryptedCharField(max_length=11)
        salary = pgcrypto.EncryptedDecimalField()
