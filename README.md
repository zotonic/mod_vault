mod_vault
=========

Encrypts data with a RSA public key.
Decrypts data using RSA private keys which are encrypted with a password.

Each public key is named.
An user can have a private key for decrypting data that has been encrypted with the same named private key.
The private key of an user is encrypted with a password.

All private and public keys are administrated in the `vault` database table.

This module uses *openssl* to generate the private and public RSA keys. Per default it generates 2048 bit keys.

