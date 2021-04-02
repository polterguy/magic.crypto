# Magic.crypto - Simplified cryptography based upon BouncyCastle

Magic.crypto gives you a simplified API wrapping BouncyCastle for .Net 5. It supports the following features.

* Creating RSA keypairs
* RSA encryption and decryption
* RSA signatures both signing messages, and verifying an existing signed message
* AES symmetric cryptography
* Combinations of the above

The latter is especially useful if you want to user public key cryptography, since it uses a CSRNG keyphrase to
symmetrically encrypt some package, for then to asymmetrically encrypt the passphrase, giving you _"the ghist"_
of features from PGP, without having to resort to PGP, or add the overhead from PGP. Where PGP is more geared
towards MIME and emails, this library is of more general purpose character.

## Examples

### RSA encryption and decryption

To create an RSA keypair, you can use something resembling the following.

```csharp
using magic.crypto.rsa;

var generator = new KeyGenerator();
var key = generator.Generate(1024);
```

The result from the above `Generate` method is a `KeyPair` object, which will contain your public key, private key,
your key's fingerprint that can be used to uniquely identify a keypair, in addition to that the keypair can be used
to encrypt, decrypt, sign, and verify an existing cryptographic signature of some payload. The integer value to the
`Generate` method is the key strength, and should typically be one of the following values.

* 1024 - Unsafe
* 2048 - Unsafe
* 4096 - Safe
* 8192 - Safe, but extremely slow and CPU intensive

**Notice** - The private key returned from the above code should *always* be kept private, and never shared. While
the public key returned from the above invocation should be freely shared to anyone wanting to encrypt messages for
the private key. The concept of public key cryptography, is that whatever is encrypted using the _public_ key,
can only be decrypted using the associated _private_ key. Hence, the public key is for _encrypting_ and the
private key for _decrypting_.

The public and private keys returned in the above code can be serialised by converting their `byte[]` values to
for instance base64 encoded strings, for then to be stored in a database or in ASCII text files. To encrypt something
using the above key, you could use code resembling the following.

```csharp
using magic.crypto.rsa;

var encrypter = new Encrypter(key.PublicKey);
var encrypted = encrypter.Encrypt(Encoding.UTF8.GetBytes("Hello World"));
```

This uses RSA encryption (only) to encrypt the above _"Hello World"_ string, returning its encrypted
raw `byte[]` representation. Notice, this is probably not that useful, since you cannot encrypt anything longer
than your key length, implying you would probably much rather want to use the _"combination examples"_ from below
to encrypt real messages.

To decrypt the above package, you can use something resembling the following.

```csharp
using magic.crypto.rsa;

var decrypter = new Decrypter(key.PrivateKey);
var decrypted = decrypter.Decrypt(encrypted);
```

Notice, only the private key associated with the public key that was used to encrypt the package in the first
place can be used to decrypt the message - Which is kind of the whole point with public key cryptography. Also,
to retrieve a string encrypted such as we do above, you'll have to convert the `byte[]` array returned from `Decrypt`
to a string using e.g. `Encoding.UTF8.GetString(decrypted)`.

### Cryptographic signatures

To sign a message, implies giving the receiver a guarantee of that the message originated from whoever owns the
private key. Hence, the signature is created using the _private_ key, and verification can be done only with the _public_
key. Below is an example that first signs the text _"Hello World"_ with a private key, for then to verify the signature
afterwards using the public key.

```csharp
using magic.crypto.rsa;

// Creating a signature of the text "Hello World".
var signer = new Signer(key.PrivateKey);
var signature = signer.Sign(Encoding.UTF8.GetBytes("Hello World"));

// Verifying the signature is valid.
var verifier = new Verifier(key.PublicKey);
verifier.Verify(Encoding.UTF8.GetBytes("Hello World"), signature);
```

If the signature does not match, the `Verify` method will throw an exception.

### AES cryptography

AES is _"symmetric cryptography"_ implying the same key is used for encrypting things, as is used for decrypting
the same package. It is typically used in combination with assymetric cryptography, with a CSRNG generated session
key, which is assymetrically encrypted using a public key. However, you can also use the AES classes as standalone
classes to encrypt some package symmetrically if you wish. Below is an example.

```csharp
using magic.crypto.aes;

// Creating en encrypter with a key of "foo", encrypting the text "Hello World".
var encrypter = new Encrypter("foo");
var encrypted = encrypter.Encrypt(Encoding.UTF8.GetBytes("Hello World"));

// Creating a decrypter with a key of "foo" to decrypt the above data.
var decrypter = new aes.Decrypter("foo");
var decrypted = decrypter.Decrypt(encrypted);
```

Yet again, the `Decrypt` method from above will return `byte[]`, which needs to be converted into a string
using e.g. `Encoding.UTF8.GetString(decrypted)` - Which of course only works if the original payload
you encrypted actually _was a string_.

#### Notes about keys and keyphrases

The above code uses a _"keyphrase"_. Internally what occurs is that magic.crypto creates a SHA256 byte array
of the specified keyphrase, which is actually used to encrypt the package. This is just a convenience overload,
allowing you to use AES with keyphrases instead of manually having to create a 256bit `byte[]` array every time
you want to encrypt and decrypt things using AES.

### Combination examples

This is where things gets interesting, since only by _combining_ AES and RSA you can really take advantage
of public key cryptography, to transmit packages securely over an inheritingly insecure channel, such as the
internet for instance. The way this works, is that your actual message is _symmetrically_ encrypted, using a
CSRNG generated key (random key). Then the key is assymmetrically encrypted at the top of the package, using
the public key, and the key's fingerprint is prepended as the first 256 bits.

This allows you to retrieve the fingerprint of the key that was used to encrypt the package, lookup the private
key using the fingerprint, and then decrypt it in the other end, all in one go - Without having to fiddle
with hundreds of different classes and methods from BouncyCastle.

```csharp
using magic.crypto.combinations;

// Encrypting a message.
var encrypter = new Encrypter(key.PublicKey);
var encrypted = encrypter.Encrypt(Encoding.UTF8.GetBytes("Hello world"));

// Decrypting the message.
var decrypter = new Decrypter(key.PrivateKey);
var decrypted = decrypter.Decrypt(encrypted);
```

This is where magic.crypto really starts to shine, since the simplicity of combining RSA with AES encryption,
becomes really simple to use. Manually doing the above using BouncyCastle would probably be beyond what most
could accomplish, without compromising security somehow. Likewise magic.crypto also have combination classes
for signing a message, and returning the whole message as a cryptographically signed message, with the key's
fingerprint, the message itself, and the signature. Below is an example of the latter.

```csharp
using magic.crypto.combinations;

// Creating a signed message.
var signer = new Signer(key.PrivateKey, key.FingerprintRaw);
var signature = signer.Sign(Encoding.UTF8.GetBytes("Hello World"));

// Verifying the message, and its signature.
var verifier = new Verifier(key.PublicKey);
verifier.Verify(signature);
```

Combining the above methods and classes allows you to rapidly create encrypted and cryptographically signed
messages, and securely transmit them to your recipients. The way you would typically do this, is by first signing
your message using your own private key, then encrypt the result from the signing invocation, before transmitting
the package to your recipient.

Your recipient could then use the `Utilities.GetPackageFingerprint` from the `magic.crypto.utilities` namespace
to retrieve the key that was used to encrypt the package, lookup the private key associated with the returned
fingerprint, decrypt the message, and use the `Utilities.GetPackageFingerprint` method again on the decrypted
package, to see which key was used to cryptographically sign the message.

This _"two layer"_ process allows _only_ the recipient who owns the private decryption key to even see who the
message originated from, since the signature itself is decrypted. This process would resemble the following.

```csharp
using magic.crypto.combinations;

// Signing content.
var signer = new Signer(signingKey, signingKeyFingerprint);
var signed = signer.Sign(arguments.Content);

// Encrypting content.
var encrypter = new Encrypter(encryptionKey);
var rawResult = encrypter.Encrypt(signed);
```

In the above example `signingKey` would be your private key, and the `signingKeyFingerprint` would be
the fingerprint of your keypair. The above `encryptionKey` is the _public_ key of the recipient. The `rawResult`
is the `byte[]` result wrapping both your encrypted content, your signature, and your key's fingerprint, in
addition to the recipient's key's fingerprint. The only thing that's visible in the package though, is
the fingerprint of the recipient's key. Everything else is hidden behind cryptography. The recipient again
would typically use something such as follows to decrypt it, assuming he knows which key the package was
encrypted for, and which key that was used to sign the package.

```csharp
using magic.crypto.combinations

// Decrypting content.
var decrypter = new Decrypter(decryptionKey);
var result = decrypter.Decrypt(content);

// Verifying signature.
var verifier = new Verifier(verifyKey);
result = verifier.Verify(result);
```

In the above, the `result` will be the raw `byte[]` array of the original message, and if the signature doesn't match,
an exception will be thrown. Of course, the above implies you _know_ which key the package was encrypted for, and who
signed it. If you don't know this, you can inspect the package using `Utilities.GetPackageFingerprint` from the
`magic.crypto.utilities` namespace. You can use this both on the original encrypted package to find the encryption key,
and on the resulting decrypted package to find the signing key. Below is some partial code, where you need to implement
the `GetPrivateKey` method and the `GetPublicKey` method that illustrate this process.

```csharp
using magic.crypto.combinations

// Decrypting content.
var decrypter = new Decrypter(GetPrivateKey(content));
var result = decrypter.Decrypt(content);

// Verifying signature.
var verifier = new Verifier(GetPublicKey(result));
result = verifier.Verify(result);
```

Typically you'd persist public keys in some database, while your own private key somewhere else, slightly more secure
hopefully. Then internally the `GetPrivateKey` and the `GetPublicKey` above would be using `Utilities.GetPackageFingerprint`
to lookup the key's fingerprint, then invoke `Utilities.CreateFingerprint` on the result returned from `GetPackageFingerprint`,
and use the returned string to lookup the key somehow, from for instance a database, etc.

## Quality gates

- [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.crypto&metric=alert_status)](https://sonarcloud.io/dashboard?id=polterguy_magic.crypto)
- [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.crypto&metric=bugs)](https://sonarcloud.io/dashboard?id=polterguy_magic.crypto)
- [![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.crypto&metric=code_smells)](https://sonarcloud.io/dashboard?id=polterguy_magic.crypto)
- [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.crypto&metric=coverage)](https://sonarcloud.io/dashboard?id=polterguy_magic.crypto)
- [![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.crypto&metric=duplicated_lines_density)](https://sonarcloud.io/dashboard?id=polterguy_magic.crypto)
- [![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.crypto&metric=ncloc)](https://sonarcloud.io/dashboard?id=polterguy_magic.crypto)
- [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.crypto&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=polterguy_magic.crypto)
- [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.crypto&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=polterguy_magic.crypto)
- [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.crypto&metric=security_rating)](https://sonarcloud.io/dashboard?id=polterguy_magic.crypto)
- [![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.crypto&metric=sqale_index)](https://sonarcloud.io/dashboard?id=polterguy_magic.crypto)
- [![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.crypto&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=polterguy_magic.crypto)
