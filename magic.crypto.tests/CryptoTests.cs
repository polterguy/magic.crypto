/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Text;
using Xunit;
using Org.BouncyCastle.Crypto;
using magic.crypto.rsa;

namespace magic.crypto.tests
{
    public class CryptoTests
    {
        [Fact]
        public void CreateKeyPair_1024()
        {
           var generator = new KeyGenerator();
           var key = generator.Generate(1024);
           Assert.Equal(79, key.Fingerprint.Length);
           Assert.True(key.PrivateKey.Length > 550 && key.PrivateKey.Length < 700);
           Assert.True(key.PublicKey.Length > 100 && key.PublicKey.Length < 200);
        }

        [Fact]
        public void CreateKeyPair_2048()
        {
           var generator = new KeyGenerator();
           var key = generator.Generate(2048);
           Assert.Equal(79, key.Fingerprint.Length);
           Assert.True(key.PrivateKey.Length > 1100 && key.PrivateKey.Length < 1400);
           Assert.True(key.PublicKey.Length > 250 && key.PublicKey.Length < 350);
        }

        [Fact]
        public void EncryptDecrypt_RSA()
        {
           var generator = new KeyGenerator();
           var key = generator.Generate(1024);

           var encrypter = new Encrypter(key.PublicKey);
           var encrypted = encrypter.Encrypt(Encoding.UTF8.GetBytes("Hello World"));

           var decrypter = new Decrypter(key.PrivateKey);
           var decrypted = decrypter.Decrypt(encrypted);

           Assert.Equal("Hello World", Encoding.UTF8.GetString(decrypted));
        }

        [Fact]
        public void Sign_RSA()
        {
           var generator = new KeyGenerator();
           var key = generator.Generate(1024);

           var signer = new Signer(key.PrivateKey);
           var signature = signer.Sign(Encoding.UTF8.GetBytes("Hello World"));

           var verifier = new Verifier(key.PublicKey);
           verifier.Verify(Encoding.UTF8.GetBytes("Hello World"), signature);
        }

        [Fact]
        public void Sign_RSA_Throws()
        {
           var generator = new KeyGenerator();
           var key = generator.Generate(1024);

           var signer = new Signer(key.PrivateKey);
           var signature = signer.Sign(Encoding.UTF8.GetBytes("Hello World"));

           var verifier = new Verifier(key.PublicKey);
           Assert.Throws<ArgumentException>(() => verifier.Verify(Encoding.UTF8.GetBytes("Hello XWorld"), signature));
        }

        [Fact]
        public void EncryptDecrypt_AES_Bytes()
        {
            var encrypter = new aes.Encrypter("foo");
            var encrypted = encrypter.Encrypt(Encoding.UTF8.GetBytes("Hello World"));

            var decrypter = new aes.Decrypter("foo");
            var decrypted = decrypter.Decrypt(encrypted);

            Assert.Equal("Hello World", Encoding.UTF8.GetString(decrypted));
        }

        [Fact]
        public void EncryptDecrypt_AES_String()
        {
            var encrypter = new aes.Encrypter("foo");
            var encrypted = encrypter.EncryptToString("Hello World");

            var decrypter = new aes.Decrypter("foo");
            var decrypted = decrypter.DecryptToString(encrypted);

            Assert.Equal("Hello World", decrypted);
        }

        [Fact]
        public void EncryptDecrypt_AES_Throws()
        {
            var encrypter = new aes.Encrypter("foo");
            var encrypted = encrypter.Encrypt(Encoding.UTF8.GetBytes("Hello World"));

            var decrypter = new aes.Decrypter("fooX");
            Assert.Throws<InvalidCipherTextException>(() => decrypter.Decrypt(encrypted));
        }
    }
}
