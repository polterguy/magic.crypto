﻿/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;

namespace magic.crypto.rsa
{
    /// <summary>
    /// Helper class to decrypt a message using RSA encryption.
    /// </summary>
    public class Decrypter
    {
        readonly AsymmetricKeyParameter _privateRsaKey;

        /// <summary>
        /// Creates a new instance of the class.
        /// </summary>
        /// <param name="privateRsaKey">Private RSA key used to decrypt the message(s)</param>
        public Decrypter(byte[] privateRsaKey)
        {
            _privateRsaKey = PrivateKeyFactory.CreateKey(privateRsaKey);
        }

        /// <summary>
        /// Decrypts the specified message, using the private RSA key supplied during creation of instance.
        /// </summary>
        /// <param name="message">Encrypted message</param>
        /// <returns>Decrypted message</returns>
        public byte[] Decrypt(byte[] message)
        {
            // Creating our encryption engine, and decorating according to caller's specifications.
            var encryptEngine = new Pkcs1Encoding(new RsaEngine());
            encryptEngine.Init(false, _privateRsaKey);

            // Decrypting message, and returning results to according to caller's specifications.
            var result = encryptEngine.ProcessBlock(message, 0, message.Length);
            return result;
        }
    }
}
