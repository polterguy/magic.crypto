/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2021, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Security;
using magic.crypto.utilities;

namespace magic.crypto.combinations
{
    /// <summary>
    /// Encrypter helper class, allowing you to combine RSA and AES cryptography, to create an
    /// encrypted package.
    /// </summary>
    public class Encrypter
    {
        readonly byte[] _encryptionKey;
        readonly SecureRandom _csrng;

        /// <summary>
        /// Creates a new instance with the specified seed and encryption key.
        /// </summary>
        /// <param name="encryptionKey">Public RSA key to use for encryption operation(s)</param>
        /// <param name="seed">Seed to use for the CSRNG used to generate a random AES key</param>
        public Encrypter(byte[] encryptionKey, byte[] seed = null)
        {
            // Creating our CS RNG instance.
            _csrng = new SecureRandom();
            if (seed != null)
                _csrng.SetSeed(seed);

            _encryptionKey = encryptionKey;
        }

        #region [ -- Overloaded API methods -- ]

        /// <summary>
        /// Encrypts the specified message, using the arguments provided during creation of instance.
        /// </summary>
        /// <param name="message">Message to encrypt</param>
        /// <returns>Encrypted message</returns>
        public byte[] Encrypt(byte[] message)
        {
            return EncryptImplementation(message);
        }

        /// <summary>
        /// Encrypts the specified message, using the arguments provided during creation of instance.
        /// </summary>
        /// <param name="message">Message to encrypt</param>
        /// <returns>Encrypted message</returns>
        public byte[] Encrypt(string message)
        {
            return EncryptImplementation(Encoding.UTF8.GetBytes(message));
        }

        /// <summary>
        /// Encrypts the specified message, using the arguments provided during creation of instance.
        /// </summary>
        /// <param name="message">Message to encrypt</param>
        /// <returns>Encrypted message base64 encoded</returns>
        public string EncryptToString(byte[] message)
        {
            return Convert.ToBase64String(EncryptImplementation(message));
        }

        /// <summary>
        /// Encrypts the specified message, using the arguments provided during creation of instance.
        /// </summary>
        /// <param name="message">Message to encrypt</param>
        /// <returns>Encrypted message base64 encoded</returns>
        public string EncryptToString(string message)
        {
            return Convert.ToBase64String(EncryptImplementation(Encoding.UTF8.GetBytes(message)));
        }

        #endregion

        #region [ -- Private helper methods -- ]

        byte[] EncryptImplementation(byte[] message)
        {
            // Creating encryption stream.
            using (var encStream = new MemoryStream())
            {
                // Simplifying life.
                var encWriter = new BinaryWriter(encStream);

                // Writing encryption key's fingerprint.
                var fingerprint = Utilities.CreateSha256(_encryptionKey);
                encWriter.Write(fingerprint);

                // Writing encrypted AES key.
                var aesKey = CreateAesKey();
                var rsaEncrypter = new rsa.Encrypter(_encryptionKey); 
                var encryptedAesKey = rsaEncrypter.Encrypt(aesKey);
                encWriter.Write(encryptedAesKey.Length);
                encWriter.Write(encryptedAesKey);

                // Writing encrypted content.
                var aesEcnrypter = new aes.Encrypter(aesKey);
                var encrypted = aesEcnrypter.Encrypt(message);
                encWriter.Write(encrypted);
                return encStream.ToArray();
            }
        }

        /*
         * Creates a symmetric AES encryption key, to encrypt payload.
         */
        byte[] CreateAesKey()
        {
            var bytes = new byte[32];
            _csrng.NextBytes(bytes);
            return bytes;
        }

        #endregion
    }
}
