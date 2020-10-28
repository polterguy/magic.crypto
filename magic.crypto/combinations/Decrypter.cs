/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.IO;
using System.Text;
using magic.crypto.utilities;

namespace magic.crypto.combinations
{
    /// <summary>
    /// Helper class allowing you to combine AES and RSA cryptography, decrypting
    /// a previously encrypted message, that was encrypted using the Encrypter equivalent.
    /// </summary>
    public class Decrypter
    {
        readonly byte[] _rsaPrivateKey;

        /// <summary>
        /// Creates a new instance, allowing you to decrypt messages, using the
        /// specified private RSA key.
        /// </summary>
        /// <param name="rsaPrivateKey">Private RSA key to use for decryption</param>
        public Decrypter(byte[] rsaPrivateKey)
        {
            _rsaPrivateKey = rsaPrivateKey;
        }

        #region [ -- Overloaded API methods -- ]

        /// <summary>
        /// Decrypts a message previously encrypted with the Encrypter equivalent.
        /// </summary>
        /// <param name="message">Encrypted message you want to decrypt</param>
        /// <returns>Decrypted message</returns>
        public byte[] Decrypt(byte[] message)
        {
            return DecryptImplementation(message);
        }

        /// <summary>
        /// Decrypts a message previously encrypted with the Encrypter equivalent.
        /// </summary>
        /// <param name="message">Encrypted message you want to decrypt in base64 encoded format</param>
        /// <returns>Decrypted message</returns>
        public byte[] Decrypt(string message)
        {
            return DecryptImplementation(Convert.FromBase64String(message));
        }

        /// <summary>
        /// Decrypts a message previously encrypted with the Encrypter equivalent.
        /// </summary>
        /// <param name="message">Encrypted message you want to decrypt</param>
        /// <returns>Decrypted message</returns>
        public string DecryptToString(byte[] message)
        {
            return Encoding.UTF8.GetString(DecryptImplementation(message));
        }

        /// <summary>
        /// Decrypts a message previously encrypted with the Encrypter equivalent.
        /// </summary>
        /// <param name="message">Encrypted message you want to decrypt in base64 encoded format</param>
        /// <returns>Decrypted message</returns>
        public string DecryptToString(string message)
        {
            return Encoding.UTF8.GetString(DecryptImplementation(Convert.FromBase64String(message)));
        }

        #endregion

        #region [ -- Private helper methods -- ]

        byte[] DecryptImplementation(byte[] message)
        {
            // Creating decryption stream.
            using (var encStream = new MemoryStream(message))
            {
                // Simplifying life.
                var encReader = new BinaryReader(encStream);

                // Discarding encryption key's fingerprint.
                encReader.ReadBytes(32);

                // Reading encrypted AES key.
                var encryptedAesKey = encReader.ReadBytes(encReader.ReadInt32());

                // Decrypting AES key.
                var rsaDecrypter = new rsa.Decrypter(_rsaPrivateKey);
                var decryptedAesKey = rsaDecrypter.Decrypt(encryptedAesKey);

                // Reading the encrypted content.
                var encryptedContent = Utilities.ReadRestOfStream(encStream);

                // Decrypting content.
                var aesDecrypter = new aes.Decrypter(decryptedAesKey);
                var decryptedContent = aesDecrypter.Decrypt(encryptedContent);
                return decryptedContent;
            }
        }

        #endregion
    }
}
