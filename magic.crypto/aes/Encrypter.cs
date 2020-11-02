/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using magic.crypto.utilities;

namespace magic.crypto.aes
{
    /// <summary>
    /// AES encrypter class, allowing you to encrypt some message with AES.
    /// </summary>
    public class Encrypter
    {
        readonly byte[] _symmetricKey;

        #region [ -- Constructors -- ]

        /// <summary>
        /// Creates a new AES encrypter, allowing you to encrypt one or more packages
        /// using the specified key.
        /// </summary>
        /// <param name="symmetricKey">Encryption key to use encryption operation(s). Will be converted to byte[32] using SHA256.</param>        
        public Encrypter(string symmetricKey)
        {
            _symmetricKey = Utilities.CreateSha256(Encoding.UTF8.GetBytes(symmetricKey));
        }

        /// <summary>
        /// Creates a new AES encrypter, allowing you to encrypt one or more packages
        /// using the specified key.
        /// </summary>
        /// <param name="symmetricKey">Encryption key to use encryption operation(s)</param>        
        public Encrypter(byte[] symmetricKey)
        {
            _symmetricKey = symmetricKey;
        }

        #endregion

        #region [ -- Overloaded API methods -- ]

        /// <summary>
        /// Encrypts the specified message, using the key supplied during creation of instance.
        /// </summary>
        /// <param name="message">Plain text message you want to encrypt</param>
        /// <returns>Encrypted message</returns>
        public byte[] Encrypt(byte[] message)
        {
            return EncryptImplementation(message);
        }

        /// <summary>
        /// Encrypts the specified message, using the key supplied during creation of instance.
        /// </summary>
        /// <param name="message">Plain text message you want to encrypt</param>
        /// <returns>Encrypted message</returns>
        public byte[] Encrypt(string message)
        {
            return EncryptImplementation(Encoding.UTF8.GetBytes(message));
        }

        /// <summary>
        /// Encrypts the specified message, using the key supplied during creation of instance.
        /// </summary>
        /// <param name="message">Plain text message you want to encrypt</param>
        /// <returns>Encrypted message in base64 encoded format</returns>
        public string EncryptToString(byte[] message)
        {
            return Convert.ToBase64String(EncryptImplementation(message));
        }

        /// <summary>
        /// Encrypts the specified message, using the key supplied during creation of instance.
        /// </summary>
        /// <param name="message">Plain text message you want to encrypt</param>
        /// <returns>Encrypted message in base64 encoded format</returns>
        public string EncryptToString(string message)
        {
            return Convert.ToBase64String(EncryptImplementation(Encoding.UTF8.GetBytes(message)));
        }

        #endregion

        #region [ -- Private helper methods -- ]

        /// <summary>
        /// Encrypts the specified message, using the key supplied during creation of instance.
        /// </summary>
        /// <param name="message">Plain text message you want to encrypt</param>
        /// <returns>Encrypted message</returns>
        byte[] EncryptImplementation(byte[] message)
        {
            // Creating our nonce, or Initial Vector (IV).
            var rnd = new SecureRandom();
            var nonce = new byte[Constants.NONCE_SIZE];
            rnd.NextBytes(nonce, 0, nonce.Length);

            // Initializing AES engine.
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(_symmetricKey), Constants.MAC_SIZE, nonce, null);
            cipher.Init(true, parameters);

            // Creating buffer to hold encrypted content, and encrypting into buffer.
            var encrypted = new byte[cipher.GetOutputSize(message.Length)];
            var len = cipher.ProcessBytes(message, 0, message.Length, encrypted, 0);
            cipher.DoFinal(encrypted, len);

            // Writing nonce and encrypted data, and returning as byte[] to caller.
            using (var stream = new MemoryStream())
            {
                using (var writer = new BinaryWriter(stream))
                {
                    writer.Write(nonce);
                    writer.Write(encrypted);
                }
                return stream.ToArray();
            }
        }

        #endregion
    }
}
