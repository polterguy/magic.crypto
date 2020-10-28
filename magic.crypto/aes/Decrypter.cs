/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using magic.crypto.utilities;

namespace magic.crypto.aes
{
    /// <summary>
    /// AES decrypter class that helps you decrypt an AES message.
    /// </summary>
    public class Decrypter
    {
        readonly byte[] _symmetricKey;

        #region [ -- Constructors -- ]

        /// <summary>
        /// Creates a new AES encrypter, allowing you to encrypt one or more packages
        /// using the specified key.
        /// </summary>
        /// <param name="symmetricKey">Encryption key to use for encryption operation(s). The key will be converted to byte[32] using SHA256.</param>
        public Decrypter(string symmetricKey)
        {
            _symmetricKey = Utilities.CreateSha256(Encoding.UTF8.GetBytes(symmetricKey));
        }

        /// <summary>
        /// Creates a new AES decrypter, allowing you to decrypt one or more packages
        /// using the specified key.
        /// </summary>
        /// <param name="symmetricKey">Key to use for decryption operation(s)</param>
        public Decrypter(byte[] symmetricKey)
        {
            _symmetricKey = symmetricKey;
        }

        #endregion

        #region [ -- Overloaded API methods -- ]

        /// <summary>
        /// Decrypts the specified data with the key supplied during creation of instance.
        /// 
        /// Notice, will throw an exception if the key is not the same key the package was encrypted with.
        /// </summary>
        /// <param name="message">The message you want to decrypt</param>
        /// <returns>Decrypted message</returns>
        public byte[] Decrypt(byte[] message)
        {
            return DecryptImplementation(message);
        }

        /// <summary>
        /// Decrypts the specified data with the key supplied during creation of instance,
        /// assuming string is the base64 encoded result of an AES encrypt operation.
        /// 
        /// Notice, will throw an exception if the key is not the same key the package was encrypted with.
        /// </summary>
        /// <param name="message">The base64 encoded message you want to decrypt</param>
        /// <returns>Decrypted message</returns>
        public byte[] Decrypt(string message)
        {
            return DecryptImplementation(Convert.FromBase64String(message));
        }

        /// <summary>
        /// Decrypts the specified message and converts to string, assuming content
        /// is UTF8 bytes.
        /// 
        /// Notice, will throw an exception if the key is not the same key the package was encrypted with.
        /// </summary>
        /// <param name="message">The message you want to decrypt</param>
        /// <returns>Decrypted message</returns>
        public string DecryptToString(byte[] message)
        {
            return Encoding.UTF8.GetString(DecryptImplementation(message));
        }

        /// <summary>
        /// Decrypts the specified message and converts to string, assuming content
        /// is UTF8 bytes.
        /// 
        /// Notice, will throw an exception if the key is not the same key the package was encrypted with.
        /// </summary>
        /// <param name="message">The message you want to decrypt</param>
        /// <returns>Decrypted message</returns>
        public string DecryptToString(string message)
        {
            return Encoding.UTF8.GetString(DecryptImplementation(Convert.FromBase64String(message)));
        }

        #endregion

        #region [ -- Private helper methods -- ]

        byte[] DecryptImplementation(byte[] message)
        {
            using (var stream = new MemoryStream(message))
            {
                using (var reader = new BinaryReader(stream))
                {
                    // Reading and discarding nonce.
                    var nonce = reader.ReadBytes(Constants.NONCE_SIZE);

                    // Creating and initializing AES engine.
                    var cipher = new GcmBlockCipher(new AesEngine());
                    var parameters = new AeadParameters(new KeyParameter(_symmetricKey), Constants.MAC_SIZE, nonce, null);
                    cipher.Init(false, parameters);

                    // Reading encrypted parts, and decrypting into result.
                    var encrypted = reader.ReadBytes(message.Length - nonce.Length);
                    var result = new byte[cipher.GetOutputSize(encrypted.Length)];
                    var len = cipher.ProcessBytes(encrypted, 0, encrypted.Length, result, 0);
                    cipher.DoFinal(result, len);

                    // Returning result as byte[].
                    return result;
                }
            }
        }

        #endregion
    }
}
