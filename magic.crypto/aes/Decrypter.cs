/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System.IO;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace magic.crypto.aes
{
    /// <summary>
    /// AES decrypter class that helps you decrypt an AES message.
    /// </summary>
    public class Decrypter
    {
        readonly byte[] _symmetricKey;

        /// <summary>
        /// Creates a new AES decrypter, allowing you to decrypt one or more packages
        /// using the specified key.
        /// </summary>
        /// <param name="symmetricKey">Key to use for decryption operation(s)</param>
        public Decrypter(byte[] symmetricKey)
        {
            _symmetricKey = symmetricKey;
        }

        /// <summary>
        /// Decrypts the specified data with the key supplied during creation of instance.
        /// Notice, will throw an exception if the key is not the same key the package was encrypted with.
        /// </summary>
        /// <param name="message">The message you want to decrypt</param>
        /// <returns>Decrypted message</returns>
        public byte[] Decrypt(byte[] message)
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
    }
}
