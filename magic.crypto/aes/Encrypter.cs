/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System.IO;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace magic.crypto.aes
{
    /// <summary>
    /// AES encrypter class, allowing you to encrypt some message with AES.
    /// </summary>
    public class Encrypter
    {
        readonly byte[] _symmetricKey;

        /// <summary>
        /// Creates a new AES encrypter, allowing you to encrypt one or more packages
        /// using the specified key.
        /// </summary>
        /// <param name="symmetricKey">Encryption key to use encryption operation(s)</param>        
        public Encrypter(byte[] symmetricKey)
        {
            _symmetricKey = symmetricKey;
        }

        /// <summary>
        /// Encrypts the specified message, using the key supplied during creation of instance.
        /// </summary>
        /// <param name="message">Plain text message you want to encrypt</param>
        /// <returns>Encrypted message</returns>
        public byte[] Encrypt(byte[] message)
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
    }
}
