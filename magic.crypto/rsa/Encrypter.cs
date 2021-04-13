/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2021, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using magic.crypto.utilities;

namespace magic.crypto.rsa
{
    /// <summary>
    /// Helper class to encrypt some message(s) using RSA cryptography
    /// </summary>
    public class Encrypter : EncrypterBase
    {
        readonly AsymmetricKeyParameter _publicRsaKey;

        /// <summary>
        /// Creates a new instance of the encrypter.
        /// </summary>
        /// <param name="publicRsaKey">Public RSA key used to encrypt the message(s)</param>
        public Encrypter(byte[] publicRsaKey)
        {
            _publicRsaKey = PublicKeyFactory.CreateKey(publicRsaKey);
        }

        #region [ -- Implementation of abstract base class -- ]

        /// <inheritdoc />
        protected override byte[] EncryptImplementation(byte[] message)
        {
            // Creating our encryption engine, and decorating according to caller's specifications.
            var encryptionEngine = new Pkcs1Encoding(new RsaEngine());
            encryptionEngine.Init(true, _publicRsaKey);

            // Encrypting message, and returning results to according to caller's specifications.
            var result = encryptionEngine.ProcessBlock(message, 0, message.Length);
            return result;
        }

        #endregion
    }
}
