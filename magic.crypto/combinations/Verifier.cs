/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2021, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.IO;
using System.Text;
using magic.crypto.utilities;

namespace magic.crypto.combinations
{
    /// <summary>
    /// Helper class to verify the signature of a message that was previously signed
    /// using the Signer equivalent.
    /// </summary>
    public class Verifier
    {
        readonly byte[] _publicKey;

        /// <summary>
        /// Creates a new instance of your class.
        /// </summary>
        /// <param name="publicKey">Public RSA key to use to verify the integrity of the message</param>
        public Verifier(byte[] publicKey)
        {
            _publicKey = publicKey;
        }

        #region [ -- Overloaded API methods -- ]

        /// <summary>
        /// Verifies the integrity of a cryptographically signed message.
        /// 
        /// Notice, will throw an exception if signature is not a match.
        /// </summary>
        /// <param name="message">Byte representation of a message previously signed with the Signer equivalent</param>
        /// <returns>The raw message, without the signature and fingerprint of the signing key used to sign the package</returns>
        public byte[] Verify(byte[] message)
        {
            return VerifyImplementation(message);
        }

        /// <summary>
        /// Verifies the integrity of a cryptographically signed message.
        /// 
        /// Notice, will throw an exception if signature is not a match.
        /// </summary>
        /// <param name="message">Base64 representation of a message previously signed with the Signer equivalent</param>
        /// <returns>The raw message, without the signature and fingerprint of the signing key used to sign the package</returns>
        public byte[] Verify(string message)
        {
            return VerifyImplementation(Convert.FromBase64String(message));
        }

        /// <summary>
        /// Verifies the integrity of a cryptographically signed message.
        /// 
        /// Notice, will throw an exception if signature is not a match.
        /// </summary>
        /// <param name="message">Byte representation of a message previously signed with the Signer equivalent</param>
        /// <returns>The raw message, without the signature and fingerprint of the signing key used to sign the package</returns>
        public string VerifyToString(byte[] message)
        {
            return Encoding.UTF8.GetString(VerifyImplementation(message));
        }

        /// <summary>
        /// Verifies the integrity of a cryptographically signed message.
        /// 
        /// Notice, will throw an exception if signature is not a match.
        /// </summary>
        /// <param name="message">Base64 representation of a message previously signed with the Signer equivalent</param>
        /// <returns>The raw message, without the signature and fingerprint of the signing key used to sign the package</returns>
        public string VerifyToString(string message)
        {
            return Encoding.UTF8.GetString(VerifyImplementation(Convert.FromBase64String(message)));
        }

        #endregion

        #region [ -- Private helper methods -- ]

        byte[] VerifyImplementation(byte[] message)
        {
            // Reading decrypted content and returning results to caller.
            using (var stream = new MemoryStream(message))
            {
                // Simplifying life.
                var reader = new BinaryReader(stream);

                // Reading signing key.
                var signingKey = reader.ReadBytes(32);
                var fingerprint = Utilities.CreateFingerprint(signingKey);

                // Reading signature.
                var lengthOfSignature = reader.ReadInt32();
                var signature = reader.ReadBytes(lengthOfSignature);

                // Reading decrypted content.
                var result = Utilities.ReadRestOfStream(stream);

                // Verifying signature.
                var rsaVerifier = new rsa.Verifier(_publicKey);
                rsaVerifier.Verify(result, signature);

                // Returning only the content of the message to the caller.
                return result;
            }
        }

        #endregion
    }
}
