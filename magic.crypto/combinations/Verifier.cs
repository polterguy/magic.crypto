/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System.IO;
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

        /*
         * Creates a new instance of class.
         */
        public Verifier(byte[] publicKey)
        {
            _publicKey = publicKey;
        }

        /*
         * Decrypts the specified message.
         */
        public Message Verify(byte[] content)
        {
            // Reading decrypted content and returning results to caller.
            using (var stream = new MemoryStream(content))
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

                // Returning a new message to caller, encapsulating decrypted message.
                return new Message(result, signature, fingerprint);
            }
        }
    }
}
