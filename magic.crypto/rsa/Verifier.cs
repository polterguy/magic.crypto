/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace magic.crypto.rsa
{
    /*
     * Utility class to provide common functions for other classes and methods.
     */
    public class Verifier
    {
        readonly AsymmetricKeyParameter _key;
        
        public Verifier(byte[] key)
        {
            _key = PublicKeyFactory.CreateKey(key);
        }

        /*
         * Verifies a cryptographic signature, according to caller's specifications.
         */
        public void Verify(string algo, byte[] message, byte[] signature)
        {
            // Creating our signer and associating it with the private key.
            var signer = SignerUtilities.GetSigner($"{algo}withRSA");
            signer.Init(false, _key);

            // Signing the specified data, and returning to caller as base64.
            signer.BlockUpdate(message, 0, message.Length);
            if (!signer.VerifySignature(signature))
                throw new ArgumentException("Signature mismatch");
        }
    }
}
