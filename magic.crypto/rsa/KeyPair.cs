/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

namespace magic.crypto.rsa
{
    /// <summary>
    /// POCO class encapsulating an RSA key pair.
    /// </summary>
    public class KeyPair
    {
        /// <summary>
        /// The public RSA key
        /// </summary>
        /// <value>The byte[] representation of your public RSA key</value>
        public byte[] PublicKey { get; private set; }

        /// <summary>
        /// The private RSA key
        /// </summary>
        /// <value>The byte[] representation of your private RSA key</value>
        public byte[] PrivateKey { get; private set; }

        /// <summary>
        /// The fingerprint for your public RSA key.
        /// </summary>
        /// <value>The fingerprint representation of your public RSA key</value>
        public string Fingerprint { get; private set; }

        internal KeyPair(byte[] publicKey, byte[] privateKey, string fingerprint)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
            Fingerprint = fingerprint;
        }
    }
}
