﻿/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2021, thomas@servergardens.com, all rights reserved.
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

        /// <summary>
        /// The SHA256 of your public key.
        /// </summary>
        /// <value>The SHA256 value of your public RSA key</value>
        public byte[] FingerprintRaw { get; private set; }

        internal KeyPair(
            byte[] publicKey,
            byte[] privateKey,
            string fingerprint,
            byte[] fingerprintRaw)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
            Fingerprint = fingerprint;
            FingerprintRaw = fingerprintRaw;
        }
    }
}
