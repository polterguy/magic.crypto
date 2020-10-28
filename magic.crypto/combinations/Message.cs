/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

namespace magic.crypto.combinations
{
    /// <summary>
    /// Helper POCO class used by some other classes, to separate
    /// between a signature, signing key's fingerprint, and the message itself.
    /// </summary>
    public class Message
    {
        /// <summary>
        /// Returns the message content.
        /// </summary>
        public readonly byte[] Content;

        /// <summary>
        /// Returns the signature.
        /// </summary>
        public readonly byte[] Signature;

        /// <summary>
        /// Returns the fingerprint of the public key associated with the private key used to sign the message.
        /// </summary>
        public readonly string Fingerprint;

        /// <summary>
        /// Creates a new instance of your message, with the specified arguments.
        /// </summary>
        /// <param name="content">Actual content of message</param>
        /// <param name="signature">Signature</param>
        /// <param name="fingerprint">Fingerprint of public key assosiated with private key used to sign message</param>
        public Message(
            byte[] content,
            byte[] signature,
            string fingerprint)
        {
            Content = content;
            Signature = signature;
            Fingerprint = fingerprint;
        }
    }
}
