/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using magic.crypto.utilities;

namespace magic.crypto.rsa
{
    /// <summary>
    /// Helper class that allows you to generate an RSA key pair.
    /// </summary>
    public class KeyGenerator
    {
        readonly SecureRandom _csrng;

        /// <summary>
        /// Creates a new instance of your class
        /// </summary>
        /// <param name="seed">Seed to use for the CSRNG</param>
        public KeyGenerator(byte[] seed = null)
        {
            _csrng = new SecureRandom();
            if (seed != null)
                _csrng.SetSeed(seed);
        }

        /// <summary>
        /// Creates a new RSA key pair for you, using the specified arguments.
        /// </summary>
        /// <param name="strength">Key strength for your kew, typically 1024, 2048 4096, etc</param>
        /// <returns>The newly created key pair</returns>
        public KeyPair Generate(int strength)
        {
            var generator = new RsaKeyPairGenerator();
            generator.Init(new KeyGenerationParameters(_csrng, strength));

            // Creating keypair.
            var keyPair = generator.GenerateKeyPair();
            var privateInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            var publicInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);

            // Returning key pair according to caller's specifications.
            var publicKey = publicInfo.GetDerEncoded();
            var fingerprint = Utilities.CreateSha256Fingerprint(publicKey);
            var fingerprintRaw = Utilities.CreateSha256(publicKey);

            // Returning as DER encoded raw byte[].
            return new KeyPair(publicKey, privateInfo.GetDerEncoded(), fingerprint, fingerprintRaw);
        }
    }
}
