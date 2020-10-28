/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using Xunit;
using magic.crypto.rsa;

namespace magic.crypto.tests
{
    public class CryptoTests
    {
        [Fact]
        public void CreateKeyPair()
        {
           var generator = new KeyGenerator();
           var key = generator.Generate(1024);
        }
    }
}
