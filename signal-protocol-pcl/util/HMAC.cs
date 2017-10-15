/** 
 * Copyright (C) 2016 smndtrl, langboost
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using PCLCrypto;

namespace WhisperSystems.Libsignal.Util
{
    public class Sign
    {
        public static byte[] Sha256Sum(byte[] key, byte[] message)
        {
            IMacAlgorithmProvider provider = WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha256);
            ICryptographicKey hmacKey = provider.CreateKey(key);
            byte [] hmac = WinRTCrypto.CryptographicEngine.Sign(hmacKey, message);
            return hmac;
        }
    }

    public class Sha256
    {
        public static byte[] Sign(byte[] key, byte[] message)
        {
            IMacAlgorithmProvider provider = WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha256);
            ICryptographicKey hmacKey = provider.CreateKey(key);
            byte[] hmac = WinRTCrypto.CryptographicEngine.Sign(hmacKey, message);
            return hmac;
        }

        public static bool Verify(byte[] key, byte[] message, byte[] signature)
        {
            IMacAlgorithmProvider provider = WinRTCrypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha256);

            ICryptographicKey hmacKey = provider.CreateKey(key);
            return WinRTCrypto.CryptographicEngine.VerifySignature(hmacKey, message, signature);
        }
    }

    /// <summary>
    /// Encryption helpers
    /// </summary>
    public class Encrypt
    {
        /// <summary>
        /// Computes PKCS5 for the message
        /// </summary>
        /// <param name="message">plaintext</param>
        /// <returns>PKCS5 of the message</returns>
        public static byte[] AesCbcPkcs5(byte[] message, byte[] key, byte[] iv)
        {
            ISymmetricKeyAlgorithmProvider objAlg = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7); // PKCS5
            ICryptographicKey ckey = objAlg.CreateSymmetricKey(key);
            byte [] result = WinRTCrypto.CryptographicEngine.Encrypt(ckey, message, iv);
            return result;
        }

        public static byte[] AesCtr(byte[] message, byte[] key, uint counter)
        {
            ISymmetricKeyAlgorithmProvider objAlg = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7); // CRT
            ICryptographicKey ckey = objAlg.CreateSymmetricKey(key);

            byte[] ivBytes = new byte[16];
            ByteUtil.IntToByteArray(ivBytes, 0, (int)counter);

            byte [] result = WinRTCrypto.CryptographicEngine.Encrypt(ckey, message, ivBytes);
            return result;
        }

    }

    /// <summary>
    /// Decryption helpers
    /// </summary>
    public class Decrypt
    {
        public static byte[] AesCbcPkcs5(byte[] message, byte[] key, byte[] iv)
        {
            ISymmetricKeyAlgorithmProvider objAlg = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
            ICryptographicKey ckey = objAlg.CreateSymmetricKey(key);

            if (message.Length % objAlg.BlockLength != 0) throw new Exception("Invalid ciphertext length");
            
            byte [] result = WinRTCrypto.CryptographicEngine.Decrypt(ckey, message, iv);
            return result;
        }

        public static byte[] AesCtr(byte[] message, byte[] key, uint counter)
        {
            ISymmetricKeyAlgorithmProvider objAlg = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
            ICryptographicKey ckey = objAlg.CreateSymmetricKey(key);

            byte[] ivBytes = new byte[16];
            ByteUtil.IntToByteArray(ivBytes, 0, (int)counter);

            byte [] result = WinRTCrypto.CryptographicEngine.Decrypt(ckey, message, ivBytes);
            return result;
        }
    }

    public static class CryptoHelper
    {
        /// <summary>
        /// TODO: dead code?
        /// </summary>
        public static void Shuffle<T>(this IList<T> list)
        {
            Random rng = new Random();
            int n = list.Count;
            while (n > 1)
            {
                n--;
                int k = rng.Next(n + 1);
                T value = list[k];
                list[k] = list[n];
                list[n] = value;
            }
        }
    }
}
