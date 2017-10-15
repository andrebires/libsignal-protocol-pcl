﻿/** 
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
using Google.ProtocolBuffers;
using Libsignal.Ecc;
using Libsignal.Util;

namespace Libsignal.Protocol
{
    public partial class SenderKeyMessage : CiphertextMessage
    {

        private static readonly int SignatureLength = 64;

        private readonly uint _messageVersion;
        private readonly uint _keyId;
        private readonly uint _iteration;
        private readonly byte[] _ciphertext;
        private readonly byte[] _serialized;

        public SenderKeyMessage(byte[] serialized)
        {
            try
            {
                byte[][] messageParts = ByteUtil.Split(serialized, 1, serialized.Length - 1 - SignatureLength, SignatureLength);
                byte version = messageParts[0][0];
                byte[] message = messageParts[1];
                byte[] signature = messageParts[2];

                if (ByteUtil.HighBitsToInt(version) < 3)
                {
                    throw new LegacyMessageException("Legacy message: " + ByteUtil.HighBitsToInt(version));
                }

                if (ByteUtil.HighBitsToInt(version) > CurrentVersion)
                {
                    throw new InvalidMessageException("Unknown version: " + ByteUtil.HighBitsToInt(version));
                }

                WhisperProtos.SenderKeyMessage senderKeyMessage = WhisperProtos.SenderKeyMessage.ParseFrom(message);

                if (!senderKeyMessage.HasId ||
                    !senderKeyMessage.HasIteration ||
                    !senderKeyMessage.HasCiphertext)
                {
                    throw new InvalidMessageException("Incomplete message.");
                }

                _serialized = serialized;
                _messageVersion = (uint)ByteUtil.HighBitsToInt(version);
                _keyId = senderKeyMessage.Id;
                _iteration = senderKeyMessage.Iteration;
                _ciphertext = senderKeyMessage.Ciphertext.ToByteArray();
            }
            catch (/*InvalidProtocolBufferException | Parse*/Exception e)
            {
                throw new InvalidMessageException(e);
            }
        }

        public SenderKeyMessage(uint keyId, uint iteration, byte[] ciphertext, IEcPrivateKey signatureKey)
        {
            byte[] version = { ByteUtil.IntsToByteHighAndLow((int)CurrentVersion, (int)CurrentVersion) };
            byte[] message = WhisperProtos.SenderKeyMessage.CreateBuilder()
                                                           .SetId(keyId)
                                                           .SetIteration(iteration)
                                                           .SetCiphertext(ByteString.CopyFrom(ciphertext))
                                                           .Build().ToByteArray();

            byte[] signature = GetSignature(signatureKey, ByteUtil.Combine(version, message));

            _serialized = ByteUtil.Combine(version, message, signature);
            _messageVersion = CurrentVersion;
            _keyId = keyId;
            _iteration = iteration;
            _ciphertext = ciphertext;
        }

        public uint GetKeyId()
        {
            return _keyId;
        }

        public uint GetIteration()
        {
            return _iteration;
        }

        public byte[] GetCipherText()
        {
            return _ciphertext;
        }

        public void VerifySignature(IEcPublicKey signatureKey)
        {
            try
            {
                byte[][] parts = ByteUtil.Split(_serialized, _serialized.Length - SignatureLength, SignatureLength);

                if (!Curve.VerifySignature(signatureKey, parts[0], parts[1]))
                {
                    throw new InvalidMessageException("Invalid signature!");
                }

            }
            catch (InvalidKeyException e)
            {
                throw new InvalidMessageException(e);
            }
        }

        private byte[] GetSignature(IEcPrivateKey signatureKey, byte[] serialized)
        {
            try
            {
                return Curve.CalculateSignature(signatureKey, serialized);
            }
            catch (InvalidKeyException e)
            {
                throw new Exception(e.Message);
            }
        }

        public override byte[] Serialize()
        {
            return _serialized;
        }


        public override uint GetMessageType()
        {
            return SenderkeyType;
        }
    }
}
