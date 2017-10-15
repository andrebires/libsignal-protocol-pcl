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
using System.IO;
using System.Linq;
using Google.ProtocolBuffers;
using Libsignal.Ecc;
using Libsignal.Util;

namespace Libsignal.Protocol
{
    public partial class SignalMessage : CiphertextMessage
    {

        private static readonly int MacLength = 8;

        private readonly uint _messageVersion;
        private readonly IEcPublicKey _senderRatchetKey;
        private readonly uint _counter;
        private readonly uint _previousCounter;
        private readonly byte[] _ciphertext;
        private readonly byte[] _serialized;

        public SignalMessage(byte[] serialized)
        {
            try
            {
                byte[][] messageParts = ByteUtil.Split(serialized, 1, serialized.Length - 1 - MacLength, MacLength);
                byte version = messageParts[0][0];
                byte[] message = messageParts[1];
                byte[] mac = messageParts[2];

                if (ByteUtil.HighBitsToInt(version) <= UnsupportedVersion)
                {
                    throw new LegacyMessageException("Legacy message: " + ByteUtil.HighBitsToInt(version));
                }

                if (ByteUtil.HighBitsToInt(version) > CurrentVersion)
                {
                    throw new InvalidMessageException("Unknown version: " + ByteUtil.HighBitsToInt(version));
                }

                WhisperProtos.SignalMessage signalMessage = WhisperProtos.SignalMessage.ParseFrom(message);

                if (!signalMessage.HasCiphertext ||
                    !signalMessage.HasCounter ||
                    !signalMessage.HasRatchetKey)
                {
                    throw new InvalidMessageException("Incomplete message.");
                }

                _serialized = serialized;
                _senderRatchetKey = Curve.DecodePoint(signalMessage.RatchetKey.ToByteArray(), 0);
                _messageVersion = (uint)ByteUtil.HighBitsToInt(version);
                _counter = signalMessage.Counter;
                _previousCounter = signalMessage.PreviousCounter;
                _ciphertext = signalMessage.Ciphertext.ToByteArray();
            }
            catch (/*InvalidProtocolBufferException | InvalidKeyException | Parse*/Exception e)
            {
                throw new InvalidMessageException(e);
            }
        }

        public SignalMessage(uint messageVersion, byte[] macKey, IEcPublicKey senderRatchetKey,
                              uint counter, uint previousCounter, byte[] ciphertext,
                              IdentityKey senderIdentityKey,
                              IdentityKey receiverIdentityKey)
        {
            byte[] version = { ByteUtil.IntsToByteHighAndLow((int)messageVersion, (int)CurrentVersion) };
            byte[] message = WhisperProtos.SignalMessage.CreateBuilder()
                                           .SetRatchetKey(ByteString.CopyFrom(senderRatchetKey.Serialize()))
                                           .SetCounter(counter)
                                           .SetPreviousCounter(previousCounter)
                                           .SetCiphertext(ByteString.CopyFrom(ciphertext))
                                           .Build().ToByteArray();

            byte[] mac = GetMac(messageVersion, senderIdentityKey, receiverIdentityKey, macKey,
                                    ByteUtil.Combine(version, message));

            _serialized = ByteUtil.Combine(version, message, mac);
            _senderRatchetKey = senderRatchetKey;
            _counter = counter;
            _previousCounter = previousCounter;
            _ciphertext = ciphertext;
            _messageVersion = messageVersion;
        }

        public IEcPublicKey GetSenderRatchetKey()
        {
            return _senderRatchetKey;
        }

        public uint GetMessageVersion()
        {
            return _messageVersion;
        }

        public uint GetCounter()
        {
            return _counter;
        }

        public byte[] GetBody()
        {
            return _ciphertext;
        }

        public void VerifyMac(uint messageVersion, IdentityKey senderIdentityKey,
                        IdentityKey receiverIdentityKey, byte[] macKey)
        {
            byte[][] parts = ByteUtil.Split(_serialized, _serialized.Length - MacLength, MacLength);
            byte[] ourMac = GetMac(messageVersion, senderIdentityKey, receiverIdentityKey, macKey, parts[0]);
            byte[] theirMac = parts[1];

            if (!Enumerable.SequenceEqual(ourMac, theirMac))
            {
                throw new InvalidMessageException("Bad Mac!");
            }
        }

        private byte[] GetMac(uint messageVersion,
                        IdentityKey senderIdentityKey,
                        IdentityKey receiverIdentityKey,
                        byte[] macKey, byte[] serialized)
        {
            try
            {
                MemoryStream stream = new MemoryStream();
                if (messageVersion >= 3)
                {
                    byte[] sik = senderIdentityKey.GetPublicKey().Serialize();
                    stream.Write(sik, 0, sik.Length);
                    byte[] rik = receiverIdentityKey.GetPublicKey().Serialize();
                    stream.Write(rik, 0, rik.Length);
                }

                stream.Write(serialized, 0, serialized.Length);
                byte[] fullMac = Sign.Sha256Sum(macKey, stream.ToArray());
                return ByteUtil.Trim(fullMac, MacLength);
            }
            catch (/*NoSuchAlgorithmException | java.security.InvalidKey*/Exception e)
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
            return WhisperType;
        }

        public static bool IsLegacy(byte[] message)
        {
            return message != null && message.Length >= 1 &&
                ByteUtil.HighBitsToInt(message[0]) <= UnsupportedVersion;
        }

    }
}
