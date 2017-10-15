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
using Strilanc.Value;
using WhisperSystems.Libsignal.Ecc;
using WhisperSystems.Libsignal.Util;

namespace WhisperSystems.Libsignal.Protocol
{
    public partial class PreKeySignalMessage : CiphertextMessage
    {
        private readonly uint _version;
        private readonly uint _registrationId;
        private readonly May<uint> _preKeyId;
        private readonly uint _signedPreKeyId;
        private readonly IEcPublicKey _baseKey;
        private readonly IdentityKey _identityKey;
        private readonly SignalMessage _message;
        private readonly byte[] _serialized;

        public PreKeySignalMessage(byte[] serialized)
        {
            try
            {
                _version = (uint)ByteUtil.HighBitsToInt(serialized[0]);

                if (_version > CurrentVersion)
                {
                    throw new InvalidVersionException("Unknown version: " + _version);
                }

      if (_version < CurrentVersion) {
        throw new LegacyMessageException("Legacy version: " + _version);
      }
                WhisperProtos.PreKeySignalMessage preKeySignalMessage
                    = WhisperProtos.PreKeySignalMessage.ParseFrom(ByteString.CopyFrom(serialized, 1,
                                                                                       serialized.Length - 1));

                if (
                    !preKeySignalMessage.HasSignedPreKeyId ||
                    !preKeySignalMessage.HasBaseKey ||
                    !preKeySignalMessage.HasIdentityKey ||
                    !preKeySignalMessage.HasMessage)
                {
                    throw new InvalidMessageException("Incomplete message.");
                }

                _serialized = serialized;
                _registrationId = preKeySignalMessage.RegistrationId;
                _preKeyId = preKeySignalMessage.HasPreKeyId ? new May<uint>(preKeySignalMessage.PreKeyId) : May<uint>.NoValue;
                _signedPreKeyId = preKeySignalMessage.HasSignedPreKeyId ? preKeySignalMessage.SignedPreKeyId : uint.MaxValue; // -1
                _baseKey = Curve.DecodePoint(preKeySignalMessage.BaseKey.ToByteArray(), 0);
                _identityKey = new IdentityKey(Curve.DecodePoint(preKeySignalMessage.IdentityKey.ToByteArray(), 0));
                _message = new SignalMessage(preKeySignalMessage.Message.ToByteArray());
            }
            catch (Exception e)
            {
                //(InvalidProtocolBufferException | InvalidKeyException | LegacyMessage
                throw new InvalidMessageException(e.Message);
            }
        }

        public PreKeySignalMessage(uint messageVersion, uint registrationId, May<uint> preKeyId,
                                    uint signedPreKeyId, IEcPublicKey baseKey, IdentityKey identityKey,
                                    SignalMessage message)
        {
            _version = messageVersion;
            _registrationId = registrationId;
            _preKeyId = preKeyId;
            _signedPreKeyId = signedPreKeyId;
            _baseKey = baseKey;
            _identityKey = identityKey;
            _message = message;

            WhisperProtos.PreKeySignalMessage.Builder builder =
                WhisperProtos.PreKeySignalMessage.CreateBuilder()
                                                  .SetSignedPreKeyId(signedPreKeyId)
                                                  .SetBaseKey(ByteString.CopyFrom(baseKey.Serialize()))
                                                  .SetIdentityKey(ByteString.CopyFrom(identityKey.Serialize()))
                                                  .SetMessage(ByteString.CopyFrom(message.Serialize()))
                                                  .SetRegistrationId(registrationId);

            if (preKeyId.HasValue) // .isPresent()
            {
                builder.SetPreKeyId(preKeyId.ForceGetValue()); // get()
            }

            byte[] versionBytes = { ByteUtil.IntsToByteHighAndLow((int)_version, (int)CurrentVersion) };
            byte[] messageBytes = builder.Build().ToByteArray();

            _serialized = ByteUtil.Combine(versionBytes, messageBytes);
        }

        public uint GetMessageVersion()
        {
            return _version;
        }

        public IdentityKey GetIdentityKey()
        {
            return _identityKey;
        }

        public uint GetRegistrationId()
        {
            return _registrationId;
        }

        public May<uint> GetPreKeyId()
        {
            return _preKeyId;
        }

        public uint GetSignedPreKeyId()
        {
            return _signedPreKeyId;
        }

        public IEcPublicKey GetBaseKey()
        {
            return _baseKey;
        }

        public SignalMessage GetSignalMessage()
        {
            return _message;
        }

        public override byte[] Serialize()
        {
            return _serialized;
        }

        public override uint GetMessageType()
        {
            return PrekeyType;
        }
    }
}
