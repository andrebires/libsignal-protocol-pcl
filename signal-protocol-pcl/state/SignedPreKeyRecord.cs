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
using Google.ProtocolBuffers;
using WhisperSystems.Libsignal.Ecc;

namespace WhisperSystems.Libsignal.State
{
    public class SignedPreKeyRecord
    {
        private readonly StorageProtos.SignedPreKeyRecordStructure _structure;

        public SignedPreKeyRecord(uint id, ulong timestamp, EcKeyPair keyPair, byte[] signature)
        {
            _structure = StorageProtos.SignedPreKeyRecordStructure.CreateBuilder()
                                                        .SetId(id)
                                                        .SetPublicKey(ByteString.CopyFrom(keyPair.GetPublicKey()
                                                                                                 .Serialize()))
                                                        .SetPrivateKey(ByteString.CopyFrom(keyPair.GetPrivateKey()
                                                                                                  .Serialize()))
                                                        .SetSignature(ByteString.CopyFrom(signature))
                                                        .SetTimestamp(timestamp)
                                                        .Build();
        }

        public SignedPreKeyRecord(byte[] serialized)
        {
            _structure = StorageProtos.SignedPreKeyRecordStructure.ParseFrom(serialized);
        }

        public uint GetId()
        {
            return _structure.Id;
        }

        public ulong GetTimestamp()
        {
            return _structure.Timestamp;
        }

        public EcKeyPair GetKeyPair()
        {
            try
            {
                IEcPublicKey publicKey = Curve.DecodePoint(_structure.PublicKey.ToByteArray(), 0);
                IEcPrivateKey privateKey = Curve.DecodePrivatePoint(_structure.PrivateKey.ToByteArray());

                return new EcKeyPair(publicKey, privateKey);
            }
            catch (InvalidKeyException e)
            {
                throw new Exception(e.Message);
            }
        }

        public byte[] GetSignature()
        {
            return _structure.Signature.ToByteArray();
        }

        public byte[] Serialize()
        {
            return _structure.ToByteArray();
        }
    }
}
