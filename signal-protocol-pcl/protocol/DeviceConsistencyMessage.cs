﻿/** 
 * Copyright (C) 2017 golf1052
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

using System.Diagnostics;
using Google.ProtocolBuffers;
using org.whispersystems.curve25519;
using WhisperSystems.Libsignal.Devices;
using WhisperSystems.Libsignal.Ecc;

namespace WhisperSystems.Libsignal.Protocol
{
    public class DeviceConsistencyMessage
    {
        private readonly DeviceConsistencySignature _signature;
        private readonly int _generation;
        private readonly byte[] _serialized;

        public DeviceConsistencyMessage(DeviceConsistencyCommitment commitment, IdentityKeyPair identityKeyPair)
        {
            try
            {
                byte[] signatureBytes = Curve.CalculateVrfSignature(identityKeyPair.GetPrivateKey(), commitment.ToByteArray());
                byte[] vrfOutputBytes = Curve.VerifyVrfSignature(identityKeyPair.GetPublicKey().GetPublicKey(), commitment.ToByteArray(), signatureBytes);

                _generation = commitment.GetGeneration();
                _signature = new DeviceConsistencySignature(signatureBytes, vrfOutputBytes);
                _serialized = SignalProtos.DeviceConsistencyCodeMessage.CreateBuilder()
                    .SetGeneration((uint)commitment.GetGeneration())
                    .SetSignature(ByteString.CopyFrom(_signature.GetSignature()))
                    .Build()
                    .ToByteArray();
            }
            catch (InvalidKeyException e)
            {
                Debug.Assert(false);
                throw e;
            }
            catch (VrfSignatureVerificationFailedException e)
            {
                Debug.Assert(false);
                throw e;
            }
        }

        public DeviceConsistencyMessage(DeviceConsistencyCommitment commitment, byte[] serialized, IdentityKey identityKey)
        {
            try
            {
                SignalProtos.DeviceConsistencyCodeMessage message = SignalProtos.DeviceConsistencyCodeMessage.ParseFrom(serialized);
                byte[] vrfOutputBytes = Curve.VerifyVrfSignature(identityKey.GetPublicKey(), commitment.ToByteArray(), message.Signature.ToByteArray());

                _generation = (int)message.Generation;
                _signature = new DeviceConsistencySignature(message.Signature.ToByteArray(), vrfOutputBytes);
                _serialized = serialized;
            }
            catch (InvalidProtocolBufferException e)
            {
                throw new InvalidMessageException(e);
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidMessageException(e);
            }
            catch (VrfSignatureVerificationFailedException e)
            {
                throw new InvalidMessageException(e);
            }
        }

        public byte[] GetSerialized()
        {
            return _serialized;
        }

        public DeviceConsistencySignature GetSignature()
        {
            return _signature;
        }

        public int GetGeneration()
        {
            return _generation;
        }
    }
}
