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

using System.Collections.Generic;
using Libsignal.Ecc;
using Libsignal.State;

namespace Libsignal.Groups.state
{
    /**
     * A durable representation of a set of SenderKeyStates for a specific
     * SenderKeyName.
     *
     * @author
     */
    public class SenderKeyRecord
    {
        private static readonly int MaxStates = 5;

        private readonly LinkedList<SenderKeyState> _senderKeyStates = new LinkedList<SenderKeyState>();

        public SenderKeyRecord() { }

        public SenderKeyRecord(byte[] serialized)
        {
            StorageProtos.SenderKeyRecordStructure senderKeyRecordStructure = StorageProtos.SenderKeyRecordStructure.ParseFrom(serialized);

            foreach (StorageProtos.SenderKeyStateStructure structure in senderKeyRecordStructure.SenderKeyStatesList)
            {
                _senderKeyStates.AddFirst(new SenderKeyState(structure));
            }
        }

        public bool IsEmpty()
        {
            return _senderKeyStates.Count == 0;
        }

        public SenderKeyState GetSenderKeyState()
        {
            if (!IsEmpty())
            {
                return _senderKeyStates.First.Value;
            }
            else
            {
                throw new InvalidKeyIdException("No key state in record!");
            }
        }

        public SenderKeyState GetSenderKeyState(uint keyId)
        {
            foreach (SenderKeyState state in _senderKeyStates)
            {
                if (state.GetKeyId() == keyId)
                {
                    return state;
                }
            }

            throw new InvalidKeyIdException("No keys for: " + keyId);
        }

        public void AddSenderKeyState(uint id, uint iteration, byte[] chainKey, IEcPublicKey signatureKey)
        {
            _senderKeyStates.AddFirst(new SenderKeyState(id, iteration, chainKey, signatureKey));

            if (_senderKeyStates.Count > MaxStates)
            {
                _senderKeyStates.RemoveLast();
            }
        }

        public void SetSenderKeyState(uint id, uint iteration, byte[] chainKey, EcKeyPair signatureKey)
        {
            _senderKeyStates.Clear();
            _senderKeyStates.AddFirst(new SenderKeyState(id, iteration, chainKey, signatureKey));
        }

        public byte[] Serialize()
        {
            StorageProtos.SenderKeyRecordStructure.Builder recordStructure = StorageProtos.SenderKeyRecordStructure.CreateBuilder();

            foreach (SenderKeyState senderKeyState in _senderKeyStates)
            {
                recordStructure.AddSenderKeyStates(senderKeyState.GetStructure());
            }

            return recordStructure.Build().ToByteArray();
        }
    }
}
