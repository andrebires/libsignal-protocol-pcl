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
using Google.ProtocolBuffers;
using Libsignal.Ecc;
using Libsignal.Groups.Ratchet;
using Libsignal.State;
using Strilanc.Value;

namespace Libsignal.Groups.State
{
    /**
     * Represents the state of an individual SenderKey ratchet.
     *
     * @author
     */
    public class SenderKeyState
	{
		private static readonly int MaxMessageKeys = 2000;

		private StorageProtos.SenderKeyStateStructure _senderKeyStateStructure;

		public SenderKeyState(uint id, uint iteration, byte[] chainKey, IEcPublicKey signatureKey)
			: this(id, iteration, chainKey, signatureKey, May<IEcPrivateKey>.NoValue)
		{
		}

		public SenderKeyState(uint id, uint iteration, byte[] chainKey, EcKeyPair signatureKey)
		: this(id, iteration, chainKey, signatureKey.GetPublicKey(), new May<IEcPrivateKey>(signatureKey.GetPrivateKey()))
		{
		}

		private SenderKeyState(uint id, uint iteration, byte[] chainKey,
							  IEcPublicKey signatureKeyPublic,
							  May<IEcPrivateKey> signatureKeyPrivate)
		{
			StorageProtos.SenderKeyStateStructure.Types.SenderChainKey senderChainKeyStructure =
				StorageProtos.SenderKeyStateStructure.Types.SenderChainKey.CreateBuilder()
													  .SetIteration(iteration)
													  .SetSeed(ByteString.CopyFrom(chainKey))
													  .Build();

			StorageProtos.SenderKeyStateStructure.Types.SenderSigningKey.Builder signingKeyStructure =
				StorageProtos.SenderKeyStateStructure.Types.SenderSigningKey.CreateBuilder()
														.SetPublic(ByteString.CopyFrom(signatureKeyPublic.Serialize()));

			if (signatureKeyPrivate.HasValue)
			{
				signingKeyStructure.SetPrivate(ByteString.CopyFrom(signatureKeyPrivate.ForceGetValue().Serialize()));
			}

			_senderKeyStateStructure = StorageProtos.SenderKeyStateStructure.CreateBuilder()
																  .SetSenderKeyId(id)
																  .SetSenderChainKey(senderChainKeyStructure)
																  .SetSenderSigningKey(signingKeyStructure)
																  .Build();
		}

		public SenderKeyState(StorageProtos.SenderKeyStateStructure senderKeyStateStructure)
		{
			_senderKeyStateStructure = senderKeyStateStructure;
		}

		public uint GetKeyId()
		{
			return _senderKeyStateStructure.SenderKeyId;
		}

		public SenderChainKey GetSenderChainKey()
		{
			return new SenderChainKey(_senderKeyStateStructure.SenderChainKey.Iteration,
									  _senderKeyStateStructure.SenderChainKey.Seed.ToByteArray());
		}

		public void SetSenderChainKey(SenderChainKey chainKey)
		{
			StorageProtos.SenderKeyStateStructure.Types.SenderChainKey senderChainKeyStructure =
				StorageProtos.SenderKeyStateStructure.Types.SenderChainKey.CreateBuilder()
													  .SetIteration(chainKey.GetIteration())
													  .SetSeed(ByteString.CopyFrom(chainKey.GetSeed()))
													  .Build();

			_senderKeyStateStructure = _senderKeyStateStructure.ToBuilder()
																  .SetSenderChainKey(senderChainKeyStructure)
																  .Build();
		}

		public IEcPublicKey GetSigningKeyPublic()
		{
			return Curve.DecodePoint(_senderKeyStateStructure.SenderSigningKey.Public.ToByteArray(), 0);
		}

		public IEcPrivateKey GetSigningKeyPrivate()
		{
			return Curve.DecodePrivatePoint(_senderKeyStateStructure.SenderSigningKey.Private.ToByteArray());
		}

		public bool HasSenderMessageKey(uint iteration)
		{
			foreach (StorageProtos.SenderKeyStateStructure.Types.SenderMessageKey senderMessageKey in _senderKeyStateStructure.SenderMessageKeysList)
			{
				if (senderMessageKey.Iteration == iteration) return true;
			}

			return false;
		}

		public void AddSenderMessageKey(SenderMessageKey senderMessageKey)
		{
			StorageProtos.SenderKeyStateStructure.Types.SenderMessageKey senderMessageKeyStructure =
				StorageProtos.SenderKeyStateStructure.Types.SenderMessageKey.CreateBuilder()
														.SetIteration(senderMessageKey.GetIteration())
														.SetSeed(ByteString.CopyFrom(senderMessageKey.GetSeed()))
														.Build();

			StorageProtos.SenderKeyStateStructure.Builder builder = _senderKeyStateStructure.ToBuilder();
			builder.AddSenderMessageKeys(senderMessageKeyStructure);

			if (builder.SenderMessageKeysList.Count > MaxMessageKeys)
			{
				builder.SenderMessageKeysList.RemoveAt(0);
			}
			_senderKeyStateStructure = builder.Build();
		}

		public SenderMessageKey RemoveSenderMessageKey(uint iteration)
		{
			LinkedList<StorageProtos.SenderKeyStateStructure.Types.SenderMessageKey> keys = new LinkedList<StorageProtos.SenderKeyStateStructure.Types.SenderMessageKey>(_senderKeyStateStructure.SenderMessageKeysList);
			IEnumerator<StorageProtos.SenderKeyStateStructure.Types.SenderMessageKey> iterator = keys.GetEnumerator(); // iterator();

			StorageProtos.SenderKeyStateStructure.Types.SenderMessageKey result = null;

			while (iterator.MoveNext()) // hastNext
			{
				StorageProtos.SenderKeyStateStructure.Types.SenderMessageKey senderMessageKey = iterator.Current; // next();

				if (senderMessageKey.Iteration == iteration) //senderMessageKey.getIteration()
				{
					result = senderMessageKey;
					keys.Remove(senderMessageKey); //iterator.remove();
					break;
				}
			}

			_senderKeyStateStructure = _senderKeyStateStructure.ToBuilder()
																	   .ClearSenderMessageKeys()
																	   //.AddAllSenderMessageKeys(keys)
																	   .AddRangeSenderMessageKeys(keys)
																	   .Build();

			if (result != null)
			{
				return new SenderMessageKey(result.Iteration, result.Seed.ToByteArray());
			}
			else
			{
				return null;
			}
		}

		public StorageProtos.SenderKeyStateStructure GetStructure()
		{
			return _senderKeyStateStructure;
		}
	}
}
