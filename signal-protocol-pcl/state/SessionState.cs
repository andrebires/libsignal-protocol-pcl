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
using System.Diagnostics;
using Google.ProtocolBuffers;
using Libsignal.Ecc;
using Libsignal.Kdf;
using Libsignal.Ratchet;
using Libsignal.Util;
using Strilanc.Value;

namespace Libsignal.State
{
    public class SessionState
	{
		private static readonly int MaxMessageKeys = 2000;

		private StorageProtos.SessionStructure _sessionStructure;

		public SessionState()
		{
			_sessionStructure = StorageProtos.SessionStructure.CreateBuilder().Build();
		}

		public SessionState(StorageProtos.SessionStructure sessionStructure)
		{
			_sessionStructure = sessionStructure;
		}

		public SessionState(SessionState copy)
		{
			_sessionStructure = copy._sessionStructure.ToBuilder().Build();
		}

		public StorageProtos.SessionStructure GetStructure()
		{
			return _sessionStructure;
		}

		public byte[] GetAliceBaseKey()
		{
			return _sessionStructure.AliceBaseKey.ToByteArray();
		}

		public void SetAliceBaseKey(byte[] aliceBaseKey)
		{
			_sessionStructure = _sessionStructure.ToBuilder()
														 .SetAliceBaseKey(ByteString.CopyFrom(aliceBaseKey))
														 .Build();
		}

		public void SetSessionVersion(uint version)
		{
			_sessionStructure = _sessionStructure.ToBuilder()
														 .SetSessionVersion(version)
														 .Build();
		}

		public uint GetSessionVersion()
		{
			uint sessionVersion = _sessionStructure.SessionVersion;

			if (sessionVersion == 0) return 2;
			else return sessionVersion;
		}

		public void SetRemoteIdentityKey(IdentityKey identityKey)
		{
			_sessionStructure = _sessionStructure.ToBuilder()
														 .SetRemoteIdentityPublic(ByteString.CopyFrom(identityKey.Serialize()))
														 .Build();
		}

		public void SetLocalIdentityKey(IdentityKey identityKey)
		{
			_sessionStructure = _sessionStructure.ToBuilder()
														 .SetLocalIdentityPublic(ByteString.CopyFrom(identityKey.Serialize()))
														 .Build();
		}

		public IdentityKey GetRemoteIdentityKey()
		{
			try
			{
				if (!_sessionStructure.HasRemoteIdentityPublic)
				{
					return null;
				}

				return new IdentityKey(_sessionStructure.RemoteIdentityPublic.ToByteArray(), 0);
			}
			catch (InvalidKeyException e)
			{
				Debug.WriteLine(e.ToString(), "SessionRecordV2");
				return null;
			}
		}

		public IdentityKey GetLocalIdentityKey()
		{
			try
			{
				return new IdentityKey(_sessionStructure.LocalIdentityPublic.ToByteArray(), 0);
			}
			catch (InvalidKeyException e)
			{
				throw new Exception(e.Message);
			}
		}

		public uint GetPreviousCounter()
		{
			return _sessionStructure.PreviousCounter;
		}

		public void SetPreviousCounter(uint previousCounter)
		{
			_sessionStructure = _sessionStructure.ToBuilder()
														 .SetPreviousCounter(previousCounter)
														 .Build();
		}

		public RootKey GetRootKey()
		{
			return new RootKey(Hkdf.CreateFor(GetSessionVersion()),
							   _sessionStructure.RootKey.ToByteArray());
		}

		public void SetRootKey(RootKey rootKey)
		{
			_sessionStructure = _sessionStructure.ToBuilder()
														 .SetRootKey(ByteString.CopyFrom(rootKey.GetKeyBytes()))
														 .Build();
		}

		public IEcPublicKey GetSenderRatchetKey()
		{
			try
			{
				return Curve.DecodePoint(_sessionStructure.SenderChain.SenderRatchetKey.ToByteArray(), 0);
			}
			catch (InvalidKeyException e)
			{
				throw new Exception(e.Message);
			}
		}

		public EcKeyPair GetSenderRatchetKeyPair()
		{
			IEcPublicKey publicKey = GetSenderRatchetKey();
			IEcPrivateKey privateKey = Curve.DecodePrivatePoint(_sessionStructure.SenderChain
																			   .SenderRatchetKeyPrivate
																			   .ToByteArray());

			return new EcKeyPair(publicKey, privateKey);
		}

		public bool HasReceiverChain(IEcPublicKey senderEphemeral)
		{
			return GetReceiverChain(senderEphemeral) != null;
		}

		public bool HasSenderChain()
		{
			return _sessionStructure.HasSenderChain;
		}

		private Pair<StorageProtos.SessionStructure.Types.Chain, uint> GetReceiverChain(IEcPublicKey senderEphemeral)
		{
			IList<StorageProtos.SessionStructure.Types.Chain> receiverChains = _sessionStructure.ReceiverChainsList;
			uint index = 0;

			foreach (StorageProtos.SessionStructure.Types.Chain receiverChain in receiverChains)
			{
				try
				{
					IEcPublicKey chainSenderRatchetKey = Curve.DecodePoint(receiverChain.SenderRatchetKey.ToByteArray(), 0);

					if (chainSenderRatchetKey.Equals(senderEphemeral))
					{
						return new Pair<StorageProtos.SessionStructure.Types.Chain, uint>(receiverChain, index);
					}
				}
				catch (InvalidKeyException e)
				{
					Debug.WriteLine(e.ToString(), "SessionRecordV2");
				}

				index++;
			}

			return null;
		}

		public ChainKey GetReceiverChainKey(IEcPublicKey senderEphemeral)
		{
			Pair<StorageProtos.SessionStructure.Types.Chain, uint> receiverChainAndIndex = GetReceiverChain(senderEphemeral);
			StorageProtos.SessionStructure.Types.Chain receiverChain = receiverChainAndIndex.First();

			if (receiverChain == null)
			{
				return null;
			}
			else
			{
				return new ChainKey(Hkdf.CreateFor(GetSessionVersion()),
									receiverChain.ChainKey.Key.ToByteArray(),
									receiverChain.ChainKey.Index);
			}
		}

		public void AddReceiverChain(IEcPublicKey senderRatchetKey, ChainKey chainKey)
		{
			StorageProtos.SessionStructure.Types.Chain.Types.ChainKey chainKeyStructure = StorageProtos.SessionStructure.Types.Chain.Types.ChainKey.CreateBuilder()
															 .SetKey(ByteString.CopyFrom(chainKey.GetKey()))
															 .SetIndex(chainKey.GetIndex())
															 .Build();

			StorageProtos.SessionStructure.Types.Chain chain = StorageProtos.SessionStructure.Types.Chain.CreateBuilder()
							   .SetChainKey(chainKeyStructure)
							   .SetSenderRatchetKey(ByteString.CopyFrom(senderRatchetKey.Serialize()))
							   .Build();

			_sessionStructure = _sessionStructure.ToBuilder().AddReceiverChains(chain).Build();

			if (_sessionStructure.ReceiverChainsList.Count > 5)
			{
				_sessionStructure = _sessionStructure.ToBuilder()/*.ClearReceiverChains()*/.Build(); //RemoveReceiverChains(0) TODO: why does it work without
			}
		}

		public void SetSenderChain(EcKeyPair senderRatchetKeyPair, ChainKey chainKey)
		{
			StorageProtos.SessionStructure.Types.Chain.Types.ChainKey chainKeyStructure = StorageProtos.SessionStructure.Types.Chain.Types.ChainKey.CreateBuilder()
															 .SetKey(ByteString.CopyFrom(chainKey.GetKey()))
															 .SetIndex(chainKey.GetIndex())
															 .Build();

			StorageProtos.SessionStructure.Types.Chain senderChain = StorageProtos.SessionStructure.Types.Chain.CreateBuilder()
									 .SetSenderRatchetKey(ByteString.CopyFrom(senderRatchetKeyPair.GetPublicKey().Serialize()))
									 .SetSenderRatchetKeyPrivate(ByteString.CopyFrom(senderRatchetKeyPair.GetPrivateKey().Serialize()))
									 .SetChainKey(chainKeyStructure)
									 .Build();

			_sessionStructure = _sessionStructure.ToBuilder().SetSenderChain(senderChain).Build();
		}

		public ChainKey GetSenderChainKey()
		{
			StorageProtos.SessionStructure.Types.Chain.Types.ChainKey chainKeyStructure = _sessionStructure.SenderChain.ChainKey;
			return new ChainKey(Hkdf.CreateFor(GetSessionVersion()),
								chainKeyStructure.Key.ToByteArray(), chainKeyStructure.Index);
		}

		public void SetSenderChainKey(ChainKey nextChainKey)
		{
			StorageProtos.SessionStructure.Types.Chain.Types.ChainKey chainKey = StorageProtos.SessionStructure.Types.Chain.Types.ChainKey.CreateBuilder()
													.SetKey(ByteString.CopyFrom(nextChainKey.GetKey()))
													.SetIndex(nextChainKey.GetIndex())
													.Build();

			StorageProtos.SessionStructure.Types.Chain chain = _sessionStructure.SenderChain.ToBuilder()
										  .SetChainKey(chainKey).Build();

			_sessionStructure = _sessionStructure.ToBuilder().SetSenderChain(chain).Build();
		}

		public bool HasMessageKeys(IEcPublicKey senderEphemeral, uint counter)
		{
			Pair<StorageProtos.SessionStructure.Types.Chain, uint> chainAndIndex = GetReceiverChain(senderEphemeral);
			StorageProtos.SessionStructure.Types.Chain chain = chainAndIndex.First();

			if (chain == null)
			{
				return false;
			}

			IList<StorageProtos.SessionStructure.Types.Chain.Types.MessageKey> messageKeyList = chain.MessageKeysList;

			foreach (StorageProtos.SessionStructure.Types.Chain.Types.MessageKey messageKey in messageKeyList)
			{
				if (messageKey.Index == counter)
				{
					return true;
				}
			}

			return false;
		}

		public MessageKeys RemoveMessageKeys(IEcPublicKey senderEphemeral, uint counter)
		{
			Pair<StorageProtos.SessionStructure.Types.Chain, uint> chainAndIndex = GetReceiverChain(senderEphemeral);
			StorageProtos.SessionStructure.Types.Chain chain = chainAndIndex.First();

			if (chain == null)
			{
				return null;
			}

			List<StorageProtos.SessionStructure.Types.Chain.Types.MessageKey> messageKeyList = new List<StorageProtos.SessionStructure.Types.Chain.Types.MessageKey>(chain.MessageKeysList);
			IEnumerator<StorageProtos.SessionStructure.Types.Chain.Types.MessageKey> messageKeyIterator = messageKeyList.GetEnumerator();
			MessageKeys result = null;

			while (messageKeyIterator.MoveNext()) //hasNext()
			{
				StorageProtos.SessionStructure.Types.Chain.Types.MessageKey messageKey = messageKeyIterator.Current; // next()

				if (messageKey.Index == counter)
				{
					result = new MessageKeys(messageKey.CipherKey.ToByteArray(),
											messageKey.MacKey.ToByteArray(),
											 messageKey.Iv.ToByteArray(),
											 messageKey.Index);

					messageKeyList.Remove(messageKey); //messageKeyIterator.remove();
					break;
				}
			}

			StorageProtos.SessionStructure.Types.Chain updatedChain = chain.ToBuilder().ClearMessageKeys()
									  .AddRangeMessageKeys(messageKeyList) // AddAllMessageKeys
									  .Build();

			_sessionStructure = _sessionStructure.ToBuilder()
														 .SetReceiverChains((int)chainAndIndex.Second(), updatedChain) // TODO: conv
														 .Build();

			return result;
		}

		public void SetMessageKeys(IEcPublicKey senderEphemeral, MessageKeys messageKeys)
		{
			Pair<StorageProtos.SessionStructure.Types.Chain, uint> chainAndIndex = GetReceiverChain(senderEphemeral);
			StorageProtos.SessionStructure.Types.Chain chain = chainAndIndex.First();
			StorageProtos.SessionStructure.Types.Chain.Types.MessageKey messageKeyStructure = StorageProtos.SessionStructure.Types.Chain.Types.MessageKey.CreateBuilder()
																	  .SetCipherKey(ByteString.CopyFrom(messageKeys.GetCipherKey()/*.getEncoded()*/))
																	  .SetMacKey(ByteString.CopyFrom(messageKeys.GetMacKey()/*.getEncoded()*/))
																	  .SetIndex(messageKeys.GetCounter())
																	  .SetIv(ByteString.CopyFrom(messageKeys.GetIv()/*.getIV()*/))
																	  .Build();

			StorageProtos.SessionStructure.Types.Chain.Builder updatedChain = chain.ToBuilder().AddMessageKeys(messageKeyStructure);
			if (updatedChain.MessageKeysList.Count > MaxMessageKeys)
			{
				updatedChain.MessageKeysList.RemoveAt(0);
			}

			_sessionStructure = _sessionStructure.ToBuilder()
														 .SetReceiverChains((int)chainAndIndex.Second(), updatedChain.Build()) // TODO: conv
														 .Build();
		}

		public void SetReceiverChainKey(IEcPublicKey senderEphemeral, ChainKey chainKey)
		{
			Pair<StorageProtos.SessionStructure.Types.Chain, uint> chainAndIndex = GetReceiverChain(senderEphemeral);
			StorageProtos.SessionStructure.Types.Chain chain = chainAndIndex.First();

			StorageProtos.SessionStructure.Types.Chain.Types.ChainKey chainKeyStructure = StorageProtos.SessionStructure.Types.Chain.Types.ChainKey.CreateBuilder()
															 .SetKey(ByteString.CopyFrom(chainKey.GetKey()))
															 .SetIndex(chainKey.GetIndex())
															 .Build();

			StorageProtos.SessionStructure.Types.Chain updatedChain = chain.ToBuilder().SetChainKey(chainKeyStructure).Build();

			_sessionStructure = _sessionStructure.ToBuilder()
														 .SetReceiverChains((int)chainAndIndex.Second(), updatedChain) // TODO: conv
														 .Build();
		}

		public void SetPendingKeyExchange(uint sequence,
										  EcKeyPair ourBaseKey,
										  EcKeyPair ourRatchetKey,
										  IdentityKeyPair ourIdentityKey)
		{
			StorageProtos.SessionStructure.Types.PendingKeyExchange structure =
				StorageProtos.SessionStructure.Types.PendingKeyExchange.CreateBuilder()
								  .SetSequence(sequence)
								  .SetLocalBaseKey(ByteString.CopyFrom(ourBaseKey.GetPublicKey().Serialize()))
								  .SetLocalBaseKeyPrivate(ByteString.CopyFrom(ourBaseKey.GetPrivateKey().Serialize()))
								  .SetLocalRatchetKey(ByteString.CopyFrom(ourRatchetKey.GetPublicKey().Serialize()))
								  .SetLocalRatchetKeyPrivate(ByteString.CopyFrom(ourRatchetKey.GetPrivateKey().Serialize()))
								  .SetLocalIdentityKey(ByteString.CopyFrom(ourIdentityKey.GetPublicKey().Serialize()))
								  .SetLocalIdentityKeyPrivate(ByteString.CopyFrom(ourIdentityKey.GetPrivateKey().Serialize()))
								  .Build();

			_sessionStructure = _sessionStructure.ToBuilder()
														 .SetPendingKeyExchange(structure)
														 .Build();
		}

		public uint GetPendingKeyExchangeSequence()
		{
			return _sessionStructure.PendingKeyExchange.Sequence;
		}

		public EcKeyPair GetPendingKeyExchangeBaseKey()
		{
			IEcPublicKey publicKey = Curve.DecodePoint(_sessionStructure.PendingKeyExchange
																.LocalBaseKey.ToByteArray(), 0);

			IEcPrivateKey privateKey = Curve.DecodePrivatePoint(_sessionStructure.PendingKeyExchange
																	   .LocalBaseKeyPrivate
																	   .ToByteArray());

			return new EcKeyPair(publicKey, privateKey);
		}

		public EcKeyPair GetPendingKeyExchangeRatchetKey()
		{
			IEcPublicKey publicKey = Curve.DecodePoint(_sessionStructure.PendingKeyExchange
																.LocalRatchetKey.ToByteArray(), 0);

			IEcPrivateKey privateKey = Curve.DecodePrivatePoint(_sessionStructure.PendingKeyExchange
																	   .LocalRatchetKeyPrivate
																	   .ToByteArray());

			return new EcKeyPair(publicKey, privateKey);
		}

		public IdentityKeyPair GetPendingKeyExchangeIdentityKey()
		{
			IdentityKey publicKey = new IdentityKey(_sessionStructure.PendingKeyExchange
															.LocalIdentityKey.ToByteArray(), 0);

			IEcPrivateKey privateKey = Curve.DecodePrivatePoint(_sessionStructure.PendingKeyExchange
																	   .LocalIdentityKeyPrivate
																	   .ToByteArray());

			return new IdentityKeyPair(publicKey, privateKey);
		}

		public bool HasPendingKeyExchange()
		{
			return _sessionStructure.HasPendingKeyExchange;
		}

		public void SetUnacknowledgedPreKeyMessage(May<uint> preKeyId, uint signedPreKeyId, IEcPublicKey baseKey)
		{
			StorageProtos.SessionStructure.Types.PendingPreKey.Builder pending = StorageProtos.SessionStructure.Types.PendingPreKey.CreateBuilder()
														 .SetSignedPreKeyId((int)signedPreKeyId)
														 .SetBaseKey(ByteString.CopyFrom(baseKey.Serialize()));

			if (preKeyId.HasValue)
			{
				pending.SetPreKeyId(preKeyId.ForceGetValue());
			}

			_sessionStructure = _sessionStructure.ToBuilder()
														 .SetPendingPreKey(pending.Build())
														 .Build();
		}

		public bool HasUnacknowledgedPreKeyMessage()
		{
			return _sessionStructure.HasPendingPreKey;
		}

		public UnacknowledgedPreKeyMessageItems GetUnacknowledgedPreKeyMessageItems()
		{
			try
			{
				May<uint> preKeyId;

				if (_sessionStructure.PendingPreKey.HasPreKeyId)
				{
					preKeyId = new May<uint>(_sessionStructure.PendingPreKey.PreKeyId);
				}
				else
				{
					preKeyId = May<uint>.NoValue;
				}

				return
					new UnacknowledgedPreKeyMessageItems(preKeyId,
														 (uint)_sessionStructure.PendingPreKey.SignedPreKeyId,
														 Curve.DecodePoint(_sessionStructure.PendingPreKey
																						   .BaseKey
																						   .ToByteArray(), 0));
			}
			catch (InvalidKeyException e)
			{
				throw new Exception(e.Message);
			}
		}

		public void ClearUnacknowledgedPreKeyMessage()
		{
			_sessionStructure = _sessionStructure.ToBuilder()
														 .ClearPendingPreKey()
														 .Build();
		}

		public void SetRemoteRegistrationId(uint registrationId)
		{
			_sessionStructure = _sessionStructure.ToBuilder()
														 .SetRemoteRegistrationId(registrationId)
														 .Build();
		}

		public uint GetRemoteRegistrationId()
		{
			return _sessionStructure.RemoteRegistrationId;
		}

		public void SetLocalRegistrationId(uint registrationId)
		{
			_sessionStructure = _sessionStructure.ToBuilder()
														 .SetLocalRegistrationId(registrationId)
														 .Build();
		}

		public uint GetLocalRegistrationId()
		{
			return _sessionStructure.LocalRegistrationId;
		}

		public byte[] Serialize()
		{
			return _sessionStructure.ToByteArray();
		}

		public class UnacknowledgedPreKeyMessageItems
		{
			private readonly May<uint> _preKeyId;
			private readonly uint _signedPreKeyId;
			private readonly IEcPublicKey _baseKey;

			public UnacknowledgedPreKeyMessageItems(May<uint> preKeyId,
													uint signedPreKeyId,
													IEcPublicKey baseKey)
			{
				_preKeyId = preKeyId;
				_signedPreKeyId = signedPreKeyId;
				_baseKey = baseKey;
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
		}
	}
}
