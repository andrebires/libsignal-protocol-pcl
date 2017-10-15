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
using System.Collections.Generic;
using Libsignal.Ecc;
using Libsignal.Protocol;
using Libsignal.Ratchet;
using Libsignal.State;
using Libsignal.Util;
using Strilanc.Value;

namespace Libsignal
{

    /**
     * The main entry point for Signal Protocol encrypt/decrypt operations.
     *
     * Once a session has been established with {@link SessionBuilder},
     * this class can be used for all encrypt/decrypt operations within
     * that session.
     *
     * @author Moxie Marlinspike
     */
    public class SessionCipher
	{

		public static readonly Object SessionLock = new Object();

		private readonly ISessionStore _sessionStore;
		private readonly SessionBuilder _sessionBuilder;
		private readonly IPreKeyStore _preKeyStore;
		private readonly SignalProtocolAddress _remoteAddress;

		/**
         * Construct a SessionCipher for encrypt/decrypt operations on a session.
         * In order to use SessionCipher, a session must have already been created
         * and stored using {@link SessionBuilder}.
         *
         * @param  sessionStore The {@link SessionStore} that contains a session for this recipient.
         * @param  remoteAddress  The remote address that messages will be encrypted to or decrypted from.
         */
		public SessionCipher(ISessionStore sessionStore, IPreKeyStore preKeyStore,
							 ISignedPreKeyStore signedPreKeyStore, IDentityKeyStore identityKeyStore,
							 SignalProtocolAddress remoteAddress)
		{
			_sessionStore = sessionStore;
			_preKeyStore = preKeyStore;
			_remoteAddress = remoteAddress;
			_sessionBuilder = new SessionBuilder(sessionStore, preKeyStore, signedPreKeyStore,
													 identityKeyStore, remoteAddress);
		}

		public SessionCipher(ISignalProtocolStore store, SignalProtocolAddress remoteAddress)
			: this(store, store, store, store, remoteAddress)
		{

		}

		/**
         * Encrypt a message.
         *
         * @param  paddedMessage The plaintext message bytes, optionally padded to a constant multiple.
         * @return A ciphertext message encrypted to the recipient+device tuple.
         */
		public CiphertextMessage Encrypt(byte[] paddedMessage)
		{
			lock (SessionLock)
			{
				SessionRecord sessionRecord = _sessionStore.LoadSession(_remoteAddress);
				SessionState sessionState = sessionRecord.GetSessionState();
				ChainKey chainKey = sessionState.GetSenderChainKey();
				MessageKeys messageKeys = chainKey.GetMessageKeys();
				IEcPublicKey senderEphemeral = sessionState.GetSenderRatchetKey();
				uint previousCounter = sessionState.GetPreviousCounter();
				uint sessionVersion = sessionState.GetSessionVersion();

				byte[] ciphertextBody = GetCiphertext(sessionVersion, messageKeys, paddedMessage);
				CiphertextMessage ciphertextMessage = new SignalMessage(sessionVersion, messageKeys.GetMacKey(),
																		 senderEphemeral, chainKey.GetIndex(),
																		 previousCounter, ciphertextBody,
																		 sessionState.GetLocalIdentityKey(),
																		 sessionState.GetRemoteIdentityKey());

				if (sessionState.HasUnacknowledgedPreKeyMessage())
				{
					SessionState.UnacknowledgedPreKeyMessageItems items = sessionState.GetUnacknowledgedPreKeyMessageItems();
					uint localRegistrationId = sessionState.GetLocalRegistrationId();

					ciphertextMessage = new PreKeySignalMessage(sessionVersion, localRegistrationId, items.GetPreKeyId(),
																 items.GetSignedPreKeyId(), items.GetBaseKey(),
																 sessionState.GetLocalIdentityKey(),
																 (SignalMessage)ciphertextMessage);
				}

				sessionState.SetSenderChainKey(chainKey.GetNextChainKey());
				_sessionStore.StoreSession(_remoteAddress, sessionRecord);
				return ciphertextMessage;
			}
		}

		/**
         * Decrypt a message.
         *
         * @param  ciphertext The {@link PreKeySignalMessage} to decrypt.
         *
         * @return The plaintext.
         * @throws InvalidMessageException if the input is not valid ciphertext.
         * @throws DuplicateMessageException if the input is a message that has already been received.
         * @throws LegacyMessageException if the input is a message formatted by a protocol version that
         *                                is no longer supported.
         * @throws InvalidKeyIdException when there is no local {@link org.whispersystems.libsignal.state.PreKeyRecord}
         *                               that corresponds to the PreKey ID in the message.
         * @throws InvalidKeyException when the message is formatted incorrectly.
         * @throws UntrustedIdentityException when the {@link IdentityKey} of the sender is untrusted.
         */
		public byte[] Decrypt(PreKeySignalMessage ciphertext)

		{
			return Decrypt(ciphertext, new NullDecryptionCallback());
		}

		/**
         * Decrypt a message.
         *
         * @param  ciphertext The {@link PreKeySignalMessage} to decrypt.
         * @param  callback   A callback that is triggered after decryption is complete,
         *                    but before the updated session state has been committed to the session
         *                    DB.  This allows some implementations to store the committed plaintext
         *                    to a DB first, in case they are concerned with a crash happening between
         *                    the time the session state is updated but before they're able to store
         *                    the plaintext to disk.
         *
         * @return The plaintext.
         * @throws InvalidMessageException if the input is not valid ciphertext.
         * @throws DuplicateMessageException if the input is a message that has already been received.
         * @throws LegacyMessageException if the input is a message formatted by a protocol version that
         *                                is no longer supported.
         * @throws InvalidKeyIdException when there is no local {@link org.whispersystems.libsignal.state.PreKeyRecord}
         *                               that corresponds to the PreKey ID in the message.
         * @throws InvalidKeyException when the message is formatted incorrectly.
         * @throws UntrustedIdentityException when the {@link IdentityKey} of the sender is untrusted.
         */
		public byte[] Decrypt(PreKeySignalMessage ciphertext, IDecryptionCallback callback)

		{
			lock (SessionLock)
			{
				SessionRecord sessionRecord = _sessionStore.LoadSession(_remoteAddress);
				May<uint> unsignedPreKeyId = _sessionBuilder.Process(sessionRecord, ciphertext);
				byte[] plaintext = Decrypt(sessionRecord, ciphertext.GetSignalMessage());

				callback.HandlePlaintext(plaintext);

				_sessionStore.StoreSession(_remoteAddress, sessionRecord);

				if (unsignedPreKeyId.HasValue)
				{
					_preKeyStore.RemovePreKey(unsignedPreKeyId.ForceGetValue());
				}

				return plaintext;
			}
		}

		/**
         * Decrypt a message.
         *
         * @param  ciphertext The {@link SignalMessage} to decrypt.
         *
         * @return The plaintext.
         * @throws InvalidMessageException if the input is not valid ciphertext.
         * @throws DuplicateMessageException if the input is a message that has already been received.
         * @throws LegacyMessageException if the input is a message formatted by a protocol version that
         *                                is no longer supported.
         * @throws NoSessionException if there is no established session for this contact.
         */
		public byte[] Decrypt(SignalMessage ciphertext)

		{
			return Decrypt(ciphertext, new NullDecryptionCallback());
		}

		/**
         * Decrypt a message.
         *
         * @param  ciphertext The {@link SignalMessage} to decrypt.
         * @param  callback   A callback that is triggered after decryption is complete,
         *                    but before the updated session state has been committed to the session
         *                    DB.  This allows some implementations to store the committed plaintext
         *                    to a DB first, in case they are concerned with a crash happening between
         *                    the time the session state is updated but before they're able to store
         *                    the plaintext to disk.
         *
         * @return The plaintext.
         * @throws InvalidMessageException if the input is not valid ciphertext.
         * @throws DuplicateMessageException if the input is a message that has already been received.
         * @throws LegacyMessageException if the input is a message formatted by a protocol version that
         *                                is no longer supported.
         * @throws NoSessionException if there is no established session for this contact.
         */
		public byte[] Decrypt(SignalMessage ciphertext, IDecryptionCallback callback)

		{
			lock (SessionLock)
			{

				if (!_sessionStore.ContainsSession(_remoteAddress))
				{
					throw new NoSessionException($"No session for: {_remoteAddress}");
				}

				SessionRecord sessionRecord = _sessionStore.LoadSession(_remoteAddress);
				byte[] plaintext = Decrypt(sessionRecord, ciphertext);

				callback.HandlePlaintext(plaintext);

				_sessionStore.StoreSession(_remoteAddress, sessionRecord);

				return plaintext;
			}
		}

		private byte[] Decrypt(SessionRecord sessionRecord, SignalMessage ciphertext)
		{
			lock (SessionLock)
			{
				IEnumerator<SessionState> previousStates = sessionRecord.GetPreviousSessionStates().GetEnumerator(); //iterator
				LinkedList<Exception> exceptions = new LinkedList<Exception>();

				try
				{
					SessionState sessionState = new SessionState(sessionRecord.GetSessionState());
					byte[] plaintext = Decrypt(sessionState, ciphertext);

					sessionRecord.SetState(sessionState);
					return plaintext;
				}
				catch (InvalidMessageException e)
				{
					exceptions.AddLast(e); // add (java default behavioir addlast)
				}

				while (previousStates.MoveNext()) //hasNext();
				{
					try
					{
						SessionState promotedState = new SessionState(previousStates.Current); //.next()
						byte[] plaintext = Decrypt(promotedState, ciphertext);

						sessionRecord.GetPreviousSessionStates().Remove(previousStates.Current); // previousStates.remove()
						sessionRecord.PromoteState(promotedState);

						return plaintext;
					}
					catch (InvalidMessageException e)
					{
						exceptions.AddLast(e);
					}
				}

				throw new InvalidMessageException("No valid sessions.", exceptions);
			}
		}

		private byte[] Decrypt(SessionState sessionState, SignalMessage ciphertextMessage)
		{
			if (!sessionState.HasSenderChain())
			{
				throw new InvalidMessageException("Uninitialized session!");
			}

			if (ciphertextMessage.GetMessageVersion() != sessionState.GetSessionVersion())
			{
				throw new InvalidMessageException($"Message version {ciphertextMessage.GetMessageVersion()}, but session version {sessionState.GetSessionVersion()}");
			}

			uint messageVersion = ciphertextMessage.GetMessageVersion();
			IEcPublicKey theirEphemeral = ciphertextMessage.GetSenderRatchetKey();
			uint counter = ciphertextMessage.GetCounter();
			ChainKey chainKey = GetOrCreateChainKey(sessionState, theirEphemeral);
			MessageKeys messageKeys = GetOrCreateMessageKeys(sessionState, theirEphemeral,
																	  chainKey, counter);

			ciphertextMessage.VerifyMac(messageVersion,
											sessionState.GetRemoteIdentityKey(),
											sessionState.GetLocalIdentityKey(),
											messageKeys.GetMacKey());

			byte[] plaintext = GetPlaintext(messageVersion, messageKeys, ciphertextMessage.GetBody());

			sessionState.ClearUnacknowledgedPreKeyMessage();

			return plaintext;
		}

		public uint GetRemoteRegistrationId()
		{
			lock (SessionLock)
			{
				SessionRecord record = _sessionStore.LoadSession(_remoteAddress);
				return record.GetSessionState().GetRemoteRegistrationId();
			}
		}

		public uint GetSessionVersion()
		{
			lock (SessionLock)
			{
				if (!_sessionStore.ContainsSession(_remoteAddress))
				{
					throw new Exception($"No session for {_remoteAddress}!"); // IllegalState
				}

				SessionRecord record = _sessionStore.LoadSession(_remoteAddress);
				return record.GetSessionState().GetSessionVersion();
			}
		}

		private ChainKey GetOrCreateChainKey(SessionState sessionState, IEcPublicKey theirEphemeral)

		{
			try
			{
				if (sessionState.HasReceiverChain(theirEphemeral))
				{
					return sessionState.GetReceiverChainKey(theirEphemeral);
				}
				else
				{
					RootKey rootKey = sessionState.GetRootKey();
					EcKeyPair ourEphemeral = sessionState.GetSenderRatchetKeyPair();
					Pair<RootKey, ChainKey> receiverChain = rootKey.CreateChain(theirEphemeral, ourEphemeral);
					EcKeyPair ourNewEphemeral = Curve.GenerateKeyPair();
					Pair<RootKey, ChainKey> senderChain = receiverChain.First().CreateChain(theirEphemeral, ourNewEphemeral);

					sessionState.SetRootKey(senderChain.First());
					sessionState.AddReceiverChain(theirEphemeral, receiverChain.Second());
					sessionState.SetPreviousCounter(Math.Max(sessionState.GetSenderChainKey().GetIndex() - 1, 0));
					sessionState.SetSenderChain(ourNewEphemeral, senderChain.Second());

					return receiverChain.Second();
				}
			}
			catch (InvalidKeyException e)
			{
				throw new InvalidMessageException(e);
			}
		}

		private MessageKeys GetOrCreateMessageKeys(SessionState sessionState,
												   IEcPublicKey theirEphemeral,
												   ChainKey chainKey, uint counter)

		{
			if (chainKey.GetIndex() > counter)
			{
				if (sessionState.HasMessageKeys(theirEphemeral, counter))
				{
					return sessionState.RemoveMessageKeys(theirEphemeral, counter);
				}
				else
				{
					throw new DuplicateMessageException($"Received message with old counter: {chainKey.GetIndex()}  , {counter}");
				}
			}

			//Avoiding a uint overflow
			uint chainKeyIndex = chainKey.GetIndex();
			if ((counter > chainKeyIndex) && (counter - chainKeyIndex > 2000))
			{
				throw new InvalidMessageException("Over 2000 messages into the future!");
			}

			while (chainKey.GetIndex() < counter)
			{
				MessageKeys messageKeys = chainKey.GetMessageKeys();
				sessionState.SetMessageKeys(theirEphemeral, messageKeys);
				chainKey = chainKey.GetNextChainKey();
			}

			sessionState.SetReceiverChainKey(theirEphemeral, chainKey.GetNextChainKey());
			return chainKey.GetMessageKeys();
		}

		private byte[] GetCiphertext(uint version, MessageKeys messageKeys, byte[] plaintext)
		{
			try
			{
				if (version >= 3)
				{
					//cipher = getCipher(Cipher.ENCRYPT_MODE, messageKeys.getCipherKey(), messageKeys.getIv());
					return Util.Encrypt.AesCbcPkcs5(plaintext, messageKeys.GetCipherKey(), messageKeys.GetIv());
				}
				else
				{
					//cipher = getCipher(Cipher.ENCRYPT_MODE, messageKeys.getCipherKey(), messageKeys.getCounter());
					return Util.Encrypt.AesCtr(plaintext, messageKeys.GetCipherKey(), messageKeys.GetCounter());
				}
			}
			catch (/*IllegalBlockSizeException | BadPadding*/Exception e)
			{
				throw new Exception(e.Message);
			}
		}

		private byte[] GetPlaintext(uint version, MessageKeys messageKeys, byte[] cipherText)
		{
			try
			{
				//Cipher cipher;

				if (version >= 3)
				{
					//cipher = getCipher(Cipher.DECRYPT_MODE, messageKeys.getCipherKey(), messageKeys.getIv());
					return Util.Decrypt.AesCbcPkcs5(cipherText, messageKeys.GetCipherKey(), messageKeys.GetIv());
				}
				else
				{
					//cipher = getCipher(Cipher.DECRYPT_MODE, messageKeys.getCipherKey(), messageKeys.getCounter())
					return Util.Decrypt.AesCtr(cipherText, messageKeys.GetCipherKey(), messageKeys.GetCounter());
				}
			}
			catch (/*IllegalBlockSizeException | BadPadding*/Exception e)
			{
				throw new InvalidMessageException(e);
			}
		}

		private class NullDecryptionCallback : IDecryptionCallback
		{

			public void HandlePlaintext(byte[] plaintext) { }
		}
	}
}
