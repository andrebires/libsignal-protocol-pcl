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

namespace WhisperSystems.Libsignal.State.Impl
{
    public class InMemorySessionStore : ISessionStore
	{
		static object _lock = new object();

		private readonly IDictionary<SignalProtocolAddress, byte[]> _sessions = new Dictionary<SignalProtocolAddress, byte[]>();

		public InMemorySessionStore() { }

		//[MethodImpl(MethodImplOptions.Synchronized)]
		public SessionRecord LoadSession(SignalProtocolAddress remoteAddress)
		{
			try
			{
				if (ContainsSession(remoteAddress))
				{
					byte[] session;
					_sessions.TryGetValue(remoteAddress, out session); // get()

					return new SessionRecord(session);
				}
				else
				{
					return new SessionRecord();
				}
			}
			catch (Exception e)
			{
				throw new Exception(e.Message);
			}
		}

		public List<uint> GetSubDeviceSessions(String name)
		{
			List<uint> deviceIds = new List<uint>();

			foreach (SignalProtocolAddress key in _sessions.Keys) //keySet()
			{
				if (key.GetName().Equals(name) &&
					key.GetDeviceId() != 1)
				{
					deviceIds.Add(key.GetDeviceId());
				}
			}

			return deviceIds;
		}

		public void StoreSession(SignalProtocolAddress address, SessionRecord record)
		{
			_sessions[address] = record.Serialize();
		}

		public bool ContainsSession(SignalProtocolAddress address)
		{
			return _sessions.ContainsKey(address);
		}

		public void DeleteSession(SignalProtocolAddress address)
		{
			_sessions.Remove(address);
		}

		public void DeleteAllSessions(String name)
		{
			foreach (SignalProtocolAddress key in _sessions.Keys) // keySet()
			{
				if (key.GetName().Equals(name))
				{
					_sessions.Remove(key);
				}
			}
		}
	}
}
