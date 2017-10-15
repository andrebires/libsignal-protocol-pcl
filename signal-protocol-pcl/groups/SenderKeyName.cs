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

namespace Libsignal.Groups
{
    /**
     * A representation of a (groupId + senderId + deviceId) tuple.
     */
    public class SenderKeyName
    {

        private readonly String _groupId;
        private readonly SignalProtocolAddress _sender;

        public SenderKeyName(String groupId, SignalProtocolAddress sender)
        {
            _groupId = groupId;
            _sender = sender;
        }

        public String GetGroupId()
        {
            return _groupId;
        }

        public SignalProtocolAddress GetSender()
        {
            return _sender;
        }

        public String Serialize()
        {
            return _groupId + "::" + _sender.GetName() + "::" + _sender.GetDeviceId();
        }


        public override bool Equals(Object other)
        {
            if (other == null) return false;
            if (!(other is SenderKeyName)) return false;

            SenderKeyName that = (SenderKeyName)other;

            return
                _groupId.Equals(that._groupId) &&
                _sender.Equals(that._sender);
        }

        public override int GetHashCode()
        {
            return _groupId.GetHashCode() ^ _sender.GetHashCode();
        }

    }
}
