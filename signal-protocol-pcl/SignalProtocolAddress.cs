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

namespace Libsignal
{
    public class SignalProtocolAddress
    {

        private readonly String _name;
        private readonly uint _deviceId;

        public SignalProtocolAddress(String name, uint deviceId)
        {
            _name = name;
            _deviceId = deviceId;
        }

        public String GetName()
        {
            return _name;
        }

        public uint GetDeviceId()
        {
            return _deviceId;
        }

        public override String ToString()
        {
            return _name + ":" + _deviceId;
        }

        public override bool Equals(Object other)
        {
            if (other == null) return false;
            if (!(other is SignalProtocolAddress)) return false;

            SignalProtocolAddress that = (SignalProtocolAddress)other;
            return _name.Equals(that._name) && _deviceId == that._deviceId;
        }


        public override int GetHashCode()
        {
            return _name.GetHashCode() ^ (int)_deviceId;
        }
    }
}
