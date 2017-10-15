/** 
 * Copyright (C) 2017 smndtrl, langboost, golf1052
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

using Google.ProtocolBuffers;
using Libsignal.Util;

namespace Libsignal.Fingerprint
{

    public class ScannableFingerprint
    {
        private static readonly int Version = 0;

        private readonly FingerprintProtos.CombinedFingerprints _fingerprints;

        internal ScannableFingerprint(byte[] localFingerprintData, byte[] remoteFingerprintData)
        {
            FingerprintProtos.LogicalFingerprint localFingerprint = FingerprintProtos.LogicalFingerprint.CreateBuilder()
                .SetContent(ByteString.CopyFrom(ByteUtil.Trim(localFingerprintData, 32)))
                .Build();

            FingerprintProtos.LogicalFingerprint remoteFingerprint = FingerprintProtos.LogicalFingerprint.CreateBuilder()
                .SetContent(ByteString.CopyFrom(ByteUtil.Trim(remoteFingerprintData, 32)))
                .Build();

            _fingerprints = FingerprintProtos.CombinedFingerprints.CreateBuilder()
                .SetVersion((uint)Version)
                .SetLocalFingerprint(localFingerprint)
                .SetRemoteFingerprint(remoteFingerprint)
                .Build();
        }

        /**
         * @return A byte string to be displayed in a QR code.
         */
        public byte[] GetSerialized()
        {
            return _fingerprints.ToByteArray();
        }

        /**
         * Compare a scanned QR code with what we expect.
         *
         * @param scannedFingerprintData The scanned data
         * @return True if matching, otehrwise false.
         * @throws FingerprintVersionMismatchException if the scanned fingerprint is the wrong version.
         * @throws FingerprintIdentifierMismatchException if the scanned fingerprint is for the wrong stable identifier.
         */
        public bool CompareTo(byte[] scannedFingerprintData)
        /* throws FingerprintVersionMismatchException,
               FingerprintIdentifierMismatchException,
               FingerprintParsingException */
        {
            try
            {
                FingerprintProtos.CombinedFingerprints scanned = FingerprintProtos.CombinedFingerprints.ParseFrom(scannedFingerprintData);

                if (!scanned.HasRemoteFingerprint || !scanned.HasLocalFingerprint ||
                    !scanned.HasVersion || scanned.Version != _fingerprints.Version)
                {
                    throw new FingerprintVersionMismatchException((int)scanned.Version, Version);
                }

                return ByteUtil.IsEqual(_fingerprints.LocalFingerprint.Content.ToByteArray(), scanned.RemoteFingerprint.Content.ToByteArray()) &&
                       ByteUtil.IsEqual(_fingerprints.RemoteFingerprint.Content.ToByteArray(), scanned.LocalFingerprint.Content.ToByteArray());
            }
            catch (InvalidProtocolBufferException e)
            {
                throw new FingerprintParsingException(e);
            }
        }
    }
}