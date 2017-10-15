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
using System.Linq;

namespace Libsignal.State
{
    /**
 * A SessionRecord encapsulates the state of an ongoing session.
 *
 * @author Moxie Marlinspike
 */
    public class SessionRecord
    {

        private static int _archivedStatesMaxLength = 40;

        private SessionState _sessionState = new SessionState();
        private LinkedList<SessionState> _previousStates = new LinkedList<SessionState>();
        private bool _fresh = false;

        public SessionRecord()
        {
            _fresh = true;
        }

        public SessionRecord(SessionState sessionState)
        {
            _sessionState = sessionState;
            _fresh = false;
        }

        public SessionRecord(byte[] serialized)
        {
            StorageProtos.RecordStructure record = StorageProtos.RecordStructure.ParseFrom(serialized);
            _sessionState = new SessionState(record.CurrentSession);
            _fresh = false;

            foreach (StorageProtos.SessionStructure previousStructure in record.PreviousSessionsList)
            {
                _previousStates.AddLast(new SessionState(previousStructure)); // add -> AddLast (java)
            }
        }

        public bool HasSessionState(uint version, byte[] aliceBaseKey)
        {
            if (_sessionState.GetSessionVersion() == version &&
                Enumerable.SequenceEqual(aliceBaseKey, _sessionState.GetAliceBaseKey()))
            {
                return true;
            }

            foreach (SessionState state in _previousStates)
            {
                if (state.GetSessionVersion() == version &&
                    Enumerable.SequenceEqual(aliceBaseKey, state.GetAliceBaseKey()))
                {
                    return true;
                }
            }

            return false;
        }

        public SessionState GetSessionState()
        {
            return _sessionState;
        }

        /**
         * @return the list of all currently maintained "previous" session states.
         */
        public LinkedList<SessionState> GetPreviousSessionStates()
        {
            return _previousStates;
        }


        public bool IsFresh()
        {
            return _fresh;
        }

        /**
         * Move the current {@link SessionState} into the list of "previous" session states,
         * and replace the current {@link org.whispersystems.libsignal.state.SessionState}
         * with a fresh reset instance.
         */
        public void ArchiveCurrentState()
        {
            PromoteState(new SessionState());
        }

        public void PromoteState(SessionState promotedState)
        {
            _previousStates.AddFirst(_sessionState);
            _sessionState = promotedState;

            if (_previousStates.Count > _archivedStatesMaxLength)
            {
                _previousStates.RemoveLast();
            }
        }

        public void SetState(SessionState sessionState)
        {
            _sessionState = sessionState;
        }

        /**
         * @return a serialized version of the current SessionRecord.
         */
        public byte[] Serialize()
        {
            List<StorageProtos.SessionStructure> previousStructures = new List<StorageProtos.SessionStructure>();

            foreach (SessionState previousState in _previousStates)
            {
                previousStructures.Add(previousState.GetStructure());
            }

            StorageProtos.RecordStructure record = StorageProtos.RecordStructure.CreateBuilder()
                                                    .SetCurrentSession(_sessionState.GetStructure())
                                                    .AddRangePreviousSessions(previousStructures)
                                                    /*.AddAllPreviousSessions(previousStructures)*/
                                                    .Build();

            return record.ToByteArray();
        }

    }
}
