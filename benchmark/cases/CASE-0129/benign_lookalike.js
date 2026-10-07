import Meetings from '/imports/api/meetings';
import Auth from '/imports/ui/services/auth';

/**
 * Same "findOne with a field projection, then read a nested lock setting"
 * shape, but the projection includes EVERY field the function goes on to
 * read (disableRecording), so the check sees the real setting.
 */
export const isRecordingLocked = () => {
  const meeting = Meetings.findOne({ meetingId: Auth.meetingID },
    { fields: { 'lockSettingsProps.disableRecording': 1 } });

  return !!(meeting
    && meeting.lockSettingsProps
    && meeting.lockSettingsProps.disableRecording);
};
