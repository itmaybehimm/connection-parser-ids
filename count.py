from collections import deque
import datetime

from const import WINDOW_DURATION


# Holds data for counting timestamp connection for last WINDOW_DURATION time
class Count:
    def __init__(self):
        self.timestamps: deque[datetime.datetime] = deque()

    def update_timestamps(self, current_time: datetime.datetime):
        self.timestamps.append(current_time)
        while self.timestamps and self.timestamps[
            0
        ] < current_time - datetime.timedelta(seconds=WINDOW_DURATION):
            self.timestamps.popleft()

    def get_count(self, current_time: datetime.datetime):
        """
        Get total number of timestamps, this effectively gets count as at the last activity, time stamp is updated properly
        """
        return len(self.timestamps)
