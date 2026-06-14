"""
Windows Event Log reader.

Uses pywin32 (win32evtlog / win32evtlogutil) to read events from a single
Windows Event Log channel. Create one EventReader per channel and call
read_new() on each poll cycle — it tracks the highest RecordNumber seen
so successive calls return only events that arrived since the last read.

This module is Windows-only. The agent is not designed to run on Linux.
"""

try:
    import win32evtlog
    import win32evtlogutil
except ImportError:
    raise SystemExit(
        "[agent] pywin32 is required. Install it with: pip install pywin32"
    )


class EventReader:
    """
    Reads new events from one Windows Event Log channel.

    Args:
        channel:    Windows channel name, e.g. "Security" or
                    "Microsoft-Windows-Sysmon/Operational".
        source:     Label attached to every event — matched against the
                    `source` field in YAML detection rules.
        hostname:   This machine's hostname, included in every event dict.
        max_events: Cap on events returned per read_new() call.
    """

    def __init__(
        self,
        channel: str,
        source: str,
        hostname: str,
        max_events: int = 100,
    ) -> None:
        self.channel    = channel
        self.source     = source
        self.hostname   = hostname
        self.max_events = max_events
        # High-water mark: the highest RecordNumber already forwarded.
        # 0 means "nothing sent yet" — first call returns up to max_events
        # recent records.
        self._high_water = 0

    def read_new(self) -> list[dict]:
        """
        Return events newer than the last call, oldest-first.
        Returns an empty list if the channel is unavailable or has no new events.
        """
        try:
            handle = win32evtlog.OpenEventLog(None, self.channel)
        except Exception as exc:
            print(f"[reader] Cannot open '{self.channel}': {exc}")
            return []

        # BACKWARDS_READ + SEQUENTIAL_READ yields records newest-first.
        # We stop as soon as we hit a record we've already seen.
        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ
            | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        new_events: list[dict] = []
        new_high_water = self._high_water
        done = False

        try:
            while not done and len(new_events) < self.max_events:
                batch = win32evtlog.ReadEventLog(handle, flags, 0)
                if not batch:
                    break
                for record in batch:
                    if record.RecordNumber <= self._high_water:
                        done = True
                        break
                    new_events.append(self._parse(record))
                    if record.RecordNumber > new_high_water:
                        new_high_water = record.RecordNumber
                    if len(new_events) >= self.max_events:
                        done = True
                        break
        finally:
            win32evtlog.CloseEventLog(handle)

        self._high_water = new_high_water
        # Reverse so the server receives events in chronological order.
        return list(reversed(new_events))

    def _parse(self, record) -> dict:
        try:
            message = win32evtlogutil.SafeFormatMessage(record, self.channel)
        except Exception:
            message = ""

        return {
            "source":       self.source,
            "hostname":     self.hostname,
            "channel":      self.channel,
            # Windows packs facility and severity flags into the upper bits
            # of EventID; mask them off to get the plain 16-bit event number.
            "EventID":      record.EventID & 0xFFFF,
            "RecordNumber": record.RecordNumber,
            "TimeCreated":  record.TimeGenerated.Format(),
            "SourceName":   record.SourceName,
            "EventType":    record.EventType,
            "Message":      message,
        }
