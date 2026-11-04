from dataclasses import dataclass

from ccdc.scanners.lse import ListedPath, LSEScanner


@dataclass(frozen=True)
class WritableScheduledTask(ListedPath):
    code = "writable-scheduled-task"
    severity = "critical"
    what = "writable cron task, timer, or file a schedule runs"


class ScheduledTaskScanner(LSEScanner):
    tests = ("ret010", "ret050", "ret060", "ret510")
    listing_type = WritableScheduledTask
