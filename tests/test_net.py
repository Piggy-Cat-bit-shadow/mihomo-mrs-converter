import unittest
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

from converter.net import retry_after_seconds


class RetryAfterTest(unittest.TestCase):
    def test_seconds_and_http_date(self) -> None:
        self.assertEqual(retry_after_seconds("120"), 120.0)
        value = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=2), usegmt=True)
        self.assertGreaterEqual(retry_after_seconds(value), 0.0)
        self.assertEqual(retry_after_seconds("not-a-date"), 0.0)

    def test_past_http_date_is_zero(self) -> None:
        value = format_datetime(datetime(2015, 10, 21, tzinfo=timezone.utc), usegmt=True)
        self.assertEqual(retry_after_seconds(value), 0.0)
