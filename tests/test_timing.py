import unittest
from unittest.mock import Mock

from converter.timing import BuildTiming


class TimingTest(unittest.TestCase):
    def test_phase_records_elapsed_time_without_changing_result(self):
        timer = BuildTiming()
        with timer.phase("phase"):
            result = {"unchanged": True}
        self.assertIs(result["unchanged"], True)
        self.assertGreaterEqual(timer.phases["phase"], 0.0)

    def test_external_timing_records_calls_and_slowest_label(self):
        timer = BuildTiming()
        command = Mock(return_value="result")
        self.assertEqual(timer.observe_external("mihomo", "compile sample", command, "ignored"), "result")
        self.assertEqual(timer.external["mihomo"].calls, 1)
        self.assertGreaterEqual(timer.external["mihomo"].seconds, 0.0)
        self.assertEqual(timer.external["mihomo"].slowest_label, "compile sample")
        command.assert_called_once_with("ignored")

    def test_phase_and_external_timing_do_not_swallow_exceptions(self):
        timer = BuildTiming()
        with self.assertRaisesRegex(RuntimeError, "phase failure"):
            with timer.phase("failing phase"):
                raise RuntimeError("phase failure")
        with self.assertRaisesRegex(RuntimeError, "command failure"):
            timer.observe_external("sing-box", "compile sample", Mock(side_effect=RuntimeError("command failure")))
        self.assertEqual(timer.external["sing-box"].calls, 1)


if __name__ == "__main__":
    unittest.main()
