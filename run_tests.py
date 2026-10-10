"""
Standalone Test Runner for Privilege Escalation Activity Monitor.
Executes the comprehensive unittest suite and outputs clean terminal diagnostics.
"""

import unittest
import sys

if __name__ == "__main__":
    print("=" * 70)
    print(" Running Privilege Escalation Activity Monitor Test Suite")
    print("=" * 70)
    suite = unittest.defaultTestLoader.discover(start_dir="tests", pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if not result.wasSuccessful():
        print("\n[FAIL] Tests failed!")
        sys.exit(1)
    else:
        print(f"\n[PASS] All {result.testsRun} tests passed successfully!")
        sys.exit(0)

