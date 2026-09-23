from __future__ import annotations

import unittest

from evalfoundry.rubric import evaluate_rubric, validate_response

from tests.helpers import evidence


class RubricTests(unittest.TestCase):
    def test_known_exploited_is_two_urgency_points(self) -> None:
        record = evidence()
        record["known_exploited"] = True
        label, trace = evaluate_rubric(record)
        self.assertEqual("critical", label)
        self.assertEqual(["CISA_KEV", "CISA_KEV", "NETWORK", "NO_AUTH"], trace["urgency_signals"])
        self.assertEqual(9, trace["final_points"])

    def test_v2_auth_and_dampening(self) -> None:
        record = evidence() | {
            "cvss_score": 4.0,
            "cvss_vector": "AV:L/AC:H/Au:M/C:P/I:P/A:P",
            "cvss_version": "2.0",
            "known_exploited": False,
        }
        label, trace = evaluate_rubric(record)
        self.assertEqual("low", label)
        self.assertEqual(
            ["LOCAL_OR_PHYSICAL", "HIGH_COMPLEXITY", "HIGH_PRIVILEGE_OR_MULTIPLE_AUTH"],
            trace["dampening_signals"],
        )

    def test_validation_rejects_conflicting_points(self) -> None:
        record = evidence()
        result = validate_response(
            {
                "triage_priority": "high",
                "rubric_trace": {"fabricated": True},
                "explanation": "A made-up explanation cannot make this trace valid.",
            },
            record,
            "high",
        )
        self.assertFalse(result.accepted)
        self.assertIn("Model rubric_trace does not match the local rubric computation.", result.errors)
