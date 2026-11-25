import unittest
from systemsentinel.mitigation import review_mitigations


class MitigationReviewTests(unittest.TestCase):
    def rows(self, updates=None, index_status=None):
        result = review_mitigations(updates, index_status,
            {"status": "standard_window", "catalog_stale": False})
        return {item["id"]: item for item in result["records"]}

    def test_missing_data_is_not_a_pass(self):
        self.assertEqual(self.rows()["patch-maintenance"]["status"], "not_assessed")
        self.assertEqual(self.rows()["credential-protection"]["status"], "manual_review")

    def test_candidate_and_expired_metadata_review(self):
        rows = self.rows([{"security_pocket": True}], {"status": "expired"})
        self.assertEqual(rows["patch-maintenance"]["status"], "review")
        self.assertEqual(rows["repository-freshness"]["status"], "review")

    def test_no_candidate_is_not_vulnerability_assessment(self):
        row = self.rows([], {"status": "within_declared_validity"})["patch-maintenance"]
        self.assertEqual(row["status"], "no_candidates_observed")
        self.assertIn("vulnerability status is not established", row["evidence"])
