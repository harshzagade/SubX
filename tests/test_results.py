import unittest
from subx.results import (
    normalize_subdomain,
    merge_sources,
    dedupe_results,
    sort_results,
)


class TestNormalizeSubdomain(unittest.TestCase):
    def test_lowercases(self):
        self.assertEqual(normalize_subdomain("WWW.Example.COM"), "www.example.com")

    def test_strips_trailing_dot(self):
        self.assertEqual(normalize_subdomain("www.example.com."), "www.example.com")

    def test_strips_whitespace(self):
        self.assertEqual(normalize_subdomain("  www.example.com  "), "www.example.com")

    def test_already_canonical(self):
        self.assertEqual(normalize_subdomain("api.example.com"), "api.example.com")


class TestMergeSources(unittest.TestCase):
    def test_same_label_unchanged(self):
        self.assertEqual(merge_sources("Passive", "Passive"), "Passive")

    def test_passive_plus_brute_is_both(self):
        self.assertEqual(merge_sources("Passive", "Brute"), "Both")
        self.assertEqual(merge_sources("Brute", "Passive"), "Both")

    def test_both_absorbs_single(self):
        self.assertEqual(merge_sources("Both", "Passive"), "Both")
        self.assertEqual(merge_sources("Brute", "Both"), "Both")


class TestDedupeResults(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(dedupe_results([]), [])

    def test_no_duplicates_pass_through(self):
        rows = [
            ("a.example.com", "200", "Passive", "1.2.3.4", ""),
            ("b.example.com", "301", "Brute", "5.6.7.8", ""),
        ]
        self.assertEqual(len(dedupe_results(rows)), 2)

    def test_case_variants_merge(self):
        rows = [
            ("WWW.Example.com", "200", "Passive", "1.2.3.4", ""),
            ("www.example.com", "No HTTP", "Brute", "1.2.3.4", ""),
        ]
        merged = dedupe_results(rows)
        self.assertEqual(len(merged), 1)
        sub, status, source, ips, cname = merged[0]
        self.assertEqual(sub, "www.example.com")
        self.assertEqual(status, "200")
        self.assertEqual(source, "Both")
        self.assertEqual(ips, "1.2.3.4")

    def test_cname_alias_kept_on_merge(self):
        rows = [
            ("WWW.Example.com", "200", "Passive", "1.2.3.4", ""),
            ("www.example.com", "No HTTP", "Brute", "1.2.3.4", "cdn.provider.net"),
        ]
        merged = dedupe_results(rows)
        self.assertEqual(len(merged), 1)
        sub, status, source, ips, cname = merged[0]
        self.assertEqual(cname, "cdn.provider.net")

    def test_trailing_dot_variants_merge(self):
        rows = [
            ("api.example.com.", "200", "Passive", "1.2.3.4", ""),
            ("api.example.com", "200", "Passive", "1.2.3.4", ""),
        ]
        self.assertEqual(len(dedupe_results(rows)), 1)

    def test_status_prefers_numeric_over_no_http(self):
        rows = [
            ("a.example.com", "No HTTP", "Passive", "1.2.3.4", ""),
            ("A.EXAMPLE.COM", "N/A", "Brute", "1.2.3.4", ""),
        ]
        (row,) = dedupe_results(rows)
        self.assertEqual(row[1], "No HTTP")

    def test_status_prefers_lower_numeric(self):
        rows = [
            ("a.example.com", "301", "Passive", "1.2.3.4", ""),
            ("a.example.com", "200", "Brute", "1.2.3.4", ""),
        ]
        (row,) = dedupe_results(rows)
        self.assertEqual(row[1], "200")

    def test_ips_are_unioned_and_sorted(self):
        rows = [
            ("a.example.com", "200", "Passive", "10.0.0.10, 10.0.0.2", ""),
            ("A.example.com", "200", "Brute", "10.0.0.2, 10.0.0.1", ""),
        ]
        (row,) = dedupe_results(rows)
        self.assertEqual(row[3], "10.0.0.1, 10.0.0.2, 10.0.0.10")

    def test_three_way_merge(self):
        rows = [
            ("MAIL.example.com", "200", "Passive", "1.1.1.1", ""),
            ("mail.example.com.", "301", "Brute", "2.2.2.2", ""),
            ("mail.example.com", "No HTTP", "Passive", "3.3.3.3", ""),
        ]
        (row,) = dedupe_results(rows)
        self.assertEqual(row[0], "mail.example.com")
        self.assertEqual(row[1], "200")
        self.assertEqual(row[2], "Both")
        self.assertEqual(row[3], "1.1.1.1, 2.2.2.2, 3.3.3.3")


class TestSortResults(unittest.TestCase):
    def test_sorts_by_subdomain(self):
        rows = [
            ("www.example.com", "200", "Passive", "1.2.3.4", ""),
            ("api.example.com", "301", "Brute", "5.6.7.8", ""),
            ("mail.example.com", "No HTTP", "Passive", "9.9.9.9", ""),
        ]
        ordered = [r[0] for r in sort_results(rows)]
        self.assertEqual(ordered, ["api.example.com", "mail.example.com", "www.example.com"])

    def test_sort_is_case_insensitive(self):
        rows = [
            ("WWW.example.com", "200", "Passive", "1.2.3.4", ""),
            ("api.example.com", "200", "Passive", "5.6.7.8", ""),
        ]
        ordered = [r[0] for r in sort_results(rows)]
        self.assertEqual(ordered, ["api.example.com", "WWW.example.com"])


if __name__ == '__main__':
    unittest.main()
