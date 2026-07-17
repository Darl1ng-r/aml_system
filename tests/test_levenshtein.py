import pytest
from routers.screening import levenshtein_ratio


def test_levenshtein_ratio_exact_match():
    """Verify exact string match produces similarity ratio 1.0."""
    assert levenshtein_ratio("Vladimir Smirnov", "Vladimir Smirnov") == 1.0
    assert levenshtein_ratio("ALICE SCHMIDT", "alice schmidt") == 1.0


def test_levenshtein_ratio_fuzzy_match():
    """Verify fuzzy similarity ratio for minor name variations and transliterations."""
    score = levenshtein_ratio("Vladimir Smirnov", "Wladimir Smirnow")
    assert score >= 0.75

    score2 = levenshtein_ratio("Mohammad Al-Mansoor", "Muhammad Al Mansoor")
    assert score2 >= 0.80


def test_levenshtein_ratio_dissimilar_strings():
    """Verify distinct names produce low similarity scores."""
    score = levenshtein_ratio("Alice Schmidt", "Bob Jones")
    assert score < 0.40


def test_levenshtein_ratio_empty_strings():
    """Verify empty string edge cases."""
    assert levenshtein_ratio("", "") == 1.0
    assert levenshtein_ratio("Alice", "") < 0.20
