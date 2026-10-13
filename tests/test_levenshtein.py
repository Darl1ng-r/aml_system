import pytest
from routers.screening import levenshtein_ratio, name_similarity_score


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


def test_name_similarity_score_jaro_winkler_and_length_discounting():
    """Verify Jaro-Winkler boost on transliterations and length discounting against short token inflation."""
    # Jaro-Winkler prefix alignment handles character substitutions
    score_jw = name_similarity_score("Aleksandr Petrov", "Alexander Petrov")
    assert score_jw >= 0.85

    # Token order invariance still scores 1.0 for matching full names
    assert name_similarity_score("Vladimir Smirnov", "Smirnov Vladimir") == 1.0

    # Asymmetric length discount: "Abu Bakr" vs "Abu Bakr Al-Baghdadi"
    # Pure token_set_ratio would yield 1.0, but length discounting scales it down to prevent alert floods
    score_asym = name_similarity_score("Abu Bakr", "Abu Bakr Al-Baghdadi")
    assert score_asym < 0.95
    assert score_asym >= 0.75

