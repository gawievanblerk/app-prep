import pytest

from dpr.model import ScanError
from dpr.reviews import LABELS, REVIEWS, RUN_ORDER, TITLES, available, number, resolve_reviews


def test_constants():
    assert number("inventory") == 1 and number("abuse") == 7
    assert set(TITLES) == set(REVIEWS) == set(LABELS) == set(RUN_ORDER)
    assert RUN_ORDER[-1] == "inventory"


def test_resolve_reviews():
    assert resolve_reviews(["all"]) == list(REVIEWS)
    assert resolve_reviews(["6", 2]) == ["rls", "leaks"]
    assert resolve_reviews(["LEAKS", "rls", "2"]) == ["rls", "leaks"]
    with pytest.raises(ScanError, match="unknown review"):
        resolve_reviews(["8"])
    with pytest.raises(ScanError, match="no reviews"):
        resolve_reviews([])


def test_available_only_lists_existing_modules():
    modules = available()
    assert set(modules) <= set(REVIEWS)
    for slug, module in modules.items():
        assert module.__name__ == f"dpr.reviews.{slug}"
        assert callable(module.run)
