import math
from cracktime_analyzer.core import analyze_password, _shannon_entropy_bits, estimate_crack_time_from_guesses

def test_shannon_entropy():
    e = _shannon_entropy_bits("aaaa")
    # all identical -> entropy should be 0
    assert math.isclose(e, 0.0, abs_tol=1e-6)

    e2 = _shannon_entropy_bits("abcd")
    # 4 unique chars, per-char entropy = 2 bits -> total 8 bits
    assert abs(e2 - 8.0) < 0.1

def test_analyze_password_basic():
    r = analyze_password("P@ssw0rd!")
    assert r["length"] == 9
    assert "entropy_bits" in r
    assert "guesses" in r
    assert 0 <= r["score"] <= 4

def test_estimate_crack_time():
    # 1e6 guesses at 1e3 gps -> 1000s
    info = estimate_crack_time_from_guesses(1_000_000, 1_000)
    assert abs(info["seconds"] - 1000.0) < 1e-6
    assert "human_readable" in info
