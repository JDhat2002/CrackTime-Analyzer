"""
Core password auditing logic for CrackTime Analyzer.

Functions:
- analyze_password(password) -> dict
- estimate_crack_time_from_guesses(guesses, preset_or_speed) -> dict
"""

from __future__ import annotations
import math
import string
from typing import Dict, Any, Optional

# Try to import zxcvbn (strong estimator). If not available, we fallback.
try:
    from zxcvbn import zxcvbn  # type: ignore
    _HAS_ZXCVBN = True
except Exception:
    _HAS_ZXCVBN = False


def _shannon_entropy_bits(password: str) -> float:
    """Compute Shannon entropy (bits) per-character * length."""
    if not password:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1
    entropy_per_char = 0.0
    length = len(password)
    for count in freq.values():
        p = count / length
        entropy_per_char -= p * math.log2(p)
    return entropy_per_char * length


def analyze_password(password: str) -> Dict[str, Any]:
    """
    Analyze the supplied password and return a result dict.

    Returned keys include:
      - password_masked
      - length
      - has_upper, has_lower, has_digit, has_symbol
      - charset_size_est (heuristic)
      - entropy_bits (prefer zxcvbn if available, else Shannon)
      - guesses (estimate from zxcvbn if available, else 2**entropy)
      - score (0-4 from zxcvbn or heuristic 0-4)
      - notes
    """
    pw = password or ""
    length = len(pw)
    has_upper = any(c.isupper() for c in pw)
    has_lower = any(c.islower() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    symbols = set(string.printable) - set(string.ascii_letters) - set(string.digits)
    has_symbol = any((c in symbols) for c in pw)

    # heuristic charset size
    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        # approximate count of common printable symbols
        charset_size += 32

    # entropy & guesses
    notes = []
    entropy_bits: float = 0.0
    guesses: Optional[float] = None
    score: Optional[int] = None

    if _HAS_ZXCVBN:
        try:
            zres = zxcvbn(pw)
            # zxcvbn returns 'entropy' (float), 'guesses' (int), 'score' (0-4)
            entropy_bits = float(zres.get("entropy", _shannon_entropy_bits(pw)))
            guesses = float(zres.get("guesses", max(1.0, 2 ** (entropy_bits))))
            score = int(zres.get("score", 0))
        except Exception as ex:
            notes.append(f"zxcvbn error: {ex}; falling back to Shannon entropy")
            entropy_bits = _shannon_entropy_bits(pw)
            guesses = max(1.0, 2 ** (entropy_bits))
            score = _heuristic_score(entropy_bits, length)
    else:
        entropy_bits = _shannon_entropy_bits(pw)
        guesses = max(1.0, 2 ** (entropy_bits))
        score = _heuristic_score(entropy_bits, length)
        notes.append("zxcvbn not available; used Shannon entropy & heuristic score")

    result = {
        "password_masked": _mask_password(pw),
        "length": length,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "charset_size_est": charset_size,
        "entropy_bits": round(float(entropy_bits), 3),
        "guesses": int(guesses) if guesses is not None else None,
        "score": int(score) if score is not None else None,
        "notes": notes,
    }
    return result


def _mask_password(pw: str) -> str:
    """Return a masked representation (keep first and last char if length>2)."""
    if not pw:
        return ""
    if len(pw) <= 2:
        return "*" * len(pw)
    return pw[0] + "*" * (len(pw) - 2) + pw[-1]


def _heuristic_score(entropy_bits: float, length: int) -> int:
    """
    Map entropy/length to a 0-4 score (similar spirit to zxcvbn).
    This is a simple heuristic for when zxcvbn isn't available.
    """
    if length == 0:
        return 0
    if entropy_bits < 28:
        return 0
    if entropy_bits < 36:
        return 1
    if entropy_bits < 60:
        return 2
    if entropy_bits < 80:
        return 3
    return 4


def estimate_crack_time_from_guesses(guesses: float, guesses_per_second: float) -> Dict[str, Any]:
    """
    Convert a guesses estimate and guesses-per-second to human-friendly crack time.

    Returns dict with:
      - seconds
      - human_readable (string)
      - assumptions (guesses_per_second)
    """
    if guesses_per_second <= 0:
        raise ValueError("guesses_per_second must be > 0")

    seconds = float(guesses) / float(guesses_per_second)
    human = _human_readable_seconds(seconds)
    return {"seconds": seconds, "human_readable": human, "guesses_per_second": guesses_per_second}


def _human_readable_seconds(seconds: float) -> str:
    """Format seconds into years/days/hours/mins/seconds approximated."""
    if seconds < 1:
        return f"{seconds:.3f} seconds"
    minute = 60.0
    hour = 60 * minute
    day = 24 * hour
    year = 365.25 * day

    if seconds < minute:
        return f"{seconds:.2f} seconds"
    if seconds < hour:
        return f"{seconds/60:.2f} minutes"
    if seconds < day:
        return f"{seconds/hour:.2f} hours"
    if seconds < year:
        return f"{seconds/day:.2f} days"
    return f"{seconds/year:.2f} years"


# Preset attacker speeds (guesses per second)
CRACK_SPEED_PRESETS = {
    "conservative_cpu": 1e3,    # 1k guesses/sec (slow CPU)
    "mid_gpu": 1e9,             # 1 billion guesses/sec (common GPU cluster)
    "fast_gpu": 1e10,           # 10 billion guesses/sec (large cluster)
}
