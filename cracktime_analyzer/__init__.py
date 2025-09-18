"""CrackTime Analyzer package"""

__version__ = "0.1.0"

# Re-export common helpers
from .core import analyze_password, estimate_crack_time_from_guesses  # noqa: F401
from .report import save_json_report, save_csv_report  # noqa: F401
