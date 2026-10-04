"""Small statistics helpers shared by the run_*.py scripts (NumPy + SciPy only)."""
import numpy as np
from scipy import stats


def mean_sem(values):
    v = np.asarray(values, dtype=float)
    return float(v.mean()), float(v.std(ddof=1) / np.sqrt(len(v)))


def cohens_dz(a, b):
    """Paired effect size: mean(a-b) / SD(a-b)."""
    d = np.asarray(a, dtype=float) - np.asarray(b, dtype=float)
    return float(d.mean() / d.std(ddof=1))


def tost_paired(a, b, margin):
    """Two one-sided paired t-tests for equivalence within +/- margin.
    Returns the TOST p-value (the larger of the two one-sided p-values)."""
    d = np.asarray(a, dtype=float) - np.asarray(b, dtype=float)
    n = len(d)
    se = d.std(ddof=1) / np.sqrt(n)
    p_lower = 1.0 - stats.t.cdf((d.mean() + margin) / se, n - 1)   # H0: diff <= -margin
    p_upper = stats.t.cdf((d.mean() - margin) / se, n - 1)         # H0: diff >= +margin
    return float(max(p_lower, p_upper))


def fmt_p(p):
    return "<0.0001" if p < 0.0001 else f"{p:.4f}"
