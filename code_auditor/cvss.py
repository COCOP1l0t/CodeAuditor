"""Static CVSS v3.1 base-score checks (FIRST specification, section 7)."""

from __future__ import annotations

import math
import re

_VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 0, "C": 1},
    "C": {"H": 0.56, "L": 0.22, "N": 0},
    "I": {"H": 0.56, "L": 0.22, "N": 0},
    "A": {"H": 0.56, "L": 0.22, "N": 0},
}
_VECTOR = re.compile(
    r"(?:CVSS:3\.1/)?(?:AV|AC|PR|UI|S|C|I|A):[A-Z](?:/(?:AV|AC|PR|UI|S|C|I|A):[A-Z]){3,}"
)


def base_score(vector: str) -> float:
    """Calculate a complete base vector; never infer missing metrics."""
    vector = vector.removeprefix("CVSS:3.1/")
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        key, sep, value = part.partition(":")
        if not sep or key in metrics or key not in _VALUES or value not in _VALUES[key]:
            raise ValueError(f"Invalid or duplicate CVSS base metric: {part}")
        metrics[key] = value
    missing = _VALUES.keys() - metrics.keys()
    if missing:
        raise ValueError("Missing CVSS base metric: " + ", ".join(sorted(missing)))
    values = {k: _VALUES[k][v] for k, v in metrics.items()}
    changed = metrics["S"] == "C"
    if changed:
        values["PR"] = {"N": 0.85, "L": 0.68, "H": 0.5}[metrics["PR"]]
    iss = 1 - math.prod(1 - values[k] for k in ("C", "I", "A"))
    impact = (
        (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if changed else 6.42 * iss
    )
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * math.prod(values[k] for k in ("AV", "AC", "PR", "UI"))
    raw = min((impact + exploitability) * (1.08 if changed else 1), 10)
    # Appendix A: round at five decimal places before rounding up to tenths.
    integer = round(raw * 100000)
    return integer / 100000 if integer % 10000 == 0 else (integer // 10000 + 1) / 10


def severity(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"


def report_score_errors(text: str, *, require_vector: bool = False) -> list[str]:
    """Compare explicitly written scores and vectors, without rescoring impact."""
    errors: list[str] = []
    matches = list(_VECTOR.finditer(text))
    if require_vector and not matches:
        return ["Missing CVSS v3.1 base vector"]
    for match in matches:
        vector = match.group()
        line = text.count("\n", 0, match.start()) + 1
        try:
            calculated = base_score(vector)
        except ValueError as exc:
            errors.append(f"Line {line}: {exc}")
            continue
        start = text.rfind("\n\n", 0, match.start())
        start = start + 2 if start >= 0 else 0
        end = text.find("\n\n", match.end())
        end = end if end >= 0 else len(text)
        paragraph = text[start:end]
        if "CVSS" not in paragraph:
            previous = text.rfind("\n\n", 0, max(0, start - 2))
            paragraph = text[previous + 2 if previous >= 0 else 0 : end]
        cleaned = _VECTOR.sub("", paragraph)
        cleaned = re.sub(r"CVSS\s*(?:v|:)?\s*3\.[01]", "CVSS", cleaned, flags=re.I)
        scores = [
            float(s)
            for s in re.findall(r"(?<![\d.])(?:10\.0|[0-9]\.[0-9])(?![\d.])", cleaned)
        ]
        if not scores and start:
            previous = text.rfind("\n\n", 0, max(0, start - 2))
            preceding = text[previous + 2 if previous >= 0 else 0 : start]
            preceding = _VECTOR.sub("", preceding)
            preceding = re.sub(
                r"CVSS\s*(?:v|:)?\s*3\.[01]", "CVSS", preceding, flags=re.I
            )
            if "CVSS" in preceding:
                scores = [
                    float(s)
                    for s in re.findall(
                        r"(?<![\d.])(?:10\.0|[0-9]\.[0-9])(?![\d.])", preceding
                    )
                ]
        if scores and calculated not in scores:
            errors.append(
                f"Line {line}: CVSS score {scores[0]:.1f} does not match "
                f"the written vector ({calculated:.1f}); verify score and metrics"
            )
    return list(dict.fromkeys(errors))
