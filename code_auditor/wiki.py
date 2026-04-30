from __future__ import annotations

from .config import AuditConfig

NO_WIKI_CONTEXT = "No wiki knowledge base configured."

_GENERIC_GUIDANCE = (
    "Use the wiki only as supporting audit knowledge. Start with `index.md` if it exists, "
    "then search root synthesis pages, `entities/`, `concepts/`, and `sources/` for pages "
    "matching the current component, vulnerability class, or historical pattern."
)

_STAGE_GUIDANCE: dict[int, str] = {
    1: (
        "Stage 1 lookup: start with `index.md` and `overview.md` if present. Search "
        "`vulnerability-timeline.md` and `sources/` for historical vulnerabilities, dates, "
        "affected components, root causes, impacts, and attacker profiles. Use root synthesis "
        "pages to supplement live research, and keep source attribution clear in the research record."
    ),
    2: (
        "Stage 2 lookup: start with `index.md`, `attack-surface.md`, `auditing-guide.md`, "
        "and `entities/`. Use entity pages to identify components that historically produce "
        "impactful vulnerabilities. Use concept pages when they help explain why an area is "
        "selected. Reflect relevant wiki knowledge in `triage.json` rationales and AU `focus` fields."
    ),
    3: (
        "Stage 3 lookup: start from the AU files, then search `entities/` for matching components "
        "or subsystem names. Search `concepts/` for vulnerability classes suggested by the code path. "
        "Search `exploit-patterns.md` and matching `sources/` pages for historical bug shapes. "
        "Use wiki pages as audit heuristics, not proof that this target is vulnerable."
    ),
    4: (
        "Stage 4 lookup: search `concepts/` and relevant `sources/` pages to calibrate "
        "false-positive checks, impact, and historical severity. Use `vulnerability-timeline.md` "
        "for broad historical comparison when useful. Do not confirm a vulnerability solely because "
        "a wiki page describes a similar historical issue; the source data-flow trace is authoritative."
    ),
    5: (
        "Stage 5 lookup: start with `reproduction-workflow.md`. Search matching entity, concept, "
        "and source pages for realistic trigger models, environment setup, expected evidence, and "
        "reproduction pitfalls. Use the wiki to choose the lowest reproduction level that preserves "
        "the vulnerable data flow."
    ),
    6: (
        "Stage 6 lookup: search relevant entity, concept, source, and reproduction pages for clear "
        "framing and maintainer-facing terminology. Use the wiki to improve report clarity, but keep "
        "disclosure claims grounded in Stage 5 evidence and the target source. Do not include internal "
        "wiki links or paths in disclosure artifacts unless they are explicitly useful for the recipient."
    ),
}


def build_wiki_context(config: AuditConfig, stage: int) -> str:
    if not config.wiki_path:
        return NO_WIKI_CONTEXT

    stage_guidance = _STAGE_GUIDANCE.get(stage, _GENERIC_GUIDANCE)
    return "\n".join([
        f"Wiki root: `{config.wiki_path}`",
        "The wiki is read-only. Do not create, edit, move, or delete files in it.",
        "If a referenced wiki file or directory is absent, skip it and continue with the available pages.",
        "Prefer `index.md` for navigation when it exists.",
        stage_guidance,
    ])
