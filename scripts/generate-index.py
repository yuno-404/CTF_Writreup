from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATEGORY_HINTS = {
    "pwn",
    "rev",
    "web",
    "crypto",
    "misc",
    "forensics",
    "osint",
    "mobile",
    "hardware",
    "ai",
    "blockchain",
    "jail",
    "pyjail",
}


def infer_category_and_name(folder_name: str) -> tuple[str, str]:
    if "_" not in folder_name:
        return "-", folder_name
    prefix, rest = folder_name.split("_", 1)
    if prefix.lower() in CATEGORY_HINTS and rest:
        return prefix.lower(), rest
    return "-", folder_name


def iter_challenges():
    seen_writeups: set[Path] = set()

    for year_dir in sorted(
        [p for p in ROOT.iterdir() if p.is_dir() and p.name.isdigit()]
    ):
        for event_dir in sorted([p for p in year_dir.iterdir() if p.is_dir()]):
            # Structured: year/event/category/challenge/README.md
            for category_dir in sorted([p for p in event_dir.iterdir() if p.is_dir()]):
                for challenge_dir in sorted(
                    [p for p in category_dir.iterdir() if p.is_dir()]
                ):
                    readme = challenge_dir / "README.md"
                    if readme.exists():
                        seen_writeups.add(readme)
                        src_dir = challenge_dir / "src"
                        source = src_dir if src_dir.exists() else challenge_dir
                        yield {
                            "year": year_dir.name,
                            "event": event_dir.name,
                            "category": category_dir.name,
                            "challenge": challenge_dir.name,
                            "writeup": readme,
                            "source": source,
                        }

            # Flat: year/event/challenge/README.md
            for challenge_dir in sorted([p for p in event_dir.iterdir() if p.is_dir()]):
                readme = challenge_dir / "README.md"
                if readme.exists() and readme not in seen_writeups:
                    seen_writeups.add(readme)
                    category, challenge = infer_category_and_name(challenge_dir.name)
                    src_dir = challenge_dir / "src"
                    source = src_dir if src_dir.exists() else challenge_dir
                    yield {
                        "year": year_dir.name,
                        "event": event_dir.name,
                        "category": category,
                        "challenge": challenge,
                        "writeup": readme,
                        "source": source,
                    }

            # Standalone markdown under event dir
            for md_file in sorted(event_dir.glob("*.md")):
                if md_file.name.lower() == "readme.md" or md_file in seen_writeups:
                    continue
                seen_writeups.add(md_file)
                yield {
                    "year": year_dir.name,
                    "event": event_dir.name,
                    "category": "article",
                    "challenge": md_file.stem,
                    "writeup": md_file,
                    "source": event_dir,
                }


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def build_table() -> str:
    header = "| Year | Event | Category | Challenge | Writeup | Source |"
    sep = "|---|---|---|---|---|---|"
    rows = [header, sep]

    for item in iter_challenges():
        rows.append(
            "| {year} | {event} | {category} | {challenge} | [Link]({writeup}) | [src]({source}) |".format(
                year=item["year"],
                event=item["event"],
                category=item["category"],
                challenge=item["challenge"],
                writeup=rel(item["writeup"]),
                source=rel(item["source"]),
            )
        )

    return "\n".join(rows)


if __name__ == "__main__":
    print(build_table())
