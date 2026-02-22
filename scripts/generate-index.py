from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def iter_challenges():
    for year_dir in sorted(
        [p for p in ROOT.iterdir() if p.is_dir() and p.name.isdigit()]
    ):
        for event_dir in sorted([p for p in year_dir.iterdir() if p.is_dir()]):
            for category_dir in sorted([p for p in event_dir.iterdir() if p.is_dir()]):
                for challenge_dir in sorted(
                    [p for p in category_dir.iterdir() if p.is_dir()]
                ):
                    readme = challenge_dir / "README.md"
                    if readme.exists():
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


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def build_table() -> str:
    header = "| Year | Event | Category | Challenge | Writeup | Source |"
    sep = "|---|---|---|---|---|---|"
    rows = [header, sep]

    for item in iter_challenges():
        rows.append(
            "| {year} | {event} | {category} | {challenge} | [README]({writeup}) | [src]({source}) |".format(
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
