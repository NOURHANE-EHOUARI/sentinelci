"""Untrusted text must stay inert in GitHub-flavoured Markdown (report.markdown)."""

import re

import pytest

from sentinelci.report.markdown import MAX_TEXT, code, visible


def gfm_cells(row: str) -> list[str]:
    """Split a table row like cmark-gfm: a backslash escapes the next character, an unescaped pipe splits."""
    inner = row.strip()
    assert inner.startswith("|") and inner.endswith("|")
    cells, current, i = [], [], 1
    while i < len(inner) - 1:
        char = inner[i]
        if char == "\\" and i + 1 < len(inner) - 1:
            current += [char, inner[i + 1]]
            i += 2
            continue
        if char == "|":
            cells.append("".join(current))
            current = []
        else:
            current.append(char)
        i += 1
    cells.append("".join(current))
    return cells


@pytest.mark.parametrize(
    "hostile",
    [
        "@NOURHANE-EHOUARI please merge",
        "see #1 and owner/repo#2",
        "[click](https://evil.example) ![x](https://evil.example/pixel.png)",
        "<img src=x onerror=alert(1)> <script>alert(1)</script>",
        "https://evil.example/autolink www.evil.example",
        "**bold** _it_ ~~del~~ :rocket:",
    ],
)
def test_markdown_constructs_end_up_inside_a_single_code_span(hostile: str) -> None:
    rendered = code(hostile)
    fence = re.match(r"^`+", rendered)
    assert fence is not None
    assert rendered.endswith(fence.group())
    inner = rendered[len(fence.group()) : -len(fence.group())]
    assert fence.group() not in inner, "the span must not close early"


@pytest.mark.parametrize("text", ["`", "a`b", "``x``", "x```", "` leading", "trailing `"])
def test_backticks_cannot_close_the_span(text: str) -> None:
    rendered = code(text, in_table=False)
    longest_inside = max(len(run) for run in re.findall(r"`+", text))
    fence = re.match(r"^`+", rendered)
    assert fence is not None and len(fence.group()) == longest_inside + 1
    # padding spaces are added only when the content starts or ends with a backtick or a space;
    # CommonMark strips them again
    pad = " " if text[0] in "` " or text[-1] in "` " else ""
    assert rendered == f"{fence.group()}{pad}{text}{pad}{fence.group()}"


@pytest.mark.parametrize(
    "path",
    [
        "a|b",
        "a\\|b",
        "a\\\\|b",
        "a\\\\\\|b",
        "a\\",
        "|||",
        "x|y`|`z",
        "line\nbreak|still one cell",
    ],
)
def test_a_value_never_adds_table_cells(path: str) -> None:
    row = f"| {code('SC-001')} | {code(path)} | {code('end')} |"
    cells = gfm_cells(row)
    assert len(cells) == 3, cells
    assert cells[2].strip() == code("end")


@pytest.mark.parametrize(
    ("char", "name"),
    [
        ("\u202e", "U+202E"),  # right-to-left override (Trojan Source)
        ("\u2066", "U+2066"),  # left-to-right isolate
        ("\u200b", "U+200B"),  # zero-width space
        ("\u0000", "U+0000"),
        ("\u001b", "U+001B"),  # terminal escape
        ("\u2028", "U+2028"),  # line separator
    ],
)
def test_invisible_and_control_characters_are_spelled_out(char: str, name: str) -> None:
    assert visible(f"app{char}.py") == f"app{name}.py"


def test_tabs_and_newlines_become_spaces_and_unicode_text_is_kept() -> None:
    assert visible("a\tb\r\nc") == "a b  c"
    assert visible("données/配置.py") == "données/配置.py"


def test_length_is_capped() -> None:
    text = visible("x" * (MAX_TEXT + 50))
    assert len(text) == MAX_TEXT and text.endswith("…")
    assert len(visible("y" * 500, limit=20)) == 20
