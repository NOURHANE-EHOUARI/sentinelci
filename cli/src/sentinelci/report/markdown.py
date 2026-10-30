"""Make untrusted text inert in GitHub-flavoured Markdown.

Paths, rule titles and snippets in a report come from the scanned change, i.e. from the person whose change
is being checked. Rendered as plain Markdown they could mention or notify people (`@org/team`), link to
issues (`#1`), inject links, images or HTML, break out of a table cell, or hide characters with
bidirectional overrides ("Trojan Source"). Every untrusted string is therefore shown as an inline code span,
where GitHub renders no Markdown, HTML, mentions or autolinks, after these steps:

1. control, format and separator characters (Unicode categories Cc, Cf, Zl, Zp, Co, Cs, Cn) become visible
   `U+XXXX` escapes, so a bidi override or a zero-width character cannot disguise a path;
2. the text is capped in length, so one value cannot push the comment over GitHub's size limit;
3. the code fence is one backtick longer than any backtick run inside the text, so the span cannot be closed
   from inside;
4. for table cells, `|` is escaped. GFM splits cells before inline parsing and treats a backslash as
   escaping the next character, so a backslash right before an escaped pipe would swallow the escape; a
   zero-width space is inserted between them.
"""

import re
import unicodedata

MAX_TEXT = 200
_HIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Co", "Cs", "Cn"})
_ZWSP = "\u200b"
_BACKTICK_RUN = re.compile(r"`+")


def visible(text: str, limit: int = MAX_TEXT) -> str:
    """One line, every invisible or control character spelled out, at most `limit` characters."""
    out = []
    for char in text:
        if char in "\t\r\n":
            out.append(" ")
        elif unicodedata.category(char) in _HIDDEN_CATEGORIES:
            out.append(f"U+{ord(char):04X}")
        else:
            out.append(char)
    result = "".join(out)
    if len(result) > limit:
        result = result[: limit - 1] + "…"
    return result


def code(text: str, *, in_table: bool = True, limit: int = MAX_TEXT) -> str:
    """Render untrusted text as an inert inline code span (safe inside a GFM table cell by default)."""
    content = visible(text, limit)
    if in_table:
        content = content.replace("\\|", "\\" + _ZWSP + "|").replace("|", "\\|")
    longest = max((len(run) for run in _BACKTICK_RUN.findall(content)), default=0)
    fence = "`" * (longest + 1)
    # CommonMark strips one space on each side when both are present, so padding is invisible.
    if not content or content[0] in "` " or content[-1] in "` ":
        content = f" {content} "
    return f"{fence}{content}{fence}"
