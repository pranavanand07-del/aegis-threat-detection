#!/usr/bin/env python3
"""Assembles site/*.html|css|js into one page and writes PlatformHtml.java (split into chunks < 64 KB each)."""
import sys, re, pathlib
root = pathlib.Path('site-src')
css = (root/'style.css').read_text() if (root/'style.css').exists() else ''
body = (root/'body.html').read_text() if (root/'body.html').exists() else '<p>placeholder</p>'
js = (root/'app.js').read_text() if (root/'app.js').exists() else ''
page = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AEGIS - explainable threat detection</title>
<meta name="description" content="AEGIS scores every event, shows the reasons, and links attack steps into campaigns.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
{css}
</style>
</head>
<body>
{body}
<script>
{js}
</script>
</body>
</html>
'''
# non-ASCII -> html entity in markup, \\u escape inside script/style handled by writing ASCII only
bad = [c for c in set(page) if ord(c) > 127]
if bad:
    print('WARNING non-ascii chars:', bad, file=sys.stderr)
    page = page.encode('ascii', 'xmlcharrefreplace').decode()
pathlib.Path('site-src/platform.html').write_text(page)

# split at line boundaries into chunks of <= 24000 chars
lines = page.split('\n')
chunks, cur, size = [], [], 0
for ln in lines:
    if size + len(ln) + 1 > 24000 and cur:
        chunks.append('\n'.join(cur) + '\n'); cur, size = [], 0
    cur.append(ln); size += len(ln) + 1
if cur: chunks.append('\n'.join(cur))

def esc(s):
    s = s.replace('\\', '\\\\')
    s = s.replace('"""', '\\"\\"\\"')
    return s

out = ['package com.threatdetection.platform;', '',
       '/**', ' * The platform website served at "/". Generated from site/platform.html by build_page.py;',
       ' * split into parts because a single Java string constant cannot exceed 64 KB.', ' */',
       'public final class PlatformHtml {', '    private PlatformHtml() {}', '']
for i, c in enumerate(chunks):
    out.append(f'    private static final String P{i} = """')
    out.append(esc(c) + '""";')
    out.append('')
joined = ', '.join(f'P{i}' for i in range(len(chunks)))
out.append(f'    public static final String PAGE = String.join("", {joined});')
out.append('}')
dst = pathlib.Path('src/com/threatdetection/platform/PlatformHtml.java')
dst.write_text('\n'.join(out) + '\n')
print('chunks:', len(chunks), 'page chars:', len(page))
