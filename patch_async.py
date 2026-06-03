from pathlib import Path
p = Path('server.js')
backup = Path('server.js.bak')
backup.write_text(p.read_text(encoding='utf-8'), encoding='utf-8')
text = p.read_text(encoding='utf-8')
lines = text.splitlines()
starts = [i+1 for i,l in enumerate(lines) if 'asyncHandler(async' in l]
new_text = text
offset = 0
for start in starts:
    i = sum(len(l)+1 for l in lines[:start-1])
    line = lines[start-1]
    pos = line.find('=>')
    if pos == -1:
        continue
    pos = text.find('{', i + pos)
    if pos == -1:
        print('No open brace for', start)
        continue
    depth = 1
    j = pos + 1
    in_single = in_double = in_back = False
    esc = False
    in_comment = None
    while j < len(text) and depth > 0:
        c = text[j]
        if in_comment == 'line':
            if c == '\n':
                in_comment = None
        elif in_comment == 'block':
            if c == '*' and j+1 < len(text) and text[j+1] == '/':
                in_comment = None
                j += 1
        elif in_single:
            if esc:
                esc = False
            elif c == '\\':
                esc = True
            elif c == "'":
                in_single = False
        elif in_double:
            if esc:
                esc = False
            elif c == '\\':
                esc = True
            elif c == '"':
                in_double = False
        elif in_back:
            if esc:
                esc = False
            elif c == '\\':
                esc = True
            elif c == '`':
                in_back = False
        else:
            if c == '/' and j+1 < len(text) and text[j+1] == '/':
                in_comment = 'line'; j += 1
            elif c == '/' and j+1 < len(text) and text[j+1] == '*':
                in_comment = 'block'; j += 1
            elif c == "'":
                in_single = True
            elif c == '"':
                in_double = True
            elif c == '`':
                in_back = True
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
        j += 1
    if depth != 0:
        print('No matching end for route start', start)
        continue
    if text[j:j+2] == ');':
        idx = j
        new_text = new_text[:idx] + '));' + new_text[idx+2:]
        offset += 1
        print('Patched end at start', start, 'pos', idx)
    elif text[j:j+3] == '));':
        print('Already good at start', start)
    else:
        print('Unexpected suffix at start', start, repr(text[j:j+5]))

p.write_text(new_text, encoding='utf-8')
print('Done')
