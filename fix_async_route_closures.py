from pathlib import Path
text = Path('server.js').read_text(encoding='utf-8')
lines = text.splitlines()
new_text = text
offset = 0
for idx, line in enumerate(lines):
    if 'asyncHandler(async' in line:
        start_char = sum(len(l) + 1 for l in lines[:idx])
        pos = line.find('=>')
        if pos == -1:
            continue
        brace_pos = line.find('{', pos)
        if brace_pos == -1:
            found = False
            for j in range(idx + 1, len(lines)):
                p = lines[j].find('{')
                if p != -1:
                    brace_pos = sum(len(l) + 1 for l in lines[:j]) + p
                    found = True
                    break
            if not found:
                continue
        else:
            brace_pos = start_char + brace_pos
        depth = 1
        i = brace_pos + 1
        in_string = None
        escape = False
        while i < len(text) and depth > 0:
            c = text[i]
            if in_string:
                if escape:
                    escape = False
                elif c == '\\':
                    escape = True
                elif c == in_string:
                    in_string = None
            else:
                if c in ('"', "'", '`'):
                    in_string = c
                elif c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
            i += 1
        if depth != 0:
            print(f'skipping route at line {idx+1}, unclosed block')
            continue
        if text[i:i+2] == ');':
            print(f'patching closure at line {text[:i].count("\n") + 1}')
            new_text = new_text[:i] + '))' + new_text[i+2:]
            offset += 1
        elif text[i:i+2] == '))':
            print(f'closure at line {text[:i].count("\n") + 1} already ))')
        else:
            print(f'closure at line {text[:i].count("\n") + 1} unexpected suffix {repr(text[i:i+4])}')

Path('server.js').write_text(new_text, encoding='utf-8')
