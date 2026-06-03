from pathlib import Path
text = Path('server.js').read_text(encoding='utf-8')
lines = text.splitlines()
for idx, line in enumerate(lines):
    if 'asyncHandler(async' in line:
        start_char = sum(len(l) + 1 for l in lines[:idx])
        pos = line.find('=>')
        if pos == -1:
            continue
        brace_index = line.find('{', pos)
        if brace_index == -1:
            # search next lines
            found = False
            for j in range(idx + 1, len(lines)):
                p = lines[j].find('{')
                if p != -1:
                    brace_index = sum(len(l) + 1 for l in lines[:j]) + p
                    found = True
                    break
            if not found:
                continue
        else:
            brace_index = start_char + brace_index
        depth = 1
        i = brace_index + 1
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
            print(f'{idx+1}: no closure')
            continue
        # find line number of closure
        line_no = text[:i].count('\n')
        suffix = text[i:i+4]
        print(f'{idx+1}: close_line={line_no+1} suffix={repr(suffix)}')
