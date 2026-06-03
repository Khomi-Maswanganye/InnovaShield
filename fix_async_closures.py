from pathlib import Path
text = Path('server.js').read_text(encoding='utf-8')
lines = text.splitlines()
new_text = text
adjust = 0
for idx, line in enumerate(lines, 1):
    if 'asyncHandler(async' in line:
        pos = line.find('=>')
        if pos == -1:
            continue
        # Determine character index of the opening brace for the async function
        line_start = sum(len(l) + 1 for l in lines[: idx - 1])
        brace_pos = line.find('{', pos)
        if brace_pos == -1:
            char_start = line_start + len(line)
            while char_start < len(text) and text[char_start] != '{':
                char_start += 1
        else:
            char_start = line_start + brace_pos
        if char_start >= len(text) or text[char_start] != '{':
            continue
        depth = 1
        j = char_start + 1
        in_single = in_double = in_back = False
        esc = False
        in_comment = None
        while j < len(text) and depth > 0:
            c = text[j]
            if in_comment == 'line':
                if c == '\n':
                    in_comment = None
            elif in_comment == 'block':
                if c == '*' and j + 1 < len(text) and text[j + 1] == '/':
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
                if c == '/' and j + 1 < len(text) and text[j + 1] == '/':
                    in_comment = 'line'; j += 1
                elif c == '/' and j + 1 < len(text) and text[j + 1] == '*':
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
            continue
        if j + 1 < len(text) and text[j:j+2] == ');' and text[j-1] != ')':
            new_text = new_text[:j] + ')' + new_text[j:]
            adjust += 1
print(f'Inserted {adjust} missing closing parenthesis(es).')
Path('server.js').write_text(new_text, encoding='utf-8')
