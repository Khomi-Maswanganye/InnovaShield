from pathlib import Path
text = Path('server.js').read_text(encoding='utf-8')
lines = text.splitlines()
for idx, line in enumerate(lines, 1):
    if 'asyncHandler(async' in line:
        pos = line.find('=>')
        if pos == -1:
            continue
        char_start = sum(len(l) + 1 for l in lines[:idx-1]) + line.find('{', pos)
        if line.find('{', pos) == -1:
            char_start = sum(len(l) + 1 for l in lines[:idx])
            while char_start < len(text) and text[char_start] != '{':
                char_start += 1
        depth = 1
        j = char_start + 1
        in_single = in_double = in_back = False
        esc = False
        in_comment = None
        while j < len(text) and depth > 0:
            c = text[j]
            if in_comment == 'line':
                if c == '\n': in_comment = None
            elif in_comment == 'block':
                if c == '*' and j + 1 < len(text) and text[j+1] == '/':
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
                if c == '/' and j + 1 < len(text) and text[j+1] == '/':
                    in_comment = 'line'; j += 1
                elif c == '/' and j + 1 < len(text) and text[j+1] == '*':
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
        end_line = text[:j].count('\n') + 1
        suffix = text[j:j+4].replace('\n','\\n')
        print(f'{idx}: end_line={end_line} suffix={repr(suffix)}')
