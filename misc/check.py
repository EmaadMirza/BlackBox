import os

for root, _, files in os.walk('dashboard/js'):
    for f in files:
        if f.endswith('.js'):
            p = os.path.join(root, f)
            with open(p, 'r', encoding='utf-8') as file:
                content = file.read()
            if '\\`' in content:
                print(f"FOUND \\` in {p}")
            if '\\${' in content:
                print(f"FOUND \\${{ in {p}")
