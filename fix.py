import os

d = 'dashboard/js/pages'
for f in os.listdir(d):
    if f.endswith('.js'):
        p = os.path.join(d, f)
        with open(p, 'r', encoding='utf-8') as file:
            content = file.read()
        
        # Replace the literal backslash followed by backtick
        content = content.replace('\\`', '`')
        # Replace the literal backslash followed by ${
        content = content.replace('\\${', '${')
        
        with open(p, 'w', encoding='utf-8') as file:
            file.write(content)

print("Fixed syntax in JS files.")
