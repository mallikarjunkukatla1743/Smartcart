import re

file_path = r'c:\Users\DELL\OneDrive\Desktop\smartcart\app.py'

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Replace cursor(dictionary=True) or cursor(dictionary = True)
content = re.sub(r'cursor\s*\(\s*dictionary\s*=\s*True\s*\)', 'cursor()', content)

# 2. Replace %s with ? in SQL queries
# This is tricky. We want to find %s inside strings that are passed to .execute()
# A simple heuristic: replace %s with ? in lines that contain "cursor.execute"
# But it might span multiple lines.

# Let's try to find strings like "SELECT ... %s ..." and replace %s with ?
# Note: SQLite uses ? as placeholder.

# Regex to find strings with %s that are likely SQL
# Search for patterns like: cursor.execute("...", ...) or cursor.execute("""...""", ...)
def replace_sql_placeholders(match):
    sql_part = match.group(1)
    # Replace %s with ? inside the SQL string
    new_sql_part = sql_part.replace('%s', '?')
    return f'cursor.execute({new_sql_part}'

# Handle double quotes
content = re.sub(r'cursor\.execute\s*\(\s*("(?:\\.|[^"])*")', replace_sql_placeholders, content)
# Handle single quotes
content = re.sub(r'cursor\.execute\s*\(\s*(\'(?:\\.|[^\'])*\')', replace_sql_placeholders, content)
# Handle triple double quotes
content = re.sub(r'cursor\.execute\s*\(\s*("""[\s\S]*?""")', replace_sql_placeholders, content)
# Handle triple single quotes
content = re.sub(r'cursor\.execute\s*\(\s*(\'\'\'[\s\S]*?\'\'\')', replace_sql_placeholders, content)

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Replacement complete.")
