#!/usr/bin/env python3
"""Fix Unicode characters in SKILL.md file"""

# Read the file in binary mode
with open('SKILL.md', 'rb') as f:
    content = f.read()

# Replace the problematic byte sequences based on hexdump
# c2 9a = ⚠ (warning)
# c2 a0 = non-breaking space
# c2 8f = control character
# And remove all ├ │ └ ─ characters

replacements = [
    (b'\xc2\x9a', b''),  # ⚠
    (b'\xc2\xa0', b''),  # non-breaking space  
    (b'\xc2\x8f', b''),  # control character
    (b'\xef\xb8\x8f', b''),  # variation selector (ï¸)
    (b'\xe2\x94\x9c', b''),  # ├
    (b'\xe2\x94\x82', b''),  # │
    (b'\xe2\x94\x94', b''),  # └
    (b'\xe2\x94\x80', b''),  # ─
    (b'\xe2\x86\x92', b''),  # →
    (b'\xe2\x9c\x93', b''),  # ✓
    (b'\xe2\x9c\x94', b''),  # ✔
]

for old, new in replacements:
    content = content.replace(old, new)

# Write back
with open('SKILL.md', 'wb') as f:
    f.write(content)

print("Fixed Unicode characters")
