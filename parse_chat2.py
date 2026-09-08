import re, json

file_path = r'C:\Users\Anshika\.gemini\antigravity\brain\1318a947-a712-40e7-a8c1-d05f8c1dac8b\.system_generated\steps\507\content.md'
with open(file_path, 'r', encoding='utf-8') as f:
    html = f.read()

print("File size:", len(html))

# Look for text in enqueue or json
with open('extracted_chat2.txt', 'w', encoding='utf-8') as out:
    # Find all quoted strings that have at least 5 words
    strings = re.findall(r'"((?:[^"\\]|\\.)*)"', html)
    print("Found total strings:", len(strings))
    for s in strings:
        if len(s) > 100 and ('DataCart' in s or 'review' in s or 'page' in s or 'cart' in s or '##' in s or 'http' in s or 'PBL' in s or 'audit' in s or 'step' in s):
            clean = s.replace('\\n', '\n').replace('\\"', '"').replace('\\u003c', '<').replace('\\u003e', '>')
            out.write("\n-------------------- ENTRY --------------------\n")
            out.write(clean)
            out.write("\n")

print("Finished writing to extracted_chat2.txt")
