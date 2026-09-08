with open('extracted_chat2.txt', 'r', encoding='utf-8') as f:
    lines = f.readlines()

with open('clean_conversation2.md', 'w', encoding='utf-8') as out:
    in_feature_gates = False
    for line in lines:
        if 'feature_gates' in line:
            continue
        if len(line.strip()) > 30:
            out.write(line)

print("Wrote clean_conversation2.md")
