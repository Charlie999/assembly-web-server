#!/usr/bin/env python3
import re, json

lr = r"^(?!#)([a-zA-Z0-9\-\/\+\.]+)\s+([\sa-zA-Z0-9]+)\n$"

matches = [re.findall(lr,line) 
            for line in open('mime.types')]
matches = [x[0] for x in matches if len(x) == 1]
matches = list(map(lambda sub: (sub[1].split(" "), sub[0]), matches))

types = {}
for m in matches:
    for ext in m[0]:
        types[ext] = m[1]

with open("mime-types.json", "w") as f:
    f.write(json.dumps(types, indent=2))