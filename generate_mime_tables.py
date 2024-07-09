#!/usr/bin/env python3
import json, struct, datetime

DEFAULT_TYPE = "application/octet-stream"
FILE_INFO = "mime tables v0.1 generated " + str(datetime.datetime.now()) + " by generate_mime_tables.py"

"""
mime-types.bin format (only allows up to 4GB MIME file size):

| version info (always 1, 32b)      |
| bin start (32b) | bin end (32b)   | <- min and max lengths (# of bins = max-min)
| default mime type ptr (32b)       | <- pointer to default mime type string (application/octet-stream normally)
| file info str ptr (32b)           | <- version info and whatever
| bin <2> pointer (32b)             | <- Bin pointers may be NULL if there is nothing in the bin
| bin <3> pointer (32b)             |
| bin <4> pointer (32b)             |
...
| bin <N> pointer (32b)             |
| bin <1> length (32b)              | <- number of ENTRIES (each entry is 16b), not number of BYTES
| bin <1> entry <1> (32b)           | <- pointer to string within file
| bin <1> entry <1> MIME type (32b) | <- pointer to null-terminated string
...
| bin <1> entry <M> (32b)           |
| bin <1> entry <M> MIME type (32b) | 
...
| bin <N> length (32b)              |
| bin <N> entry <1> (32b)           |
| bin <N> entry <1> MIME type (32b) |
...
| bin <N> entry <M> (32b)           |
| bin <N> entry <M> MIME type (32b) |
| file extension str 1 (null t str) |
...
| file extension str N (null t str) |
| MIME type str 1 (null t'd string) |
| MIME type str 2 (null t'd string) |
...
| MIME type str N (null t'd string) |
"""

bin_len_sz = 4
bin_ptr_sz = 4
entry_sz = bin_ptr_sz * 2
hdr_len = 12

with open("mime-types.json", "r") as f:
    types = json.load(f)

bins = {}

for v in types:
    if len(v) not in bins:
        bins[len(v)] = []
    bins[len(v)] += [v]

types = {key:types[key] for key in sorted(types.keys())}

def gen_bin_str(s):
    return struct.pack("<"+str(len(s))+"sB", s.encode('ascii'), 0)

min_bin = min(list(bins.keys()))
max_bin = max(list(bins.keys()))
n_bins = (max_bin - min_bin) + 1

for i in range(n_bins):
    i += min_bin
    if i not in bins:
        bins[i] = []

bins = {key:bins[key] for key in sorted(bins.keys())}

print("min bin =", min_bin," max_bin =",max_bin," n_bins =",n_bins)

bin_sizes = {}
n_entries = 0

for v in bins:
    bin_sizes[v] = len(bins[v])
    n_entries += bin_sizes[v]

print("bin_sizes =",bin_sizes," n_entries =",n_entries)

entries_total_sz = n_entries * entry_sz + (n_bins * bin_len_sz)
binptr_total_sz = n_bins * bin_ptr_sz

total_size_excl_strs = entries_total_sz + binptr_total_sz + bin_ptr_sz + bin_ptr_sz + hdr_len

print("entries_total_sz =",entries_total_sz," binptr_total_sz =",binptr_total_sz," total_size_excl_strs =",total_size_excl_strs)

strings = {}
cur_str_ptr = 0
for k in types:
    v = types[k]
    if k not in strings:
        b = gen_bin_str(k)
        strings[k] = {"ptr": cur_str_ptr + total_size_excl_strs, "bin": b}
        cur_str_ptr += len(b)
    if v not in strings:
        b = gen_bin_str(v)
        strings[v] = {"ptr": cur_str_ptr + total_size_excl_strs, "bin": b}
        cur_str_ptr += len(b)

if DEFAULT_TYPE not in strings:
    b = gen_bin_str(DEFAULT_TYPE)
    strings[DEFAULT_TYPE] = {"ptr": cur_str_ptr + total_size_excl_strs, "bin": b}
    cur_str_ptr += len(b)

if FILE_INFO not in strings:
    b = gen_bin_str(FILE_INFO)
    strings[FILE_INFO] = {"ptr": cur_str_ptr + total_size_excl_strs, "bin": b}
    cur_str_ptr += len(b)

print("strings sz =",cur_str_ptr)

print("total file size =",cur_str_ptr + total_size_excl_strs,"=",round((cur_str_ptr + total_size_excl_strs)/1024,2),"KiB")

bin_entries = {}
cur_bin_ptr = 0
for l in bins:
    bin_entries[l] = {"ptr":cur_bin_ptr + (len(bins) * bin_ptr_sz) + bin_ptr_sz + bin_ptr_sz + hdr_len,"entries":[]}
    for extn in bins[l]:
        bin_entries[l]["entries"] += [{"data": struct.pack("<II", strings[extn]["ptr"], strings[types[extn]]["ptr"]), "extn":extn, "mime":types[extn]}]
    bin_entries[l]["length"] = len(bin_entries[l]["entries"])
    cur_bin_ptr += len(bin_entries[l]["entries"] * entry_sz) + bin_len_sz

with open("mime-types.bin", "wb") as f:
    f.write(struct.pack("<I", 1)) # vers info
    f.write(struct.pack("<II", min_bin, max_bin))
    f.write(struct.pack("<I", strings[DEFAULT_TYPE]["ptr"]))
    f.write(struct.pack("<I", strings[FILE_INFO]["ptr"]))
    #print("dfl ptr=",strings[DEFAULT_TYPE]["ptr"])

    for bin in bin_entries:
        f.write(struct.pack("<I", bin_entries[bin]["ptr"]))
        #print("bin",bin,"ptr =",bin_entries[bin]["ptr"])

    for bin in bin_entries:
        f.write(struct.pack("<I", bin_entries[bin]["length"]))
        for ent in bin_entries[bin]["entries"]:
            f.write(ent["data"])

    for strn in strings:
        f.write(strings[strn]["bin"])

## now self-test
        
mapping = {}
with open("mime-types.bin", "rb") as f:
    ver = struct.unpack("<I", f.read(4))
    print("fver =",ver[0])
    min_bin, max_bin = struct.unpack("<II", f.read(8))
    #print("min_bin =",min_bin," max_bin =",max_bin)

    dfl_str_ptr = struct.unpack("<I",f.read(4))
    f.seek(dfl_str_ptr[0])
    dfl_str = ''.join(iter(lambda: f.read(1).decode('ascii'), '\x00'))
    #print("dfl_str_ptr =",dfl_str_ptr[0]," dfl_str =",dfl_str)

    # now let's enumerate a bin!
    for i in range((max_bin - min_bin) + 1):
        f.seek(20 + 4*i)
        bin_ptr = struct.unpack("<I",f.read(4))
        f.seek(bin_ptr[0])
        bin_len = struct.unpack("<I",f.read(4))
        #print("bin_ptr =",bin_ptr[0]," bin_len =",bin_len[0])
        for i in range(bin_len[0]):
            extn_ptr, mime_ptr = struct.unpack("<II", f.read(8))
            cp = f.tell()
            f.seek(extn_ptr)
            extn_str = ''.join(iter(lambda: f.read(1).decode('ascii'), '\x00'))
            f.seek(mime_ptr)
            mime_str = ''.join(iter(lambda: f.read(1).decode('ascii'), '\x00'))
            f.seek(cp)
            mapping[extn_str] = mime_str

for typ in types:
    if types[typ] != mapping[typ]:
        print("FAIL at",typ)
        exit(1)

if dfl_str != DEFAULT_TYPE:
    print("FAIL dfl_str")
    exit(1)

print("OK, checked",len(mapping),"entries")