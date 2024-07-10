#!/bin/bash

./generate_mime_json.py
./generate_mime_tables.py

nasm -felf64 -g webserver.asm
ld -dynamic-linker /lib64/ld-linux-x86-64.so.2 -o webserver -lc webserver.o -z noexecstack -z relro -z now