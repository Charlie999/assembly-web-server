BITS 64
; TODO: use syscalls instead of libc functions for network stuff completely
%include "defs.asm"
%define SERVER_BRAND "assembly-webserver"
;args rdi, rsi, rdx, rcx, r8, r9
;scrh rax, rdi, rsi, rdx, rcx, r8, r9, r10, r11
section .data ; none of this is really aligned, but I'm on holiday and I do not care!
argc: dd 0
argv: dq 0
sock_fd: dd 0
port: dw 0
peer_addr: times 16 db 0xFF
peer_len: dd 16
dd 0
cli_fd: dd 0
tcp_buf: dq 0
recv_len: dq 0
page_fd: dd 0
page_len: dq 0
page_buf: dq 0
hdr_len: dq 0
hdr_buf: dq 0
page_name: dq 0
webroot: dq 0
mime_type: dq 0
reap_status: dq 0
index_addl: dq blank_str
cur_wd: dq 0

section .rodata
; constants
intro_msg: db "horrible dodgy webserver, webroot = %s",0xa,0
usage_msg: db "usage: %s <webroot> <port>",0xa,0
perr_sock_msg: db "socket()",0
perr_sockopt_msg: db "setsockopt()",0
perr_bind_msg: db "bind() error %d",0xa,0
perr_listen_msg: db "listen() error %d",0xa,0
perr_accept_msg: db "accept() error %d",0xa,0
perr_fork_msg: db "fork() error %d",0xa,0
accepted_msg: db "accepted connection from %s",0xa,0
inval_port: db "invalid port %lu",0xa,0
access_log: db "access [%s]",0xa,0
rsp_debug: db "rsp = 0x%016lX",0xa,0
int32_one: dd 1

msg_bad_req: db "HTTP/1.1 400 Bad request",0xd,0xa,"Connection: close",0xd,0xa,"Content-Type: text/plain",0xd,0xa,"Server: ",SERVER_BRAND,0xd,0xa,"Content-Length: 12",0xd,0xa,0xd,0xa,"Bad request",0xa
msg_bad_req_end:
%define msg_bad_req_len (msg_bad_req_end - msg_bad_req) 

msg_404: db "HTTP/1.1 404 Not Found",0xd,0xa,"Connection: close",0xd,0xa,"Content-Type: text/plain",0xd,0xa,"Server: ",SERVER_BRAND,0xd,0xa,"Content-Length: 10",0xd,0xa,0xd,0xa,"Not Found",0xa
msg_404_end:
%define msg_404_len (msg_404_end - msg_404) 

msg_500: db "HTTP/1.1 500 Internal Server Error",0xd,0xa,"Connection: close",0xd,0xa,"Content-Type: text/plain",0xd,0xa,"Server: ",SERVER_BRAND,0xd,0xa,"Content-Length: 22",0xd,0xa,0xd,0xa,"Internal Server Error",0xa
msg_500_end:
%define msg_500_len (msg_500_end - msg_500) 

hdr_fmt: db "HTTP/1.1 200 OK",0xd,0xa,"Connection: close",0xd,0xa,"Content-Type: %s",0xd,0xa,"Server: ",SERVER_BRAND,0xd,0xa,"Content-Length: %lu",0xd,0xa,0xd,0xa,0
page_name_fmt: db "./%s%s",0

; hardcoded! yay!
mime_html: db "text/html",0
mime_js: db "text/javascript",0
mime_css: db "text/css",0
mime_jpeg: db "image/jpeg",0
mime_png: db "image/png",0
mime_plain: db "text/plain",0
mime_icon: db "image/x-icon",0

extn_html0: db "html",0
extn_html1: db "htm",0
extn_js: db "js",0
extn_css: db "css",0
extn_jpeg0: db "jpg",0
extn_jpeg1: db "jpeg",0
extn_png: db "png",0
extn_ico: db "ico",0

index_path: db "/index.html",0
blank_str: db 0
double_dot: db '..',0

section .text
global _start

; TODO: eliminate these!
extern printf
extern putc
extern perror
extern errno
extern strtoul
extern raise
extern inet_ntoa
extern free
extern asprintf
extern strdup
extern strcmp
extern putchar

;;;;; int _start(int argc[rsp], char** argv[rsp+4 (to rsp+4+(8*argc))])
_start:
mov eax, [rsp]
mov dword [argc], eax ; set up argc

cmp dword eax, 3
je .argc_ok
lea rax, [rsp+8]
mov rsi, [rax]
call usage
.argc_ok:

lea rax, [rsp+8]
mov qword [argv], rax ; same for argv

;; printf(intro_msg, argv[1])
mov rbp, [argv]
add rbp, 8
mov rsi, [rbp]
mov rdi, intro_msg
call printf

;; webroot = strdup(argv[1])
mov rdi, [rbp]
call strdup
cmp rax, 0
jne .strdup_ok
mov rdi, 1
mov rax, SYS_EXIT
syscall
.strdup_ok:
mov qword [webroot], rax

;; port = htons(strtoul(argv[2]))
mov rbp, [argv]
add rbp, 16
mov rdi, [rbp]
mov rsi, NULL
mov rdx, 10
call strtoul
cmp rax, 65536
jge .port_bad
cmp rax, 0
je .port_bad
jmp .port_ok
.port_bad:
mov rdi, inval_port
mov rsi, rax
call printf
mov rdi, 1
mov rax, SYS_EXIT
syscall
ret
.port_ok:
xchg al, ah
mov word [port], ax

;; conn_loop()
call conn_loop

;; free(webroot)
mov qword rdi, [webroot]
call free

;; exit(0)
mov rdi, 0
mov rax, SYS_EXIT
syscall

pop rbp
mov rax, 0
ret ; not technically needed but eeh


;;;;; int conn_loop()
conn_loop:
;; socket(AF_INET, SOCK_STREAM, 0)
mov rax, SYS_SOCKET
mov rdi, AF_INET
mov rsi, SOCK_STREAM
mov rdx, 0
syscall
mov dword [sock_fd], eax

cmp rax, 0
jge .no_sock_fail
mov rdi, rax
mov rax, SYS_EXIT
syscall
ret
.no_sock_fail:

;; setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, int32_one, 4)
mov dword edi, [sock_fd]
mov rsi, SOL_SOCKET
mov rdx, SO_REUSEADDR
mov r10, int32_one
mov r8, 4
mov rax, SYS_SETSOCKOPT
syscall

cmp rax, 0
jge .no_setsockopt_reuseaddr_fail
mov rdi, rax
mov rax, SYS_EXIT
syscall
ret
.no_setsockopt_reuseaddr_fail:

;; setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, int32_one, 4)
mov dword edi, [sock_fd]
mov rsi, SOL_SOCKET
mov rdx, SO_REUSEPORT
mov r10, int32_one
mov r8, 4
mov rax, SYS_SETSOCKOPT
syscall

cmp rax, 0
jge .no_setsockopt_reuseport_fail
mov rdi, rax
mov rax, SYS_EXIT
syscall
ret
.no_setsockopt_reuseport_fail:

;; bind(sock_fd, &sockaddr_listen, sockaddr_listen_len)
;; prepare sockaddr struct
push qword 0             ; pad
push dword 0x00000000    ; sin_addr
mov word ax, [port]
push word ax         ; sin_port
push word AF_INET        ; sin_family

mov rax, SYS_BIND
mov dword edi, [sock_fd] ; arg 0
mov rsi, rsp ; arg 1
mov rdx, 16 ; arg 2
mov rbx, rsp
syscall
mov rsp, rbx
pop qword rdi ; fix the stack!
pop qword rdi
pop word di
pop word di ; yeah it's too late at night for me to bother making this not insane
;;
cmp rax, 0
jge .bind_ok
mov rdi, perr_bind_msg
mov rsi, rax
push rsi
call printf
pop rsi
mov rdi, rsi
neg rdi
mov rax, SYS_EXIT
syscall
ret
.bind_ok:

;; listen(sock_fd, 1024)
mov rax, SYS_LISTEN
mov dword edi, [sock_fd]
mov rsi, 1024
syscall
cmp rax, 0
jge .listen_ok
mov rdi, perr_listen_msg
mov rsi, rax
push rsi
call printf
pop rsi
mov rdi, rsi
neg rdi
mov rax, SYS_EXIT
syscall
.listen_ok:

;; for(;;)
.accept_loop:

;; accept(sock_fd, &peer_addr, peer_Len)
mov rax, SYS_ACCEPT
mov dword edi, [sock_fd]
mov rsi, peer_addr
mov rdx, peer_len
syscall
mov [cli_fd], rax
cmp rax, 0
jge .accept_ok
mov rdi, perr_accept_msg
mov rsi, rax
push rsi
call printf
pop rsi
mov rdi, rsi
neg rdi
mov rax, SYS_EXIT
syscall
.accept_ok:

;; print client addr
lea rax, [peer_addr + 4] ; sin_addr
mov rdi, [rax]
call inet_ntoa
mov rsi, rax
mov rdi, accepted_msg
push qword rsi
call printf
pop qword rsi

;; fork()
mov rax, SYS_FORK
syscall
cmp rax, 0
jne .fork_no_child
;; child -> cli_fd should be valid
call serv_child

mov rdi, 0
mov rax, SYS_EXIT
syscall
ret
.fork_no_child:
jg .fork_no_err
mov rdi, perr_fork_msg
mov rsi, rax
push rsi
call printf
pop rsi
mov rdi, rsi
mov rax, SYS_EXIT
syscall
ret
.fork_no_err:

;; close(cli_fd)
mov rax, SYS_CLOSE
mov dword edi, [cli_fd]
syscall

.reap_children:
mov rax, SYS_WAIT4
mov rdi, -1
mov rsi, reap_status
mov rdx, 1 ; WNOHANG
mov r10, 0 ; rusage = NULL
syscall
cmp rax, 0
jg .reap_children

jmp .accept_loop

;; close(sock_fd)
mov rax, SYS_CLOSE
mov dword edi, [sock_fd]
syscall

;; return
mov rax, 0
ret

;;;;; int usage()
usage:
push rbp ; 16-align!

mov rdi, usage_msg
call printf

mov rdi, 1
mov rax, SYS_EXIT
syscall

pop rbp
mov rax, 0
ret

%define TCP_BUF_SZ 4096

;;
serv_child:

;; chdir(webroot)
mov rax, SYS_CHDIR
mov qword rdi, [webroot]
syscall
cmp rax, 0
jge .initial_chdir_ok
mov rdi, rax
mov rax, SYS_EXIT
syscall
.initial_chdir_ok:

;; tcp_buf = mmap(NULL, TCP_BUF_SZ, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0)
mov rdi, NULL
mov rsi, TCP_BUF_SZ
mov rdx, (PROT_READ | PROT_WRITE)
mov r10, (MAP_ANONYMOUS | MAP_PRIVATE)
mov r8 , -1
mov r9,  0
mov rax, SYS_MMAP
syscall
mov qword [tcp_buf], rax
cmp rax, 0
jge .mmap_first_ok
mov rdi, rax
mov rax, SYS_EXIT
syscall
.mmap_first_ok:

;; cur_wd = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0)
mov rdi, NULL
mov rsi, 4096
mov rdx, (PROT_READ | PROT_WRITE)
mov r10, (MAP_ANONYMOUS | MAP_PRIVATE)
mov r8 , -1
mov r9,  0
mov rax, SYS_MMAP
syscall
mov qword [cur_wd], rax
cmp rax, 0
jge .mmap_second_ok
mov rdi, rax
mov rax, SYS_EXIT
syscall
.mmap_second_ok:

;.loop:
;; read(cli_fd, tcp_buf, TCP_BUF_SZ)
mov dword edi, [cli_fd]
mov qword rsi, [tcp_buf]
mov rdx, TCP_BUF_SZ
mov rax, SYS_READ
syscall
cmp rax, 0
jle .out
cmp rax, 4095 ; request too long
jge .bad_req

mov qword [recv_len], rax

mov qword rbp, [tcp_buf]
mov dword eax, [rbp]
mov dword ebx, 'GET '
cmp dword eax, ebx
jne .bad_req

mov al, ' '
mov qword rdi, [tcp_buf]
lea rdi, [rdi + 4]
mov qword rcx, [recv_len]
repne scasb
mov byte [rdi - 1], 0

; check path
mov qword rdi, [tcp_buf]
lea rdi, [rdi + 4]
call check_access
cmp rax, 0
jne .404 ; we can just pretend to 404 if the path is invalid

; divine the mime type
mov qword rdi, [tcp_buf]
lea rdi, [rdi + 4]
call populate_mime

;; getcwd - in prep for next step
mov rax, SYS_GETCWD
mov qword rdi, [cur_wd]
mov rsi, 4095
syscall
cmp rax, 0
jne .cwd_ok
mov rdi, rax
mov rax, SYS_EXIT
syscall
.cwd_ok:

.open_page:

;; asprintf(page_name, "./%s%s", access, index_addl)
mov qword rdi, [tcp_buf]
lea rdx, [rdi + 4]
mov rdi, page_name
mov rsi, page_name_fmt
mov qword rcx, [index_addl]
call asprintf
cmp rax, 0
jle .500

;; chdir - used to check if access path is a directory
mov rax, SYS_CHDIR
mov qword rdi, [page_name]
syscall
cmp rax, 0
jne .not_dir

mov rax, SYS_CHDIR
mov qword rdi, [cur_wd]
syscall
cmp rax, 0
jge .chdir_inner_ok
mov rdi, rax
mov rax, SYS_EXIT
syscall
.chdir_inner_ok:

mov rax, index_path
mov qword [index_addl], rax

mov qword rdi, [page_name]
call free

jmp .open_page
.not_dir:

;; printf(access)
mov rdi, access_log
mov qword rsi, [page_name]
call printf

;; page_fd = open(fname, O_RDONLY, 0)
mov rax, SYS_OPEN
mov qword rdi, [page_name]
mov rsi, O_RDONLY
mov rdx, 0
syscall
cmp rax, 0
jle .404
mov dword [page_fd], eax

;; free(page_name)
mov qword rdi, [page_name]
call free

;; page_len = lseek(page_fd, 0, SEEK_END)
mov rax, SYS_LSEEK
mov dword edi, [page_fd]
mov rsi, 0
mov rdx, SEEK_END
syscall
mov qword [page_len], rax

;; lseek(page_fd, 0, SEEK_SET)
mov rax, SYS_LSEEK
mov dword edi, [page_fd]
mov rsi, 0
mov rdx, SEEK_SET
syscall

;; page_buf = mmap(NULL, page_len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0)
mov rdi, NULL
mov qword rsi, [page_len]
mov rdx, (PROT_READ | PROT_WRITE)
mov r10, (MAP_ANONYMOUS | MAP_PRIVATE)
mov r8 , -1
mov r9,  0
mov rax, SYS_MMAP
syscall
mov qword [page_buf], rax
cmp rax, 0
jge .mmap_third_ok
mov rdi, rax
mov rax, SYS_EXIT
syscall
.mmap_third_ok:

;; read(page_fd, page_buf, page_len)
mov rax, SYS_READ
mov dword edi, [page_fd]
mov qword rsi, [page_buf]
mov qword rdx, [page_len]
syscall
cmp qword rax, [page_len]
jne .404

;; hdr_len = asprintf(&hdr_buf, hdr_fmt, mime_type, page_len)
mov qword rdi, hdr_buf
mov qword rsi, hdr_fmt
mov qword rdx, [mime_type]
mov qword rcx, [page_len]
call asprintf
cmp rax, 0
jle .500
mov qword [hdr_len], rax

;; write(cli_fd, hdr_buf, hdr_len)
mov rax, SYS_WRITE
mov dword edi, [cli_fd]
mov qword rsi, [hdr_buf]
mov qword rdx, [hdr_len]
syscall
cmp qword rax, [hdr_len]
jne .500

;; free(hdr_buf)
mov qword rdi, [hdr_buf]
call free

;; write(cli_fd, page_buf, page_len)
mov rax, SYS_WRITE
mov dword edi, [cli_fd]
mov qword rsi, [page_buf]
mov qword rdx, [page_len]
syscall
cmp qword rax, [page_len]
jne .500

;; munmap(page_buf, page_len)
mov rax, SYS_MUNMAP
mov qword rdi, [page_buf]
mov qword rsi, [page_len]
syscall

;; close(page_fd)
mov rax, SYS_CLOSE
mov dword edi, [page_fd]
syscall

; nope, we are HTTP 1.0! jmp .loop
.out:

;; munmap(tcp_buf, length)
mov qword rdi, [tcp_buf]
mov rsi, TCP_BUF_SZ
mov rax, SYS_MUNMAP
syscall

;; munmap(cur_wd, length)
mov qword rdi, [cur_wd]
mov rsi, 4096
mov rax, SYS_MUNMAP
syscall

;; close(cli_fd)
mov dword edi, [cli_fd]
mov rax, SYS_CLOSE
syscall

;; free(webroot)
mov qword rdi, [webroot]
call free

mov rdi, 0
mov rax, SYS_EXIT
syscall

mov rax, 0
ret

.bad_req:
mov dword edi, [cli_fd]
mov rsi, msg_bad_req
mov rdx, msg_bad_req_len 
mov rax, SYS_WRITE
syscall
jmp .out

.404:
mov dword edi, [cli_fd]
mov rsi, msg_404
mov rdx, msg_404_len
mov rax, SYS_WRITE
syscall
jmp .out

.500:
mov dword edi, [cli_fd]
mov rsi, msg_500
mov rdx, msg_500_len
mov rax, SYS_WRITE
syscall

;; munmap(page_buf, page_len)
mov qword rdi, [page_buf]
cmp rdi, 0
je .out
mov rax, SYS_MUNMAP
mov qword rsi, [page_len]
syscall

mov dword edi, [page_fd]
mov rax, SYS_CLOSE
syscall

jmp .out

;; rdi = access path, we need to remove .. and %
;; rax = bad or not, 0 for good
check_access:

.loop:
cmp word [rdi], '..'
jne .no_dotdot
mov rax, 1
ret
.no_dotdot:

cmp byte [rdi], '%'
jne .no_percent
mov rax, 1
ret
.no_percent:

cmp byte [rdi], 0x20
jge .lower_bound_ok
mov rax, 1
ret
.lower_bound_ok:

cmp byte [rdi], 0x7D
jle .upper_bound_ok
mov rax, 1
ret
.upper_bound_ok:

inc rdi
cmp byte [rdi], 0
jne .loop

mov rax, 0
ret

;; rdi = access path
populate_mime:

mov rcx, 4095
mov al, 0
mov rbp, rdi
repne scasb
dec rdi ; rdi is now end char
mov rcx, rdi
sub rcx, rbp ; string length!
mov al, '.'
mov rdi, rbp
repne scasb
cmp rcx, 0
jne .extn_found
mov rax, mime_plain
mov qword [mime_type], rax
ret
.extn_found:
mov byte [rdi - 1], 0 ; remove dot, rdi is now extension!
mov rbp, rdi

; i'm a lazy bum!
mov rdi, rbp
mov rsi, extn_html0
call strcmp
cmp rax, 0
jne .not_html0
mov rax, mime_html
mov qword [mime_type], rax
mov byte [rbp - 1], '.'
ret
.not_html0:

mov rdi, rbp
mov rsi, extn_html1
call strcmp
cmp rax, 0
jne .not_html1
mov rax, mime_html
mov qword [mime_type], rax
mov byte [rbp - 1], '.'
ret
.not_html1:

mov rdi, rbp
mov rsi, extn_css
call strcmp
cmp rax, 0
jne .not_css
mov rax, mime_css
mov qword [mime_type], rax
mov byte [rbp - 1], '.'
ret
.not_css:

mov rdi, rbp
mov rsi, extn_jpeg0
call strcmp
cmp rax, 0
jne .not_jpeg0
mov rax, mime_jpeg
mov qword [mime_type], rax
mov byte [rbp - 1], '.'
ret
.not_jpeg0:

mov rdi, rbp
mov rsi, extn_jpeg1
call strcmp
cmp rax, 0
jne .not_jpeg1
mov rax, mime_jpeg
mov qword [mime_type], rax
mov byte [rbp - 1], '.'
ret
.not_jpeg1:

mov rdi, rbp
mov rsi, extn_js
call strcmp
cmp rax, 0
jne .not_js
mov rax, mime_js
mov qword [mime_type], rax
mov byte [rbp - 1], '.'
ret
.not_js:

mov rdi, rbp
mov rsi, extn_png
call strcmp
cmp rax, 0
jne .not_png
mov rax, mime_png
mov qword [mime_type], rax
mov byte [rbp - 1], '.'
ret
.not_png:

mov rdi, rbp
mov rsi, extn_ico
call strcmp
cmp rax, 0
jne .not_icon
mov rax, mime_icon
mov qword [mime_type], rax
mov byte [rbp - 1], '.'
ret
.not_icon:

mov rax, mime_plain
mov qword [mime_type], rax
mov byte [rbp - 1], '.'
ret