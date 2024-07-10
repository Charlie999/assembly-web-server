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
webroot_len: dq 0
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
sigint_msg: db "SIGINT caught, exiting",0xa,0
inval_mime_types_file_msg: db "Invalid compiled-in mime-types.bin",0xa,0
mime_types_file_info_msg: db "mime-types.bin: %s",0xa,0

msg_bad_req: db "HTTP/1.1 400 Bad request",0xd,0xa,"Connection: close",0xd,0xa,"Content-Type: text/plain",0xd,0xa,"Server: ",SERVER_BRAND,0xd,0xa,"Content-Length: 12",0xd,0xa,0xd,0xa,"Bad request",0xa
msg_bad_req_end:
%define msg_bad_req_len (msg_bad_req_end - msg_bad_req) 

msg_bad_meth: db "HTTP/1.1 405 Method Not Allowed",0xd,0xa,"Connection: close",0xd,0xa,"Content-Type: text/plain",0xd,0xa,"Server: ",SERVER_BRAND,0xd,0xa,"Content-Length: 19",0xd,0xa,0xd,0xa,"Method Not Allowed",0xa
msg_bad_meth_end:
%define msg_bad_meth_len (msg_bad_meth_end - msg_bad_meth) 

msg_large_payload: db "HTTP/1.1 413 Payload Too Large",0xd,0xa,"Connection: close",0xd,0xa,"Content-Type: text/plain",0xd,0xa,"Server: ",SERVER_BRAND,0xd,0xa,"Content-Length: 18",0xd,0xa,0xd,0xa,"Payload Too Large",0xa
msg_large_payload_end:
%define msg_large_payload_len (msg_large_payload_end - msg_large_payload) 

msg_404: db "HTTP/1.1 404 Not Found",0xd,0xa,"Connection: close",0xd,0xa,"Content-Type: text/plain",0xd,0xa,"Server: ",SERVER_BRAND,0xd,0xa,"Content-Length: 10",0xd,0xa,0xd,0xa,"Not Found",0xa
msg_404_end:
%define msg_404_len (msg_404_end - msg_404) 

msg_408: db "HTTP/1.1 408 Request Timeout",0xd,0xa,"Connection: close",0xd,0xa,"Content-Type: text/plain",0xd,0xa,"Server: ",SERVER_BRAND,0xd,0xa,0xd,0xa,"Request Timed Out",0xa
msg_408_end:
%define msg_408_len (msg_408_end - msg_408) 

msg_500: db "HTTP/1.1 500 Internal Server Error",0xd,0xa,"Connection: close",0xd,0xa,"Content-Type: text/plain",0xd,0xa,"Server: ",SERVER_BRAND,0xd,0xa,"Content-Length: 22",0xd,0xa,0xd,0xa,"Internal Server Error",0xa
msg_500_end:
%define msg_500_len (msg_500_end - msg_500) 

hdr_fmt: db "HTTP/1.1 200 OK",0xd,0xa,"Connection: close",0xd,0xa,"Content-Type: %s",0xd,0xa,"Server: ",SERVER_BRAND,0xd,0xa,"Content-Length: %lu",0xd,0xa,0xd,0xa,0
page_name_fmt: db "./%s%s",0

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

rcvtimeo_timeval: dq 10 ; tv_sec
                  dq 0  ; tv_usec

method_get: db "GET",0
method_post: db "POST",0
method_head: db "HEAD",0

sigaction_sigint:
dq sigint_hdlr ; sa_handler
dq (SA_RESTORER | SA_RESTART) ; sa_flags
dq sig_restorer ; sa_restorer
dq 0 ; sa_mask

sigaction_sigint_child:
dq sigint_child_hdlr ; sa_handler
dq (SA_RESTORER | SA_RESTART) ; sa_flags
dq sig_restorer ; sa_restorer
dq 0 ; sa_mask

sigaction_sigchld:
dq sigchld_hdlr ; sa_handler
dq (SA_RESTORER | SA_RESTART) ; sa_flags
dq sig_restorer ; sa_restorer
dq 0 ; sa_mask

section .mime-table alloc progbits align=4 
mime_tables: incbin "mime-types.bin"

section .text
global _start

; TODO: eliminate these!
extern printf
extern putc
extern perror
extern errno
extern strtoul
extern raise
extern free
extern asprintf
extern inet_ntoa

;;;;; int _start(int argc[rsp], char** argv[rsp+4 (to rsp+4+(8*argc))])
_start:
mov dword eax, [mime_tables]
cmp eax, 1
je .mime_ver_ok
mov rdi, inval_mime_types_file_msg
call printf
mov rax, SYS_EXIT
syscall
.mime_ver_ok:

mov rdi, mime_types_file_info_msg
mov dword esi, [mime_tables + 16]
lea esi, [esi + mime_tables]
call printf

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

;; webroot_len = repne scasb until \0
mov rbp, [argv]
mov rdi, [rbp + 8]
mov al, 0
mov rcx, 4095
mov rbx, rcx
cld
repne scasb
sub rbx, rcx
mov qword [webroot_len], rbx

;; webroot = mmap(NULL, webroot_len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0)
mov rax, SYS_MMAP
mov rdi, 0
mov qword rsi, [webroot_len]
mov rdx, (PROT_READ | PROT_WRITE)
mov r10, (MAP_ANONYMOUS | MAP_SHARED)
mov r8, -1
mov r9, 0
syscall
cmp rax, 0
jge .mmap_webroot_ok
mov rdi, rax
mov rax, SYS_EXIT
syscall
.mmap_webroot_ok:
mov qword [webroot], rax

;; strcpy(webroot, argv[1])
mov rbp, [argv]
mov rsi, [rbp + 8]
mov qword rdi, [webroot]
mov qword rcx, [webroot_len]
rep movsb

;; mprotect(webroot, webroot_len, PROT_READ)
mov rax, SYS_MPROTECT
mov qword rdi, [webroot]
mov qword rsi, [webroot_len]
mov rdx, PROT_READ
syscall

;; printf(intro_msg, argv[1])
mov rdi, intro_msg
mov qword rsi, [webroot]
call printf

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

;; munmap(webroot, webroot_len)
mov rax, SYS_MUNMAP
mov qword rdi, [webroot]
mov qword rsi, [webroot_len]
syscall

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

; set sigint handler to sigaction_sigint
mov rax, SYS_RT_SIGACTION
mov rdi, SIGINT
mov rsi, sigaction_sigint
mov rdx, 0
mov r10, 8
syscall
cmp rax, 0
je .sigint_ok
mov rdi, rax
mov rax, SYS_EXIT
syscall
.sigint_ok:

; set sigchld handler to sigaction_sigchld
mov rax, SYS_RT_SIGACTION
mov rdi, SIGCHLD
mov rsi, sigaction_sigchld
mov rdx, 0
mov r10, 8
syscall
cmp rax, 0
je .sigchld_ok
mov rdi, rax
mov rax, SYS_EXIT
syscall
.sigchld_ok:

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
.attempt_fork:
mov rax, SYS_FORK
syscall
cmp rax, 0
jne .fork_no_child

;; setsockopt(cli_fd, SOL_SOCKET, SO_REUSEADDR, int32_one, 4)
mov dword edi, [cli_fd]
mov rsi, SOL_SOCKET
mov rdx, SO_RCVTIMEO_NEW
mov r10, rcvtimeo_timeval
mov r8, 16
mov rax, SYS_SETSOCKOPT
syscall

cmp rax, 0
jge .no_setsockopt_rcvtimeo_fail
mov rdi, rax
mov rax, SYS_EXIT
syscall
ret
.no_setsockopt_rcvtimeo_fail:

;; change SIGINT handler
mov rax, SYS_RT_SIGACTION
mov rdi, SIGINT
mov rsi, sigaction_sigint_child
mov rdx, 0
mov r10, 8
syscall
cmp rax, 0
je .sigint_change_ok
mov rdi, rax
mov rax, SYS_EXIT
syscall
.sigint_change_ok:

;; remove SIGCHLD handler
mov rax, SYS_RT_SIGACTION
mov rdi, SIGCHLD
mov rsi, NULL
mov rdx, NULL
mov r10, 8
syscall
cmp rax, 0
je .sigchld_remove_ok
mov rdi, rax
mov rax, SYS_EXIT
syscall
.sigchld_remove_ok:

;; child -> cli_fd should be valid
call serv_child

mov rdi, 0
mov rax, SYS_EXIT
syscall
ret
.fork_no_child:
jg .fork_no_err
cmp rax, -11
je .attempt_fork
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

%define TCP_BUF_SZ 65536
%define TX_MAX_BLOCK_SZ 1048576

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
cmp rax, -EAGAIN ; if EAGAIN, then return 408 (request timeout)
je .408
cmp rax, 0
jle .out
cmp rax, (TCP_BUF_SZ - 1) ; request too long
jge .payload_too_large

mov qword [recv_len], rax


; get total request length
mov qword rdi, [tcp_buf]
mov al, 0
mov rcx, TCP_BUF_SZ
mov rdx, rcx
repne scasb
sub rdx, rcx

; extract the method, we allow GET/POST
mov qword [no_send_body], 0

mov qword rdi, [tcp_buf]
mov al, ' '
mov rcx, rdx
mov rdx, rcx
repne scasb
sub rdx, rcx
mov qword [meth_len], rdx
mov byte [rdi - 1], 0

mov qword rdi, [tcp_buf]
mov rsi, method_get
call _strcmp
cmp rax, 0
je .method_ok

mov qword rdi, [tcp_buf]
mov rsi, method_post
call _strcmp
cmp rax, 0
je .method_ok

mov qword rdi, [tcp_buf]
mov rsi, method_head
call _strcmp
cmp rax, 0
jne .meth_not_head
mov qword [no_send_body], 1
jmp .method_ok
.meth_not_head:

jmp .meth_not_allowed
.method_ok:

;;;

mov al, ' '
mov qword rdi, [tcp_buf]
mov qword rcx, [meth_len]
lea rdi, [rdi + rcx]
mov qword rcx, [recv_len]
repne scasb
mov byte [rdi - 1], 0

; remove query string
mov qword rdi, [tcp_buf]
mov qword rcx, [meth_len]
lea rdi, [rdi + rcx]
mov rcx, rax
mov al, '?'
cld
repne scasb
cmp rcx, 0
je .rem_query_str_rcx_zero
mov byte [rdi - 1], 0
.rem_query_str_rcx_zero:

; check path
mov qword rdi, [tcp_buf]
mov qword rcx, [meth_len]
lea rdi, [rdi + rcx]
call check_access
cmp rax, 0
jne .404 ; we can just pretend to 404 if the path is invalid

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
mov qword rcx, [meth_len]
lea rdx, [rdi + rcx]
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

; divine the mime type
mov qword rdi, [page_name]
call populate_mime

;; page_fd = open(page_name, O_RDONLY, 0)
mov rax, SYS_OPEN
mov qword rdi, [page_name]
mov rsi, O_RDONLY
mov rdx, 0
syscall
cmp rax, 0
jg .open_ok
mov qword rdi, [page_name]
call free
jmp .404
.open_ok:
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
cmp rax, 0
je .page_zero_len_0

;; lseek(page_fd, 0, SEEK_SET)
mov rax, SYS_LSEEK
mov dword edi, [page_fd]
mov rsi, 0
mov rdx, SEEK_SET
syscall

;; page_buf = mmap(NULL, page_len, PROT_READ, MAP_PRIVATE, page_fd, 0)
mov rdi, NULL
mov qword rsi, [page_len]
mov rdx, (PROT_READ)
mov r10, (MAP_PRIVATE)
mov r9 , 0
xor rax, rax
mov dword eax, [page_fd]
mov r8,  rax
mov rax, SYS_MMAP
syscall
mov qword [page_buf], rax
cmp rax, 0
jge .mmap_third_ok
mov rdi, rax
mov rax, SYS_EXIT
syscall
.mmap_third_ok:

.page_zero_len_0:

;; close(page_fd)
mov rax, SYS_CLOSE
mov dword edi, [page_fd]
syscall


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

mov qword rax, [page_len]
cmp rax, 0
je .page_zero_len_1

mov qword rax, [no_send_body]
cmp rax, 1
je .no_send_body

mov r10, 0 ; write progress

.write_loop:
;; write(cli_fd, page_buf, page_len)
mov rax, SYS_WRITE
mov dword edi, [cli_fd]
mov qword rsi, [page_buf]
lea rsi, [rsi + r10]
mov qword rdx, [page_len]
sub rdx, r10
cmp rdx, TX_MAX_BLOCK_SZ
jle .block_smaller
mov rdx, TX_MAX_BLOCK_SZ
.block_smaller:
push r10
push rdx
syscall
pop rdx
pop r10
add r10, rax
cmp qword rax, rdx
jne .500
cmp qword [page_len], r10
jne .write_loop

.no_send_body:

;; munmap(page_buf, page_len)
mov rax, SYS_MUNMAP
mov qword rdi, [page_buf]
mov qword rsi, [page_len]
syscall

.page_zero_len_1:

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

.meth_not_allowed:
mov dword edi, [cli_fd]
mov rsi, msg_bad_meth
mov rdx, msg_bad_meth_len 
mov rax, SYS_WRITE
syscall
jmp .out

.payload_too_large:
mov dword edi, [cli_fd]
mov rsi, msg_large_payload
mov rdx, msg_large_payload_len 
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

.408:
mov dword edi, [cli_fd]
mov rsi, msg_408
mov rdx, msg_408_len
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

cmp byte [rdi], '#'
jne .no_hash
mov rax, 1
ret
.no_hash:

cmp byte [rdi], '&'
jne .no_and
mov rax, 1
ret
.no_and:

cmp byte [rdi], '?'
jne .no_question
mov rax, 1
ret
.no_question:

cmp byte [rdi], ';'
jne .no_semicolon
mov rax, 1
ret
.no_semicolon:

cmp byte [rdi], '\'
jne .no_backslash
mov rax, 1
ret
.no_backslash:

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
cmp rcx, 1
jg .str_len_ok
xor eax, eax
mov dword eax, [mime_tables + 12]
lea rax, [rax + mime_tables]
mov qword [mime_type], rax
ret
.str_len_ok:
cmp byte [rbp], '.'
jne .first_char_not_dot
inc rbp
dec rcx
.first_char_not_dot:
mov al, '.'
lea rdi, [rbp + rcx]
std
repne scasb
cld
inc rcx
inc rcx
lea rdi, [rbp + rcx]

cmp rcx, 2
jg .extn_found
xor eax, eax
mov dword eax, [mime_tables + 12]
lea rax, [rax + mime_tables]
mov qword [mime_type], rax
ret
.extn_found:
mov byte [rdi - 1], 0 ; remove dot, rdi is now extension!
mov rbp, rdi
push rbp
call derive_mime
pop rbp
mov byte [rbp - 1], '.'
ret

;; void sigint_hdlr(int)
sigint_hdlr:

and rsp, -16 ; align stack

mov rdi, sigint_msg
call printf

;; close(sock_fd)
mov rax, SYS_CLOSE
mov dword edi, [sock_fd]
syscall

;; munmap(webroot, webroot_len)
mov rax, SYS_MUNMAP
mov qword rdi, [webroot]
mov qword rsi, [webroot_len]
syscall

;; get pid and kill all children
mov rax, SYS_GETPID
syscall

mov rdi, rax
mov rax, SYS_GETPGID
syscall

neg rax
mov rdi, rax
mov rax, SYS_KILL
mov rsi, SIGINT
syscall

.reap_children:
mov rax, SYS_WAIT4
mov rdi, -1
mov rsi, reap_status
mov rdx, 0 ; no flags, wait for state change
mov r10, 0 ; rusage = NULL
syscall
cmp rax, 0
jg .reap_children

;; exit(0)
mov rax, SYS_EXIT
mov rdi, 0
syscall

ret

;; void sigchld_hdlr(int)
sigchld_hdlr:

.reap_children:
mov rax, SYS_WAIT4
mov rdi, -1
mov rsi, reap_status
mov rdx, WNOHANG
mov r10, 0 ; rusage = NULL
syscall
cmp rax, 0
jg .reap_children

ret

;; void sigint_child_hdlr(int)
sigint_child_hdlr:

; close(cli_fd)
mov rax, SYS_CLOSE
mov dword edi, [cli_fd]
syscall

; exit(0)
mov rax, SYS_EXIT
mov rdi, 0
syscall

ret

sig_restorer:
mov rax, SYS_RT_SIGRETURN
syscall
ret

; strcmp
_strcmp:

push rbx
push rdi
push rsi

mov rcx, 65535
mov al, 0
mov rbx, rcx
repne scasb
sub rbx, rcx
mov rdx, rbx

mov rdi, rsi
mov rcx, 65535
mov al, 0
mov rbx, rcx
repne scasb
sub rbx, rcx

cmp rbx, rdx
jc .first_bigger
mov rax, rdx
jmp .sz_chk_end
.first_bigger:
mov rax, rbx
.sz_chk_end:

pop rdi
pop rsi

mov rcx, rax
repe cmpsb
jne .differ
mov rax, 0
pop rbx

ret
.differ:
pop rbx
mov rax, 1
ret

extern strcasecmp ; todo: use my own!
;; void derive_mime(char* extn)
derive_mime:
mov qword [file_extn], rdi

push rdi
mov rcx, 4095
mov al, 0
mov rdx, rcx
cld
repne scasb
pop rdi
sub rdx, rcx
dec rdx

mov rbp, mime_tables
mov dword eax, [rbp + 12] ; dfl_str_ptr
lea rax, [rax + rbp]
xor r8, r8
mov r8, rax

mov qword [dfl_type], r8

mov dword eax, [rbp + 4] ; min_bin
mov dword ecx, [rbp + 8] ; max_bin

cmp dword edx, eax 
jge .lower_bound_ok
mov qword [mime_type], r8
ret
.lower_bound_ok:

cmp dword edx, ecx
jle .upper_bound_ok
mov qword [mime_type], r8
ret
.upper_bound_ok:

sub rdx, rax 
lea rax, [20 + mime_tables + (4*rdx)]
mov dword eax, [rax]
mov r10, 0xffffffff
and qword rax, r10
mov qword [mime_search_list_ptr], rax
xor rdx, rdx
mov dword edx, [rax + mime_tables] ; edx is now total len -> initial UPPER bound
cmp edx, 0
je .no_type_found
cmp edx, 1
jne .not_one
dec edx
.not_one:
mov rcx, 0 ; initial LOWER bound

.search_loop:
mov rsi, rdx
sub rsi, rcx
shr rsi, 1
add rsi, rcx

push rsi
mov qword rax, [mime_search_list_ptr]
lea rdi, [rax + mime_tables + 4 + (rsi*8)]
mov dword edi, [rdi]
lea esi, [edi + mime_tables]
mov qword rdi, [file_extn]

push rcx
push rdx
call strcasecmp ; -ve if before, +ve if after
pop rdx
pop rcx
pop rsi

mov dword [last_strcmp], eax

cmp eax, 0
jz .loop_escape

cmp rcx, rdx
je .loop_escape

cmp rcx, rsi
jne .no_force_odd
mov rcx, rdx ; set lower bound to upper bound to force an odd compare
jmp .search_loop
.no_force_odd:

cmp eax, 0
jl .not_after
; str is located after midpoint, therefore set lower bound to current midpoint
mov rcx, rsi
jmp .search_loop
.not_after:
jg .not_before
; str is located before midpoint, therefore set upper bound to current midpoint
mov rdx, rsi
jmp .search_loop
.not_before:

.loop_escape:

mov dword eax, [last_strcmp]
cmp eax, 0
jne .no_type_found

mov qword rax, [mime_search_list_ptr]
lea rdi, [rax + mime_tables + 8 + (rsi*8)]
mov dword edi, [rdi]
lea rdi, [edi + mime_tables]
mov qword [mime_type], rdi

ret

.no_type_found:
mov qword r8, [dfl_type]
mov qword [mime_type], r8
ret

;;
section .bss alloc write
file_extn: resq 1
mime_search_list_ptr: resq 1
last_strcmp: resd 1
resd 1
dfl_type: resq 1
meth_len: resq 1
no_send_body: resq 1