%define NULL 0
;;

%define AF_INET 2

%define SOCK_STREAM 1

%define SOL_SOCKET 1

%define SO_REUSEADDR 2
%define SO_REUSEPORT 15

;;
%define SYS_BIND 49
%define SYS_LISTEN 50
%define SYS_CLOSE 3
%define SYS_ACCEPT 43
%define SYS_FORK 57
%define SYS_MMAP 9
%define SYS_MUNMAP 11
%define SYS_EXIT 60
%define SYS_READ 0
%define SYS_WRITE 1
%define SYS_OPEN 2
%define SYS_LSEEK 8
%define SYS_SETSOCKOPT 54
%define SYS_WAIT4 61
%define SYS_SOCKET 41

;;
%define PROT_READ 1
%define PROT_WRITE 2

%define MAP_ANONYMOUS 0x20
%define MAP_PRIVATE 0x02

;;
%define O_RDONLY 0

;;
%define SIGTRAP 5

;;
%define SEEK_SET 0
%define SEEK_END 2