/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#define SE_EPERM            1      /* Operation not permitted */
#define SE_ENOENT           2      /* No such file or directory */
#define SE_ESRCH            3      /* No such process */
#define SE_EINTR            4      /* Interrupted system call */
#define SE_EIO              5      /* I/O error */
#define SE_ENXIO            6      /* No such device or address */
#define SE_E2BIG            7      /* Arg list too long */
#define SE_ENOEXEC          8      /* Exec format error */
#define SE_EBADF            9      /* Bad file number */
#define SE_ECHILD          10      /* No child processes */
#define SE_EAGAIN          11      /* Try again */
#define SE_ENOMEM          12      /* Out of memory */
#define SE_EACCES          13      /* Permission denied */
#define SE_EFAULT          14      /* Bad address */
#define SE_ENOTBLK         15      /* Block device required */
#define SE_EBUSY           16      /* Device or resource busy */
#define SE_EEXIST          17      /* File exists */
#define SE_EXDEV           18      /* Cross-device link */
#define SE_ENODEV          19      /* No such device */
#define SE_ENOTDIR         20      /* Not a directory */
#define SE_EISDIR          21      /* Is a directory */
#define SE_EINVAL          22      /* Invalid argument */
#define SE_ENFILE          23      /* File table overflow */
#define SE_EMFILE          24      /* Too many open files */
#define SE_ENOTTY          25      /* Not a typewriter */
#define SE_ETXTBSY         26      /* Text file busy */
#define SE_EFBIG           27      /* File too large */
#define SE_ENOSPC          28      /* No space left on device */
#define SE_ESPIPE          29      /* Illegal seek */
#define SE_EROFS           30      /* Read-only file system */
#define SE_EMLINK          31      /* Too many links */
#define SE_EPIPE           32      /* Broken pipe */
#define SE_EDOM            33      /* Math argument out of domain of func */
#define SE_ERANGE          34      /* Math result not representable */
#define SE_EDEADLK         35      /* Resource deadlock would occur */
#define SE_ENAMETOOLONG    36      /* File name too long */
#define SE_ENOLCK          37      /* No record locks available */
#define SE_ENOSYS          38      /* Function not implemented */
#define SE_ENOTEMPTY       39      /* Directory not empty */
#define SE_ELOOP           40      /* Too many symbolic links encountered */
#define SE_EWOULDBLOCK     EAGAIN  /* Operation would block */
#define SE_ENOMSG          42      /* No message of desired type */
#define SE_EIDRM           43      /* Identifier removed */
#define SE_ECHRNG          44      /* Channel number out of range */
#define SE_EL2NSYNC        45      /* Level 2 not synchronized */
#define SE_EL3HLT          46      /* Level 3 halted */
#define SE_EL3RST          47      /* Level 3 reset */
#define SE_ELNRNG          48      /* Link number out of range */
#define SE_EUNATCH         49      /* Protocol driver not attached */
#define SE_ENOCSI          50      /* No CSI structure available */
#define SE_EL2HLT          51      /* Level 2 halted */
#define SE_EBADE           52      /* Invalid exchange */
#define SE_EBADR           53      /* Invalid request descriptor */
#define SE_EXFULL          54      /* Exchange full */
#define SE_ENOANO          55      /* No anode */
#define SE_EBADRQC         56      /* Invalid request code */
#define SE_EBADSLT         57      /* Invalid slot */
#define SE_EDEADLOCK       EDEADLK
#define SE_EBFONT          59      /* Bad font file format */
#define SE_ENOSTR          60      /* Device not a stream */
#define SE_ENODATA         61      /* No data available */
#define SE_ETIME           62      /* Timer expired */
#define SE_ENOSR           63      /* Out of streams resources */
#define SE_ENONET          64      /* Machine is not on the network */
#define SE_ENOPKG          65      /* Package not installed */
#define SE_EREMOTE         66      /* Object is remote */
#define SE_ENOLINK         67      /* Link has been severed */
#define SE_EADV            68      /* Advertise error */
#define SE_ESRMNT          69      /* Srmount error */
#define SE_ECOMM           70      /* Communication error on send */
#define SE_EPROTO          71      /* Protocol error */
#define SE_EMULTIHOP       72      /* Multihop attempted */
#define SE_EDOTDOT         73      /* RFS specific error */
#define SE_EBADMSG         74      /* Not a data message */
#define SE_EOVERFLOW       75      /* Value too large for defined data type */
#define SE_ENOTUNIQ        76      /* Name not unique on network */
#define SE_EBADFD          77      /* File descriptor in bad state */
#define SE_EREMCHG         78      /* Remote address changed */
#define SE_ELIBACC         79      /* Can not access a needed shared library */
#define SE_ELIBBAD         80      /* Accessing a corrupted shared library */
#define SE_ELIBSCN         81      /* .lib section in a.out corrupted */
#define SE_ELIBMAX         82      /* Attempting to link in too many shared libraries */
#define SE_ELIBEXEC        83      /* Cannot exec a shared library directly */
#define SE_EILSEQ          84      /* Illegal byte sequence */
#define SE_ERESTART        85      /* Interrupted system call should be restarted */
#define SE_ESTRPIPE        86      /* Streams pipe error */
#define SE_EUSERS          87      /* Too many users */
#define SE_ENOTSOCK        88      /* Socket operation on non-socket */
#define SE_EDESTADDRREQ    89      /* Destination address required */
#define SE_EMSGSIZE        90      /* Message too long */
#define SE_EPROTOTYPE      91      /* Protocol wrong type for socket */
#define SE_ENOPROTOOPT     92      /* Protocol not available */
#define SE_EPROTONOSUPPORT 93      /* Protocol not supported */
#define SE_ESOCKTNOSUPPORT 94      /* Socket type not supported */
#define SE_EOPNOTSUPP      95      /* Operation not supported on transport endpoint */
#define SE_EPFNOSUPPORT    96      /* Protocol family not supported */
#define SE_EAFNOSUPPORT    97      /* Address family not supported by protocol */
#define SE_EADDRINUSE      98      /* Address already in use */
#define SE_EADDRNOTAVAIL   99      /* Cannot assign requested address */
#define SE_ENETDOWN        100     /* Network is down */
#define SE_ENETUNREACH     101     /* Network is unreachable */
#define SE_ENETRESET       102     /* Network dropped connection because of reset */
#define SE_ECONNABORTED    103     /* Software caused connection abort */
#define SE_ECONNRESET      104     /* Connection reset by peer */
#define SE_ENOBUFS         105     /* No buffer space available */
#define SE_EISCONN         106     /* Transport endpoint is already connected */
#define SE_ENOTCONN        107     /* Transport endpoint is not connected */
#define SE_ESHUTDOWN       108     /* Cannot send after transport endpoint shutdown */
#define SE_ETOOMANYREFS    109     /* Too many references: cannot splice */
#define SE_ETIMEDOUT       110     /* Connection timed out */
#define SE_ECONNREFUSED    111     /* Connection refused */
#define SE_EHOSTDOWN       112     /* Host is down */
#define SE_EHOSTUNREACH    113     /* No route to host */
#define SE_EALREADY        114     /* Operation already in progress */
#define SE_EINPROGRESS     115     /* Operation now in progress */
#define SE_ESTALE          116     /* Stale NFS file handle */
#define SE_EUCLEAN         117     /* Structure needs cleaning */
#define SE_ENOTNAM         118     /* Not a XENIX named type file */
#define SE_ENAVAIL         119     /* No XENIX semaphores available */
#define SE_EISNAM          120     /* Is a named type file */
#define SE_EREMOTEIO       121     /* Remote I/O error */
#define SE_EDQUOT          122     /* Quota exceeded */
#define SE_ENOMEDIUM       123     /* No medium found */
#define SE_EMEDIUMTYPE     124     /* Wrong medium type */
#define SE_ECANCELED       125
#define SE_ERESTARTSYS     512     /* Interrupted system call */
#define SE_ERESTARTNOINTR  513
#define SE_ERESTARTNOHAND  514     /* restart if no handler.. */
#define SE_ENOIOCTLCMD     515     /* No ioctl command */
#define SE_ERESTART_RESTARTBLOCK 516  /* restart by calling sys_restart_syscall */
/* Defined for the NFSv3 protocol */
#define SE_EBADHANDLE      521     /* Illegal NFS file handle */
#define SE_ENOTSYNC        522     /* Update synchronization mismatch */
#define SE_EBADCOOKIE      523     /* Cookie is stale */
#define SE_ENOTSUPP        524     /* Operation is not supported */
#define SE_ETOOSMALL       525     /* Buffer or request is too small */
#define SE_ESERVERFAULT    526     /* An untranslatable error occurred */
#define SE_EBADTYPE        527     /* Type not supported by server */
#define SE_EJUKEBOX        528     /* Request initiated, but will not complete before timeout */
#define SE_EIOCBQUEUED     529     /* iocb queued, will get completion event */
#define SE_EIOCBRETRY      530     /* iocb queued, will trigger a retry */
