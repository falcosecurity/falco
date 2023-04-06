#ifndef __SYSTYPE_COMPACT_H__
#define __SYSTYPE_COMPACT_H__

/* If WIFEXITED(STATUS), the low-order 8 bits of the status.  */
#define __WEXITSTATUS(status) (((status)&0xff00) >> 8)

/* If WIFSIGNALED(STATUS), the terminating signal.  */
#define __WTERMSIG(status) ((status)&0x7f)

/* Nonzero if STATUS indicates termination by a signal.  */
#define __WIFSIGNALED(status) \
	(((signed char)(((status)&0x7f) + 1) >> 1) > 0)

/* Nonzero if STATUS indicates the child dumped core.  */
#define __WCOREDUMP(status) ((status)&__WCOREFLAG)

#define __WCOREFLAG 0x80

#endif /* __SYSTYPE_COMPACT_H__ */
