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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*!
	\mainpage libscap documentation

	\section Introduction

	libscap is the low-level sysdig component that exports the following functionality:
	- live capture control (start/stop/pause...)
	- trace file management
	- event retrieval
	- extraction of system state from /proc

	This manual includes the following sections:
	- \ref scap_defs
	- \ref scap_functs
*/

///////////////////////////////////////////////////////////////////////////////
// Public structs and defines
///////////////////////////////////////////////////////////////////////////////

/** @defgroup scap_defs public definitions and structures
 *  @{
 */

//
// Forward declarations
//
typedef struct scap scap_t;
typedef struct ppm_evt_hdr scap_evt;

struct iovec;

//
// Core types
//
#include "uthash.h"
#include "../common/sysdig_types.h"
#include "../../driver/ppm_events_public.h"

//
// Return types
//
#define SCAP_SUCCESS 0
#define SCAP_FAILURE 1
#define SCAP_TIMEOUT -1
#define SCAP_ILLEGAL_INPUT 3
#define SCAP_NOTFOUND 4
#define SCAP_INPUT_TOO_SMALL 5
#define SCAP_EOF 6
#define SCAP_UNEXPECTED_BLOCK 7
#define SCAP_VERSION_MISMATCH 8
#define SCAP_NOT_SUPPORTED 9

//
// Last error string size for scap_open_live()
//
#define SCAP_LASTERR_SIZE 256

/*!
  \brief Statistics about an in progress capture
*/
typedef struct scap_stats
{
	uint64_t n_evts; ///< Total number of events that were received by the driver.
	uint64_t n_drops; ///< Number of dropped events.
	uint64_t n_drops_buffer; ///< Number of dropped events caused by full buffer.
	uint64_t n_drops_pf; ///< Number of dropped events caused by invalid memory access.
	uint64_t n_drops_bug; ///< Number of dropped events caused by an invalid condition in the kernel instrumentation.
	uint64_t n_preemptions; ///< Number of preemptions.
	uint64_t n_suppressed; ///< Number of events skipped due to the tid being in a set of suppressed tids
	uint64_t n_tids_suppressed; ///< Number of threads currently being suppressed
}scap_stats;

/*!
  \brief Information about the parameter of an event
*/
typedef struct evt_param_info
{
	const char* name; ///< The event name.
	uint32_t type; ///< The event type. See the ppm_event_type enum in driver/ppm_events_public.h
	uint32_t len; ///< The event total length.
	char* val; ///< The event data.
}evt_param_info;

#define SCAP_MAX_PATH_SIZE 1024
#define SCAP_MAX_ARGS_SIZE 4096
#define SCAP_MAX_ENV_SIZE 4096
#define SCAP_MAX_CGROUPS_SIZE 4096
#define SCAP_MAX_SUPPRESSED_COMMS 32

/*!
  \brief File Descriptor type
*/
typedef enum scap_fd_type
{
	SCAP_FD_UNINITIALIZED = -1,
	SCAP_FD_UNKNOWN = 0,
	SCAP_FD_FILE = 1,
	SCAP_FD_DIRECTORY = 2,
	SCAP_FD_IPV4_SOCK = 3,
	SCAP_FD_IPV6_SOCK = 4,
	SCAP_FD_IPV4_SERVSOCK = 5,
	SCAP_FD_IPV6_SERVSOCK = 6,
	SCAP_FD_FIFO = 7,
	SCAP_FD_UNIX_SOCK = 8,
	SCAP_FD_EVENT = 9,
	SCAP_FD_UNSUPPORTED = 10,
	SCAP_FD_SIGNALFD = 11,
	SCAP_FD_EVENTPOLL = 12,
	SCAP_FD_INOTIFY = 13,
	SCAP_FD_TIMERFD = 14,
	SCAP_FD_NETLINK = 15,
	SCAP_FD_FILE_V2 = 16
}scap_fd_type;

/*!
  \brief Socket type / transport protocol
*/
typedef enum scap_l4_proto
{
	SCAP_L4_UNKNOWN = 0, ///< unknown protocol, likely caused by some parsing problem
	SCAP_L4_NA = 1, ///< protocol not available, because the fd is not a socket
	SCAP_L4_TCP = 2,
	SCAP_L4_UDP = 3,
	SCAP_L4_ICMP = 4,
	SCAP_L4_RAW = 5, ///< Raw socket
}scap_l4_proto;

/*!
  \brief Information about a file descriptor
*/
typedef struct scap_fdinfo
{
	int64_t fd; ///< The FD number, which uniquely identifies this file descriptor.
	uint64_t ino; ///< For unix sockets, the inode.
	scap_fd_type type; ///< This file descriptor's type.
	union
	{
		struct
		{
		  uint32_t sip; ///< Source IP
		  uint32_t dip; ///< Destination IP
		  uint16_t sport; ///< Source port
		  uint16_t dport; ///< Destination port
		  uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv4info; ///< Information specific to IPv4 sockets
		struct
		{
			uint32_t sip[4]; ///< Source IP
			uint32_t dip[4]; ///< Destination IP
			uint16_t sport; ///< Source Port
			uint16_t dport; ///< Destination Port
			uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv6info; ///< Information specific to IPv6 sockets
		struct
		{
		  uint32_t ip; ///< Local IP
		  uint16_t port; ///< Local Port
		  uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv4serverinfo; ///< Information specific to IPv4 server sockets, e.g. sockets used for bind().
		struct
		{
			uint32_t ip[4]; ///< Local IP
			uint16_t port; ///< Local Port
			uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv6serverinfo; ///< Information specific to IPv6 server sockets, e.g. sockets used for bind().
		struct
		{
			uint64_t source; ///< Source socket endpoint
		  	uint64_t destination; ///< Destination socket endpoint
			char fname[SCAP_MAX_PATH_SIZE]; ///< Name associated to this unix socket
		} unix_socket_info; ///< Information specific to unix sockets
		struct
		{
			uint32_t open_flags; ///< Flags associated with the file
			char fname[SCAP_MAX_PATH_SIZE]; ///< Name associated to this file
			uint32_t dev; ///< Major/minor number of the device containing this file
		} regularinfo; ///< Information specific to regular files
		char fname[SCAP_MAX_PATH_SIZE];  ///< The name for file system FDs
	}info;
	UT_hash_handle hh; ///< makes this structure hashable
}scap_fdinfo;

/*!
  \brief Process information
*/
typedef struct scap_threadinfo
{
	uint64_t tid; ///< The thread/task id.
	uint64_t pid; ///< The id of the process containing this thread. In single thread processes, this is equal to tid.
	uint64_t ptid; ///< The id of the thread that created this thread.
	uint64_t sid; ///< The session id of the process containing this thread.
	uint64_t vpgid; ///< The process group of this thread, as seen from its current pid namespace
	char comm[SCAP_MAX_PATH_SIZE+1]; ///< Command name (e.g. "top")
	char exe[SCAP_MAX_PATH_SIZE+1]; ///< argv[0] (e.g. "sshd: user@pts/4")
	char exepath[SCAP_MAX_PATH_SIZE+1]; ///< full executable path
	char args[SCAP_MAX_ARGS_SIZE+1]; ///< Command line arguments (e.g. "-d1")
	uint16_t args_len; ///< Command line arguments length
	char env[SCAP_MAX_ENV_SIZE+1]; ///< Environment
	uint16_t env_len; ///< Environment length
	char cwd[SCAP_MAX_PATH_SIZE+1]; ///< The current working directory
	int64_t fdlimit; ///< The maximum number of files this thread is allowed to open
	uint32_t flags; ///< the process flags.
	uint32_t uid; ///< user id
	uint32_t gid; ///< group id
	uint32_t vmsize_kb; ///< total virtual memory (as kb)
	uint32_t vmrss_kb; ///< resident non-swapped memory (as kb)
	uint32_t vmswap_kb; ///< swapped memory (as kb)
	uint64_t pfmajor; ///< number of major page faults since start
	uint64_t pfminor; ///< number of minor page faults since start
	int64_t vtid;
	int64_t vpid;
	char cgroups[SCAP_MAX_CGROUPS_SIZE];
	uint16_t cgroups_len;
	char root[SCAP_MAX_PATH_SIZE+1];
	int filtered_out; ///< nonzero if this entry should not be saved to file
	scap_fdinfo* fdlist; ///< The fd table for this process
	uint64_t clone_ts;
	int32_t tty;
    int32_t loginuid; ///< loginuid (auid)

	UT_hash_handle hh; ///< makes this structure hashable
}scap_threadinfo;

/*!
  \brief Mount information
*/
typedef struct {
	uint64_t mount_id; ///< mount id from /proc/self/mountinfo
	uint32_t dev; ///< device number
	UT_hash_handle hh; ///< makes this structure hashable
} scap_mountinfo;

typedef void (*proc_entry_callback)(void* context,
									scap_t* handle,
									int64_t tid,
									scap_threadinfo* tinfo,
									scap_fdinfo* fdinfo);

/*!
  \brief Arguments for scap_open
*/
typedef enum {
	/*!
	 * Default value that mostly exists so that sinsp can have a valid value
	 * before it is initialized.
	 */
	SCAP_MODE_NONE = 0,
	/*!
	 * Read system call data from a capture file.
	 */
	SCAP_MODE_CAPTURE,
	/*!
	 * Read system call data from the underlying operating system.
	 */
	SCAP_MODE_LIVE,
	/*!
	 * Do not read system call data. If next is called, a dummy event is
	 * returned.
	 */
	SCAP_MODE_NODRIVER
} scap_mode_t;

typedef struct scap_open_args
{
	scap_mode_t mode;
	int fd; // If non-zero, will be used instead of fname.
	const char* fname; ///< The name of the file to open. NULL for live captures.
	proc_entry_callback proc_callback; ///< Callback to be invoked for each thread/fd that is extracted from /proc, or NULL if no callback is needed.
	void* proc_callback_context; ///< Opaque pointer that will be included in the calls to proc_callback. Ignored if proc_callback is NULL.
	bool import_users; ///< true if the user list should be created when opening the capture.
	uint64_t start_offset; ///< Used to start reading a capture file from an arbitrary offset. This is leveraged when opening merged files.
	const char *bpf_probe; ///< The name of the BPF probe to open. If NULL, the kernel driver will be used.
	const char *suppressed_comms[SCAP_MAX_SUPPRESSED_COMMS]; ///< A list of processes (comm) for which no
	                                                         // events should be returned, with a trailing NULL value.
	                                                         // You can provide additional comm
	                                                         // values via scap_suppress_events_comm().
}scap_open_args;


//
// The follwing stuff is byte aligned because we save it to disk.
//
#if defined _MSC_VER
#pragma pack(push)
#pragma pack(1)
#elif defined __sun
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif

/*!
  \brief Machine information
*/
typedef struct _scap_machine_info
{
	uint32_t num_cpus;	///< Number of processors
	uint64_t memory_size_bytes; ///< Physical memory size
	uint64_t max_pid; ///< Highest PID number on this machine
	char hostname[128]; ///< The machine hostname
	uint64_t reserved1; ///< reserved for future use
	uint64_t reserved2; ///< reserved for future use
	uint64_t reserved3; ///< reserved for future use
	uint64_t reserved4; ///< reserved for future use
}scap_machine_info;


#define SCAP_IPV6_ADDR_LEN 16

/*!
  \brief Interface address type
*/
typedef enum scap_ifinfo_type
{
	SCAP_II_UNKNOWN = 0,
	SCAP_II_IPV4 = 1,
	SCAP_II_IPV6 = 2,
	SCAP_II_IPV4_NOLINKSPEED = 3,
	SCAP_II_IPV6_NOLINKSPEED = 4,
}scap_ifinfo_type;

/*!
  \brief IPv4 interface address information
*/
typedef struct scap_ifinfo_ipv4
{
	// NB: new fields must be appended
	uint16_t type; ///< Interface type
	uint16_t ifnamelen;
	uint32_t addr; ///< Interface address
	uint32_t netmask; ///< Interface netmask
	uint32_t bcast; ///< Interface broadcast address
	uint64_t linkspeed; ///< Interface link speed
	char ifname[SCAP_MAX_PATH_SIZE]; ///< interface name (e.g. "eth0")
}scap_ifinfo_ipv4;

/*!
  \brief For backward compatibility only
*/
typedef struct scap_ifinfo_ipv4_nolinkspeed
{
	uint16_t type;
	uint16_t ifnamelen;
	uint32_t addr;
	uint32_t netmask;
	uint32_t bcast;
	char ifname[SCAP_MAX_PATH_SIZE];
}scap_ifinfo_ipv4_nolinkspeed;

/*!
  \brief IPv6 interface address information
*/
typedef struct scap_ifinfo_ipv6
{
	// NB: new fields must be appended
	uint16_t type;
	uint16_t ifnamelen;
	char addr[SCAP_IPV6_ADDR_LEN]; ///< Interface address
	char netmask[SCAP_IPV6_ADDR_LEN]; ///< Interface netmask
	char bcast[SCAP_IPV6_ADDR_LEN]; ///< Interface broadcast address
	uint64_t linkspeed; ///< Interface link speed
	char ifname[SCAP_MAX_PATH_SIZE]; ///< interface name (e.g. "eth0")
}scap_ifinfo_ipv6;

/*!
  \brief For backword compatibility only
*/
typedef struct scap_ifinfo_ipv6_nolinkspeed
{
	uint16_t type;
	uint16_t ifnamelen;
	char addr[SCAP_IPV6_ADDR_LEN];
	char netmask[SCAP_IPV6_ADDR_LEN];
	char bcast[SCAP_IPV6_ADDR_LEN];
	char ifname[SCAP_MAX_PATH_SIZE];
}scap_ifinfo_ipv6_nolinkspeed;

#if defined __sun
#pragma pack()
#else
#pragma pack(pop)
#endif

/*!
  \brief List of the machine network interfaces
*/
typedef struct scap_addrlist
{
	uint32_t n_v4_addrs; ///< Number of IPv4 addresses
	uint32_t n_v6_addrs; ///< Number of IPv6 addresses
	uint32_t totlen; ///< For internal use
	scap_ifinfo_ipv4* v4list; ///< List of IPv4 Addresses
	scap_ifinfo_ipv6* v6list; ///< List of IPv6 Addresses
}scap_addrlist;

#define MAX_CREDENTIALS_STR_LEN 256
#define USERBLOCK_TYPE_USER 0
#define USERBLOCK_TYPE_GROUP 1

/*!
  \brief Information about one of the machine users
*/
typedef struct scap_userinfo
{
	uint32_t uid; ///< User ID
	uint32_t gid; ///< Group ID
	char name[MAX_CREDENTIALS_STR_LEN]; ///< Username
	char homedir[SCAP_MAX_PATH_SIZE]; ///< Home directory
	char shell[SCAP_MAX_PATH_SIZE]; ///< Shell program
}scap_userinfo;

/*!
  \brief Information about one of the machine user groups
*/
typedef struct scap_groupinfo
{
	uint32_t gid; ///< Group ID
	char name[MAX_CREDENTIALS_STR_LEN]; ///< Group name
}scap_groupinfo;

/*!
  \brief List of the machine users and groups
*/
typedef struct scap_userlist
{
	uint32_t nusers; ///< Number of users
	uint32_t ngroups; ///< Number of groups
	uint32_t totsavelen; ///< For internal use
	scap_userinfo* users;  ///< User list
	scap_groupinfo* groups; ///< Group list
}scap_userlist;

//
// Misc definitions
//

/*!
  \brief The OS on which the capture was made
*/
typedef enum scap_os_platform
{
	SCAP_PFORM_UNKNOWN = 0,
	SCAP_PFORM_LINUX_I386 = 1,
	SCAP_PFORM_LINUX_X64 = 2,
	SCAP_PFORM_WINDOWS_I386 = 3,
	SCAP_PFORM_WINDOWS_X64 = 4,
}scap_os_platform;

/*!
  \brief Indicates if an event is an enter one or an exit one
*/
typedef enum event_direction
{
	SCAP_ED_IN = 0,
	SCAP_ED_OUT = 1
}event_direction;

/*!
  \brief Indicates the compression type used when writing a tracefile
*/
typedef enum compression_mode
{
	SCAP_COMPRESSION_NONE = 0,
	SCAP_COMPRESSION_GZIP = 1
}compression_mode;

/*!
  \brief Flags for scap_dump
*/
typedef enum scap_dump_flags
{
	SCAP_DF_NONE = 0,
	SCAP_DF_STATE_ONLY = 1,		///< The event should be used for state update but it should
								///< not be shown to the user
	SCAP_DF_TRACER = (1 << 1)	///< This event is a tracer
}scap_dump_flags;

typedef struct scap_dumper scap_dumper_t;

/*!
  \brief System call description struct.
*/
struct ppm_syscall_desc {
	enum ppm_event_category category; /**< System call category. */
	enum ppm_event_flags flags;
	char *name; /**< System call name, e.g. 'open'. */
};

/*@}*/

///////////////////////////////////////////////////////////////////////////////
// Structs and defines used internally
///////////////////////////////////////////////////////////////////////////////

#define IN
#define OUT

///////////////////////////////////////////////////////////////////////////////
// API functions
///////////////////////////////////////////////////////////////////////////////

/** @defgroup scap_functs API Functions
 *  @{
 */

/*!
  \brief Start a live event capture.

  \param error Pointer to a buffer that will contain the error string in case the
    function fails. The buffer must have size SCAP_LASTERR_SIZE.
  \param rc Integer pointer that will contain the scap return code in case the
    function fails.

  \return The capture instance handle in case of success. NULL in case of failure.
*/
scap_t* scap_open_live(char *error, int32_t *rc);

/*!
  \brief Start an event capture from file.

  \param fname The name of the file to open.
  \param error Pointer to a buffer that will contain the error string in case the
    function fails. The buffer must have size SCAP_LASTERR_SIZE.
  \param rc Integer pointer that will contain the scap return code in case the
    function fails.

  \return The capture instance handle in case of success. NULL in case of failure.
*/
scap_t* scap_open_offline(const char* fname, char *error, int32_t *rc);

/*!
  \brief Start an event capture from an already opened file descriptor.

  \param fd The fd to use.
  \param error Pointer to a buffer that will contain the error string in case the
    function fails. The buffer must have size SCAP_LASTERR_SIZE.
  \param rc Integer pointer that will contain the scap return code in case the
    function fails.

  \return The capture instance handle in case of success. NULL in case of failure.
*/
scap_t* scap_open_offline_fd(int fd, char *error, int32_t *rc);

/*!
  \brief Advanced function to start a capture.

  \param args a \ref scap_open_args structure containing the open paraneters.
  \param error Pointer to a buffer that will contain the error string in case the
    function fails. The buffer must have size SCAP_LASTERR_SIZE.
  \param rc Integer pointer that will contain the scap return code in case the
    function fails.

  \return The capture instance handle in case of success. NULL in case of failure.
*/
scap_t* scap_open(scap_open_args args, char *error, int32_t *rc);

/*!
  \brief Close a capture handle.

  \param handle Handle to the capture instance.
*/
void scap_close(scap_t* handle);

/*!
  \brief Retrieve the OS platform for the given capture handle.

  \param handle Handle to the capture instance.

  \return The type of operating system on which the capture was made.

  \note For live handles, the return value indicates the current local OS.
    For offline handles, the return value indicates the OS where the data was
	originally captured.
*/
scap_os_platform scap_get_os_platform(scap_t* handle);

/*!
  \brief Return a string with the last error that happened on the given capture.
*/
const char* scap_getlasterr(scap_t* handle);

/*!
 * \brief returns the maximum amount of memory used by any driver queue
 */
uint64_t scap_max_buf_used(scap_t* handle);

/*!
  \brief Get the next event from the from the given capture instance

  \param handle Handle to the capture instance.
  \param pevent User-provided event pointer that will be initialized with address of the event.
  \param pcpuid User-provided event pointer that will be initialized with the ID if the CPU
    where the event was captured.

  \return SCAP_SUCCESS if the call is successful and pevent and pcpuid contain valid data.
   SCAP_TIMEOUT in case the read timeout expired and no event is available.
   SCAP_EOF when the end of an offline capture is reached.
   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain the cause of the error.
*/
int32_t scap_next(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid);

/*!
  \brief Get the length of an event

  \param e pointer to an event returned by \ref scap_next.

  \return The event length in bytes.
*/
uint32_t scap_event_getlen(scap_evt* e);

/*!
  \brief Get the timestamp of an event

  \param e pointer to an event returned by \ref scap_next.

  \return The event timestamp, in nanoseconds since epoch.
*/
uint64_t scap_event_get_ts(scap_evt* e);

/*!
  \brief Get the number of events that have been captured from the given capture
  instance

  \param handle Handle to the capture instance.

  \return The total number of events.
*/
uint64_t scap_event_get_num(scap_t* handle);

/*!
  \brief Reset the event count to 0.

  \param handle Handle to the capture instance.
*/
void scap_event_reset_count(scap_t* handle);

/*!
  \brief Return the meta-information describing the given event

  \param e pointer to an event returned by \ref scap_next.

  \return The pointer to the the event table entry for the given event.
*/
const struct ppm_event_info* scap_event_getinfo(scap_evt* e);

/*!
  \brief Return the dump flags for the last event received from this handle

  \param handle Handle to the capture instance.

  \return The flags if the capture is offline, 0 if the capture is live.
*/
uint32_t scap_event_get_dump_flags(scap_t* handle);

/*!
  \brief Return the current offset in the file opened by scap_open_offline(),
  or -1 if this is a live capture.

  \param handle Handle to the capture instance.
*/
int64_t scap_get_readfile_offset(scap_t* handle);

/*!
  \brief Open a trace file for writing

  \param handle Handle to the capture instance.
  \param fname The name of the trace file.

  \return Dump handle that can be used to identify this specific dump instance.
*/
scap_dumper_t* scap_dump_open(scap_t *handle, const char *fname, compression_mode compress, bool skip_proc_scan);

/*!
  \brief Open a trace file for writing, using the provided fd.

  \param handle Handle to the capture instance.
  \param fd A file descriptor to which the dumper will write

  \return Dump handle that can be used to identify this specific dump instance.
*/
scap_dumper_t* scap_dump_open_fd(scap_t *handle, int fd, compression_mode compress, bool skip_proc_scan);

/*!
  \brief Close a trace file.

  \param d The dump handle, returned by \ref scap_dump_open
*/
void scap_dump_close(scap_dumper_t *d);

/*!
  \brief Return the current size of a trace file.

  \param d The dump handle, returned by \ref scap_dump_open
  \return The current size of the dump file pointed by d.
*/
int64_t scap_dump_get_offset(scap_dumper_t *d);

/*!
  \brief Return the position for the next write to a trace file.
         This uses gztell, while scap_dump_get_offset uses gzoffset.

  \param d The dump handle, returned by \ref scap_dump_open
  \return The next write position.
*/
int64_t scap_dump_ftell(scap_dumper_t *d);

/*!
  \brief Flush all pending output into the file.

  \param d The dump handle, returned by \ref scap_dump_open
*/
void scap_dump_flush(scap_dumper_t *d);

/*!
  \brief Tell how many bytes would be written (a dry run of scap_dump)

  \param e pointer to an event returned by \ref scap_next.
  \param cpuid The cpu from which the event was captured. Returned by \ref scap_next.
  \param bytes The number of bytes to write

  \return SCAP_SUCCESS if the call is successful.
   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain
   the cause of the error.
*/
int32_t scap_number_of_bytes_to_write(scap_evt *e, uint16_t cpuid, int32_t* bytes);

/*!
  \brief Write an event to a trace file

  \param handle Handle to the capture instance.
  \param d The dump handle, returned by \ref scap_dump_open
  \param e pointer to an event returned by \ref scap_next.
  \param cpuid The cpu from which the event was captured. Returned by \ref scap_next.
  \param flags The event flags. 0 means no flags.

  \return SCAP_SUCCESS if the call is successful.
   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain
   the cause of the error.
*/
int32_t scap_dump(scap_t *handle, scap_dumper_t *d, scap_evt* e, uint16_t cpuid, uint32_t flags);

/*!
  \brief Get the process list for the given capture instance

  \param handle Handle to the capture instance.

  \return Pointer to the process list.

  for live captures, the process list is created when the capture starts by scanning the
  proc file system. For offline captures, it is retrieved from the file.
  The process list contains information about the processes that were already open when
  the capture started. It can be traversed with uthash, using the following syntax:

  \code
  scap_threadinfo *pi;
  scap_threadinfo *tpi;
  scap_threadinfo *table = scap_get_proc_table(phandle);

  HASH_ITER(hh, table, pi, tpi)
  {
    // do something with pi
  }
  \endcode

  Refer to the documentation of the \ref scap_threadinfo struct for details about its
  content.
*/
scap_threadinfo* scap_get_proc_table(scap_t* handle);

/*!
  \brief Return the capture statistics for the given capture handle.

  \param handle Handle to the capture instance.
  \param stats Pointer to a \ref scap_stats structure that will be filled with the
  statistics.

  \return SCAP_SECCESS if the call is successful.
   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain
   the cause of the error.
*/
int32_t scap_get_stats(scap_t* handle, OUT scap_stats* stats);

/*!
  \brief This function can be used to temporarily interrupt event capture.

  \param handle Handle to the capture that will be stopped.

  \return SCAP_SUCCESS if the call is successful.
   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain
   the cause of the error.
*/
int32_t scap_stop_capture(scap_t* handle);

/*!
  \brief Start capture the events, if it was stopped with \ref scap_stop_capture.

  \param handle Handle to the capture that will be started.

  \return SCAP_SUCCESS if the call is successful.
   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain
   the cause of the error.
*/
int32_t scap_start_capture(scap_t* handle);

/*!
  \brief Return the list of the the user interfaces of the machine from which the
  events are being captured.

  \param handle Handle to the capture instance.

  \return The pointer to a \ref scap_addrlist structure containing the interface list,
  or NULL if the function fails.
*/
scap_addrlist* scap_get_ifaddr_list(scap_t* handle);

/*!
  \brief Return the machine user and group lists

  \param handle Handle to the capture instance.

  \return The pointer to a \ref scap_userlist structure containing the user and
  group lists, or NULL if the function fails.
*/
scap_userlist* scap_get_user_list(scap_t* handle);

/*!
  \brief Retrieve the table with the description of every event type that
  the capture driver supports.

  \return The pointer to a table of \ref scap_userlist entries, each of which describes
  one of the events that can come from the driver. The table contains PPM_EVENT_MAX entries,
  and the position of each entry in the table corresponds to its event ID.
  The ppm_event_info contains the full information necessary to decode an event coming from
  \ref scap_next.
*/
const struct ppm_event_info* scap_get_event_info_table();

/*!
  \brief Retrieve the table with the description of system call that
  the capture driver supports.

  \return The pointer to a table of \ref ppm_syscall_desc entries, each of which describes
  one of the events that can come from the driver. The table contains SYSCALL_TABLE_SIZE entries,
  and the position of each entry in the table corresponds to the system call ID.

  This table can be used to interpret the ID parameter of PPME_GENERIC_E and PPME_GENERIC_X.
*/
const struct ppm_syscall_desc* scap_get_syscall_info_table();

/*!
  \brief Get generic machine information

  \return The pointer to a \ref scap_machine_info structure containing the information.

  \note for live captures, the information is collected from the operating system. For
  offline captures, it comes from the capture file.
*/
const scap_machine_info* scap_get_machine_info(scap_t* handle);

/*!
  \brief Set the capture snaplen, i.e. the maximum size an event parameter can
  reach before the driver starts truncating it.

  \param handle Handle to the capture instance.
  \param snaplen the snaplen for this capture instance, in bytes.

  \note This function can only be called for live captures.
  \note By default, the driver captures the first 80 bytes of the buffers coming from
  events like read, write, send, recv, etc.
  If you're not interested in payloads, smaller values will save capture buffer space and
  make capture files smaller.
  Conversely, big values should be used with care because they can easily generate huge
  capture files.
*/
int32_t scap_set_snaplen(scap_t* handle, uint32_t snaplen);

/*!
  \brief Clear the event mask: no events will be passed to sysdig

  \param handle Handle to the capture instance.

  \note This function can only be called for live captures.
*/
int32_t scap_clear_eventmask(scap_t* handle);

/*!
  \brief Set the event into the eventmask so that
  sysdig-based apps can receive the event. Useful for offloading
  operations such as evt.type=open

  \param handle Handle to the capture instance.
  \param event id (example PPME_SOCKET_BIND_X)
  \note This function can only be called for live captures.
*/
int32_t scap_set_eventmask(scap_t* handle, uint32_t event_id);


/*!
  \brief Unset the event into the eventmask so that
  sysdig-based apps can no longer receive the event. It is
  the opposite of scap_set_eventmask

  \param handle Handle to the capture instance.
  \param event id (example PPME_SOCKET_BIND_X)
  \note This function can only be called for live captures.
*/
int32_t scap_unset_eventmask(scap_t* handle, uint32_t event_id);


/*!
  \brief Get the root directory of the system. This usually changes
  if sysdig runs in a container, so that all the information for the
  host can be correctly extracted.
*/
const char* scap_get_host_root();

/*!
  \brief Get the process list.
*/
struct ppm_proclist_info* scap_get_threadlist(scap_t* handle);

const char *scap_get_bpf_probe_from_env();

bool scap_get_bpf_enabled(scap_t* handle);

/*!
  \brief stop returning events for all subsequently spawned
  processes with the provided comm, as well as their children.
  This includes fork()/clone()ed processes that might later
  exec to a different comm.

  returns SCAP_FAILURE if there are already MAX_SUPPRESSED_COMMS comm
  values, SCAP_SUCCESS otherwise.
*/

int32_t scap_suppress_events_comm(scap_t* handle, const char *comm);

/*!
  \brief return whether the provided tid is currently being suppressed.
*/

bool scap_check_suppressed_tid(scap_t *handle, int64_t tid);

/*@}*/

///////////////////////////////////////////////////////////////////////////////
// Non public functions
///////////////////////////////////////////////////////////////////////////////

//
// Return the number of event capture devices that the library is handling. Each processor
// has its own event capture device.
//
uint32_t scap_get_ndevs(scap_t* handle);

// Retrieve a buffer of events from one of the cpus
extern int32_t scap_readbuf(scap_t* handle, uint32_t cpuid, OUT char** buf, OUT uint32_t* len);

#ifdef PPM_ENABLE_SENTINEL
// Get the sentinel at the beginning of the event
uint32_t scap_event_get_sentinel_begin(scap_evt* e);
#endif

// Get the information about a process.
// The returned pointer must be freed via scap_proc_free by the caller.
struct scap_threadinfo* scap_proc_get(scap_t* handle, int64_t tid, bool scan_sockets);

// Check if the given thread exists in ;proc
bool scap_is_thread_alive(scap_t* handle, int64_t pid, int64_t tid, const char* comm);

// like getpid() but returns the global PID even inside a container
int32_t scap_getpid_global(scap_t* handle, int64_t* pid);

struct scap_threadinfo *scap_proc_alloc(scap_t* handle);
void scap_proc_free(scap_t* handle, struct scap_threadinfo* procinfo);
void scap_dev_delete(scap_t* handle, scap_mountinfo* dev);
int32_t scap_stop_dropping_mode(scap_t* handle);
int32_t scap_start_dropping_mode(scap_t* handle, uint32_t sampling_ratio);
int32_t scap_enable_dynamic_snaplen(scap_t* handle);
int32_t scap_disable_dynamic_snaplen(scap_t* handle);
void scap_proc_free_table(scap_t* handle);
void scap_free_device_table(scap_t* handle);
void scap_refresh_iflist(scap_t* handle);
void scap_refresh_proc_table(scap_t* handle);
void scap_set_refresh_proc_table_when_saving(scap_t* handle, bool refresh);
uint64_t scap_ftell(scap_t *handle);
void scap_fseek(scap_t *handle, uint64_t off);
int32_t scap_enable_tracers_capture(scap_t* handle);
int32_t scap_enable_page_faults(scap_t *handle);
uint64_t scap_get_unexpected_block_readsize(scap_t* handle);
int32_t scap_proc_add(scap_t* handle, uint64_t tid, scap_threadinfo* tinfo);
int32_t scap_fd_add(scap_t *handle, scap_threadinfo* tinfo, uint64_t fd, scap_fdinfo* fdinfo);
scap_dumper_t *scap_memory_dump_open(scap_t *handle, uint8_t* targetbuf, uint64_t targetbufsize);
int32_t compr(uint8_t* dest, uint64_t* destlen, const uint8_t* source, uint64_t sourcelen, int level);
uint8_t* scap_get_memorydumper_curpos(scap_dumper_t *d);
int32_t scap_write_proc_fds(scap_t *handle, struct scap_threadinfo *tinfo, scap_dumper_t *d);
int32_t scap_write_proclist_header(scap_t *handle, scap_dumper_t *d, uint32_t totlen);
int32_t scap_write_proclist_trailer(scap_t *handle, scap_dumper_t *d, uint32_t totlen);
int32_t scap_write_proclist_entry(scap_t *handle, scap_dumper_t *d, struct scap_threadinfo *tinfo, uint32_t len);
// Variant of scap_write_proclist_entry where array-backed information
// about the thread is provided separate from the scap_threadinfo
// struct.
int32_t scap_write_proclist_entry_bufs(scap_t *handle, scap_dumper_t *d, struct scap_threadinfo *tinfo, uint32_t len,
				       const char *comm,
				       const char *exe,
				       const char *exepath,
				       const struct iovec *args, int argscnt,
				       const struct iovec *envs, int envscnt,
				       const char *cwd,
				       const struct iovec *cgroups, int cgroupscnt,
				       const char *root);

// Turn on processing only a subset syscalls. This is only appliable when scap
// is in LIVE mode.
int32_t scap_enable_simpledriver_mode(scap_t* handle);
int32_t scap_get_n_tracepoint_hit(scap_t* handle, long* ret);
#ifdef CYGWING_AGENT
typedef struct wh_t wh_t;
wh_t* scap_get_wmi_handle(scap_t* handle);
#endif
int32_t scap_set_fullcapture_port_range(scap_t* handle, uint16_t range_start, uint16_t range_end);

/**
 * By default we have an expanded snaplen for the default statsd port. If the
 * statsd port is non-standard, communicate that port value to the kernel to
 * get the expanded snaplen for the correct port.
 */
int32_t scap_set_statsd_port(scap_t* handle, uint16_t port);

#ifdef __cplusplus
}
#endif
