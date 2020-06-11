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

////////////////////////////////////////////////////////////////////////////
// Private definitions for the scap library
////////////////////////////////////////////////////////////////////////////

#include "settings.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CYGWING_AGENT
typedef struct wh_t wh_t;
#endif

#ifdef _WIN32
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif
#include <assert.h>
#ifdef USE_ZLIB
#include <zlib.h>
#else
#define	gzFile FILE*
#define gzflush(X, Y) fflush(X)
#define gzopen fopen
#define	gzdopen(fd, mode) stdout
#define gzclose fclose
#define gzoffset ftell
#define gzwrite(F, B, S) fwrite(B, 1, S, F)
#define gzread(F, B, S) fread(B, 1, S, F)
#define gzseek fseek
#endif

//
// Read buffer timeout constants
//
#define BUFFER_EMPTY_WAIT_TIME_US_START 500
#define BUFFER_EMPTY_WAIT_TIME_US_MAX (30 * 1000)
#define BUFFER_EMPTY_THRESHOLD_B 20000

//
// Process flags
//
#define PF_CLONING 1

//
// ebpf defs
//
#define BPF_PROGS_MAX 128
#define BPF_MAPS_MAX 32

//
// The device descriptor
//
typedef struct scap_device
{
	int m_fd;
	char* m_buffer;
	uint32_t m_lastreadsize;
	char* m_sn_next_event; // Pointer to the next event available for scap_next
	uint32_t m_sn_len; // Number of bytes available in the buffer pointed by m_sn_next_event
	union
	{
		// Anonymous struct with ppm stuff
		struct
		{
			struct ppm_ring_buffer_info* m_bufinfo;
		};
		// Anonymous struct with bpf stuff
		struct
		{
			uint64_t m_evt_lost;
		};
	};
}scap_device;


typedef struct scap_tid
{
	uint64_t tid;

	UT_hash_handle hh; ///< makes this structure hashable
} scap_tid;

//
// The open instance handle
//
struct scap
{
	scap_mode_t m_mode;
	scap_device* m_devs;
	uint32_t m_ndevs;
#ifdef USE_ZLIB
	gzFile m_file;
#else
	FILE* m_file;
#endif
	char* m_file_evt_buf;
	uint32_t m_last_evt_dump_flags;
	char m_lasterr[SCAP_LASTERR_SIZE];

	// Used for scap_strerror
	char m_strerror_buf[SCAP_LASTERR_SIZE];

	scap_threadinfo* m_proclist;
	scap_mountinfo* m_dev_list;
	scap_threadinfo m_fake_kernel_proc;
	uint64_t m_evtcnt;
	scap_addrlist* m_addrlist;
	scap_machine_info m_machine_info;
	scap_userlist* m_userlist;
	uint64_t m_buffer_empty_wait_time_us;
	proc_entry_callback m_proc_callback;
	void* m_proc_callback_context;
	struct ppm_proclist_info* m_driver_procinfo;
	bool refresh_proc_table_when_saving;
	uint32_t m_fd_lookup_limit;
	uint64_t m_unexpected_block_readsize;
	uint32_t m_ncpus;
	// Abstraction layer for windows
#ifdef CYGWING_AGENT
	wh_t* m_whh;
#endif
	bool m_bpf;
	// Anonymous struct with bpf stuff
	struct
	{
		int m_bpf_prog_fds[BPF_PROGS_MAX];
		int m_bpf_prog_cnt;
		bool m_bpf_fillers[BPF_PROGS_MAX];
		int m_bpf_event_fd[BPF_PROGS_MAX];
		int m_bpf_map_fds[BPF_MAPS_MAX];
		int m_bpf_prog_array_map_idx;
	};

	// The set of process names that are suppressed
	char **m_suppressed_comms;
	uint32_t m_num_suppressed_comms;

	// The active set of threads that are suppressed
	scap_tid *m_suppressed_tids;

	// The number of events that were skipped due to the comm
	// matching an entry in m_suppressed_comms.
	uint64_t m_num_suppressed_evts;
};

typedef enum ppm_dumper_type
{
	DT_FILE = 0,
	DT_MEM = 1,
}ppm_dumper_type;

struct scap_dumper
{
	gzFile m_f;
	ppm_dumper_type m_type;
	uint8_t* m_targetbuf;
	uint8_t* m_targetbufcurpos;
	uint8_t* m_targetbufend;
};

struct scap_ns_socket_list
{
	int64_t net_ns;
	scap_fdinfo* sockets;
	UT_hash_handle hh;
};

//
// Misc stuff
//
#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)
#define FILE_READ_BUF_SIZE 65536

//
// Internal library functions
//

// Read the full event buffer for the given processor
int32_t scap_readbuf(scap_t* handle, uint32_t proc, OUT char** buf, OUT uint32_t* len);
// Read a single thread info from /proc
int32_t scap_proc_read_thread(scap_t* handle, char* procdirname, uint64_t tid, struct scap_threadinfo** pi, char *error, bool scan_sockets);
// Scan a directory containing process information
int32_t scap_proc_scan_proc_dir(scap_t* handle, char* procdirname, char *error);
// Remove an entry from the process list by parsing a PPME_PROC_EXIT event
// void scap_proc_schedule_removal(scap_t* handle, scap_evt* e);
// Remove the process that was scheduled for deletion for this handle
// void scap_proc_remove_scheduled(scap_t* handle);
// Free the process table
void scap_proc_free_table(scap_t* handle);
// Copy the fd table of a process into the one of another process
// int32_t scap_proc_copy_fd_table(scap_t* handle, scap_threadinfo* dst, scap_threadinfo* src);
// Internal helper function to output the process table to screen
void scap_proc_print_info(scap_t *handle, scap_threadinfo* pi);
void scap_proc_print_table(scap_t* handle);
// Free all the state related to a process and delete it from the fd table
void scap_proc_delete(scap_t* handle, scap_threadinfo* proc);
// Internal helper function to output the fd table of a process
void scap_fd_print_table(scap_t *handle, scap_threadinfo* pi);
// Internal helper function to output an fd table
void scap_fd_print_fd_table(scap_t *handle, scap_fdinfo* fds);
// Given an event, get the info entry for the process that generated it.
// NOTE: this is different from scap_event_getprocinfo() because it returns the full event information
// struct scap_threadinfo* scap_proc_get_from_event(scap_t* handle, scap_evt* e);
// Return the process info entry given a tid
// Free an fd table and set it to NULL when done
void scap_fd_free_table(scap_t* handle, scap_fdinfo** fds);
void scap_fd_free_ns_sockets_list(scap_t* handle, struct scap_ns_socket_list** sockets);
// Free a process' fd table
void scap_fd_free_proc_fd_table(scap_t* handle, scap_threadinfo* pi);
// Convert an fd entry's info into a string
int32_t scap_fd_info_to_string(scap_t *handle, scap_fdinfo* fdi, OUT char* str, uint32_t strlen);
// Calculate the length on disk of an fd entry's info
uint32_t scap_fd_info_len(scap_fdinfo* fdi);
// Write the given fd info to disk
int32_t scap_fd_write_to_disk(scap_t* handle, scap_fdinfo* fdi, scap_dumper_t* dumper, uint32_t len);
// Populate the given fd by reading the info from disk
uint32_t scap_fd_read_from_disk(scap_t* handle, OUT scap_fdinfo* fdi, OUT size_t* nbytes, uint32_t block_type, gzFile f);
// Parse the headers of a trace file and load the tables
int32_t scap_read_init(scap_t* handle, gzFile f);
// Add the file descriptor info pointed by fdi to the fd table for process pi.
// Note: silently skips if fdi->type is SCAP_FD_UNKNOWN.
int32_t scap_add_fd_to_proc_table(scap_t* handle, scap_threadinfo* pi, scap_fdinfo* fdi, char *error);
// Remove the given fd from the process table of the process pointed by pi
void scap_fd_remove(scap_t* handle, scap_threadinfo* pi, int64_t fd);
// Read an event from disk
int32_t scap_next_offline(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid);
// read the file descriptors for a given process directory
int32_t scap_fd_scan_fd_dir(scap_t* handle, char * procdir, scap_threadinfo* pi, struct scap_ns_socket_list** sockets_by_ns, char *error);
// read tcp or udp sockets from the proc filesystem
int32_t scap_fd_read_ipv4_sockets_from_proc_fs(scap_t* handle, const char * dir, int l4proto, scap_fdinfo ** sockets);
// read all sockets and add them to the socket table hashed by their ino
int32_t scap_fd_read_sockets(scap_t* handle, char* procdir, struct scap_ns_socket_list* sockets, char *error);
// prints procs details for a give tid
void scap_proc_print_proc_by_tid(scap_t* handle, uint64_t tid);
// Allocate and return the list of interfaces on this system
int32_t scap_create_iflist(scap_t* handle);
// Free a previously allocated list of interfaces
void scap_free_iflist(scap_addrlist* ifhandle);
// Allocate and return the list of users on this system
int32_t scap_create_userlist(scap_t* handle);
// Free a previously allocated list of users
void scap_free_userlist(scap_userlist* uhandle);

int32_t scap_fd_post_process_unix_sockets(scap_t* handle, scap_fdinfo* sockets);

int32_t scap_proc_fill_cgroups(scap_t *handle, struct scap_threadinfo* tinfo, const char* procdirname);

bool scap_alloc_proclist_info(scap_t* handle, uint32_t n_entries);

// Determine whether or not the provided event should be suppressed,
// based on its event type and parameters. May update the set of
// suppressed tids as a side-effect.
//
// Returns SCAP_FAILURE if we tried to add the tid to the suppressed
// tid set, but it could *not* be added, SCAP_SUCCESS otherwise.
int32_t scap_check_suppressed(scap_t *handle, scap_evt *pevent,
			      bool *suppressed);

// Possibly add or remove the provided comm, tid combination to the
// set of suppressed processes. If the ptid is currently in the
// suppressed set, the tid will always be added to the suppressed
// set. Otherwise, the tid will be added if the comm matches an entry
// in suppressed_comms.
//
// Sets *suppressed to whether, after this check, the tid is suppressed.
//
// Returns SCAP_FAILURE if we tried to add the tid to the suppressed
// tid set, but it could *not* be added, SCAP_SUCCESS otherwise.
int32_t scap_update_suppressed(scap_t *handle,
			       const char *comm,
			       uint64_t tid, uint64_t ptid,
			       bool *suppressed);

// Wrapper around strerror using buffer in handle
const char *scap_strerror(scap_t *handle, int errnum);

//
// ASSERT implementation
//

#ifdef ASSERT
#undef ASSERT
#endif // ASSERT
#ifdef _DEBUG
#define ASSERT(X) assert(X)
#else // _DEBUG
#define ASSERT(X)
#endif // _DEBUG

#define CHECK_READ_SIZE(read_size, expected_size) if(read_size != expected_size) \
	{\
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "expecting %d bytes, read %d at %s, line %d. Is the file truncated?",\
			(int)expected_size,\
			(int)read_size,\
			__FILE__,\
			__LINE__);\
		return SCAP_FAILURE;\
	}

#define CHECK_READ_SIZE_WITH_FREE(alloc_buffer, read_size, expected_size) if(read_size != expected_size) \
    	{\
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "expecting %d bytes, read %d at %s, line %d. Is the file truncated?",\
			(int)expected_size,\
			(int)read_size,\
			__FILE__,\
			__LINE__);\
		free(alloc_buffer);\
		return SCAP_FAILURE;\
	}

//
// Useful stuff
//
#ifndef MIN
#define MIN(X,Y) ((X) < (Y)? (X):(Y))
#define MAX(X,Y) ((X) > (Y)? (X):(Y))
#endif

//
// Driver proc info table sizes
//
#define SCAP_DRIVER_PROCINFO_INITIAL_SIZE 7
#define SCAP_DRIVER_PROCINFO_MAX_SIZE 128000

extern const enum ppm_syscall_code g_syscall_code_routing_table[];
extern const struct syscall_evt_pair g_syscall_table[];
extern const struct ppm_event_info g_event_info[];
extern const struct ppm_syscall_desc g_syscall_info_table[];
extern const struct ppm_event_entry g_ppm_events[];
extern bool validate_info_table_size();

#ifdef __cplusplus
}
#endif
