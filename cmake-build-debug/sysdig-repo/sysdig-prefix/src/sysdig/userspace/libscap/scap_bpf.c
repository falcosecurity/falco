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
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <gelf.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <dirent.h>

#include "scap.h"
#include "scap-int.h"
#include "scap_bpf.h"
#include "driver_config.h"
#include "../../driver/bpf/types.h"
#include "compat/misc.h"
#include "compat/bpf.h"

//
// Some of this code is taken from the kernel samples under samples/bpf,
// namely the parsing of the ELF objects, which is very tedious and not
// worth reinventing from scratch. The code has been readapted and simplified
// to tailor the sysdig use case. In the future, sysdig can fully switch to
// libbpf, but at the moment is not very worth the effort considering the
// subset of features needed.
//

struct bpf_map_data {
	int fd;
	size_t elf_offset;
	struct bpf_map_def def;
};

static const int BUF_SIZE_PAGES = 2048;

static const int BPF_LOG_SIZE = 1 << 18;

#define FILLER_NAME_FN(x) #x,
static const char *g_filler_names[PPM_FILLER_MAX] = {
	FILLER_LIST_MAPPER(FILLER_NAME_FN)
};
#undef FILLER_NAME_FN

static int32_t lookup_filler_id(const char *filler_name)
{
	int j;

	for(j = 0; j < sizeof(g_filler_names) / sizeof(g_filler_names[0]); ++j)
	{
		if(strcmp(filler_name, g_filler_names[j]) == 0)
		{
			return j;
		}
	}

	return -1;
}

static int bpf_map_update_elem(int fd, const void *key, const void *value, uint64_t flags)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));

	attr.map_fd = fd;
	attr.key = (unsigned long) key;
	attr.value = (unsigned long) value;
	attr.flags = flags;

	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));

	attr.map_fd = fd;
	attr.key = (unsigned long) key;
	attr.value = (unsigned long) value;

	return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static int bpf_map_create(enum bpf_map_type map_type,
			  int key_size, int value_size, int max_entries,
			  uint32_t map_flags)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));

	attr.map_type = map_type;
	attr.key_size = key_size;
	attr.value_size = value_size;
	attr.max_entries = max_entries;
	attr.map_flags = map_flags;

	return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int bpf_load_program(const struct bpf_insn *insns,
			    enum bpf_prog_type type,
			    size_t insns_cnt,
			    char *log_buf,
			    size_t log_buf_sz)
{
	union bpf_attr attr;
	int fd;

	bzero(&attr, sizeof(attr));

	attr.prog_type = type;
	attr.insn_cnt = (uint32_t) insns_cnt;
	attr.insns = (unsigned long) insns;
	attr.license = (unsigned long) "GPL";
	attr.log_buf = (unsigned long) NULL;
	attr.log_size = 0;
	attr.log_level = 0;

	fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
	if(fd >= 0 || !log_buf || !log_buf_sz)
	{
		return fd;
	}

	attr.log_buf = (unsigned long) log_buf;
	attr.log_size = log_buf_sz;
	attr.log_level = 1;
	log_buf[0] = 0;

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int bpf_raw_tracepoint_open(const char *name, int prog_fd)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));
	attr.raw_tracepoint.name = (unsigned long) name;
	attr.raw_tracepoint.prog_fd = prog_fd;

	return sys_bpf(BPF_RAW_TRACEPOINT_OPEN, &attr, sizeof(attr));
}

static int32_t get_elf_section(Elf *elf, int i, GElf_Ehdr *ehdr, char **shname, GElf_Shdr *shdr, Elf_Data **data)
{
	Elf_Scn *scn = elf_getscn(elf, i);
	if(!scn)
	{
		return SCAP_FAILURE;
	}

	if(gelf_getshdr(scn, shdr) != shdr)
	{
		return SCAP_FAILURE;
	}

	*shname = elf_strptr(elf, ehdr->e_shstrndx, shdr->sh_name);
	if(!*shname || !shdr->sh_size)
	{
		return SCAP_FAILURE;
	}

	*data = elf_getdata(scn, 0);
	if(!*data || elf_getdata(scn, *data) != NULL)
	{
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

static int cmp_symbols(const void *l, const void *r)
{
	const GElf_Sym *lsym = (const GElf_Sym *)l;
	const GElf_Sym *rsym = (const GElf_Sym *)r;

	if(lsym->st_value < rsym->st_value)
	{
		return -1;
	}
	else if(lsym->st_value > rsym->st_value)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

static int32_t load_elf_maps_section(scap_t *handle, struct bpf_map_data *maps,
				     int maps_shndx, Elf *elf, Elf_Data *symbols,
				     int strtabidx, int *nr_maps)
{
	Elf_Data *data_maps;
	GElf_Sym *sym;
	Elf_Scn *scn;
	int i;

	scn = elf_getscn(elf, maps_shndx);
	if(scn)
	{
		data_maps = elf_getdata(scn, NULL);
	}

	if(!scn || !data_maps)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Failed to get Elf_Data from maps section %d", maps_shndx);
		return SCAP_FAILURE;
	}

	*nr_maps = 0;
	sym = calloc(BPF_MAPS_MAX + 1, sizeof(GElf_Sym));
	for(i = 0; i < symbols->d_size / sizeof(GElf_Sym); i++)
	{
		ASSERT(*nr_maps < BPF_MAPS_MAX + 1);
		if(!gelf_getsym(symbols, i, &sym[*nr_maps]))
		{
			continue;
		}

		if(sym[*nr_maps].st_shndx != maps_shndx)
		{
			continue;
		}

		(*nr_maps)++;
	}

	qsort(sym, *nr_maps, sizeof(GElf_Sym), cmp_symbols);

	ASSERT(data_maps->d_size / *nr_maps == sizeof(struct bpf_map_def));

	for(i = 0; i < *nr_maps; i++)
	{
		struct bpf_map_def *def;
		size_t offset;

		offset = sym[i].st_value;
		def = (struct bpf_map_def *)(data_maps->d_buf + offset);
		maps[i].elf_offset = offset;
		memcpy(&maps[i].def, def, sizeof(struct bpf_map_def));
	}

	free(sym);
	return SCAP_SUCCESS;
}

static int32_t load_maps(scap_t *handle, struct bpf_map_data *maps, int nr_maps)
{
	int j;

	for(j = 0; j < nr_maps; ++j)
	{
		if(j == SYSDIG_PERF_MAP ||
		   j == SYSDIG_LOCAL_STATE_MAP ||
		   j == SYSDIG_FRAME_SCRATCH_MAP ||
		   j == SYSDIG_TMP_SCRATCH_MAP)
		{
			maps[j].def.max_entries = handle->m_ncpus;
		}

		handle->m_bpf_map_fds[j] = bpf_map_create(maps[j].def.type,
							  maps[j].def.key_size,
							  maps[j].def.value_size,
							  maps[j].def.max_entries,
							  maps[j].def.map_flags);

		maps[j].fd = handle->m_bpf_map_fds[j];

		if(handle->m_bpf_map_fds[j] < 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't create map: %s", scap_strerror(handle, errno));
			return SCAP_FAILURE;
		}

		if(maps[j].def.type == BPF_MAP_TYPE_PROG_ARRAY)
		{
			handle->m_bpf_prog_array_map_idx = j;
		}
	}

	return SCAP_SUCCESS;
}

static int32_t parse_relocations(scap_t *handle, Elf_Data *data, Elf_Data *symbols,
				 GElf_Shdr *shdr, struct bpf_insn *insn,
				 struct bpf_map_data *maps, int nr_maps)
{
	int nrels;
	int i;

	nrels = shdr->sh_size / shdr->sh_entsize;

	for(i = 0; i < nrels; i++)
	{
		GElf_Sym sym;
		GElf_Rel rel;
		unsigned int insn_idx;
		bool match = false;
		int map_idx;

		gelf_getrel(data, i, &rel);

		insn_idx = rel.r_offset / sizeof(struct bpf_insn);

		gelf_getsym(symbols, GELF_R_SYM(rel.r_info), &sym);

		if(insn[insn_idx].code != (BPF_LD | BPF_IMM | BPF_DW))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid relocation for insn[%d].code 0x%x", insn_idx, insn[insn_idx].code);
			return SCAP_FAILURE;
		}

		insn[insn_idx].src_reg = BPF_PSEUDO_MAP_FD;

		for(map_idx = 0; map_idx < nr_maps; map_idx++)
		{
			if(maps[map_idx].elf_offset == sym.st_value)
			{
				match = true;
				break;
			}
		}

		if(match)
		{
			insn[insn_idx].imm = maps[map_idx].fd;
		}
		else
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid relocation for insn[%d] no map_data match\n", insn_idx);
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
}

static int32_t load_tracepoint(scap_t* handle, const char *event, struct bpf_insn *prog, int size)
{
	struct perf_event_attr attr = {};
	enum bpf_prog_type program_type;
	size_t insns_cnt;
	char buf[256];
	bool raw_tp;
	int efd;
	int err;
	int fd;
	int id;

	insns_cnt = size / sizeof(struct bpf_insn);

	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;

	char *error = malloc(BPF_LOG_SIZE);
	if(!error)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "malloc(BPF_LOG_BUF_SIZE)");
		return SCAP_FAILURE;
	}

	if(memcmp(event, "raw_tracepoint/", sizeof("raw_tracepoint/") - 1) == 0)
	{
		raw_tp = true;
		program_type = BPF_PROG_TYPE_RAW_TRACEPOINT;
		event += sizeof("raw_tracepoint/") - 1;
	}
	else
	{
		raw_tp = false;
		program_type = BPF_PROG_TYPE_TRACEPOINT;
		event += sizeof("tracepoint/") - 1;
	}

	if(*event == 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "event name cannot be empty");
		return SCAP_FAILURE;
	}

	fd = bpf_load_program(prog, program_type, insns_cnt, error, BPF_LOG_SIZE);
	if(fd < 0)
	{
		fprintf(stderr, "%s", error);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "bpf_load_program() err=%d event=%s message=%s", errno, event, error);
		free(error);
		return SCAP_FAILURE;
	}

	free(error);

	handle->m_bpf_prog_fds[handle->m_bpf_prog_cnt++] = fd;

	if(memcmp(event, "filler/", sizeof("filler/") - 1) == 0)
	{
		int prog_id;

		event += sizeof("filler/") - 1;
		if(*event == 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "filler name cannot be empty");
			return SCAP_FAILURE;
		}

		prog_id = lookup_filler_id(event);
		if(prog_id == -1)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid filler name: %s", event);
			return SCAP_FAILURE;
		}

		err = bpf_map_update_elem(handle->m_bpf_map_fds[handle->m_bpf_prog_array_map_idx], &prog_id, &fd, BPF_ANY);
		if(err < 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "failure populating program array");
			return SCAP_FAILURE;
		}

		handle->m_bpf_fillers[prog_id] = true;

		return SCAP_SUCCESS;
	}

	if(raw_tp)
	{
		efd = bpf_raw_tracepoint_open(event, fd);
		if(efd < 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "BPF_RAW_TRACEPOINT_OPEN: event %s: %s", event, scap_strerror(handle, errno));
			return SCAP_FAILURE;
		}
	}
	else
	{
		strcpy(buf, "/sys/kernel/debug/tracing/events/");
		strcat(buf, event);
		strcat(buf, "/id");

		efd = open(buf, O_RDONLY, 0);
		if(efd < 0)
		{
			if(strcmp(event, "exceptions/page_fault_user") == 0 ||
			strcmp(event, "exceptions/page_fault_kernel") == 0)
			{
				return SCAP_SUCCESS;
			}

			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "failed to open event %s", event);
			return SCAP_FAILURE;
		}

		err = read(efd, buf, sizeof(buf));
		if(err < 0 || err >= sizeof(buf))
		{
			close(efd);
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "read from '%s' failed '%s'", event, scap_strerror(handle, errno));
			return SCAP_FAILURE;
		}

		close(efd);

		buf[err] = 0;
		id = atoi(buf);
		attr.config = id;

		efd = sys_perf_event_open(&attr, -1, 0, -1, 0);
		if(efd < 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "event %d fd %d err %s", id, efd, scap_strerror(handle, errno));
			return SCAP_FAILURE;
		}

		if(ioctl(efd, PERF_EVENT_IOC_SET_BPF, fd))
		{
			close(efd);
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "PERF_EVENT_IOC_SET_BPF: %s", scap_strerror(handle, errno));
			return SCAP_FAILURE;
		}
	}

	handle->m_bpf_event_fd[handle->m_bpf_prog_cnt - 1] = efd;

	return SCAP_SUCCESS;
}

static int32_t load_bpf_file(scap_t *handle, const char *path)
{
	int j;
	int maps_shndx = 0;
	int strtabidx = 0;
	GElf_Shdr shdr;
	GElf_Shdr shdr_prog;
	Elf_Data *data;
	Elf_Data *data_prog;
	Elf_Data *symbols = NULL;
	char *shname;
	char *shname_prog;
	int nr_maps = 0;
	struct bpf_map_data maps[BPF_MAPS_MAX];
	struct utsname osname;
	int32_t res = SCAP_FAILURE;

	if(uname(&osname))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't call uname()");
		return SCAP_FAILURE;
	}

	if(elf_version(EV_CURRENT) == EV_NONE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid ELF version");
		return SCAP_FAILURE;
	}

	int program_fd = open(path, O_RDONLY, 0);
	if(program_fd < 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't open BPF probe '%s': %s", path, scap_strerror(handle, errno));
		return SCAP_FAILURE;
	}

	Elf *elf = elf_begin(program_fd, ELF_C_READ_MMAP_PRIVATE, NULL);
	if(!elf)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't read ELF format");
		goto cleanup;
	}

	GElf_Ehdr ehdr;
	if(gelf_getehdr(elf, &ehdr) != &ehdr)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't read ELF header");
		goto cleanup;
	}

	for(j = 0; j < ehdr.e_shnum; ++j)
	{
		if(get_elf_section(elf, j, &ehdr, &shname, &shdr, &data) != SCAP_SUCCESS)
		{
			continue;
		}

		if(strcmp(shname, "maps") == 0)
		{
			maps_shndx = j;
		}
		else if(shdr.sh_type == SHT_SYMTAB)
		{
			strtabidx = shdr.sh_link;
			symbols = data;
		}
		else if(strcmp(shname, "kernel_version") == 0) {
			if(strcmp(osname.release, data->d_buf))
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "BPF probe is compiled for %s, but running version is %s",
					 (char *) data->d_buf, osname.release);
				goto cleanup;
			}
		}
		else if(strcmp(shname, "probe_version") == 0) {
			if(strcmp(PROBE_VERSION, data->d_buf))
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "BPF probe version is %s, but running version is %s",
					 (char *) data->d_buf, PROBE_VERSION);
				goto cleanup;
			}
		}
	}

	if(!symbols)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "missing SHT_SYMTAB section");
		goto cleanup;
	}

	if(maps_shndx)
	{
		if(load_elf_maps_section(handle, maps, maps_shndx, elf, symbols, strtabidx, &nr_maps) != SCAP_SUCCESS)
		{
			goto cleanup;
		}

		if(load_maps(handle, maps, nr_maps) != SCAP_SUCCESS)
		{
			goto cleanup;
		}
	}

	for(j = 0; j < ehdr.e_shnum; ++j)
	{
		if(get_elf_section(elf, j, &ehdr, &shname, &shdr, &data) != SCAP_SUCCESS)
		{
			continue;
		}

		if(shdr.sh_type == SHT_REL)
		{
			struct bpf_insn *insns;

			if(get_elf_section(elf, shdr.sh_info, &ehdr, &shname_prog, &shdr_prog, &data_prog) != SCAP_SUCCESS)
			{
				continue;
			}

			insns = (struct bpf_insn *) data_prog->d_buf;

			if(parse_relocations(handle, data, symbols, &shdr, insns, maps, nr_maps))
			{
				continue;
			}
		}
	}

	for(j = 0; j < ehdr.e_shnum; ++j)
	{
		if(get_elf_section(elf, j, &ehdr, &shname, &shdr, &data) != SCAP_SUCCESS)
		{
			continue;
		}

		if(memcmp(shname, "tracepoint/", sizeof("tracepoint/") - 1) == 0 ||
		   memcmp(shname, "raw_tracepoint/", sizeof("raw_tracepoint/") - 1) == 0)
		{
			if(load_tracepoint(handle, shname, data->d_buf, data->d_size) != SCAP_SUCCESS)
			{
				goto cleanup;
			}
		}
	}

	res = SCAP_SUCCESS;
cleanup:
	elf_end(elf);
	close(program_fd);
	return res;
}

static void *perf_event_mmap(scap_t *handle, int fd)
{
	int page_size = getpagesize();
	int ring_size = page_size * BUF_SIZE_PAGES;
	int header_size = page_size;
	int total_size = ring_size * 2 + header_size;

	//
	// All this playing with MAP_FIXED might be very very wrong, revisit
	//

	void *tmp = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if(tmp == MAP_FAILED)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "mmap (1): %s", scap_strerror(handle, errno));
		return MAP_FAILED;
	}

	// Map the second copy to allow us to handle the wrap case normally
	void *p1 = mmap(tmp + ring_size, ring_size + header_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
	if(p1 == MAP_FAILED)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "mmap (2): %s", scap_strerror(handle, errno));
		munmap(tmp, total_size);
		return MAP_FAILED;
	}

	ASSERT(p1 == tmp + ring_size);

	// Map the main copy
	void *p2 = mmap(tmp, ring_size + header_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
	if(p2 == MAP_FAILED)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "mmap (3): %s", scap_strerror(handle, errno));
		munmap(tmp, total_size);
		return MAP_FAILED;
	}

	ASSERT(p2 == tmp);

	return tmp;
}

static int32_t populate_syscall_routing_table_map(scap_t *handle)
{
	int j;

	for(j = 0; j < SYSCALL_TABLE_SIZE; ++j)
	{
		long code = g_syscall_code_routing_table[j];
		if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SYSCALL_CODE_ROUTING_TABLE], &j, &code, BPF_ANY) != 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SYSCALL_CODE_ROUTING_TABLE bpf_map_update_elem < 0");
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
}

static int32_t populate_syscall_table_map(scap_t *handle)
{
	int j;

	for(j = 0; j < SYSCALL_TABLE_SIZE; ++j)
	{
		const struct syscall_evt_pair *p = &g_syscall_table[j];
		if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SYSCALL_TABLE], &j, p, BPF_ANY) != 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SYSCALL_TABLE bpf_map_update_elem < 0");
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
}

static int32_t populate_event_table_map(scap_t *handle)
{
	int j;

	for(j = 0; j < PPM_EVENT_MAX; ++j)
	{
		const struct ppm_event_info *e = &g_event_info[j];
		if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_EVENT_INFO_TABLE], &j, e, BPF_ANY) != 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_EVENT_INFO_TABLE bpf_map_update_elem < 0");
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
}

static int32_t populate_fillers_table_map(scap_t *handle)
{
	int j;

	for(j = 0; j < PPM_EVENT_MAX; ++j)
	{
		const struct ppm_event_entry *e = &g_ppm_events[j];
		if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_FILLERS_TABLE], &j, e, BPF_ANY) != 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_FILLERS_TABLE bpf_map_update_elem < 0");
			return SCAP_FAILURE;
		}
	}

	for(j = 0; j < PPM_FILLER_MAX; ++j)
	{
		if(!handle->m_bpf_fillers[j])
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Missing filler %d (%s)\n", j, g_filler_names[j]);
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
}

//
// This is needed to make sure that the driver can properly
// lookup sockets. We generate a fake socket system call
// at the beginning so the calibration will surely take place.
// For more info, read the corresponding filler in kernel space.
//
static int32_t calibrate_socket_file_ops()
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd == -1)
	{
		return SCAP_FAILURE;
	}

	close(fd);
	return SCAP_SUCCESS;
}

int32_t scap_bpf_start_capture(scap_t *handle)
{
	struct sysdig_bpf_settings settings;
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.capture_enabled = true;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	if(calibrate_socket_file_ops() != SCAP_SUCCESS)
	{
		ASSERT(false);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "calibrate_socket_file_ops");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_stop_capture(scap_t *handle)
{
	struct sysdig_bpf_settings settings;
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.capture_enabled = false;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_set_snaplen(scap_t* handle, uint32_t snaplen)
{
	struct sysdig_bpf_settings settings;
	int k = 0;

	if(snaplen > RW_MAX_SNAPLEN)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "snaplen can't exceed %d\n", RW_MAX_SNAPLEN);
		return SCAP_FAILURE;
	}

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.snaplen = snaplen;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_set_fullcapture_port_range(scap_t* handle, uint16_t range_start, uint16_t range_end)
{
	struct sysdig_bpf_settings settings;
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.fullcapture_port_range_start = range_start;
	settings.fullcapture_port_range_end = range_end;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_set_statsd_port(scap_t* const handle, const uint16_t port)
{
	struct sysdig_bpf_settings settings = {};
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.statsd_port = port;

	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_disable_dynamic_snaplen(scap_t* handle)
{
	struct sysdig_bpf_settings settings;
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.do_dynamic_snaplen = false;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_start_dropping_mode(scap_t* handle, uint32_t sampling_ratio)
{
	switch(sampling_ratio)
	{
		case 1:
		case 2:
		case 4:
		case 8:
		case 16:
		case 32:
		case 64:
		case 128:
			break;
		default:
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid sampling ratio size");
			return SCAP_FAILURE;
	}

	struct sysdig_bpf_settings settings;
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.sampling_ratio = sampling_ratio;
	settings.dropping_mode = true;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_stop_dropping_mode(scap_t* handle)
{
	struct sysdig_bpf_settings settings;
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.sampling_ratio = 1;
	settings.dropping_mode = false;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_enable_dynamic_snaplen(scap_t* handle)
{
	struct sysdig_bpf_settings settings;
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.do_dynamic_snaplen = true;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_enable_page_faults(scap_t* handle)
{
	struct sysdig_bpf_settings settings;
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.page_faults = true;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_enable_tracers_capture(scap_t* handle)
{
	struct sysdig_bpf_settings settings;
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.tracers_enabled = true;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_close(scap_t *handle)
{
	int j;

	int page_size = getpagesize();
	int ring_size = page_size * BUF_SIZE_PAGES;
	int header_size = page_size;
	int total_size = ring_size * 2 + header_size;

	for(j = 0; j < handle->m_ndevs; j++)
	{
		if(handle->m_devs[j].m_buffer != MAP_FAILED)
		{
#ifdef _DEBUG
			int ret;
			ret = munmap(handle->m_devs[j].m_buffer, total_size);
#else
			munmap(handle->m_devs[j].m_buffer, total_size);
#endif
			ASSERT(ret == 0);
		}

		if(handle->m_devs[j].m_fd > 0)
		{
			close(handle->m_devs[j].m_fd);
		}
	}

	for(j = 0; j < sizeof(handle->m_bpf_event_fd) / sizeof(handle->m_bpf_event_fd[0]); ++j)
	{
		if(handle->m_bpf_event_fd[j] > 0)
		{
			close(handle->m_bpf_event_fd[j]);
			handle->m_bpf_event_fd[j] = 0;
		}
	}

	for(j = 0; j < sizeof(handle->m_bpf_prog_fds) / sizeof(handle->m_bpf_prog_fds[0]); ++j)
	{
		if(handle->m_bpf_prog_fds[j] > 0)
		{
			close(handle->m_bpf_prog_fds[j]);
			handle->m_bpf_prog_fds[j] = 0;
		}
	}

	for(j = 0; j < sizeof(handle->m_bpf_map_fds) / sizeof(handle->m_bpf_map_fds[0]); ++j)
	{
		if(handle->m_bpf_map_fds[j] > 0)
		{
			close(handle->m_bpf_map_fds[j]);
			handle->m_bpf_map_fds[j] = 0;
		}
	}

	handle->m_bpf_prog_cnt = 0;
	handle->m_bpf_prog_array_map_idx = -1;

	return SCAP_SUCCESS;
}

//
// This is completely horrible, revisit this shameful code
// with a proper solution
//
static int32_t set_boot_time(scap_t *handle, uint64_t *boot_time)
{
	struct timespec ts_uptime;
	struct timeval tv_now;
	uint64_t now;
	uint64_t uptime;

	if(gettimeofday(&tv_now, NULL))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "gettimeofday");
		return SCAP_FAILURE;
	}

	now = tv_now.tv_sec * (uint64_t) 1000000000 + tv_now.tv_usec * 1000;

	if(clock_gettime(CLOCK_BOOTTIME, &ts_uptime))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "clock_gettime");
		return SCAP_FAILURE;
	}

	uptime = ts_uptime.tv_sec * (uint64_t) 1000000000 + ts_uptime.tv_nsec;

	*boot_time = now - uptime;

	return SCAP_SUCCESS;
}

static int32_t set_runtime_params(scap_t *handle)
{
	struct rlimit rl;
	rl.rlim_max = RLIM_INFINITY;
	rl.rlim_cur = rl.rlim_max;
	if(setrlimit(RLIMIT_MEMLOCK, &rl))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "setrlimit failed");
		return SCAP_FAILURE;
	}

	FILE *f = fopen("/proc/sys/net/core/bpf_jit_enable", "w");
	if(!f)
	{
		// snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Can't open /proc/sys/net/core/bpf_jit_enable");
		// return SCAP_FAILURE;

		// Not every kernel has BPF_JIT enabled. Fix this after COS changes.
		return SCAP_SUCCESS;
	}

	if(fprintf(f, "1") != 1)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Can't write to /proc/sys/net/core/bpf_jit_enable");
		fclose(f);
		return SCAP_FAILURE;
	}

	fclose(f);

	f = fopen("/proc/sys/net/core/bpf_jit_harden", "w");
	if(!f)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Can't open /proc/sys/net/core/bpf_jit_harden");
		return SCAP_FAILURE;
	}

	if(fprintf(f, "0") != 1)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Can't write to /proc/sys/net/core/bpf_jit_harden");
		fclose(f);
		return SCAP_FAILURE;
	}

	fclose(f);

	f = fopen("/proc/sys/net/core/bpf_jit_kallsyms", "w");
	if(!f)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Can't open /proc/sys/net/core/bpf_jit_kallsyms");
		return SCAP_FAILURE;
	}

	if(fprintf(f, "1") != 1)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Can't write to /proc/sys/net/core/bpf_jit_kallsyms");
		fclose(f);
		return SCAP_FAILURE;
	}

	fclose(f);

	return SCAP_SUCCESS;
}

static int32_t set_default_settings(scap_t *handle)
{
	struct sysdig_bpf_settings settings;

	if(set_boot_time(handle, &settings.boot_time) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	settings.socket_file_ops = NULL;
	settings.snaplen = RW_SNAPLEN;
	settings.sampling_ratio = 1;
	settings.capture_enabled = false;
	settings.do_dynamic_snaplen = false;
	settings.page_faults = false;
	settings.dropping_mode = false;
	settings.is_dropping = false;
	settings.tracers_enabled = false;
	settings.fullcapture_port_range_start = 0;
	settings.fullcapture_port_range_end = 0;
	settings.statsd_port = 8125;

	int k = 0;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_load(scap_t *handle, const char *bpf_probe)
{
	int online_cpu;
	int j;

	if(set_runtime_params(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	handle->m_bpf_prog_array_map_idx = -1;

	if(!bpf_probe)
	{
		ASSERT(false);
		return SCAP_FAILURE;
	}

	if(load_bpf_file(handle, bpf_probe) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	if(populate_syscall_routing_table_map(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	if(populate_syscall_table_map(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	if(populate_event_table_map(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	if(populate_fillers_table_map(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	//
	// Open and initialize all the devices
	//
	online_cpu = 0;
	for(j = 0; j < handle->m_ncpus; ++j)
	{
		struct perf_event_attr attr = {
			.sample_type = PERF_SAMPLE_RAW,
			.type = PERF_TYPE_SOFTWARE,
			.config = PERF_COUNT_SW_BPF_OUTPUT,
		};
		int pmu_fd;

		if(j > 0)
		{
			char filename[SCAP_MAX_PATH_SIZE];
			int online;
			FILE *fp;

			snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/online", j);

			fp = fopen(filename, "r");
			if(fp == NULL)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't open %s: %s", filename, scap_strerror(handle, errno));
				return SCAP_FAILURE;
			}

			if(fscanf(fp, "%d", &online) != 1)
			{
				fclose(fp);

				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't read %s: %s", filename, scap_strerror(handle, errno));
				return SCAP_FAILURE;
			}

			fclose(fp);

			if(!online)
			{
				continue;
			}
		}

		if(online_cpu >= handle->m_ndevs)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "processors online: %d, expected: %d", online_cpu, handle->m_ndevs);
			return SCAP_FAILURE;
		}

		pmu_fd = sys_perf_event_open(&attr, -1, j, -1, 0);
		if(pmu_fd < 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "pmu_fd < 0: %s", scap_strerror(handle, errno));
			return SCAP_FAILURE;
		}

		handle->m_devs[online_cpu].m_fd = pmu_fd;

		if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_PERF_MAP], &j, &pmu_fd, BPF_ANY) != 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_PERF_MAP bpf_map_update_elem < 0: %s", scap_strerror(handle, errno));
			return SCAP_FAILURE;
		}

		if(ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "PERF_EVENT_IOC_ENABLE");
			return SCAP_FAILURE;
		}

		//
		// Map the ring buffer
		//
		handle->m_devs[online_cpu].m_buffer = perf_event_mmap(handle, pmu_fd);
		if(handle->m_devs[online_cpu].m_buffer == MAP_FAILED)
		{
			return SCAP_FAILURE;
		}

		++online_cpu;
	}

	if(online_cpu != handle->m_ndevs)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "processors online: %d, expected: %d", j, handle->m_ndevs);
		return SCAP_FAILURE;
	}

	if(set_default_settings(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

struct ppm_proclist_info *scap_bpf_get_threadlist(scap_t *handle)
{
	DIR *dir_p = NULL;
	DIR *taskdir_p = NULL;
	FILE *fp = NULL;
	struct ppm_proclist_info *res = NULL;
	struct dirent *dir_entry_p;
	char procdirname[SCAP_MAX_PATH_SIZE];

	handle->m_driver_procinfo->n_entries = 0;

	snprintf(procdirname, sizeof(procdirname), "%s/proc", scap_get_host_root());

	dir_p = opendir(procdirname);
	if(dir_p == NULL)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error opening the %s directory", procdirname);
		goto error;
	}

	while((dir_entry_p = readdir(dir_p)) != NULL)
	{
		char tasksdirname[SCAP_MAX_PATH_SIZE];
		struct dirent *taskdir_entry_p;
		DIR *taskdir_p;

		if(strspn(dir_entry_p->d_name, "0123456789") != strlen(dir_entry_p->d_name))
		{
			continue;
		}

		snprintf(tasksdirname, sizeof(tasksdirname), "%s/%s/task", procdirname, dir_entry_p->d_name);

		taskdir_p = opendir(tasksdirname);
		if(taskdir_p == NULL)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "error opening the %s directory", tasksdirname);
			continue;
		}

		while((taskdir_entry_p = readdir(taskdir_p)) != NULL)
		{
			char filename[SCAP_MAX_PATH_SIZE];
			unsigned long utime;
			unsigned long stime;
			int tid;

			if(strspn(taskdir_entry_p->d_name, "0123456789") != strlen(taskdir_entry_p->d_name))
			{
				continue;
			}

			snprintf(filename, sizeof(filename), "%s/%s/stat", tasksdirname, taskdir_entry_p->d_name);

			fp = fopen(filename, "r");
			if(fp == NULL)
			{
				continue;
			}

			if(fscanf(fp, "%d %*[^)] %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %lu %lu", &tid, &utime, &stime) != 3)
			{
				fclose(fp);
				fp = NULL;
				continue;
			}

			if(handle->m_driver_procinfo->n_entries == handle->m_driver_procinfo->max_entries)
			{
				if(!scap_alloc_proclist_info(handle, handle->m_driver_procinfo->n_entries + 256))
				{
					goto error;
				}
			}

			handle->m_driver_procinfo->entries[handle->m_driver_procinfo->n_entries].pid = tid;
			handle->m_driver_procinfo->entries[handle->m_driver_procinfo->n_entries].utime = utime;
			handle->m_driver_procinfo->entries[handle->m_driver_procinfo->n_entries].stime = stime;
			++handle->m_driver_procinfo->n_entries;

			fclose(fp);
			fp = NULL;
		}

		closedir(taskdir_p);
		taskdir_p = NULL;
	}

	res = handle->m_driver_procinfo;
error:
	if(dir_p)
	{
		closedir(dir_p);
	}

	if(taskdir_p)
	{
		closedir(taskdir_p);
	}

	if(fp)
	{
		fclose(fp);
	}

	return res;
}

int32_t scap_bpf_get_stats(scap_t* handle, OUT scap_stats* stats)
{
	int j;

	for(j = 0; j < handle->m_ncpus; j++)
	{
		struct sysdig_bpf_per_cpu_state v;
		if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_LOCAL_STATE_MAP], &j, &v))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Error looking up local state %d\n", j);
			return SCAP_FAILURE;
		}

		stats->n_evts += v.n_evts;
		stats->n_drops_buffer += handle->m_devs[j].m_evt_lost + v.n_drops_buffer;
		stats->n_drops_pf += v.n_drops_pf;
		stats->n_drops_bug += v.n_drops_bug;
		stats->n_drops += handle->m_devs[j].m_evt_lost +
				  v.n_drops_buffer +
				  v.n_drops_pf +
				  v.n_drops_bug;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_get_n_tracepoint_hit(scap_t* handle, long* ret)
{
	int j;

	for(j = 0; j < handle->m_ncpus; j++)
	{
		struct sysdig_bpf_per_cpu_state v;
		if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_LOCAL_STATE_MAP], &j, &v))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Error looking up local state %d\n", j);
			return SCAP_FAILURE;
		}

		ret[j] = v.n_evts;
	}

	return SCAP_SUCCESS;
}
