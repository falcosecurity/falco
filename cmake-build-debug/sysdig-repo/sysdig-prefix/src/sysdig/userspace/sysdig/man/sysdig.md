NAME
----

sysdig - the definitive system and process troubleshooting tool

SYNOPSIS
--------

**sysdig** [*option*]... [*filter*]

DESCRIPTION
-----------

**Note: if you are interested in an easier to use interface for the sysdig functionality, use the csysdig command line utility.**

sysdig is a tool for system troubleshooting, analysis and exploration. It can be used to capture, filter and decode system calls and other OS events. 
sysdig can be both used to inspect live systems, or to generate trace files that can be analyzed at a later stage.

sysdig includes a powerul filtering language, has customizable output, and can be extended through Lua scripts, called chisels.

**Output format**

By default, sysdig prints the information for each captured event on a single line, with the following format:

```*%evt.num %evt.time %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type %evt.info```

where:
* evt.num is the incremental event number
* evt.time is the event timestamp
* evt.cpu is the CPU number where the event was captured
* proc.name is the name of the process that generated the event
* thread.tid id the TID that generated the event, which corresponds to the PID for single thread processes
* evt.dir is the event direction, > for enter events and < for exit events
* evt.type is the name of the event, e.g. 'open' or 'read'
* evt.args is the list of event arguments.

The output format can be customized with the -p switch, using any of the fields listed by 'sysdig -l'.

Using -pc or -pcontainer, the default format will be changed to a container-friendly one:

```*%evt.num %evt.time %evt.cpu %container.name (%container.id) %proc.name (%thread.tid:%thread.vtid) %evt.dir %evt.type %evt.info```

**Trace Files**  

A trace file can be created using the -w switch:
> $ sysdig -w trace.scap

The -s switch can be used to specify how many bytes of each data buffer should be saved to disk. And filters can be
used to save only certain events to disk: 
> $ sysdig -s 2000 -w trace.scap proc.name=cat

Trace files can be read this using the -r switch: 
> $ sysdig -r trace.scap

**Filtering**  

sysdig filters are specified at the end of the command line. The simplest filter is a basic field-value check:
> $ sysdig proc.name=cat

The list of available fields can be obtained with 'sysdig -l'.
Filter expressions can use one of these comparison operators: _=_, _!=_, _<_, _<=_, _>_, _>=_, _contains_, _icontains_, _in_ and _exists_. e.g.
> $ sysdig fd.name contains /etc
> $ sysdig "evt.type in ( 'select', 'poll' )"
> $ sysdig proc.name exists

Multiple checks can be combined through brackets and the following boolean operators: _and_, _or_, _not_. e.g.
> $ sysdig "not (fd.name contains /proc or fd.name contains /dev)"

**Chisels**  

sysdig's chisels are little scripts that analyze the sysdig event stream to perform useful actions.
To get the list of available chisels, type
> $ sysdig -cl  

To get details about a specific chisel, type
> $ sysdig -i spy_ip

To run one of the chisels, you use the -c flag, e.g.
> $ sysdig -c topfiles_bytes

If a chisel needs arguments, you specify them after the chisel name:
> $ sysdig -c spy_ip 192.168.1.157

If a chisel has more than one argument, specify them after the chisel name, enclosed in quotes:
> $ sysdig -c chisel_name "arg1 arg2 arg3"

Chisels can be combined with filters:
> $ sysdig -c topfiles_bytes "not fd.name contains /dev"

OPTIONS
-------

**-A**, **--print-ascii**
  Only print the text portion of data buffers, and echo end-of-lines. This is useful to only display human-readable data.

**-b**, **--print-base64**
  Print data buffers in base64. This is useful for encoding binary data that needs to be used over media designed to handle textual data (i.e., terminal or json).
    
**-c** _chiselname_ _chiselargs_, **--chisel**=_chiselname_ _chiselargs_
  run the specified chisel. If the chisel require arguments, they must be specified in the command line after the name.

**-C** _filesize_
  Break a capture into separate files, and limit the size of each file based on the specified number of megabytes. The units of _filesize_ are millions of bytes (10^6, not 2^20). Use in conjunction with **-W** to enable automatic file rotation. Otherwise, new files will continue to be created until the capture is manually stopped. 
  
  Files will have the name specified by **-w** with a counter added starting at 0.
  
**-cl**, **--list-chisels**
  lists the available chisels. Looks for chisels in ./chisels, ~/.chisels and /usr/share/sysdig/chisels.
  
**-d**, **--displayflt**
  Make the given filter a display one. Setting this option causes the events to be filtered after being parsed by the state system. Events are normally filtered before being analyzed, which is more efficient, but can cause state (e.g. FD names) to be lost.
  
**-D**, **--debug**
  Capture events about sysdig itself, display internal events in addition to system events, and print additional logging on standard error.

**-E**, **--exclude-users**
  Don't create the user/group tables by querying the OS when sysdig starts. This also means that no user or group info will be written to the tracefile by the **-w** flag. The user/group tables are necessary to use filter fields like user.name or group.name. However, creating them can increase sysdig's startup time. Moreover, they contain information that could be privacy sensitive.

**-e** _numevents_
  Break a capture into separate files, and limit the size of each file based on the specified number of events. Use in conjunction with **-W** to enable automatic file rotation. Otherwise, new files will continue to be created until the capture is manually stopped.
  
  Files will have the name specified by **-w** with a counter added starting at 0.

**-F**, **--fatfile**
  Enable fatfile mode. When writing in fatfile mode, the output file will contain events that will be invisible when reading the file, but that are necessary to fully reconstruct the state. Fatfile mode is useful when saving events to disk with an aggressive filter. The filter could drop events that would cause the state to be updated (e.g. clone() or open()). With fatfile mode, those events are still saved to file, but 'hidden' so that they won't appear when reading the file. Be aware that using this flag might generate substantially bigger traces files.

**--filter-proclist**
  apply the filter to the process table. A full dump of /proc is typically included in any trace file to make sure all the state required to decode events is in the file. This could cause the file to contain unwanted or sensitive information. Using this flag causes the command line filter to be applied to the /proc dump as well.

**-G** _numseconds_
  Break a capture into separate files, and limit the size of each file based on the specified number of seconds. Use in conjunction with **-W** to enable automatic file rotation. Otherwise, new files will continue to be created until the capture is manually stopped. 
  
  Files will have the name specified by **-w** which should include a time format as defined by strftime(3). If no time format is specified, a counter will be used.

**-h**, **--help**
  Print this page

**-i _chiselname_**, **--chisel-info=**_chiselname_
  Get a longer description and the arguments associated with a chisel found in the -cl option list.
  
**-j**, **--json**
  Emit output as json, data buffer encoding will depend from the print format selected.

**-k**, **--k8s-api**
  Enable Kubernetes support by connecting to the API server specified as argument. E.g. "http://admin:password@127.0.0.1:8080". The API server can also be specified via the environment variable SYSDIG_K8S_API.

**-K** _btfile | certfile:keyfile[#password][:cacertfile]_, **--k8s-api-cert=**_btfile | certfile:keyfile[#password][:cacertfile]_
  Use the provided files names to authenticate user and (optionally) verify the K8S API server identity. Each entry must specify full (absolute, or relative to the current directory) path to the respective file. Private key password is optional (needed only if key is password protected). CA certificate is optional. For all files, only PEM file format is supported. Specifying CA certificate only is obsoleted - when single entry is provided for this option, it will be interpreted as the name of a file containing bearer token. Note that the format of this command-line option prohibits use of files whose names contain ':' or '#' characters in the file name. Option can also be provided via the environment variable SYSDIG_K8S_API_CERT.

**-L**, **--list-events**
  List the events that the engine supports
  
**-l**, **--list**
  List the fields that can be used for filtering and output formatting. Use -lv to get additional information for each field.

**--list-markdown**
  Like -l, but produces markdown output

**-m** _url[,marathon-url]_, **--mesos-api=**_url[,marathon-url]_
  Enable Mesos support by connecting to the API server specified as argument (e.g. http://admin:password@127.0.0.1:5050). Mesos url is required. Marathon url is optional, defaulting to auto-follow - if Marathon API server is not provided, sysdig will attempt to retrieve (and subsequently follow, if it migrates) the location of Marathon API server from the Mesos master. Note that, with auto-follow, sysdig will likely receive a cluster internal IP address for Marathon API server, so running sysdig with Marathon auto-follow from a node that is not part of Mesos cluster may not work. Additionally, running sysdig with Mesos support on a node that has no containers managed by Mesos is of limited use because, although cluster metadata will be collected, there will be no Mesos/Marathon filtering capability. The API servers can also be specified via the environment variable SYSDIG_MESOS_API.

**-M** _num_seconds_
  Stop collecting after reaching <num_seconds>

**-n** _num_, **--numevents**=_num_  
  Stop capturing after _num_ events

**--page-faults**
  Capture user/kernel major/minor page faults

**-P**, **--progress**  
  Print progress on stderr while processing trace files.
  
**-p** _outputformat_, **--print**=_outputformat_  
  Specify the format to be used when printing the events. With -pc or -pcontainer will use a container-friendly format. With -pk or -pkubernetes will use a kubernetes-friendly format. With -pm or -pmesos will use a mesos-friendly format. Specifying **-pp** on the command line will cause sysdig to print the default command line format and exit.
  
**-q**, **--quiet**  
  Don't print events on the screen. Useful when dumping to disk.
  
**-r** _readfile_, **--read**=_readfile_  
  Read the events from _readfile_.

**-R**, **--resolve-ports**
  Resolve port numbers to names.

**-S**, **--summary**  
  print the event summary (i.e. the list of the top events) when the capture ends.
  
**-s** _len_, **--snaplen**=_len_  
  Capture the first _len_ bytes of each I/O buffer. By default, the first 80 bytes are captured. Use this option with caution, it can generate huge trace files.

**-t** _timetype_, **--timetype**=_timetype_  
  Change the way event time is displayed. Accepted values are **h** for human-readable string, **a** for absolute timestamp from epoch, **r** for relative time from the first displayed event, **d** for delta between event enter and exit, and **D** for delta from the previous event.

**-T**, **--force-tracers-capture**  
  Tell the driver to make sure full buffers are captured from /dev/null, to make sure that tracers are completely captured. Note that sysdig will enable extended /dev/null capture by itself after detecting that tracers are written there, but that could result in the truncation of some tracers at the beginning of the capture. This option allows preventing that.

**--unbuffered**  
  Turn off output buffering. This causes every single line emitted by sysdig to be flushed, which generates higher CPU usage but is useful when piping sysdig's output into another process or into a script. 
  
**-v**, **--verbose**  
  Verbose output. This flag will cause the full content of text and binary buffers to be printed on screen, instead of being truncated to 40 characters. Note that data buffers length is still limited by the snaplen (refer to the -s flag documentation) -v will also make sysdig print some summary information at the end of the capture.
  
**--version**  
  Print version number.
  
**-w** _writefile_, **--write**=_writefile_  
  Write the captured events to _writefile_.

**-W** _num_  
  Turn on file rotation for continuous capture, and limit the number of files created to the specified number. Once the cap is reached, older files will be overwritten (ring buffer). Use in conjunction with the **-C** / **-G** / **-e** options to limit the size of each file based on number of megabytes, seconds, and/or events (respectively).

**-x**, **--print-hex**  
  Print data buffers in hex.
  
**-X**, **--print-hex-ascii**  
  Print data buffers in hex and ASCII.

**-z**, **--compress**  
  Used with **-w**, enables compression for tracefiles.
  
EXAMPLES
--------

Capture all the events from the live system and print them to screen
> $ sysdig

Capture all the events from the live system and save them to disk
> $ sysdig -w dumpfile.scap

Capture all the events in the latest 24 hours and save them to disk organized in files containing 1 hour of system activity each
> $ sysdig -G 3600 -W 24 -w dumpfile.scap

Read events from a file and print them to screen
> $ sysdig -r dumpfile.scap

Prepare a sanitized version of a system capture
> $ sysdig -r dumpfile.scap 'not evt.buffer contains foo' -w cleandump.scap

Print all the open system calls invoked by cat
> $ sysdig proc.name=cat and evt.type=open

Print the name of the files opened by cat
> $ sysdig -p"%evt.arg.name" proc.name=cat and evt.type=open

List the available chisels
> $ sysdig -cl

Use the spy_ip chisel to look at the data exchanged with 192.168.1.157:
> $ sysdig -c spy_ip 192.168.1.157

FILES
-----

*/usr/share/sysdig/chisels*  
  The global chisels directory.

*~/.chisels*  
  The personal chisels directory.

BUGS
----

* sysdig and its chisels are designed to be used with LuaJIT in Lua 5.1 mode. While it is possible to use sysdig with LuaJIT in Lua 5.2 mode or regular Lua, some chisels may not work as expected.

AUTHOR
------

Draios Inc. aka sysdig <info@sysdigcloud.com>

SEE ALSO
--------

**csysdig**(8), **strace**(8), **tcpdump**(8), **lsof**(8)
