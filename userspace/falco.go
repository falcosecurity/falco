package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/process"
	log "github.com/sirupsen/logrus"
)

// #include <linux/connector.h>
// #include <linux/cn_proc.h>
import "C"

type NetLinkSocket struct {
	fd  int
	lsa syscall.SockaddrNetlink
}

type NetlinkRequestData interface {
	Len() int
	ToWireFormat() []byte
}

type NetLinkRequest struct {
	syscall.NlMsghdr
	Data []NetlinkRequestData
}

func (rr *NetLinkRequest) ToWireFormat() []byte {
	native := binary.LittleEndian
	length := rr.Len
	dataBytes := make([][]byte, len(rr.Data))
	for i, data := range rr.Data {
		dataBytes[i] = data.ToWireFormat()
		length += uint32(len(dataBytes[i]))
	}
	b := make([]byte, length)
	native.PutUint32(b[0:4], length)
	native.PutUint16(b[4:6], rr.Type)
	native.PutUint16(b[6:8], rr.Flags)
	native.PutUint32(b[8:12], rr.Seq)
	native.PutUint32(b[12:16], rr.Pid)
	next := 16
	for _, data := range dataBytes {
		copy(b[next:], data)
		next += len(data)
	}
	return b
}

type ProcEvent struct {
	what uint32
	cpu  uint32
	ts   uint64
	data EventData
}

type EventData interface {
	getPid() uint32
	getPPid() uint32
	name() string
}

type ForkEvent struct {
	ptid uint32
	ppid uint32
	tid  uint32
	pid  uint32
}

func (fork ForkEvent) getPid() uint32 {
	return fork.pid // returns parent!
}

func (fork ForkEvent) getPPid() uint32 {
	return fork.ppid // returns parent!
}

func (fork ForkEvent) name() string {
	return "fork"
}

type ExecEvent struct {
	pid uint32
}

func (exec ExecEvent) getPid() uint32 {
	return exec.pid
}

func (exec ExecEvent) getPPid() uint32 {
	return exec.pid
}

func (exec ExecEvent) name() string {
	return "exec"
}

type ConnectorMsg struct {
	idx   uint32
	val   uint32
	seq   uint32
	ack   uint32
	len   uint16
	flags uint16
	op    uint32
}

func (self ConnectorMsg) Len() int {
	return (4 + 4 + 4 + 4 + 2 + 2 /* + 1*/)
}

func (self ConnectorMsg) ToWireFormat() []byte {
	b := make([]byte, self.Len()+4)
	binary.LittleEndian.PutUint32(b[0:4], self.idx)
	binary.LittleEndian.PutUint32(b[4:8], self.val)
	binary.LittleEndian.PutUint32(b[8:12], self.seq)
	binary.LittleEndian.PutUint32(b[12:16], self.ack)
	binary.LittleEndian.PutUint16(b[16:18], self.len)
	binary.LittleEndian.PutUint16(b[18:20], self.flags)
	binary.LittleEndian.PutUint32(b[20:24], self.op)
	return b
}

var (
	ErrWrongSockType = errors.New("Wrong socket type")
	ErrShortResponse = errors.New("Got short response from netlink")
)

func NewNetLinkSocket() (*NetLinkSocket, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_CONNECTOR)
	if err != nil {
		return nil, err
	}
	s := &NetLinkSocket{fd: fd}
	s.lsa.Family = syscall.AF_NETLINK
	s.lsa.Groups = C.CN_IDX_PROC
	if err = syscall.Bind(fd, &s.lsa); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return s, nil
}

func listen(on bool) *NetLinkRequest {
	var msg ConnectorMsg
	var request NetLinkRequest
	msg.idx = C.CN_IDX_PROC
	msg.val = C.CN_VAL_PROC
	msg.len = 4
	if on {
		msg.op = C.PROC_CN_MCAST_LISTEN
	} else {
		msg.op = C.PROC_CN_MCAST_IGNORE
	}
	request.Data = make([]NetlinkRequestData, 1)
	request.Data[0] = msg
	request.Len = 16
	request.Pid = uint32(syscall.Getpid())
	request.Type = syscall.NLMSG_DONE
	return &request
}

func (self *NetLinkSocket) Send(request *NetLinkRequest) error {
	if err := syscall.Sendto(self.fd, request.ToWireFormat(), 0, &self.lsa); err != nil {
		return err
	}
	return nil
}

func parseProcEvent(bytes []byte) (*ProcEvent, error) {
	var ev ProcEvent
	if len(bytes) < syscall.NLMSG_HDRLEN+20 {
		return nil, ErrShortResponse
	}
	msg := bytes[syscall.NLMSG_HDRLEN+20:]
	ev.what = binary.LittleEndian.Uint32(msg[0:4])
	switch ev.what {
	case C.PROC_EVENT_NONE:
		log.Info("Running ProcEventBeat")
	case C.PROC_EVENT_EXEC:
		if len(msg) >= 32 {
			event_data := msg[16:]
			exec_event := ExecEvent{
				pid: binary.LittleEndian.Uint32(event_data[4:8]),
			}
			ev.data = exec_event
		}
	default:
	}
	return &ev, nil
}

func (self *NetLinkSocket) Receive() (*ProcEvent, error) {
	//var flags int
	//flags |= syscall.MSG_DONTWAIT
	rb := make([]byte, 76)
	nr, _, err := syscall.Recvfrom(self.fd, rb, 0)
	if err != nil {
		return nil, err
	}
	if nr < syscall.NLMSG_HDRLEN {
		return nil, ErrShortResponse
	}
	rb = rb[:nr]
	return parseProcEvent(rb)
}

type ProcMessage struct {
	AuditTime string              `json:"timestamp"`
	PidMap    []map[string]string `json:"pid_map"`
	PidMapLen int                 `json:"pid_map_len"`
	Plugin    string              `json:"plugin"`
}

func parseMessage(pid uint32) (procMessage *ProcMessage, err error) {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return nil, err
	}
	cmdline, err := p.Cmdline()
	if err != nil {
		return nil, nil
	}
	ppid, err := p.Ppid()
	if err != nil {
		return nil, nil
	}
	cwd, _ := p.Cwd()
	uname, _ := p.Username()
	pname, _ := p.Name()
	if pname == "" {
		return nil, nil
	}
	procMessage = &ProcMessage{}
	// rules
	if strings.Contains(cmdline, "curl") {
		procMessage.Plugin = "cmd execute"
		procMessage.PidMap = make([]map[string]string, 10, 10)
		pid_map := make(map[string]string, 10)
		exe, _ := p.Exe()
		terminal, _ := p.Terminal()
		boot_time, _ := p.CreateTime()
		pid_map["pid"] = strconv.FormatInt(int64(pid), 10)
		pid_map["name"] = pname
		pid_map["ppid"] = strconv.FormatInt(int64(ppid), 10)
		pid_map["username"] = uname
		pid_map["cmdline"] = cmdline
		pid_map["exe"] = exe
		pid_map["cwd"] = cwd
		pid_map["terminal"] = terminal
		pid_map["bootTime"] = time.Unix(boot_time/1000, 0).Format("2006-01-02 15:04:05.000")
		procMessage.PidMap[0] = pid_map
		procMessage.PidMapLen = 1
		for i := 1; i < 6; i++ {
			p, err = process.NewProcess(int32(ppid))
			if err != nil {
				break
			}
			cwd, _ = p.Cwd()
			uname, _ = p.Username()
			pid_map = make(map[string]string, 10)
			pid_map["pid"] = strconv.FormatInt(int64(ppid), 10)
			pname, _ = p.Name()
			ppid, _ = p.Ppid()
			cmdline, _ = p.Cmdline()
			exe, _ = p.Exe()
			terminal, _ = p.Terminal()
			boot_time, _ := p.CreateTime()
			pid_map["name"] = pname
			pid_map["ppid"] = strconv.FormatInt(int64(ppid), 10)
			pid_map["username"] = uname
			pid_map["cmdline"] = cmdline
			pid_map["exe"] = exe
			pid_map["cwd"] = cwd
			pid_map["terminal"] = terminal
			pid_map["boottime"] = time.Unix(boot_time/1000, 0).Format("2006-01-02 15:04:05.000")
			procMessage.PidMap[i] = pid_map
			procMessage.PidMapLen = i + 1
			if ppid == 0 || ppid == -1 {
				break
			}
		}
		procMessage.AuditTime = time.Now().Format("2006-01-02 15:04:05.000")
	}
	return procMessage, nil
}

/*
Linux kernels since 2.6.15 contains a userspace <-> kernelspace connector built on netlink sockets.
This can be used by the kernel to broadcast internal information to userspace, like process events in our case.
This exposes a possibility to know in near-realtime when a process starts, dies, forks, etc.
to do so, we need creates a netlink socket and tells the kernel to start broadcasting process events.
Either you use this socket manually, or use the simple supplied callback loop.
*/
func Run() {
	s, err := NewNetLinkSocket()
	if err != nil {
		log.Print(err)
	}
	err = s.Send(listen(true))
	if err != nil {
		log.Print(err)
	}
	for {
		ev, err := s.Receive()
		if err != nil || ev.data == nil {
			continue
		}
		procMessage, err := parseMessage(ev.data.getPid())
		if err == nil {
			if (procMessage != nil) && (procMessage.Plugin != "") {
				fmt.Println(procMessage)
			}
		}
	}
}

func main() {
	var wg sync.WaitGroup
	wg.Add(1)
	Run()
	wg.Wait()
}
