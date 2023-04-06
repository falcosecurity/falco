# Helpers hierarchy

### 0. base: 
    * BPF maps intefaces. 
    * push raw data into buffers.
    * read kernel memory.

### 1. extract
    * extract kernel information.

### 2. store
    * copy data into the auxiliary map.
    * copy data into the ring buffer.
  
### 3. interfaces (used directly by BPF programs)
    * programs directly attached to the kernel.
    * programs that send a fixed size event.
    * programs that send a variable size event.
    * programs that dispatch syscall events.