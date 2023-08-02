<p align="center"><img src="primary-logo.png" width="360"></p>
<p align="center"><b>Cloud Native Runtime Security.</b></p>

# Falco Branding Guidelines

Falco is an open source security project whose brand and identity are governed by the [Cloud Native Computing Foundation](https://www.linuxfoundation.org/legal/trademark-usage).

This document describes the official branding guidelines of The Falco Project. Please see the [Falco Branding](https://falco.org/community/falco-brand/) page on our website for further details.

### Logo

There are 3 logos available for use in this directory. Use the primary logo unless required otherwise due to background issues or printing.

The Falco logo is Apache 2 licensed and free to use in media and publication for the CNCF Falco project.

### Colors

| Name      | PMS  | RGB         |
|-----------|------|-------------|
| Teal      | 3125 |   0 174 199 |
| Cool Gray |   11 |  83  86  90 |
| Black     |      |   0   0   0 |
| Blue-Gray | 7700 |  22 92 125  |
| Gold      | 1375 | 255 158  27 |
| Orange    |  171 | 255  92  57 |
| Emerald   | 3278 |   0 155 119 |
| Green     |  360 | 108 194  74 |

The primary colors are those in the first two rows.

### Slogan

> Cloud Native Runtime Security

### Writing about Falco

##### Yes

Notice the capitalization of the following terms.

 - The Falco Project
 - Falco

##### No

 - falco
 - the falco project
 - the Falco project

---

# Glossary

This section contains key terms specifically used within the context of The Falco Project. For a more comprehensive list of Falco-related terminology, we invite you to visit the [Glossary](https://falco.org/docs/reference/glossary/) page on our official website.

#### eBPF Probe

Used to describe the `.o` object that would be dynamically loaded into the kernel as a secure and stable (e)BPF probe. 
This is one option used to pass kernel events up to userspace for Falco to consume.

#### Modern eBPF Probe

More robust [eBPF probe](#ebpf-probe), which brings the CO-RE paradigm, better performances, and maintainability. 
Unlike the legacy probe, the modern eBPF probe is not shipped as a separate artifact but bundled into the Falco binary itself.
This is one option used to pass kernel events up to userspace for Falco to consume.

#### Kernel Module

Used to describe the `.ko` object that would be loaded into the kernel as a potentially risky kernel module.
This is one option used to pass kernel events up to userspace for Falco to consume.

#### Driver 

The global term for the software that sends events from the kernel. Such as the [eBPF probe](#ebpf-probe), the [Modern eBPF probe](#modern-ebpf-probe), or the [Kernel Module](#kernel-module).

#### Plugin

Used to describe a dynamic shared library (`.so` files in Unix, `.dll` files in Windows) that conforms to a documented API and allows to extend Falco's capabilities.

#### Falco

The name of the project and also the name of [the main engine](https://github.com/falcosecurity/falco) that the rest of the project is built on.

