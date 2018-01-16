# A Example of Ethernet OAM (IEEE 802.3ah)

This project implement a example of Ethernet OAM protocol.  You can utilize it as an
software OAM protocol tester :question: or can either integrate the code into any 
project that need OAM functionality.

It has been only tested in macOS 10.13.x and Debian 9 (running in VirtualBox or in 
Docker's container), but because the build system is "cmake", it will be easily to build
and test in other Linux variants. 

During the development, just a few operations, like remote loopback, event report, etc.
have been tested with Cisco 3XXX router.

:question:It does not means this project fully compliant with the OAM spec., but it came 
with source code, so you can easily custimize it to execute any OAM related testing.

Features:

- Remote Fault Indication
- Link Monitoring
- Remote Loopback
- Statistics (partial)
- OAM session management
- Event Configuration
- Event Log 
- [RFC 4978](https://tools.ietf.org/html/rfc4878)
    * dot3OamTable (MANDATORY-GROUPS)
    * dot3OamPeerTable (MANDATORY-GROUPS)
    * dot3OamLoopbackTable
    * dot3OamStatsTable (MANDATORY-GROUPS)
    * dot3OamEventConfigTable
    * dot3OamEventLogTable
    * dot3OamThresholdEvent (Event)

In this document, the meaning of 'OSX' is the same as 'macOS'. 

# Environment

* Linux - Debian 9 (Use Debian 8 or Ubuntu 16.x should be also fine), or
* macOS - 10.13.x

## GCC

** FYI.  For compiling GoolgTest, it is needed to enable "-std=c++11" flag. 

## Common

Install [GTest](https://github.com/Ed-Yang/gmockc#download-and-install)

## Linux
```
apt update 
apt-get install build-essential -y
apt-get install doxygen -y
apt install cmake -y
apt install libpcap-dev -y
```

## OSX
```
brew install pkg-config
brew install automake
brew install doxygen
brew install cmake
brew innstall libpcap
```
## Source Tree

```
<this-repository>
├── README.md (this file)
├── build
├── example
│   ├── client (oam management client command)
│   └── server (oam sample program)
│       ├── oam_cout.cpp (example of porting callout API)
│       ├── oam_main.cpp (main program)
│       └── user_params.h (configurables)
├── external (open sources)
│   ├── getopt
│   └── uthash
├── include
├── src
│   ├── eoamapi
│   ├── eoamlib (lib for oam functions)
│   └── xutl (some netowrk lib, include pcap wrapper)
├── test (GTest for Ethernet OAM)
│   ├── gt_cout.cpp
│   ├── gt_eoam.cpp
│   └── user_params.h
```

## Linux/OSX

```
$ mkdir build
$ cd build
$ cmake ..
$ make

# NOTE:  For OSX, it don't need root priviledge for accessing libpcap, 
  so it can just use "make test"

$ sudo make test
Running tests...
Test project eoam
    Start 1: gt-xdev
1/8 Test #1: gt-xdev ..........................   Passed    5.20 sec
    Start 2: gt-xipc
2/8 Test #2: gt-xipc ..........................   Passed    2.14 sec
    Start 3: gt-xnet
3/8 Test #3: gt-xnet ..........................   Passed   28.96 sec
    Start 4: test_net
4/8 Test #4: test_net .........................   Passed   11.01 sec
    Start 5: test_xdev
5/8 Test #5: test_xdev ........................   Passed    1.20 sec
    Start 6: test_xipc
6/8 Test #6: test_xipc ........................   Passed    0.11 sec
    Start 7: test_ipc
7/8 Test #7: test_ipc .........................   Passed    0.33 sec
    Start 8: gt-eoam
8/8 Test #8: gt-eoam ..........................   Passed   13.78 sec

100% tests passed, 0 tests failed out of 8

Total Test time (real) =  62.83 sec
```

# Run

## Testing Environment

All of the testing is executed in Debian 9, but you can replace the host environment
to Linux Debian variant OS (like Ubuntu, etc.) or OSX.

The VM-A, or VM-B is represented a Linux shell, Docker container, or OSX shell in a host OS.

In this document, the testing is running with the following configuration:

VM-A: VirtualBox VM running Debian 9. 
VM-B: A Docker container in VirtualBox.

SHELL-A-Client:  command shell for executing testing command on VM-A
SHELL-A-Server:  command shell for executing oeam program on VM-A

SHELL-B-Server: command shell for executing oeam program on VM-B

In the sample eoam program, it is configured with a device with **OAM_PARAM_MAX_PORTS** 
ethernet ports and only **port 2** is link up.

The "eoam" example server take one argument for interface name, without any argument, 
it will auto select the "eth0" on Linux and "en0" on OSX.  


### Run eoam example server

VM-A-Server:

The VM-A and VM-B (Docker container) is connected with Docker default bridge, so
eoam server on VM-A is running with interface name "docker0".

```
$ sudo ./example/eoam docker0

10:47:48.391 [0x7b712740, 0x848e6180] xdev_open:  src mac filled by upper layer
10:47:48.391 xdev_open: mac filter 02:42:58:07:77:ee (mask 5 bytes)
10:47:48.395 [7b712740] xnet_start: xnet thread is running ...
10:47:48.395 xnet thread run user_init ...
10:47:48.396 eoam_fsm_usr_init: init interfaces
10:47:48.396 [ 2] CO: state changed old FAULT --> new ACTIVE_SEND
10:47:48.396 xnet thread enter loop (sec = 1, wait time: usec = 0).
10:47:48.396 xdev_wait: wait xdev thread terminated ...
10:47:49.225 [ 2] new remote flags [0/1, 0/0]
10:47:49.225 [ 2] rx pdu, remote valid, flags:[0/1, 0/0]
10:47:49.225 [ 2] send local: save mac 02:42:ac:11:00:02
10:47:49.225 [ 2] CO: state changed old ACTIVE_SEND --> new LOC_REM
10:47:50.265 [ 2] CO: state changed old LOC_REM --> new LOC_REM_OK
10:47:50.395 [ 2] SEND INFO: flags [1/0, 0/1]
10:47:51.201 [ 2] remote flags changes [0/1, 0/0] --> [0/1, 1/0]
10:47:51.201 [ 2] remote unstable state:LOC_REM_OK remote flag:[0/1, 1/0]
10:47:51.201 [ 2] CO: state changed old LOC_REM_OK --> new SEND_ANY
10:47:52.241 [ 2] remote flags changes [0/1, 1/0] --> [1/0, 1/0]
10:47:52.395 [ 2] SEND INFO: flags [1/0, 1/0]

```
VM-B-Server:
```
# ./example/eoam

02:47:17.176 [0xa2367740, 0x015ab570] xdev_open:  src mac filled by upper layer
02:47:17.176 xdev_open: mac filter 02:42:ac:11:00:02 (mask 5 bytes)
02:47:17.177 [a2367740] xnet_start: xnet thread is running ...
02:47:17.177 xnet thread run user_init ...
02:47:17.177 eoam_fsm_usr_init: init interfaces
02:47:17.178 [ 2] CO: state changed old FAULT --> new ACTIVE_SEND
02:47:17.178 xnet thread enter loop (sec = 1, wait time: usec = 0).
02:47:17.178 xdev_wait: wait xdev thread terminated ...
02:47:19.179 [ 2] SEND INFO: flags [0/1, 0/0]
02:47:50.457 [ 2] new remote flags [1/0, 0/1]
02:47:50.457 [ 2] rx pdu, remote valid, flags:[1/0, 0/1]
02:47:50.457 [ 2] send local: save mac 02:42:58:07:77:02
02:47:50.457 [ 2] CO: state changed old ACTIVE_SEND --> new LOC_REM
02:47:51.180 [ 2] SEND INFO: flags [0/1, 1/0]
02:47:51.497 [ 2] CO: state changed old LOC_REM --> new LOC_REM_OK
02:47:52.180 [ 2] SEND INFO: flags [1/0, 1/0]
02:47:52.433 [ 2] remote flags changes [1/0, 0/1] --> [1/0, 1/0]
02:47:52.433 [ 2] CO: state changed old LOC_REM_OK --> new SEND_ANY
```

### Run Test Client

The default ethernet port is hard-coded as port 2, so it is not necessary to specify
the port with '-i' option.

```
$ ./example/ctrl_eoam -h
Usage:
    -i <ifindex>: interface: oam interface
    -a [1|2]: enable/disable admin mode
    -m [1|2]: active/passive
    -l [2|4]: start/stop loopback
    -r [1|2]: ignore/process loopback
    -s [1|2|3] set link failure/dying gasp/critical
    -c [1|2|3] clear link failure/dying gasp/critical
    -S [1|2|3|4] set link error event
    -e [1|2]: enable/disable link event
    -d [1-9] set debug level <XDBG_EMERG...XDBG_DEBUG>
    -q quit eoam program
    -x: show event log

```

## OAM session status

SHELL-A-Client:
```
$ ./example/ctrl_eoam -x

ifindex:2 (state = SEND_ANY)
  rev:0 admin:On, oam-mode:active max-pdu-size:1500 func:0x06
 Peer:
  mac:02:42:ac:11:00:02 oam-mode:active max-pdu-size:1500
  rev:0 oui:11:11:11 func:0x06
 Loopback:
  lpbk-status:no loopback, ignore-lpbk:Off
  info-pdu:(tx 96: rx 95) lpbk:(tx 0:rx 0)
 Events:  LF:Off, Dying Gasp:Off, Critical:Off
  err-symbols-period evt win:(1000) threshold:(1) enable:On
  err-frame--period evt win:(1000) threshold:(1) enable:On
  err-frame evt win:(10) threshold:(1) enable:On
  err-summary-sec evt win:(100) threshold:(1) enable:On

time     port idx  type loc window thresh value   run-total e-total
======== ==== ===  ==== === ====== ====== ======= ========= =========
```

## OAM Config

Condition: Both eoam in SEND_ANY state

SHELL-A-Client:
```
$ ./example/ctrl_eoam -m 2

original admin On, mode On
set config success.

$ ./example/ctrl_eoam -m 1

original admin On, mode Off
set config success.
```

SHELL-A-Server:
```
10:49:38.924 [ 2] adm:On->On mo:active->passive (rev 1), next=PASSIVE_WAIT
10:49:38.924 [ 2] CO: state changed old SEND_ANY --> new PASSIVE_WAIT
10:49:39.257 [ 2] new remote flags [1/0, 1/0]
10:49:39.257 [ 2] rx pdu, remote valid, flags:[1/0, 1/0]
10:49:39.257 [ 2] passive wait: save mac 02:42:ac:11:00:02
10:49:39.257 [ 2] CO: state changed old PASSIVE_WAIT --> new LOC_REM
10:49:39.394 [ 2] SEND INFO: flags [0/1, 1/0]
10:49:40.193 [ 2] remote flags changes [1/0, 1/0] --> [1/0, 0/1]
10:49:40.193 [ 2] CO: state changed old LOC_REM --> new LOC_REM_OK
10:49:40.395 [ 2] SEND INFO: flags [1/0, 1/0]
10:49:41.233 [ 2] remote flags changes [1/0, 0/1] --> [1/0, 1/0]
10:49:41.233 [ 2] CO: state changed old LOC_REM_OK --> new SEND_ANY

```

SHELL-B-Server:
```
02:49:39.457 [ 2] remote flags changes [1/0, 1/0] --> [0/1, 1/0]
02:49:39.457 [ 2] remote unstable state:SEND_ANY remote flag:[0/1, 1/0]
02:49:39.457 [ 2] CO: state changed old SEND_ANY --> new LOC_REM_OK
02:49:40.180 [ 2] SEND INFO: flags [1/0, 0/1]
02:49:40.497 [ 2] remote flags changes [0/1, 1/0] --> [1/0, 1/0]
02:49:40.497 [ 2] CO: state changed old LOC_REM_OK --> new SEND_ANY
02:49:41.179 [ 2] SEND INFO: flags [1/0, 1/0]
```

## Remote Loopback
SHELL-A-Client:
```
$ ./example/ctrl_eoam -l 2

set loopback success.

$ ./example/ctrl_eoam -l 4

set loopback success.
```
SHELL-A-Server:
```
10:53:06.637 [ 2] rev 1 cfg (0d ->  0d), state (00 -> 05)
10:53:06.637 [ 2] peer config: M:A/U:-/L:Y/E:Y/V:- state: mux:drop, par:lpbk
10:53:06.637 [ 2] CO: loopback status - remote loopback (3)
10:53:30.665 [ 2] rev 2 cfg (0d ->  0d), state (05 -> 00)
10:53:30.665 [ 2] peer config: M:A/U:-/L:Y/E:Y/V:- state: mux:fwd, par:fwd
10:53:30.665 [ 2] CO: loopback status - no loopback (1)
```
SHELL-B-Server:
```
02:53:06.633 [ 2] eoam_proc_lpbk_pdu_indication: loopback cmd 1
02:53:06.633 [ 2] eoam_proc_lpbk_pdu_indication: lpbk respond info pdu
02:53:06.633 [ 2] CO: loopback status - local loopback (5)
02:53:08.401 [ 2] rev 4 cfg (0d ->  0d), state (00 -> 02)
02:53:08.401 [ 2] peer config: M:A/U:-/L:Y/E:Y/V:- state: mux: fwd, par:drop
02:53:30.561 [ 2] eoam_proc_lpbk_pdu_indication: loopback cmd 2
02:53:30.561 [ 2] eoam_proc_lpbk_pdu_indication: lpbk respond info pdu
02:53:30.561 [ 2] CO: loopback status - no loopback (1)
02:53:32.433 [ 2] rev 6 cfg (0d ->  0d), state (02 -> 00)
02:53:32.433 [ 2] peer config: M:A/U:-/L:Y/E:Y/V:- state: mux:fwd, par:fwd
```

## Link Event

SHELL-A-Client:
```
$ ./example/ctrl_eoam -S 1

set link event success.
```
SHELL-A-Server:
```
10:54:46.027 [0x7a272700][ 2] eoam_proc_report_event: type 1
10:54:46.027 [ 2] CO: raise l-events: type 1 ts 30722 loc 1 value 200 r-total 10200, e-total 1
```
SHELL-B-Server:
```
02:54:46.081 [ 2] rx evt pdu: seq 0 ts 45076 type 1 value 0:200
02:54:46.081 [ 2] CO: raise l-events: type 1 ts 30722 loc 2 value 200 r-total 10200, e-total 1
```
## Critical Event
SHELL-A-Client:
```
$ ./example/ctrl_eoam -s 1

set critical success.

$ ./example/ctrl_eoam -c 1

clear critical success.
```
SHELL-A-Server:
```
10:55:54.023 [0x7a272700][ 2] eoam_proc_report_event: type 256
10:55:54.023 [ 2] SEND INFO: flags [1/0, 1/0]
10:55:54.023 [ 2] CO: raise c-events: type 256 ts 30790 loc 1 r-total 1, e-total 1
10:55:57.883 [0x7a272700][ 2] eoam_proc_report_event: type 256
10:55:57.883 [ 2] SEND INFO: flags [1/0, 1/0]
10:55:57.883 [ 2] CO: clear c-events: type 256 ts 30794 loc 1 r-total 0, e-total 0
```
SHELL-B-Server:
```
02:55:54.097 [ 2] remote flags changes [1/0, 1/0] --> [1/0, 1/0]
02:55:54.097 [ 2] CO: raise c-events: type 256 ts 30790 loc 2 r-total 0, e-total 0
02:55:57.945 [ 2] remote flags changes [1/0, 1/0] --> [1/0, 1/0]
02:55:57.945 [ 2] CO: clear c-events: type 256 ts 30794 loc 2 r-total 0, e-total 0
```
## Log and Statistics
SHELL-A-Client:
```
$ ./example/ctrl_eoam -x

ifindex:2 (state = SEND_ANY)
  rev:6 admin:On, oam-mode:active max-pdu-size:1500 func:0x06
 Peer:
  mac:02:42:ac:11:00:02 oam-mode:active max-pdu-size:1500
  rev:2 oui:11:11:11 func:0x06
 Loopback:
  lpbk-status:no loopback, ignore-lpbk:Off
  info-pdu:(tx 600: rx 604) lpbk:(tx 2:rx 0)
 Events:  LF:Off, Dying Gasp:Off, Critical:Off
  err-symbols-period evt win:(1000) threshold:(1) enable:On
  err-frame--period evt win:(1000) threshold:(1) enable:On
  err-frame evt win:(10) threshold:(1) enable:On
  err-summary-sec evt win:(100) threshold:(1) enable:On

time     port idx  type loc window thresh value   run-total e-total
======== ==== ===  ==== === ====== ====== ======= ========= =========
   30722   2    1    1    1 1000   1      200     10200     1        
   30790   2    2  256    1 NA     NA     NA      NA                1

```
TODO

The xutl library is meant for fast prototyping or small scale network application(s),
so it do not utilize modern epoll or kqueue system call.  If the performance is
important, it might be replaced by other networking library.

* Porting to Win32.
* Cross-compiling for Raspberry Pi
* Variable Request
* send Organization Specific OAMPDUs

# Reference

* [IEEE 802.3ah](http://www.ieee802.org/21/doctree/2006_Meeting_Docs/2006-11_meeting_docs/802.3ah-2004.pdf)
* [RFC 4878](https://tools.ietf.org/html/rfc4878)

# Author

Welcome any comment.

Edward Yang 
<edwardyangyang@hotmail.com>




