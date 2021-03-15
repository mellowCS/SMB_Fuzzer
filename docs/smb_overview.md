# Server Message Block Protocol Overview

## Key Data:

- Provides file sharing, network browsing, printing and inter-process communication (IPC).
- Relies on lower level protocols for transport (TCP/IP).
- Most common among Windows systems.
- Was often used with **NetBIOS over TCP/IP** over UDP, using ports 137/138 and TCP ports 137/139.
    - SMB/NBT generally used for backwards compatibility
    - NetBIOS also often used with NetBEUI (until Windows 2000) and IPX/SPX
- The SMB protocol can also be used without a separate transport protocol over TCP port 445.
- The IPC provides **named pipes** and a means for services to inherit the authentication carried out when a client first connects to an SMB.
- **MSRPC** (DCE/RPC) over SMB also allows MSRPC client programs to perform authentication which overrides the authorization provided by the SMB server but only in the context of the MSRPC client program.
- **SMB Signing**: Windows NT 4.0 SP3 and up have the capability to use cryptography to digitally sign SMB connections.
    - Signing of incoming SMB connections is handled by the **LanManServer** service and outgoing by the **LanManWorkstation** service.
    - Default setting from Windows 98 and up is **Opportunistic encryption** which means it falls back to unencrypted communication if it can't encrypt the communication channel.
    - Default setting for Windows domain controllers from Windows Server 2003 and up does not allow fallbacks for incoming connections.
    - This should protect against **Man-In-The-Middle** attacks against clients retrieving their policies from domain controllers at login.
- Supports **Opportunistic Locking** which is designed to improve performance by controlling caching of network files by the client.
---
## Practical Applications:

1. **File storage vor virtualization (Hyper-V over SMB)**
    - Hyper-V can store vm files, such as config, vhd files, and snapshots in file shares over SMB.
    - Can be used for stand-alone and clustered file servers.
2. **Microsoft SQL Server over SMB**
    - Can store user database files on SMB file shares.
    - Currently supported for SQL Server 2008 R2 stand-alone servers.
3. **Traditional storage for end-user data**
    - Provides enhancements to the Information Worker (or client) workloads.
---
## Versions:

- **SMB / CIFS / SMB1**
    - Originally designed to work on NetBIOS/NetBEUI API. (typically with NBF, NetBIOS over IPX/SPX, or NBT)
    - Since Windows 2000, SMB runs, by default, with a thin layer, similar to the Session Message packet of NBT's Session Service, on top of TCP port 445.
    - Windows Server 2003 and older NAS devices use SMB1/CIFS natively. An extremely chatty protocol and therefore slow in WANs as the back and forth handshake magnifies the high latency. In later versions the number of handshake exchanges was reduced.
    - Uses 16-bit data sizes, limits maximum block size to 64K.

- **SMB 2.0**
    - Windows Vista 2006, Server 2008 and up.
    - Reduces 'chattiness' by reducing commands and subcommands from over a hundred to nineteen.
    - Supports pipelining of messages sent improving latency of high-latency links.
    - Ability to compound multiple actions into a single request reducing the number of round-trips.
    - Supports symbolic links, caching of file properties and improve message signing with HMAC SHA-256.
    - Uses 32- or 64-bit wide storage fields, and 128 bits in the case of file-handles. (Removes block size limitations)
    - Supported by SAMBA 3.6 and OS X 10.7 (SMBX) and up as non-default.
    - Supported by Linux Kernel's CIFS client file system since version 3.7.

- **SMB 2.1**
    - Windows 7 and Server 2008 R2
    - Minor performance improvements
    - New locking mechanism

- **SMB 3.0**
    - Windows 8 and Server 2012
    - Introduces SMB direct protocol (SMB over remote direct memory access [RDMA])
    - SMB Multichannel (multiple connections per SMB session)
    - SMB Transparent Failover
    - New security enhancements, such as end-to-end encryption and new AES based signing algorithm.

- **SMB 3.0.2**
    - Windows 8.1 and Server 2012 R2

- **SMB 3.1.1**
    - Windows 10 and Windows Server 2016
    - Supports AES-128 GCM encryption in addition to AES-128 CCM
    - Implements pre-authentication integrity check using SHA-512.
    - Makes secure negotiation mandatory when connecting to clients using 2.x and up.
---
## Opportunistic Locking:

- Mechanism designed to improve performance by controlling caching of network files by the client. There four types:
- **Batch Locks**
    - Batch OpLocks were originally created to support a particular behavior of DOS batch file execution operation in which the file is opened and closed many times in a short period, which is a performance problem. To solve this, a client may ask for an OpLock of type "batch". In this case, the client delays sending the close request and if a subsequent open request is given, the two requests cancel each other.
- **Level 1 OpLocks / Exclusive Locks**
    - When an application opens in "shared mode" a file hosted on an SMB server which is not opened by any other process (or other clients) the client receives an exclusive OpLock from the server. This means that the client may now assume that it is the only process with access to this particular file, and the client may now cache all changes to the file before committing it to the server. This is a performance improvement, since fewer round-trips are required in order to read and write to the file. If another client/process tries to open the same file, the server sends a message to the client (called a break or revocation) which invalidates the exclusive lock previously given to the client. The client then flushes all changes to the file.

 - **Level 2 OpLocks**
     - If an exclusive OpLock is held by a client and a locked file is opened by a third party, the client has to relinquish its exclusive OpLock to allow the other client's write/read access. A client may then receive a "Level 2 OpLock" from the server. A Level 2 OpLock allows the caching of read requests but excludes write caching.

- **Filter OpLocks**
    - Added in NT 4.0, Filter Oplocks are similar to Level 2 OpLocks but prevent sharing-mode violations between file open and lock reception. Microsoft advises use of Filter OpLocks only where it is important to allow multiple readers and Level 2 OpLocks in other circumstances.

- Clients holding an OpLock do not really hold a lock on the file, instead they are notified via a break when another client wants to access the file in a way inconsistent with their lock. The other client's request is held up while the break is being processed. 

- **Breaks**
    - In contrast with the SMB protocol's "standard" behavior, a break request may be sent from server to client. It informs the client that an OpLock is no longer valid. This happens, for example, when another client wishes to open a file in a way that invalidates the OpLock. The first client is then sent an OpLock break and required to send all its local changes (in case of batch or exclusive OpLocks), if any, and acknowledge the OpLock break. Upon this acknowledgment the server can reply to the second client in a consistent manner.
---
##  Security

- Over the years, there have been many security vulnerabilities in Microsoft's implementation of the protocol or components on which it directly relies. Other vendors' security vulnerabilities lie primarily in a lack of support for newer authentication protocols like NTLMv2 and Kerberos in favor of protocols like NTLMv1, LanMan, or plaintext passwords. Real-time attack tracking shows that SMB is one of the primary attack vectors for intrusion attempts, for example the 2014 Sony Pictures attack, and the WannaCry ransomware attack of 2017. In 2020, two SMB high-severity vulnerabilities were disclosed and dubbed as SMBGhost (CVE-2020-0796) and SMBleed (CVE-2020-1206), which when chained together can provide RCE (Remote Code Execution) privilege to the attacker.
---
# References

 - https://en.wikipedia.org/wiki/Server_Message_Block
 - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh831795(v=ws.11)