# SMB_Fuzzer
The SMB Fuzzer fuzzes the Server Message Block Protocol that enables file sharing, printing and IPC between Unix and Windows systems.

# Usage
The SMB Fuzzer requires the rustup tool chain. If not already installed, just follow the [Rust Installation Guide](https://www.rust-lang.org/learn/get-started). 

Listed here are the current dependencies:

 - Rust 1.50.0
 - Cargo 1.50.0
 - bitflags 1.2.1
 - hex 0.4.3
 - rand 0.8.3

The current user API is very limited. To execute the SMB Fuzzer, enter the following command within the root directory of the project:

    cargo run -- [message] [strategy] [state]

!Note that the flags have to be in the order given by the placeholders above! This will later be changed.

e.g. to execute the Predefined fuzzing strategy for the negotiate message in the initial state, run the following command:

    cargo run -- --negotiate --predefined -init_state

The specific flags can be shown by running

    cargo run -- -h / --help

### NOTE!! Currently only certain messages can be fuzzed in certain state. Which messages can be fuzzed in which state is shown below.

<table>
   <thead>
      <tr>
         <th>State</th>
         <th>Messages</th>
      </tr>
   </thead>
   <tbody>
      <tr>
         <td>Initial</td>
         <td>Negotiate, Echo</td>
      </tr>
      <tr>
         <td>Negotiate</td>
         <td>Session Setup Negotiate, Echo</td>
      </tr>
      <tr>
         <td>Session Setup Negotiate</td>
         <td>Session Setup Authenticate, Echo</td>
      </tr>
      <tr>
         <td>Session Setup Authenticate</td>
         <td>Tree Connect, Echo</td>
      </tr>
      <tr>
         <td>Tree Connect</td>
         <td>Create, Echo</td>
      </tr>
      <tr>
         <td>Create</td>
         <td>Query Info, Close, Echo</td>
      </tr>
      <tr>
         <td>Close</td>
         <td>Create, Echo</td>
      </tr>
   </tbody>
</table>

___

Below is a complete presentation of all currently available flags.

## Message Flags

<table>
   <thead>
      <tr>
         <th>Message</th>
         <th>Flag</th>
      </tr>
   </thead>
   <tbody>
      <tr>
         <td>Negotiate</td>
         <td>-n / --negotiate / --Negotiate</td>
      </tr>
      <tr>
         <td>Session Setup Negotiate</td>
         <td>-sn / --session_setup_neg / --Session_setup_neg</td>
      </tr>
      <tr>
         <td>Session Setup Authenticate</td>
         <td>-sa / --session_setup_auth / --Session_setup_auth</td>
      </tr>
      <tr>
         <td>Tree Connect</td>
         <td>-t / --tree_connect / --Tree_connect</td>
      </tr>
      <tr>
         <td>Create</td>
         <td>-cr / --create / --Create</td>
      </tr>
      <tr>
         <td>Query Info</td>
         <td>-q / --query_info / --Query_info</td>
      </tr>
      <tr>
         <td>Close</td>
         <td>-cl / --close / --Close</td>
      </tr>
      <tr>
         <td>Echo</td>
         <td>-e / --echo / --Echo</td>
      </tr>
   </tbody>
</table>

</br>

## Strategy Flags

<table>
   <thead>
      <tr>
         <th>Strategy</th>
         <th>Flag</th>
      </tr>
   </thead>
   <tbody>
      <tr>
         <td>Predefined</td>
         <td>-pre / --predefined / --Predefined</td>
      </tr>
      <tr>
         <td>Random Fields</td>
         <td>-rf / --random_fields / --Random_fields</td>
      </tr>
      <tr>
         <td>Completely Random</td>
         <td>-cran / --completely_random / --Completely_random</td>
      </tr>
   </tbody>
</table>

</br>

## State Flags

<table>
   <thead>
      <tr>
         <th>State</th>
         <th>Flag</th>
      </tr>
   </thead>
   <tbody>
      <tr>
         <td>Initial</td>
         <td>-init_state</td>
      </tr>
      <tr>
         <td>Negotiate</td>
         <td>-neg_state</td>
      </tr>
      <tr>
         <td>Session Setup Negotiate</td>
         <td>-session_setup_neg_state</td>
      </tr>
      <tr>
         <td>Session Setup Authenticate</td>
         <td>-session_setup_auth_state</td>
      </tr>
      <tr>
         <td>Tree Connect</td>
         <td>-tree_state</td>
      </tr>
      <tr>
         <td>Create</td>
         <td>-create_state</td>
      </tr>
      <tr>
         <td>Close</td>
         <td>-close_state</td>
      </tr>
   </tbody>
</table>

___

## Server Config 

The target is a samba server with the following configuration of the /etc/samba/smb.conf:

    [global]
        workgroup = WORKGROUP
        lanman auth = no
        ntlm auth = no
        
        server role = standalone server
        obey pam restrictions = yes

        unix password sync = yes
        passwd program = /usr/bin/passwd %u
        passwd chat *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated/ssuccessfully* .
        pam password change = yes

        map to guest = bad user

    [share]
        comment = Pi share folder
        path = /share
        browseable = yes
        writeable = yes
        create mask = 0777
        directory mask = 0777
        public = yes
        guest ok = yes
