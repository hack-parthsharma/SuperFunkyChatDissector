# TCP Dissector for the SuperFunkyChat Protocol

This is a Wireshark protocol parser written in Lua for the SuperFunkyChat program.

The chat application can be found here: https://github.com/tyranid/ExampleChatApplication/releases/

In the book *Attacking Network Protocols*, James Forshaw writes the UDP version of the parser, however, my implementation is for TCP.

The TCP version is slightly more difficult because you must account for multiple packets that make up the entire exchange of data i.e. the checksum, command id, data, etc. The modified script contains additional logic to parse these parameters.

Below is an example of how the parsed protocol looks in Wireshark.

![Screenshot](images/wireshark.png)
