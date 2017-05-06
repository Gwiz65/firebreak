# firebreak

Someday this might grow up to be an easy-to-use personal firewall with a 
traffic monitor. Basically a new version of Firestarter that supports IPv6.

As of now it's a simple network traffic monitor that uses a raw socket to
monitor tcp and udp traffic. Device scanning is working in the monitor program
(fbmon), but I haven't got that data back to the GUI yet, so the device info at
top is dummy info. Real device info is ouput to the command line for now. The
Rescan button is also a placeholder and doesn't do anything.
