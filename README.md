## Osteria 0.09 — secure point-to-point messenger
Offers an example code in fields of network programming using [Berkeley sockets] (https://en.wikipedia.org/wiki/Berkeley_sockets), GUI programming using [GTK+] (http://www.gtk.org) and applied cryptography programming using [TweetNaCl] (http://tweetnacl.cr.yp.to).
Licence: [BSD 2-clause] (http://opensource.org/licenses/bsd-license.php) with public domain parts.

Please note that project is not offering backward compatibility feature now!

## Features
* direct point-to-point connection of two users via global or local network
* all user messages are protected by strong cryptographic functions written by well-known professionals
* [perfect forward secrecy] (https://en.wikipedia.org/wiki/Forward_secrecy) property of conversations
* protocol allows protection against [man-in-the-middle attack] (https://en.wikipedia.org/wiki/Man-in-the-middle_attack) by comparsion of hashes of keys and/or by master key exchange via secure channel (e.g. via USB flash drives on offline meeting), against [replay attack] (https://en.wikipedia.org/wiki/Replay_attack) and partially against concealment of messages
* handy and simple GUI
* supports both IPv4 and IPv6

## Platform
* GNU/Linux
* other *nix (porting should be very easy)
* Windows (porting shouldn't be hard: you have to use Winsock, change a code for random number generation and asynchronous reading from socket for data exchange)

## Dependencies
GTK+ >= 3.10

On *nix it means libgtk-3-0 libgtk-3-bin libgtk-3-common libgtk-3-dev packets.

## Todo
* file sending is just a must-have feature

## Contributors
Developer: Zuboff Ivan // anotherdiskmag on gooooooogle mail

Testing, ideas: Yelmanov Andrew, Danilenko Egor
