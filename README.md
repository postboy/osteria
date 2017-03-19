## Osteria 0.09 — secure point-to-point messenger
This project offers an example code in fields of network programming using [Berkeley sockets](https://en.wikipedia.org/wiki/Berkeley_sockets), GUI programming using [GTK+](http://www.gtk.org) and applied cryptography programming using [TweetNaCl](http://tweetnacl.cr.yp.to).
Licence: [BSD 2-clause](http://opensource.org/licenses/bsd-license.php) with public domain parts.

## Features
* direct point-to-point connection of two users via global or local network
* all user messages are protected by strong cryptographic functions written by well-known professionals
* [perfect forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy) property of conversations
* protocol allows protection against [man-in-the-middle attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) by comparsion of hashes of keys and/or by master key exchange via secure channel (e.g. via USB flash drives on offline meeting), against [replay attack](https://en.wikipedia.org/wiki/Replay_attack) and partially against concealment of messages
* handy and simple GUI
* supports both IPv4 and IPv6

## Platform
* GNU/Linux (tested)
* other *nix and Windows (not tested; porting should be easy because code for that platforms is already included in sources)

## Dependencies
GTK+ >= 3.10

On *nix it means `libgtk-3-0 libgtk-3-bin libgtk-3-common libgtk-3-dev` packages.

## Posts about it in Russian
1. [О выборе криптографической библиотеки](https://medium.com/@posthedgehog/crypting-without-creeps-876448a6517e).
2. [О разработанном криптографическом протоколе](https://medium.com/@posthedgehog/%D1%82%D1%80%D0%B5%D1%82%D0%B8%D0%B9-%D0%BB%D0%B8%D1%88%D0%BD%D0%B8%D0%B9-%D0%BC%D0%B0%D1%81%D1%82%D0%B5%D1%80%D0%B8%D0%BC-%D1%81%D0%B2%D0%BE%D0%B9-%D0%BA%D1%80%D0%B8%D0%BF%D1%82%D0%BE%D0%B3%D1%80%D0%B0%D1%84%D0%B8%D1%87%D0%B5%D1%81%D0%BA%D0%B8%D0%B9-%D0%BF%D1%80%D0%BE%D1%82%D0%BE%D0%BA%D0%BE%D0%BB-c04c5074ebdd).

## Todo
* file sending is just a must-have feature

## Contributors
Developer: Zuboff Ivan // anotherdiskmag on gooooooogle mail

Testing, ideas: Yelmanov Andrew, Danilenko Egor
