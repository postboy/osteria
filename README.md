# Osteria 0.09
Secure point-to-point messenger.
Offers an example code in fields of network programming using [Berkeley sockets] (https://en.wikipedia.org/wiki/Berkeley_sockets), GUI programming using [GTK+] (http://www.gtk.org) and applied cryptography programming using [TweetNaCl] (http://tweetnacl.cr.yp.to).
Licence: BSD 2-clause with public domain parts.

Please note that project is not offering backward compatibility feature now!

## Platform
* GNU/Linux
* other UNIXes (porting should be very easy)
* Windows (porting shouldn't be hard: you have to use winsock.h, change a code for random number generation and asynchronous reading from socket for data exchange)

## Dependencies
GTK+ >= 3.10: libgtk-3-0 libgtk-3-bin libgtk-3-common libgtk-3-dev

## Todo
* file sending is just a must-have feature

## Authors
Developer: Zubov Ivan // anotherdiskmag on gooooooogle mail

Testing, ideas: Yelmanov Andrew, Danilenko Egor
