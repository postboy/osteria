/* 
tweetnacl.h - header for cryptographic library TweetNaCl version 20140427, modified
License: public domain
*/

//macro guard used to avoid the problem of double inclusion
#ifndef TWEETNACL_H
#define TWEETNACL_H

//headers for all Osteria source files:

//Windows only
#ifdef WIN32
#include <windows.h>
#include <Wincrypt.h>
#include <windef.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Ws2_32.lib")
#define close(fd) closesocket(fd)
HCRYPTPROV hCryptProv = -1;

//*nix only
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#endif

//should be generic (not tested well!)
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <time.h>
#include <inttypes.h>
#include <string.h>
#include <locale.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <gtk/gtk.h>

#include "poison.h"		//we need to include it to ban unsafe C functions

//constants for all Osteria's source files:
#define maxmlen 4000	//maximal length of user's text message
#define varmlen maxmlen+crypto_sign_BYTES+crypto_box_ZEROBYTES
//size of variables that contain messages during program's work
#define version "0.09"	//program version

//all defines below is just for code pithiness

extern void randombytes (unsigned char *x,unsigned long long xlen);
//this function is used for first nonce generation

#define crypto_box_keypair crypto_box_curve25519xsalsa20poly1305_tweet_keypair
#define crypto_box_beforenm crypto_box_curve25519xsalsa20poly1305_tweet_beforenm
#define crypto_box_afternm crypto_box_curve25519xsalsa20poly1305_tweet_afternm
#define crypto_box_open_afternm crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm
extern int crypto_box_curve25519xsalsa20poly1305_tweet_keypair(unsigned char *,unsigned char *);
extern int crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(unsigned char *,const unsigned char *,const unsigned char *);
extern int crypto_box_curve25519xsalsa20poly1305_tweet_afternm(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
extern int crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
#define crypto_box_PUBLICKEYBYTES 32
#define crypto_box_SECRETKEYBYTES 32
#define crypto_box_BEFORENMBYTES 32
#define crypto_box_NONCEBYTES 24
#define crypto_box_ZEROBYTES 32
#define crypto_box_BOXZEROBYTES 16

#define crypto_hash crypto_hash_sha512_tweet
extern int crypto_hash_sha512_tweet(unsigned char *,const unsigned char *,unsigned long long);
#define crypto_hash_BYTES 64

#define crypto_sign crypto_sign_ed25519_tweet
#define crypto_sign_open crypto_sign_ed25519_tweet_open
#define crypto_sign_keypair crypto_sign_ed25519_tweet_keypair
extern int crypto_sign_ed25519_tweet(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
extern int crypto_sign_ed25519_tweet_open(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
extern int crypto_sign_ed25519_tweet_keypair(unsigned char *,unsigned char *);
#define crypto_sign_BYTES 64
#define crypto_sign_PUBLICKEYBYTES 32
#define crypto_sign_SECRETKEYBYTES 64

#endif
