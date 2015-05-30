/*
crypto.h - header for crypto.c
License: BSD 2-Clause
*/

//macro guard used to avoid the problem of double inclusion
#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "stuff.h"

//generation of files with persistent keys
int generate_key_files(const char *companion_name);
//saving current session's persistent keys to files
int save_current_keys(const char *companion_name, unsigned char m_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char m_ss[crypto_sign_SECRETKEYBYTES],
						unsigned char x_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char m_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char m_cs[crypto_box_SECRETKEYBYTES],
						unsigned char x_cp[crypto_box_PUBLICKEYBYTES]);
//load persistent keys from files
int load_key_files(const char *companion_name, unsigned char *out_m_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_m_ss[crypto_sign_SECRETKEYBYTES],
						unsigned char *out_x_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_m_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char *out_m_cs[crypto_box_SECRETKEYBYTES],
						unsigned char *out_x_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char *out_h[crypto_hash_BYTES]);
//persistent keys exchange via network
int net_key_exchange(int sock, unsigned char *out_m_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_m_ss[crypto_sign_SECRETKEYBYTES],
						unsigned char *out_x_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_m_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char *out_m_cs[crypto_box_SECRETKEYBYTES],
						unsigned char *out_x_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char *out_h[crypto_hash_BYTES]);
//session keys exchange via network
int create_session_keys(int sock, unsigned char Mm_ss[crypto_sign_SECRETKEYBYTES],
						unsigned char Mx_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char M_ckey[crypto_box_BEFORENMBYTES],
						unsigned char *out_m_ss[crypto_sign_SECRETKEYBYTES],
						unsigned char *out_x_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_ckey[crypto_box_BEFORENMBYTES],
						unsigned char *out_m_n[crypto_box_NONCEBYTES],
						unsigned char *out_x_n[crypto_box_NONCEBYTES],
						unsigned char *out_h[crypto_hash_BYTES]);

#endif
