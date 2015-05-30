/*
crypto.h - заголовочный файл для crypto.c
Лицензия: BSD 2-Clause
*/

//макрозащита, запрещающая подключать этот файл более одного раза
#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "stuff.h"

//генерация файлов с постоянными ключами
int generate_key_files(const char *companion_name);
//сохранить в файлы постоянные ключи текущего сеанса
int save_current_keys(const char *companion_name, unsigned char m_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char m_ss[crypto_sign_SECRETKEYBYTES],
						unsigned char x_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char m_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char m_cs[crypto_box_SECRETKEYBYTES],
						unsigned char x_cp[crypto_box_PUBLICKEYBYTES]);
//загрузить постоянные ключи из файлов на диске
int load_key_files(const char *companion_name, unsigned char *out_m_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_m_ss[crypto_sign_SECRETKEYBYTES],
						unsigned char *out_x_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_m_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char *out_m_cs[crypto_box_SECRETKEYBYTES],
						unsigned char *out_x_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char *out_h[crypto_hash_BYTES]);
//обмен постоянными публичными ключами ЭП и шифрования по сети
int net_key_exchange(int sock, unsigned char *out_m_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_m_ss[crypto_sign_SECRETKEYBYTES],
						unsigned char *out_x_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_m_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char *out_m_cs[crypto_box_SECRETKEYBYTES],
						unsigned char *out_x_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char *out_h[crypto_hash_BYTES]);
//обмен сеансовыми публичными ключами ЭП и шифрования по сети
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
