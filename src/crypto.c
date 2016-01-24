/*
crypto.c - cryptographic functions of Osteria
License: BSD 2-Clause
*/

#include "crypto.h"

//--GET HASH OF SIGNATURE AND ENCRYPTION PUBLIC KEYS-----------------------------------------------

static void get_pubkeys_hash (unsigned char m_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char x_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char m_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char x_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char *out_h[crypto_hash_BYTES])

{

//message for hashing, hash
unsigned char fm[2*crypto_sign_PUBLICKEYBYTES+2*crypto_box_PUBLICKEYBYTES], h[crypto_hash_BYTES];

//bigger signature public key goes in a message for hashing first
if (memcmp(m_sp, x_sp, crypto_sign_PUBLICKEYBYTES) > 0) {
	//if it's our key then first write it and secondly companion's one
	memcpy(fm, m_sp, crypto_sign_PUBLICKEYBYTES);
	memcpy(fm+crypto_sign_PUBLICKEYBYTES, x_sp, crypto_sign_PUBLICKEYBYTES);
	}
else {
	//otherwise it's companion's key then first write it than our one
	memcpy(fm, x_sp, crypto_sign_PUBLICKEYBYTES);
	memcpy(fm+crypto_sign_PUBLICKEYBYTES, m_sp, crypto_sign_PUBLICKEYBYTES);
	}
	
//after signature keys, bigger encryption public key goes in a message for hashing first
if (memcmp(m_cp, x_cp, crypto_box_PUBLICKEYBYTES) > 0) {
	//if it's our key then first write it and secondly companion's one
	memcpy(fm+2*crypto_sign_PUBLICKEYBYTES, m_cp, crypto_box_PUBLICKEYBYTES);
	memcpy(fm+2*crypto_sign_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES, x_cp, crypto_box_PUBLICKEYBYTES);
	}
else {
	//otherwise it's companion's key then first write it than our one
	memcpy(fm+2*crypto_sign_PUBLICKEYBYTES, x_cp, crypto_box_PUBLICKEYBYTES);
	memcpy(fm+2*crypto_sign_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES, m_cp, crypto_box_PUBLICKEYBYTES);
	}

//get hash of resulted message
crypto_hash(h, fm, (2*crypto_sign_PUBLICKEYBYTES+2*crypto_box_PUBLICKEYBYTES));

//send hash back to caller
memcpy(out_h, h, crypto_hash_BYTES);
    
}

//--GENERATION OF FILES WITH PERSISTENT KEYS-------------------------------------------------------

extern int generate_key_files (const char *companion_name)
{

FILE *fp;			//file variable
char path[200], path_master[200] = "keys/";
//current path to file or folder, master path to folder
size_t really_written;	//number of really written bytes

//signatures, we: public and secret keys
unsigned char m_sp[crypto_sign_PUBLICKEYBYTES], m_ss[crypto_sign_SECRETKEYBYTES];

//encryption, we: public and secret keys
unsigned char m_cp[crypto_box_PUBLICKEYBYTES], m_cs[crypto_box_SECRETKEYBYTES];

//generate signature and encryption persistent keys
crypto_sign_keypair(m_sp,m_ss);
crypto_box_keypair(m_cp, m_cs);

//--write our public keys--------------------------------------------------------------------------

//get a path like "keys/companion"
strncat(path_master, companion_name, 30);

//get a path like "keys/companion/my_public"
memcpy(path, path_master, 200);
strncat(path, "/my_public", 10);

//if "my_public" folder doesn't exists then create it
if (mkdir(path, 0700) == -1)
	if (errno != EEXIST) {
    	perror("mkdir(my_public) error");
    	return 1;
	   	}

//get a path like "keys/companion/my_public/public.keys"
strncat(path, "/public.keys", 12);

//try to open "public.keys" binary file for writing
if ((fp = fopen(path, "wb")) == NULL) {
	fprintf(stderr, "Error: cannot open file my_public/public.keys for writing.\n");
    return 1;
	}

//write our signature and encryption public keys in file
really_written = fwrite(m_sp, 1, crypto_sign_PUBLICKEYBYTES, fp);
if (really_written < crypto_sign_PUBLICKEYBYTES) {
	fprintf(stderr, "Error: cannot write m_sp in my_public/public.keys file.\n");
	fclose(fp);
    return 1;
	}
really_written = fwrite(m_cp, 1, crypto_box_PUBLICKEYBYTES, fp);
if (really_written < crypto_box_PUBLICKEYBYTES) {
	fprintf(stderr, "Error: cannot write m_cp in my_public/public.keys file.\n");
	fclose(fp);
    return 1;
	}

if (fclose(fp) == EOF) perror("fclose(my_public/public.keys) error");

//--write our secret keys--------------------------------------------------------------------------

//get a path like "keys/companion/my_secret"
memcpy(path, path_master, 200);
strncat(path, "/my_secret", 10);

//if "my_secret" folder doesn't exists then create it
if (mkdir(path, 0700) == -1)
	if (errno != EEXIST) {
    	perror("mkdir(my_secret) error");
    	return 1;
	   	}

//get a path like "keys/companion/my_secret/secret.keys"
strncat(path, "/secret.keys", 12);

//try to open "secret.keys" binary file for writing
if ((fp = fopen(path, "wb")) == NULL) {
	fprintf(stderr, "Error: cannot open file my_secret/secret.keys for writing.\n");
    return 1;
	}

//write our signature and encryption secret keys in file
really_written = fwrite(m_ss, 1, crypto_sign_SECRETKEYBYTES, fp);
if (really_written < crypto_sign_SECRETKEYBYTES) {
	fprintf(stderr, "Error: cannot write m_ss in my_secret/secret.keys file.\n");
	fclose(fp);
    return 1;
	}
really_written = fwrite(m_cs, 1, crypto_box_SECRETKEYBYTES, fp);
if (really_written < crypto_box_SECRETKEYBYTES) {
	fprintf(stderr, "Error: cannot write m_cs in my_secret/secret.keys file.\n");
	fclose(fp);
    return 1;
	}

if (fclose(fp) == EOF) perror("fclose(my_secret/secret.keys) error");

//--create a folder for companion's public keys----------------------------------------------------

//get a path like "keys/companion/ext_public"
memcpy(path, path_master, 200);
strncat(path, "/ext_public", 11);

//if "ext_public" folder doesn't exists then create it
if (mkdir(path, 0700) == -1)
	if (errno != EEXIST) {
    	perror("mkdir(ext_public) error");
    	return 1;
	   	}

return 0;
}

//--SAVING CURRENT SESSION'S PERSISTENT KEYS TO FILES----------------------------------------------

extern int save_current_keys (const char *companion_name, unsigned char m_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char m_ss[crypto_sign_SECRETKEYBYTES],
						unsigned char x_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char m_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char m_cs[crypto_box_SECRETKEYBYTES],
						unsigned char x_cp[crypto_box_PUBLICKEYBYTES])
{

FILE *fp;			//file variable
char path[200], path_master[200] = "keys/";
//current path to file or folder, master path to folder
size_t really_written;	//number of really written bytes

//--write our public keys--------------------------------------------------------------------------

//get a path like "keys/companion"
strncat(path_master, companion_name, 30);

//get a path like "keys/companion/my_public"
memcpy(path, path_master, 200);
strncat(path, "/my_public", 11);

//if "ext_public" folder doesn't exists then create it
if (mkdir(path, 0700) == -1)
	if (errno != EEXIST) {
    	perror("mkdir(my_public) error");
    	return 1;
	   	}

//get a path like "keys/companion/my_public/public.keys"
strncat(path, "/public.keys", 12);

//try to open "public.keys" binary file for writing
if ((fp = fopen(path, "wb")) == NULL) {
	fprintf(stderr, "Error: can't open my_public/public.keys file for writing.\n");
    return 1;
	}

//write our signature and encryption public keys in file
really_written = fwrite(m_sp, 1, crypto_sign_PUBLICKEYBYTES, fp);
if (really_written < crypto_sign_PUBLICKEYBYTES) {
	fprintf(stderr, "Error: can't write m_sp in my_public/public.keys file.\n");
	fclose(fp);
    return 1;
	}
really_written = fwrite(m_cp, 1, crypto_box_PUBLICKEYBYTES, fp);
if (really_written < crypto_box_PUBLICKEYBYTES) {
	fprintf(stderr, "Error: can't write m_cp in my_public/public.keys file.\n");
	fclose(fp);
    return 1;
	}

if (fclose(fp) == EOF) perror("fclose(my_public/public.keys) error");

//--write our secret keys--------------------------------------------------------------------------

//get a path like "keys/companion/my_secret"
memcpy(path, path_master, 200);
strncat(path, "/my_secret", 10);

//if "my_secret" folder doesn't exists then create it
if (mkdir(path, 0700) == -1)
	if (errno != EEXIST) {
    	perror("mkdir(my_secret) error");
    	return 1;
	   	}

//get a path like "keys/companion/my_secret/secret.keys"
strncat(path, "/secret.keys", 12);

//try to open "secret.keys" binary file for writing
if ((fp = fopen(path, "wb")) == NULL) {
	fprintf(stderr, "Error: can't open my_secret/secret.keys file for writing.\n");
    return 1;
	}

//write our signature and encryption secret keys in file
really_written = fwrite(m_ss, 1, crypto_sign_SECRETKEYBYTES, fp);
if (really_written < crypto_sign_SECRETKEYBYTES) {
	fprintf(stderr, "Error: can't write m_ss in my_secret/secret.keys file.\n");
	fclose(fp);
    return 1;
	}
really_written = fwrite(m_cs, 1, crypto_box_SECRETKEYBYTES, fp);
if (really_written < crypto_box_SECRETKEYBYTES) {
	fprintf(stderr, "Error: can't write m_cs in my_secret/secret.keys file.\n");
	fclose(fp);
    return 1;
	}

if (fclose(fp) == EOF) perror("fclose(my_secret/secret.keys) error");

//--write companion's public keys------------------------------------------------------------------

//get a path like "keys/companion/ext_public"
memcpy(path, path_master, 200);
strncat(path, "/ext_public", 11);

//if "ext_public" folder doesn't exists then create it
if (mkdir(path, 0700) == -1)
	if (errno != EEXIST) {
    	perror("mkdir(ext_public) error");
    	return 1;
	   	}

//get a path like "keys/companion/ext_public/public.keys"
strncat(path, "/public.keys", 12);

//try to open "public.keys" binary file for writing
if ((fp = fopen(path, "wb")) == NULL) {
	fprintf(stderr, "Error: can't open ext_public/public.keys file for writing.\n");
    return 1;
	}

//write companion's signature and encryption public keys in file
really_written = fwrite(x_sp, 1, crypto_sign_PUBLICKEYBYTES, fp);
if (really_written < crypto_sign_PUBLICKEYBYTES) {
	fprintf(stderr, "Error: can't write x_sp in ext_public/public.keys file.\n");
	fclose(fp);
    return 1;
	}
really_written = fwrite(x_cp, 1, crypto_box_PUBLICKEYBYTES, fp);
if (really_written < crypto_box_PUBLICKEYBYTES) {
	fprintf(stderr, "Error: can't write x_cp in ext_public/public.keys file.\n");
	fclose(fp);
    return 1;
	}

if (fclose(fp) == EOF) perror("fclose(ext_public/public.keys) error");

printf("Persistent keys for talk with %s successfully saved.\n\n", companion_name);

return 0;
}

//--LOAD PERSISTENT KEYS FROM FILES----------------------------------------------------------------

extern int load_key_files (const char *companion_name, unsigned char *out_m_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_m_ss[crypto_sign_SECRETKEYBYTES],
						unsigned char *out_x_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_m_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char *out_m_cs[crypto_box_SECRETKEYBYTES],
						unsigned char *out_x_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char *out_h[crypto_hash_BYTES])
{
FILE *fp;				//file variable
char path[200], path_master[200] = "keys/";
//current path to file or folder, master path to folder
size_t really_readed;		//number of really readed bytes
struct stat st = {0};	//structure for stat() function


//signatures, we: public and secret keys
unsigned char m_sp[crypto_sign_PUBLICKEYBYTES], m_ss[crypto_sign_SECRETKEYBYTES],
//signatures, companion: public key
x_sp[crypto_sign_PUBLICKEYBYTES];

//encryption, we: public and secret keys
unsigned char m_cp[crypto_box_PUBLICKEYBYTES], m_cs[crypto_box_SECRETKEYBYTES],
//encryption, companion: public key
x_cp[crypto_box_PUBLICKEYBYTES],

h[crypto_hash_BYTES];	//hash of public keys

//check for existence of "keys" folder
if (stat("keys", &st) == -1) {
   	perror("stat(keys) error");
   	return 1;
   	}

//get a path like "keys/companion"
strncat(path_master, companion_name, 30);

//check for existence of a folder with companion's name
if (stat(path_master, &st) == -1) {
	perror("stat(companion) error");
	return 1;
	}

//--read our public keys---------------------------------------------------------------------------

//get a path like "keys/companion/my_public"
memcpy(path, path_master, 200);
strncat(path, "/my_public", 11);

//check for existence of "ext_public" folder
if (stat(path, &st) == -1) {
   	perror("stat(my_public) error");
   	return 1;
   	}

//get a path like "keys/companion/my_public/public.keys"
strncat(path, "/public.keys", 12);

//try to open "public.keys" binary file for reading
if ((fp = fopen(path, "rb")) == NULL) {
	fprintf(stderr, "Error: can't open my_public/public.keys file for reading.\n");
    return 1;
	}

//load our signature and encryption public keys from file
really_readed = fread(m_sp, 1, crypto_sign_PUBLICKEYBYTES, fp);
if (really_readed < crypto_sign_PUBLICKEYBYTES) {
	fprintf(stderr, "Error: failed to read m_sp from my_public/public.keys file.\n");
	fclose(fp);
    return 1;
	}
really_readed = fread(m_cp, 1, crypto_box_PUBLICKEYBYTES, fp);
if (really_readed < crypto_box_PUBLICKEYBYTES) {
	fprintf(stderr, "Error: failed to read m_cp from my_public/public.keys file.\n");
	fclose(fp);
    return 1;
	}

if (fclose(fp) == EOF) perror("fclose(my_public/public.keys) error");

//--read our secret keys---------------------------------------------------------------------------

//get a path like "keys/companion/my_secret"
memcpy(path, path_master, 200);
strncat(path, "/my_secret", 10);

//check for existence of "my_secret" folder
if (stat(path, &st) == -1) {
	perror("stat(my_secret) error");
   	return 1;
   	}

//get a path like "keys/companion/my_secret/secret.keys"
strncat(path, "/secret.keys", 12);

//try to open "secret.keys" binary file for reading
if ((fp = fopen(path, "rb")) == NULL) {
	fprintf(stderr, "Error: can't open my_secret/secret.keys file for reading.\n");
    return 1;
	}

//load our signature and encryption secret keys from file
really_readed = fread(m_ss, 1, crypto_sign_SECRETKEYBYTES, fp);
if (really_readed < crypto_sign_SECRETKEYBYTES) {
	fprintf(stderr, "Error: failed to read m_ss from my_secret/secret.keys file.\n");
	fclose(fp);
    return 1;
	}
really_readed = fread(m_cs, 1, crypto_box_SECRETKEYBYTES, fp);
if (really_readed < crypto_box_SECRETKEYBYTES) {
	fprintf(stderr, "Error: failed to read m_cs from my_secret/secret.keys file.\n");
	fclose(fp);
    return 1;
	}

if (fclose(fp) == EOF) perror("fclose(my_secret/secret.keys) error");

//--read companion's public keys-------------------------------------------------------------------

//get a path like "keys/companion/ext_public"
memcpy(path, path_master, 200);
strncat(path, "/ext_public", 11);

//check for existence of "ext_public" folder
if (stat(path, &st) == -1) {
   	perror("stat(ext_public) error");
   	return 1;
   	}

//get a path like "keys/companion/ext_public/public.keys"
strncat(path, "/public.keys", 12);

//try to open "public.keys" binary file for reading
if ((fp = fopen(path, "rb")) == NULL) {
	fprintf(stderr, "Error: can't open ext_public/public.keys file for reading.\n");
    return 1;
	}

//load companion's signature and encryption public keys from file
really_readed = fread(x_sp, 1, crypto_sign_PUBLICKEYBYTES, fp);
if (really_readed < crypto_sign_PUBLICKEYBYTES) {
	fprintf(stderr, "Error: failed to read x_sp from ext_public/public.keys file.\n");
	fclose(fp);
    return 1;
	}
really_readed = fread(x_cp, 1, crypto_box_PUBLICKEYBYTES, fp);
if (really_readed < crypto_box_PUBLICKEYBYTES) {
	fprintf(stderr, "Error: failed to read x_cp from ext_public/public.keys file.\n");
	fclose(fp);
    return 1;
	}

if (fclose(fp) == EOF) perror("fclose(ext_public/public.keys) error");

printf("Persistent keys for talk with %s successfully loaded.\n", companion_name);

//get hash of persistent public keys for protection against "man-in-the-middle" attack
get_pubkeys_hash(m_sp, x_sp, m_cp, x_cp, (unsigned char **)&h);

//send results back to caller
memcpy(out_m_sp, m_sp, crypto_sign_PUBLICKEYBYTES);
memcpy(out_m_ss, m_ss, crypto_sign_SECRETKEYBYTES);
memcpy(out_x_sp, x_sp, crypto_sign_PUBLICKEYBYTES);
memcpy(out_m_cp, m_cp, crypto_box_PUBLICKEYBYTES);
memcpy(out_m_cs, m_cs, crypto_box_SECRETKEYBYTES);
memcpy(out_x_cp, x_cp, crypto_box_PUBLICKEYBYTES);
memcpy(out_h, h, crypto_hash_BYTES);

return 0;
}

//--PERSISTENT KEYS EXCHANGE VIA NETWORK-----------------------------------------------------------

extern int net_key_exchange (int sock, unsigned char *out_m_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_m_ss[crypto_sign_SECRETKEYBYTES],
						unsigned char *out_x_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_m_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char *out_m_cs[crypto_box_SECRETKEYBYTES],
						unsigned char *out_x_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char *out_h[crypto_hash_BYTES])
{

unsigned char fm[2*crypto_sign_PUBLICKEYBYTES+2*crypto_sign_PUBLICKEYBYTES];
//message with public keys
unsigned long long really_received;	//number of really received bytes

//signatures, we: public and secret keys
unsigned char m_sp[crypto_sign_PUBLICKEYBYTES], m_ss[crypto_sign_SECRETKEYBYTES],
//signatures, companion: public key
x_sp[crypto_sign_PUBLICKEYBYTES];

//encryption, we: public and secret keys
unsigned char m_cp[crypto_box_PUBLICKEYBYTES], m_cs[crypto_box_SECRETKEYBYTES],
//encryption, companion: public key
x_cp[crypto_box_PUBLICKEYBYTES],

h[crypto_hash_BYTES];	//hash of public keys

//generate signature and encryption persistent keys
crypto_sign_keypair(m_sp, m_ss);
crypto_box_keypair(m_cp, m_cs);

//write signature and encryption public keys signatures in a message with public keys
memcpy(fm, m_sp, crypto_sign_PUBLICKEYBYTES);
memcpy(fm+crypto_sign_PUBLICKEYBYTES, m_cp, crypto_box_PUBLICKEYBYTES);

//send 2 public keys to companion
if (sendall(sock, (char *)fm, (crypto_sign_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES)) == -1) {
	perror("sendall(m_sp+m_cp) error");
	return 1;
	}

//receive companion's signature public key
really_received = recv(sock, x_sp, crypto_sign_PUBLICKEYBYTES, MSG_WAITALL);
switch(really_received)
	{case 0: {
		printf("\nCompanion closed the connection.\n");
		return 0;};
	case -1: {
		perror("recv(x_sp) error");
		return 1;};
	}

//receive companion's encryption public key
really_received = recv(sock, x_cp, crypto_box_PUBLICKEYBYTES, MSG_WAITALL);
switch(really_received)
	{case 0: {
		printf("\nCompanion closed the connection.\n");
		return 0;
		};
	case -1: {
		perror("recv(x_cp) error");
		return 1;
		};
	}

printf("Persistent keys exchange via network done.\n");

//get hash of persistent public keys for protection against "man-in-the-middle" attack
get_pubkeys_hash(m_sp, x_sp, m_cp, x_cp, (unsigned char **)&h);

//send results back to caller
memcpy(out_m_sp, m_sp, crypto_sign_PUBLICKEYBYTES);
memcpy(out_m_ss, m_ss, crypto_sign_SECRETKEYBYTES);
memcpy(out_x_sp, x_sp, crypto_sign_PUBLICKEYBYTES);
memcpy(out_m_cp, m_cp, crypto_box_PUBLICKEYBYTES);
memcpy(out_m_cs, m_cs, crypto_box_SECRETKEYBYTES);
memcpy(out_x_cp, x_cp, crypto_box_PUBLICKEYBYTES);
memcpy(out_h, h, crypto_hash_BYTES);

return 0;
}

//--SESSION KEYS EXCHANGE VIA NETWORK--------------------------------------------------------------

extern int create_session_keys (int sock, unsigned char Mm_ss[crypto_sign_SECRETKEYBYTES],
						unsigned char Mx_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char M_ckey[crypto_box_BEFORENMBYTES],
						unsigned char *out_m_ss[crypto_sign_SECRETKEYBYTES],
						unsigned char *out_x_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_ckey[crypto_box_BEFORENMBYTES],
						unsigned char *out_m_n[crypto_box_NONCEBYTES],
						unsigned char *out_x_n[crypto_box_NONCEBYTES],
						unsigned char *out_h[crypto_hash_BYTES])
{

unsigned char m[crypto_sign_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES], fm[varmlen];
//message with public keys (original, after signing and encryption with persistent keys)
unsigned long long mlen, really_received;
//size of original and final messages, number of really received bytes

//signatures, we: session public and secret keys
unsigned char m_sp[crypto_sign_PUBLICKEYBYTES], m_ss[crypto_sign_SECRETKEYBYTES],
//signatures, companion: session public key
x_sp[crypto_sign_PUBLICKEYBYTES],
//signatures, both sides: signed message, it's length
sm[varmlen];
unsigned long long smlen;

//encryption, we: session public and secret keys, nonce
unsigned char m_cp[crypto_box_PUBLICKEYBYTES], m_cs[crypto_box_SECRETKEYBYTES],
m_n[crypto_box_NONCEBYTES],
//encryption, companion: session public key, nonce, unverified nonce
x_cp[crypto_box_PUBLICKEYBYTES], x_n[crypto_box_NONCEBYTES], x_n_tmp[crypto_box_NONCEBYTES],
/*encryption, both sides: encrypted and temporary messages, combination of our secret and
companion's public keys, hash for nonce generation, lengths of encrypted and temporary messages*/
cm[varmlen], tm[varmlen], ckey[crypto_box_BEFORENMBYTES], h[crypto_hash_BYTES];
unsigned long long cmlen, tmlen;

//generate our first nonce, signature and encryption session keys
randombytes(m_n, crypto_box_NONCEBYTES);
crypto_sign_keypair(m_sp, m_ss);
crypto_box_keypair(m_cp, m_cs);

//write our signature and encryption public keys in message for signing and encryption
memcpy(m, m_sp, crypto_sign_PUBLICKEYBYTES);
memcpy(m+crypto_sign_PUBLICKEYBYTES, m_cp, crypto_box_PUBLICKEYBYTES);

//sign that message through our persistent secret key
crypto_sign(sm, &smlen, m, (crypto_sign_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES), Mm_ss);
//first 32 bytes of message should be cleared before encryption, add 32 zero bytes
bzero(&tm, crypto_box_ZEROBYTES);
memcpy(tm+crypto_box_ZEROBYTES, sm, smlen);
cmlen = smlen+crypto_box_ZEROBYTES;
crypto_box_afternm(cm, tm, cmlen, m_n, M_ckey);	//encryption of message through persistent keys
//first 16 bytes of message are zero bytes, remove them
tmlen = cmlen-crypto_box_BOXZEROBYTES;
memcpy(tm,cm+crypto_box_BOXZEROBYTES,tmlen);

//write a nonce and encrypted message with public keys in final message
memcpy(fm, m_n, crypto_box_NONCEBYTES);
memcpy(fm+crypto_box_NONCEBYTES, tm, tmlen);

//write final message in socket for data exchange
if (sendall(sock, (char *)fm, (crypto_box_NONCEBYTES+tmlen)) == -1) {
	perror("sendall(m_n+m_sp+m_cp) error");
	return 1;
	}
	
//get a nonce for our next message as first 24 bytes of hash of encrypted message
crypto_hash(h, tm, tmlen);
memcpy(m_n, h, crypto_box_NONCEBYTES);

//receive a first companion's nonce
really_received = recv(sock, x_n, crypto_box_NONCEBYTES, MSG_WAITALL);
switch(really_received)
	{case 0: {
		printf("\nCompanion closed the connection.\n");
		return 0;};
	case -1: {
		perror("recv(x_n) error");
		return 1;};
	}

//receive a message with session public keys, decrypt it, check it's signature and use that keys
really_received = recv(sock, tm, tmlen, MSG_WAITALL);
switch(really_received)
	{case 0: {
		printf("\nCompanion closed the connection.\n");
		if (close(sock) != 0) {
			perror("close(sock) error");
			return 1;
			}
		return 0;};
	case -1: {
		perror("recv(m) error");
		if (close(sock) != 0) perror("close(sock) error");
		return 1;};
	}
	
/*get a nonce for companion's next message as first 24 bytes of hash of encrypted message (we will
overwrite an old nonce if this message will be successfully authentificated)*/
crypto_hash(h, tm, tmlen);
memcpy(x_n_tmp, h, crypto_box_NONCEBYTES);

//first 16 bytes should be zero bytes for successful decryption, add them
bzero(&cm, crypto_box_BOXZEROBYTES);
cmlen = really_received+crypto_box_BOXZEROBYTES;
memcpy(cm+crypto_box_BOXZEROBYTES, tm, really_received);

//try to decrypt message
if (crypto_box_open_afternm(tm, cm, cmlen, x_n, M_ckey) == -1) {
	fprintf(stderr, "Error: failed to decrypt received message with session keys.\n");
	return 1;
	}
else {
	//message has been successfully decrypted, delete first 32 zero bytes in the beginning
	memcpy(sm, tm+crypto_box_ZEROBYTES, really_received-crypto_box_BOXZEROBYTES);

	//check a signature of decrypted message
	if (crypto_sign_open(tm, &mlen, sm, really_received-crypto_box_BOXZEROBYTES, Mx_sp) == -1) {
		fprintf(stderr, "Error: received message with session keys has wrong signature.\n");
		return 1;
		}
	else {
		//message was successfully authentificated, so save keys from it
		memcpy(x_n, x_n_tmp, crypto_box_NONCEBYTES);
		memcpy(x_sp, tm, crypto_sign_PUBLICKEYBYTES);
		memcpy(x_cp, tm+crypto_sign_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);				
		}	//else memcpy(x_n)
				
	}	//else memcpy(sm)

//get a combination of our secret and companion's public keys for faster work
crypto_box_beforenm(ckey, x_cp, m_cs);

printf("Session keys exchange via network done.\n");

//get hash of session public keys for protection against "man-in-the-middle" attack
get_pubkeys_hash(m_sp, x_sp, m_cp, x_cp, (unsigned char **)&h);

memcpy(out_m_ss, m_ss, crypto_sign_SECRETKEYBYTES);
memcpy(out_x_sp, x_sp, crypto_sign_PUBLICKEYBYTES);
memcpy(out_ckey, ckey, crypto_box_BEFORENMBYTES);
memcpy(out_m_n, m_n, crypto_box_NONCEBYTES);
memcpy(out_x_n, x_n, crypto_box_NONCEBYTES);
memcpy(out_h, h, crypto_hash_BYTES);

return 0;
}
