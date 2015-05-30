/*
crypto.c - cryptographic functions of Osteria
License: BSD 2-Clause
*/

#include "crypto.h"

//--GET HASH OF SIGNATURE AND ENCRYPTION PUBLIC KEYS-----------------------------------------------

void get_pubkeys_hash (unsigned char m_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char x_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char m_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char x_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char *out_h[crypto_hash_BYTES])

{

//сообщение для хеширования, хеш
unsigned char fm[2*crypto_sign_PUBLICKEYBYTES+2*crypto_box_PUBLICKEYBYTES], h[crypto_hash_BYTES];

//сначала записываем в сообщение для хеширования ключи ЭП стороны с бОльшим публичным ключом
if (memcmp(m_sp, x_sp, crypto_sign_PUBLICKEYBYTES) > 0) {
	//если это мы, то сперва записываем наши ключи, потом собеседника
	memcpy(fm, m_sp, crypto_sign_PUBLICKEYBYTES);
	memcpy(fm+crypto_sign_PUBLICKEYBYTES, x_sp, crypto_sign_PUBLICKEYBYTES);
	}
else {
	//иначе это собеседник, то сперва записываем его ключи, потом наши
	memcpy(fm, x_sp, crypto_sign_PUBLICKEYBYTES);
	memcpy(fm+crypto_sign_PUBLICKEYBYTES, m_sp, crypto_sign_PUBLICKEYBYTES);
	}
	
//сначала записываем в сообщение для хеширования ключи шифрования стороны с бОльшим публичным ключом
if (memcmp(m_cp, x_cp, crypto_box_PUBLICKEYBYTES) > 0) {
	//если это мы, то сперва записываем наши ключи, потом собеседника
	memcpy(fm+2*crypto_sign_PUBLICKEYBYTES, m_cp, crypto_box_PUBLICKEYBYTES);
	memcpy(fm+2*crypto_sign_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES, x_cp, crypto_box_PUBLICKEYBYTES);
	}
else {
	//иначе это собеседник, то сперва записываем его ключи, потом наши
	memcpy(fm+2*crypto_sign_PUBLICKEYBYTES, x_cp, crypto_box_PUBLICKEYBYTES);
	memcpy(fm+2*crypto_sign_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES, m_cp, crypto_box_PUBLICKEYBYTES);
	}

//считаем хеш от получившегося сообщения
crypto_hash(h, fm, (2*crypto_sign_PUBLICKEYBYTES+2*crypto_box_PUBLICKEYBYTES));

//возвращаем его в место вызова
memcpy(out_h, h, crypto_hash_BYTES);
    
}

//--GENERATION OF FILES WITH PERSISTENT KEYS-------------------------------------------------------

int generate_key_files (const char *companion_name)
{

FILE *fp;	//файловая переменная
char path[200], path_master[200] = "keys/";
/*текущий путь к файлу/папке, постоянный путь к файлу/папке, имя собеседника, строка для считывания
выбора пользователя "да/нет"*/
size_t bytes_real;	//число реально записанных байт

//ЭП, мы: публичный и секретный ключи
unsigned char m_sp[crypto_sign_PUBLICKEYBYTES], m_ss[crypto_sign_SECRETKEYBYTES];

//шифрование, мы: публичный и секретный ключи
unsigned char m_cp[crypto_box_PUBLICKEYBYTES], m_cs[crypto_box_SECRETKEYBYTES];

//генерируем постоянные ключи ЭП и шифрования
crypto_sign_keypair(m_sp,m_ss);
crypto_box_keypair(m_cp, m_cs);

//--записываем наши публичные ключи-----------------------------------------------------------------

//получаем путь вида "keys/user"
strncat(path_master, companion_name, 30);

//получаем путь вида "keys/user/my_public"
memcpy(path, path_master, 200);
strncat(path, "/my_public", 10);

//если папка my_public не создана, то пытаемся создать её
if (mkdir(path, 0700) == -1)
	if (errno != EEXIST) {
    	perror("mkdir(my_public) error");
    	return 1;
	   	}

//получаем путь вида "keys/user/my_public/public.keys"
strncat(path, "/public.keys", 12);

//пытаемся открыть бинарный файл public.keys для записи
if ((fp = fopen(path, "wb")) == NULL) {
	fprintf(stderr, "Error: cannot open file my_public/public.keys for writing.\n");
    return 1;
	}

//записываем наши публичные ключи ЭП и шифрования в файл
bytes_real = fwrite(m_sp, 1, crypto_sign_PUBLICKEYBYTES, fp);
if (bytes_real < crypto_sign_PUBLICKEYBYTES) {
	fprintf(stderr, "Error: cannot write m_sp in my_public/public.keys.\n");
	fclose(fp);
    return 1;
	}
bytes_real = fwrite(m_cp, 1, crypto_box_PUBLICKEYBYTES, fp);
if (bytes_real < crypto_box_PUBLICKEYBYTES) {
	fprintf(stderr, "Error: cannot write m_cp in my_public/public.keys.\n");
	fclose(fp);
    return 1;
	}

//закрываем открытый файл
if (fclose(fp) == EOF) perror("fclose(my_public/public.keys) error");

//--записываем наши секретные ключи----------------------------------------------------------------

//получаем путь вида "keys/user/my_secret"
memcpy(path, path_master, 200);
strncat(path, "/my_secret", 10);

//если папка my_secret не создана, то пытаемся создать её
if (mkdir(path, 0700) == -1)
	if (errno != EEXIST) {
    	perror("mkdir(my_secret) error");
    	return 1;
	   	}

//получаем путь вида "keys/user/my_secret/secret.keys"
strncat(path, "/secret.keys", 12);

//пытаемся открыть бинарный файл secret.keys для записи
if ((fp = fopen(path, "wb")) == NULL) {
	fprintf(stderr, "Error: cannot open file my_secret/secret.keys for writing.\n");
    return 1;
	}

//записываем наши секретные ключи ЭП и шифрования в файл
bytes_real = fwrite(m_ss, 1, crypto_sign_SECRETKEYBYTES, fp);
if (bytes_real < crypto_sign_SECRETKEYBYTES) {
	fprintf(stderr, "Error: cannot write m_ss in my_secret/secret.keys.\n");
	fclose(fp);
    return 1;
	}
bytes_real = fwrite(m_cs, 1, crypto_box_SECRETKEYBYTES, fp);
if (bytes_real < crypto_box_SECRETKEYBYTES) {
	fprintf(stderr, "Error: cannot write m_cs in my_secret/secret.keys.\n");
	fclose(fp);
    return 1;
	}

//закрываем открытый файл
if (fclose(fp) == EOF) perror("fclose(my_secret/secret.keys) error");

//--создаём папку для публичных ключей собеседника--------------------------------------------------

//получаем путь вида "keys/user/ext_public"
memcpy(path, path_master, 200);
strncat(path, "/ext_public", 11);

//если папка ext_public не создана, то пытаемся создать её
if (mkdir(path, 0700) == -1)
	if (errno != EEXIST) {
    	perror("mkdir(ext_public) error");
    	return 1;
	   	}

return 0;
}

//--SAVING CURRENT SESSION'S PERSISTENT KEYS TO FILES----------------------------------------------

int save_current_keys (const char *companion_name, unsigned char m_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char m_ss[crypto_sign_SECRETKEYBYTES],
						unsigned char x_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char m_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char m_cs[crypto_box_SECRETKEYBYTES],
						unsigned char x_cp[crypto_box_PUBLICKEYBYTES])
{

FILE *fp;	//файловая переменная
char path[200], path_master[200] = "keys/";
//текущий путь к файлу/папке, постоянный путь к файлу/папке
size_t bytes_real;	//число реально записанных байт

//--записываем наши публичные ключи----------------------------------------------------------------

//получаем путь вида "keys/user"
strncat(path_master, companion_name, 30);

//получаем путь вида "keys/user/my_public"
memcpy(path, path_master, 200);
strncat(path, "/my_public", 11);

//если папка ext_public не создана, то пытаемся создать её
if (mkdir(path, 0700) == -1)
	if (errno != EEXIST) {
    	perror("mkdir(my_public) error");
    	return 1;
	   	}

//получаем путь вида "keys/user/my_public/public.keys"
strncat(path, "/public.keys", 12);

//пытаемся открыть бинарный файл public.keys для записи
if ((fp = fopen(path, "wb")) == NULL) {
	fprintf(stderr, "Ошибка: невозможно открыть файл my_public/public.keys для записи.\n");
    return 1;
	}

//записываем наши публичные ключи ЭП и шифрования в файл
bytes_real = fwrite(m_sp, 1, crypto_sign_PUBLICKEYBYTES, fp);
if (bytes_real < crypto_sign_PUBLICKEYBYTES) {
	fprintf(stderr, "Ошибка: невозможно записать m_sp в my_public/public.keys.\n");
	fclose(fp);
    return 1;
	}
bytes_real = fwrite(m_cp, 1, crypto_box_PUBLICKEYBYTES, fp);
if (bytes_real < crypto_box_PUBLICKEYBYTES) {
	fprintf(stderr, "Ошибка: невозможно записать m_cp в my_public/public.keys.\n");
	fclose(fp);
    return 1;
	}

//закрываем открытый файл
if (fclose(fp) == EOF) perror("fclose(my_public/public.keys) error");

//--записываем наши секретные ключи----------------------------------------------------------------

//получаем путь вида "keys/user/my_secret"
memcpy(path, path_master, 200);
strncat(path, "/my_secret", 10);

//если папка my_secret не создана, то пытаемся создать её
if (mkdir(path, 0700) == -1)
	if (errno != EEXIST) {
    	perror("mkdir(my_secret) error");
    	return 1;
	   	}

//получаем путь вида "keys/user/my_secret/secret.keys"
strncat(path, "/secret.keys", 12);

//пытаемся открыть бинарный файл secret.keys для записи
if ((fp = fopen(path, "wb")) == NULL) {
	fprintf(stderr, "Ошибка: невозможно открыть файл my_secret/secret.keys для записи.\n");
    return 1;
	}

//записываем наши секретные ключи ЭП и шифрования в файл
bytes_real = fwrite(m_ss, 1, crypto_sign_SECRETKEYBYTES, fp);
if (bytes_real < crypto_sign_SECRETKEYBYTES) {
	fprintf(stderr, "Ошибка: невозможно записать m_ss в my_secret/secret.keys.\n");
	fclose(fp);
    return 1;
	}
bytes_real = fwrite(m_cs, 1, crypto_box_SECRETKEYBYTES, fp);
if (bytes_real < crypto_box_SECRETKEYBYTES) {
	fprintf(stderr, "Ошибка: невозможно записать m_cs в my_secret/secret.keys.\n");
	fclose(fp);
    return 1;
	}

//закрываем открытый файл
if (fclose(fp) == EOF) perror("fclose(my_secret/secret.keys) error");

//--записываем публичные ключи собеседника---------------------------------------------------------

//получаем путь вида "keys/user/ext_public"
memcpy(path, path_master, 200);
strncat(path, "/ext_public", 11);

//если папка ext_public не создана, то пытаемся создать её
if (mkdir(path, 0700) == -1)
	if (errno != EEXIST) {
    	perror("mkdir(ext_public) error");
    	return 1;
	   	}

//получаем путь вида "keys/user/ext_public/public.keys"
strncat(path, "/public.keys", 12);

//пытаемся открыть бинарный файл public.keys для записи
if ((fp = fopen(path, "wb")) == NULL) {
	fprintf(stderr, "Ошибка: невозможно открыть файл ext_public/public.keys для записи.\n");
    return 1;
	}

//записываем наши публичные ключи ЭП и шифрования в файл
bytes_real = fwrite(x_sp, 1, crypto_sign_PUBLICKEYBYTES, fp);
if (bytes_real < crypto_sign_PUBLICKEYBYTES) {
	fprintf(stderr, "Ошибка: невозможно записать x_sp в ext_public/public.keys.\n");
	fclose(fp);
    return 1;
	}
bytes_real = fwrite(x_cp, 1, crypto_box_PUBLICKEYBYTES, fp);
if (bytes_real < crypto_box_PUBLICKEYBYTES) {
	fprintf(stderr, "Ошибка: невозможно записать x_cp в ext_public/public.keys.\n");
	fclose(fp);
    return 1;
	}

//закрываем открытый файл
if (fclose(fp) == EOF) perror("fclose(ext_public/public.keys) error");

printf("Постоянные ключи для общения с %s успешно сохранены.\n\n", companion_name);

return 0;
}

//--LOAD PERSISTENT KEYS FROM FILES----------------------------------------------------------------

int load_key_files (const char *companion_name, unsigned char *out_m_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_m_ss[crypto_sign_SECRETKEYBYTES],
						unsigned char *out_x_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_m_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char *out_m_cs[crypto_box_SECRETKEYBYTES],
						unsigned char *out_x_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char *out_h[crypto_hash_BYTES])
{
FILE *fp;	//файловая переменная
char path[200], path_master[200] = "keys/";
//текущий путь к файлу/папке, постоянный путь к файлу/папке
size_t bytes_real;					//число реально записанных байт
struct stat st = {0};				//структура для функции stat


//ЭП, мы: публичный и секретный ключи
unsigned char m_sp[crypto_sign_PUBLICKEYBYTES], m_ss[crypto_sign_SECRETKEYBYTES],
//ЭП, собеседник: публичный ключ
x_sp[crypto_sign_PUBLICKEYBYTES];

//шифрование, мы: публичный и секретный ключи
unsigned char m_cp[crypto_box_PUBLICKEYBYTES], m_cs[crypto_box_SECRETKEYBYTES],
//шифрование, собеседник: публичный ключ
x_cp[crypto_box_PUBLICKEYBYTES],

h[crypto_hash_BYTES];	//хеш от публичных ключей

//при отсуствии папки keys выдаём ошибку
if (stat("keys", &st) == -1) {
   	perror("stat(keys) error");
   	return 1;
   	}

//получаем путь вида "keys/user"
strncat(path_master, companion_name, 30);

//при отсуствии папки для собеседника с таким именем выдаём ошибку
if (stat(path_master, &st) == -1) {
	perror("stat(user) error");
	return 1;
	}

//--считываем наши публичные ключи-----------------------------------------------------------------

//получаем путь вида "keys/user/my_public"
memcpy(path, path_master, 200);
strncat(path, "/my_public", 11);

//если папка ext_public не создана, то пытаемся создать её
if (stat(path, &st) == -1) {
   	perror("stat(my_public) error");
   	return 1;
   	}

//получаем путь вида "keys/user/my_public/public.keys"
strncat(path, "/public.keys", 12);

//пытаемся открыть бинарный файл public.keys для чтения
if ((fp = fopen(path, "rb")) == NULL) {
	fprintf(stderr, "Ошибка: невозможно открыть файл my_public/public.keys для чтения.\n");
    return 1;
	}

//записываем наши публичные ключи ЭП и шифрования в файл
bytes_real = fread(m_sp, 1, crypto_sign_PUBLICKEYBYTES, fp);
if (bytes_real < crypto_sign_PUBLICKEYBYTES) {
	fprintf(stderr, "Ошибка: невозможно считать m_sp из my_public/public.keys.\n");
	fclose(fp);
    return 1;
	}
bytes_real = fread(m_cp, 1, crypto_box_PUBLICKEYBYTES, fp);
if (bytes_real < crypto_box_PUBLICKEYBYTES) {
	fprintf(stderr, "Ошибка: невозможно считать m_cp из my_public/public.keys.\n");
	fclose(fp);
    return 1;
	}

//закрываем открытый файл
if (fclose(fp) == EOF) perror("fclose(my_public/public.keys) error");

//--считываем наши секретные ключи-----------------------------------------------------------------

//получаем путь вида "keys/user/my_secret"
memcpy(path, path_master, 200);
strncat(path, "/my_secret", 10);

//при отсуствии папки my_secret выдаём ошибку
if (stat(path, &st) == -1) {
	perror("stat(my_secret) error");
   	return 1;
   	}

//получаем путь вида "keys/user/my_secret/secret.keys"
strncat(path, "/secret.keys", 12);

//пытаемся открыть бинарный файл secret.keys для чтения
if ((fp = fopen(path, "rb")) == NULL) {
	fprintf(stderr, "Ошибка: невозможно открыть файл my_secret/secret.keys для чтения.\n");
    return 1;
	}

//записываем наши секретные ключи ЭП и шифрования в файл
bytes_real = fread(m_ss, 1, crypto_sign_SECRETKEYBYTES, fp);
if (bytes_real < crypto_sign_SECRETKEYBYTES) {
	fprintf(stderr, "Ошибка: невозможно считать m_ss из my_secret/secret.keys.\n");
	fclose(fp);
    return 1;
	}
bytes_real = fread(m_cs, 1, crypto_box_SECRETKEYBYTES, fp);
if (bytes_real < crypto_box_SECRETKEYBYTES) {
	fprintf(stderr, "Ошибка: невозможно считать m_cs из my_secret/secret.keys.\n");
	fclose(fp);
    return 1;
	}

//закрываем открытый файл
if (fclose(fp) == EOF) perror("fclose(my_secret/secret.keys) error");

//--считываем публичные ключи собеседника----------------------------------------------------------

//получаем путь вида "keys/user/ext_public"
memcpy(path, path_master, 200);
strncat(path, "/ext_public", 11);

//если папка ext_public не создана, то пытаемся создать её
if (stat(path, &st) == -1) {
   	perror("stat(ext_public) error");
   	return 1;
   	}

//получаем путь вида "keys/user/ext_public/public.keys"
strncat(path, "/public.keys", 12);

//пытаемся открыть бинарный файл public.keys для чтения
if ((fp = fopen(path, "rb")) == NULL) {
	fprintf(stderr, "Ошибка: невозможно открыть файл ext_public/public.keys для чтения.\n");
    return 1;
	}

//записываем наши публичные ключи ЭП и шифрования в файл
bytes_real = fread(x_sp, 1, crypto_sign_PUBLICKEYBYTES, fp);
if (bytes_real < crypto_sign_PUBLICKEYBYTES) {
	fprintf(stderr, "Ошибка: невозможно считать x_sp из ext_public/public.keys.\n");
	fclose(fp);
    return 1;
	}
bytes_real = fread(x_cp, 1, crypto_box_PUBLICKEYBYTES, fp);
if (bytes_real < crypto_box_PUBLICKEYBYTES) {
	fprintf(stderr, "Ошибка: невозможно считать x_cp из ext_public/public.keys.\n");
	fclose(fp);
    return 1;
	}

//закрываем открытый файл
if (fclose(fp) == EOF) perror("fclose(ext_public/public.keys) error");

printf("Persistent keys for talk with %s successfully loaded.\n", companion_name);

//считаем и выводим хеш от постоянных публичных ключей для защиты от атаки "человек посередине"
get_pubkeys_hash(m_sp, x_sp, m_cp, x_cp, (unsigned char **)&h);

//всё выполнилось правильно, передаём результаты в место вызова
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

int net_key_exchange (int sock, unsigned char *out_m_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_m_ss[crypto_sign_SECRETKEYBYTES],
						unsigned char *out_x_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_m_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char *out_m_cs[crypto_box_SECRETKEYBYTES],
						unsigned char *out_x_cp[crypto_box_PUBLICKEYBYTES],
						unsigned char *out_h[crypto_hash_BYTES])
{

unsigned char fm[2*crypto_sign_PUBLICKEYBYTES+2*crypto_sign_PUBLICKEYBYTES];
//сообщение с публичными ключами для хеширования
unsigned long long bytes_real;
//число фактически переданных/полученных байт

//ЭП, мы: публичный и секретный ключи
unsigned char m_sp[crypto_sign_PUBLICKEYBYTES], m_ss[crypto_sign_SECRETKEYBYTES],
//ЭП, собеседник: публичный ключ
x_sp[crypto_sign_PUBLICKEYBYTES];

//шифрование, мы: публичный и секретный ключи
unsigned char m_cp[crypto_box_PUBLICKEYBYTES], m_cs[crypto_box_SECRETKEYBYTES],
//шифрование, собеседник: публичный ключ
x_cp[crypto_box_PUBLICKEYBYTES],

h[crypto_hash_BYTES];	//хеш от публичных ключей

//генерируем постоянные ключи ЭП и шифрования
crypto_sign_keypair(m_sp, m_ss);
crypto_box_keypair(m_cp, m_cs);

//записываем публичные ключи ЭП и шифрования в сообщение с публичными ключами
memcpy(fm, m_sp, crypto_sign_PUBLICKEYBYTES);
memcpy(fm+crypto_sign_PUBLICKEYBYTES, m_cp, crypto_box_PUBLICKEYBYTES);

//посылаем два публичных ключа собеседнику
if (sendall(sock, (char *)fm, (crypto_sign_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES)) == -1) {
	perror("sendall(m_sp+m_cp) error");
	return 1;
	}

//принимаем публичный ключ ЭП собеседника
bytes_real = recv(sock, x_sp, crypto_sign_PUBLICKEYBYTES, MSG_WAITALL);
switch(bytes_real)
	{case 0: {
		printf("\nCompanion closed the connection.\n");
		return 0;};
	case -1: {
		perror("recv(x_sp) error");
		return 1;};
	}

//принимаем публичный ключ шифрования собеседника
bytes_real = recv(sock, x_cp, crypto_box_PUBLICKEYBYTES, MSG_WAITALL);
switch(bytes_real)
	{case 0: {
		printf("\nCompanion closed the connection.\n");
		return 0;
		};
	case -1: {
		perror("recv(x_cp) error");
		return 1;
		};
	}

printf("Persistent keys exchange via network successfully done.\n");

//считаем и выводим хеш от постоянных публичных ключей для защиты от атаки "человек посередине"
get_pubkeys_hash(m_sp, x_sp, m_cp, x_cp, (unsigned char **)&h);

//всё выполнилось правильно, передаём результаты в место вызова
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

int create_session_keys (int sock, unsigned char Mm_ss[crypto_sign_SECRETKEYBYTES],
						unsigned char Mx_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char M_ckey[crypto_box_BEFORENMBYTES],
						unsigned char *out_m_ss[crypto_sign_SECRETKEYBYTES],
						unsigned char *out_x_sp[crypto_sign_PUBLICKEYBYTES],
						unsigned char *out_ckey[crypto_box_BEFORENMBYTES],
						unsigned char *out_m_n[crypto_box_NONCEBYTES],
						unsigned char *out_x_n[crypto_box_NONCEBYTES],
						unsigned char *out_h[crypto_hash_BYTES])
{

unsigned char m[varmlen], fm[sizeof(uint16_t)+crypto_box_NONCEBYTES+varmlen];
//пользовательское и финальное (передаваемое по сети) сообщения
unsigned long long mlen, bytes_real;
//размер пользовательского и финального сообщений, число фактически переданных/полученных байт

//ЭП, мы: сеансовые публичный и секретный ключи
unsigned char m_sp[crypto_sign_PUBLICKEYBYTES], m_ss[crypto_sign_SECRETKEYBYTES],
//ЭП, собеседник: сеансовый публичный ключ
x_sp[crypto_sign_PUBLICKEYBYTES],
//ЭП, обе стороны: сообщение с ЭП, его длина
sm[varmlen];
unsigned long long smlen;

//шифрование, мы: сеансовые публичный и секретный ключи, нонс
unsigned char m_cp[crypto_box_PUBLICKEYBYTES], m_cs[crypto_box_SECRETKEYBYTES],
m_n[crypto_box_NONCEBYTES],
//шифрование, собеседник: сеансовый публичный ключ, нонс, временный нонс
x_cp[crypto_box_PUBLICKEYBYTES], x_n[crypto_box_NONCEBYTES], x_n_tmp[crypto_box_NONCEBYTES],
/*шифрование, обе стороны: зашифрованное и временное сообщения, комбинация (сеансовых) секретного
нашего и публичного ключа собеседника, хеш для генерации нонса, длины зашифрованного и временного
сообщений (в обычном формате и в формате для передачи по сети), хеш от публичных ключей*/
cm[varmlen], tm[varmlen], ckey[crypto_box_BEFORENMBYTES], h[crypto_hash_BYTES];
unsigned long long cmlen, tmlen;

//генерируем наш начальный нонс, сеансовые ключи ЭП и шифрования
crypto_box_getnonce(m_n);
crypto_sign_keypair(m_sp, m_ss);
crypto_box_keypair(m_cp, m_cs);

//записываем публичные ключи ЭП и шифрования в сообщение для подписи и шифрования
memcpy(m, m_sp, crypto_sign_PUBLICKEYBYTES);
memcpy(m+crypto_sign_PUBLICKEYBYTES, m_cp, crypto_box_PUBLICKEYBYTES);

//подписываем сообщение c ключами нашим постоянным секретным ключом
crypto_sign(sm, &smlen, m, (crypto_sign_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES), Mm_ss);
//перед шифрованием первые 32 байта сообщения должны быть заполнены нулями, добавляем их
bzero(&tm, crypto_box_ZEROBYTES);
memcpy(tm+crypto_box_ZEROBYTES, sm, smlen);
cmlen = smlen+crypto_box_ZEROBYTES;
crypto_box_afternm(cm, tm, cmlen, m_n, M_ckey);	//шифрование cообщения постоянными ключами
//после шифрования первые 16 байтов сообщения заполнены нулями, удаляем их
tmlen = cmlen-crypto_box_BOXZEROBYTES;
memcpy(tm,cm+crypto_box_BOXZEROBYTES,tmlen);

//записываем нонс и зашифрованное сообщение с ключами в сообщение для передачи
memcpy(fm, m_n, crypto_box_NONCEBYTES);
memcpy(fm+crypto_box_NONCEBYTES, tm, tmlen);

//посылаем это сообщение собеседнику
if (sendall(sock, (char *)fm, (crypto_box_NONCEBYTES+tmlen)) == -1) {
	perror("sendall(m_n+m_sp+m_cp) error");
	return 1;
	}
	
//считаем нонс для следующего сообщения как первые 24 байта от хеша зашифрованного сообщения
crypto_hash(h, tm, tmlen);
memcpy(m_n, h, crypto_box_NONCEBYTES);

//принимаем начальный нонс собеседника
bytes_real = recv(sock, x_n, crypto_box_NONCEBYTES, MSG_WAITALL);
switch(bytes_real)
	{case 0: {
		printf("\nCompanion closed the connection.\n");
		return 0;};
	case -1: {
		perror("recv(x_n) error");
		return 1;};
	}

/*принимаем сообщение с сеансовыми ключами, расшифровываем его, проверяем его ЭП для использования
этих ключей при последующем общении*/
bytes_real = recv(sock, tm, tmlen, MSG_WAITALL);
switch(bytes_real)
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
	
/*считаем нонс для следующего сообщения как первые 24 байта от хеша подписанного и зашифрованного
сообщения (запишем его на место старого в случае успешной проверки этого сообщения)*/
crypto_hash(h, tm, tmlen);
memcpy(x_n_tmp, h, crypto_box_NONCEBYTES);

/*после шифрования первые 16 символов сообщения были нулями, мы удалили их перед передачей, а
теперь восстанавливаем*/
bzero(&cm, crypto_box_BOXZEROBYTES);
cmlen = bytes_real+crypto_box_BOXZEROBYTES;
memcpy(cm+crypto_box_BOXZEROBYTES, tm, bytes_real);

//пытаемся расшифровать сообщение
if (crypto_box_open_afternm(tm, cm, cmlen, x_n, M_ckey) == -1) {
	fprintf(stderr, "Error: failed to decrypt message with session keys.\n");
	return 1;
	}
else {
	/*сообщение успешно расшифровано, теперь удаляем из него 32 начальных нуля, добавленных нами
	для функции шифрования*/
	memcpy(sm, tm+crypto_box_ZEROBYTES, bytes_real-crypto_box_BOXZEROBYTES);

	//проверяем электронную подпись сообщения
	if (crypto_sign_open(tm, &mlen, sm, bytes_real-crypto_box_BOXZEROBYTES, Mx_sp) == -1) {
		fprintf(stderr, "Error: message with session keys has wrong signature.\n");
		return 1;
		}
	else {
		//сообщение успешно прошло проверку, а значит, сохраняем полученные значения
		memcpy(x_n, x_n_tmp, crypto_box_NONCEBYTES);
		memcpy(x_sp, tm, crypto_sign_PUBLICKEYBYTES);
		memcpy(x_cp, tm+crypto_sign_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);				
		}	//else memcpy(x_n)
				
	}	//else memcpy(sm)

//собираем комбинацию секретного нашего и публичного ключа собеседника для ускорения работы
crypto_box_beforenm(ckey, x_cp, m_cs);

printf("Session keys exchange via network successfully done.\n");

//считаем и выводим хеш от сеансовых публичных ключей для защиты от атаки "человек посередине"
get_pubkeys_hash(m_sp, x_sp, m_cp, x_cp, (unsigned char **)&h);

memcpy(out_m_ss, m_ss, crypto_sign_SECRETKEYBYTES);
memcpy(out_x_sp, x_sp, crypto_sign_PUBLICKEYBYTES);
memcpy(out_ckey, ckey, crypto_box_BEFORENMBYTES);
memcpy(out_m_n, m_n, crypto_box_NONCEBYTES);
memcpy(out_x_n, x_n, crypto_box_NONCEBYTES);
memcpy(out_h, h, crypto_hash_BYTES);

return 0;
}
