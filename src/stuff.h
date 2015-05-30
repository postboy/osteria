/*
stuff.h - заголовочный файл для stuff.c
Лицензия: BSD 2-Clause
*/

//макрозащита, запрещающая подключать этот файл более одного раза
#ifndef __STUFF_H__
#define __STUFF_H__

#include "tweetnacl.h"

int go_server(unsigned int serv_port, int mode);	//установка соединения в режиме	"сервер"
//установка соединения в режиме	"клиент"
int go_client(const char *server_address, unsigned int serv_port, int mode);
int sendall(int s, char *buf, int len);	//передача всего сообщения
int datetime(char[50]);					//узнать дату и время
int time_talk(char time_str[10]);		//узнать время для показа в беседе

#endif
