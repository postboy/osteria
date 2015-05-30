/*
stuff.h - header for stuff.c
License: BSD 2-Clause
*/

//macro guard used to avoid the problem of double inclusion
#ifndef __STUFF_H__
#define __STUFF_H__

#include "tweetnacl.h"

int go_server(unsigned int serv_port, int mode);	//make connection as server
//make connection as client
int go_client(const char *server_address, unsigned int serv_port, int mode);
int sendall(int s, char *buf, int len);	//send the whole message
int datetime(char[50]);					//get date and time
int time_talk(char time_str[10]);		//get time

#endif
