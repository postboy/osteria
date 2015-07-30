/*
stuff.c - additional functions of Osteria
License: BSD 2-Clause
*/

#include "stuff.h"
#include "crypto.h"	//we have to include it for using functions from crypto.c

//--GET SOCKADDR RECORD FOR IPv4 OR IPv6-----------------------------------------------------------

void *get_in_addr (struct sockaddr *sa)
{
	//if we use IPv4, act accordingly
	if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);

	//if not then we use IPv6, act accordingly
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//--MAKE CONNECION AS SERVER-----------------------------------------------------------------------

int go_server (unsigned int serv_port, int net_protocol)
{

char serv_port_str[10], cliaddr[INET6_ADDRSTRLEN];
//server port as string, client address as string
int fresult, listensock, sock, cliport;
//return of called function, sockets for connection and data exchange, cleint port number
const int yes=1;						//variable for function setsockopt()
struct addrinfo *servinfo, hints, *p;
//array of info about server, socket parameters, pointer to next record in servinfo
struct sockaddr_storage clinfo;			//info about client
socklen_t clinfo_size = sizeof clinfo;
//size of clinfo; initialization there is really important to avoid errors & problems with accept()
struct sockaddr_in *s;		//temporary record to get client IP and port number
char datetime_str[50]; 		//date and time as string

printf("Launching server on %i port...\n",serv_port);

//setting up socket
memset(&hints, 0, sizeof hints);		//clear a record with socket parameters
hints.ai_family = net_protocol;					//use IPv4 or IPv6 depending on user's choice
hints.ai_socktype = SOCK_STREAM;		//use stream socket and TCP protocol
hints.ai_flags = AI_PASSIVE;			//get IP address of this computer automatically

//convert server port from int to char for getaddrinfo()
if (snprintf(serv_port_str, 10, "%d", serv_port)<0) {
	fprintf(stderr,"snprintf(serv_port) error\n");
	return 1;
	}

/*create a servinfo record, where IP address is current computer's IP, port is choosen by user,
settings are written in hints record*/
if ((fresult = getaddrinfo(NULL, serv_port_str, &hints, &servinfo)) != 0) {
	fprintf(stderr, "getaddrinfo() error: %s\n", gai_strerror(fresult));
	freeaddrinfo(servinfo);
	return 1;
}

//loop through all results and bind to first we can
for (p = servinfo; p != NULL; p = p->ai_next) {

	//create a socket that will wait for client connection
	if ((listensock = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol)) == -1) {
		perror("socket() error");
		continue;
		}

	/*allow port reusing to avoid "bind() error: address already in use" error. it appears if you
	try to start server on port that was used for same reason less than a minute ago.*/
	if (setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) != 0) {
		perror("setsockopt() error");
		continue;
		}

	//bind newly created socket to port choosen by user
	if ((bind(listensock, servinfo->ai_addr, servinfo->ai_addrlen)) != 0) {
		perror("bind() error");
		//close that socket
		if (close(listensock) != 0) perror("close(listensock) error");
		continue;
		}	//if bind()
		
	break;

	}	//for

freeaddrinfo(servinfo);

//if we could not bind
if (p == NULL)  {
	fprintf(stderr, "Error: can't bind to that port.\n");
	return 1;
	}

//wait for incoming connection from client
if ((listen(listensock, 1)) != 0) {
	perror("listen() error");
	if (close(listensock) != 0) perror("close(listensock) error");
	return 1;
	}

//accept that connection and get a new socket to talk with client
if ((sock = accept(listensock, (struct sockaddr *)&clinfo, &clinfo_size)) == -1) {
	perror("accept() error");
	if (close(listensock) != 0) perror("close(listensock) error");
	return 1;
	}

//close a socket that waited for client connection
if (close(listensock) != 0) perror("close(listensock) error");

//gea an IP address and port from clinfo record
s = (struct sockaddr_in *)&clinfo;
cliport = ntohs(s->sin_port);
inet_ntop(clinfo.ss_family, get_in_addr((struct sockaddr *)&clinfo), cliaddr, sizeof cliaddr);

datetime(datetime_str);	//get date and time of connection

printf("Client %s port %i connected at %s", cliaddr, cliport, datetime_str);

return sock;
}

//--MAKE CONNECION AS CLIENT-----------------------------------------------------------------------

int go_client (const char *server_address, unsigned int serv_port, int net_protocol)
{

int fresult;			//return of called function
struct sockaddr_in6 sa;	//record with server IP address

//convert IP address from string to system format
fresult = inet_pton(net_protocol, server_address, &(sa.sin6_addr));
switch(fresult)
	{case 0: {
		fprintf(stderr, "inet_pton() error: invalid IP address.\n");
		return 1;};
	case -1: {
		perror("inet_pton() error");
		return 1;};
	}

//--connect to server------------------------------------------------------------------------------

char serv_port_str[10];		//server port as string
int sock;					//socket for data exchange
struct addrinfo *servinfo, hints, *p;
//array of info about server, socket parameters, pointer to next record in servinfo
char datetime_str[50];		//date and time as string

printf("Connecting to server %s port %i...\n", server_address, serv_port);

//setting up socket
memset(&hints, 0, sizeof hints);		//clear a record with socket parameters
hints.ai_family = net_protocol;					//use IPv4 or IPv6 depending on user's choice
hints.ai_socktype = SOCK_STREAM;		//use stream socket and TCP protocol

//convert server port from int to char for getaddrinfo()
if (snprintf(serv_port_str, 10, "%d", serv_port)<0)
	{fprintf(stderr,"snprintf(serv_port) error\n");
	return 1;
	}

/*create a servinfo record, where IP address is server IP, port is choosen by user, settings are
written in hints record*/
if ((fresult = getaddrinfo(server_address, serv_port_str, &hints, &servinfo)) != 0) {
	fprintf(stderr, "getaddrinfo() error: %s\n", gai_strerror(fresult));
	freeaddrinfo(servinfo);
	return 1;
	}

//loop through all results and connect to first we can
for (p = servinfo; p != NULL; p = p->ai_next) {

	//create a socket that will be used for data exchange
	if ((sock = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol)) == -1) {
		perror("socket() error");
		freeaddrinfo(servinfo);
		continue;
		}

	//connect to server with IP and port choosen by user
	if ((connect(sock, servinfo->ai_addr, servinfo->ai_addrlen)) != 0) {
		perror("connect() error");
		freeaddrinfo(servinfo);
		if (close(sock) != 0) perror("close() error");
		continue;
		}	//if connect()
		
	break;
	
	}	//for

freeaddrinfo(servinfo);

//if we could not connect
if (p == NULL)  {
	fprintf(stderr, "Error: cannot connect to server.\n");
	return 1;
	}

datetime(datetime_str);	//get date and time of connection

printf("Connected to server at %s",datetime_str);

return sock;
}

//--SEND THE WHOLE MESSAGE-----------------------------------------------------------------------

/*this function forces send() function try to send the whole message - send() don't do it by
default*/
int sendall (int sock, char *buf, int len)
{

//bytes sent, bytes left to send, send() result
int total = 0, bytesleft = len, fresult;

while(total < len) {
	fresult = send(sock, buf+total, bytesleft, 0);
	if (fresult == -1) break;	//an error occured
	total = total + fresult;
	bytesleft = bytesleft - fresult;
	}

    return fresult==-1?-1:0;	//return -1 if an error occured, 0 otherwise
}

//--GET DATE AND TIME------------------------------------------------------------------------------

int datetime (char datetime_str[50])
{

time_t timer;
struct tm *tm_now;

//get current date and time
if (time(&timer) == ((time_t)-1)) {			
	perror("time() error");
	return 1;
	};

if (localtime(&timer) == NULL) {
	fprintf(stderr, "localtime()  error\n");
	return 1;
	};
tm_now = localtime(&timer);

//convert it to string
if (strftime(datetime_str, 50, "%H:%M %d.%m.%y.\n", tm_now) == 0) {
	fprintf(stderr, "strftime(datetime) error\n");
	return 1;
	};

return 0;
}

//--GET TIME---------------------------------------------------------------------------------------

int time_talk (char time_str[15])
{

time_t timer;
struct tm *tm_now;

//get current time
if (time(&timer) == ((time_t)-1)) {			
	perror("time() error");
	return 1;
	};

if (localtime(&timer) == NULL) {
	fprintf(stderr, "localtime() error\n");
	return 1;
	};

tm_now = localtime(&timer);

//convert it to string
if (strftime(time_str, 15, " [%H:%M]\n", tm_now) == 0) {
	fprintf(stderr, "strftime(time) error\n");
	return 1;
	};

return 0;
}
