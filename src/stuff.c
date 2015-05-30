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

int go_server (unsigned int serv_port, int mode)
{

//--server launch---------------------------------------------------------------------------------

char serv_port_str[10], cliaddr[INET6_ADDRSTRLEN]; //строка-номер порта сервера, строка-адрес клиента
int fresult, listensock, sock, cliport;
//результат выполнения функции, сокеты для соединения и общения, номер порта клиента
const int yes=1;						//переменная для работы функции setsockopt()
struct addrinfo *servinfo, hints, *p;
//массив информации о сервере, параметры сокета, указатель на текущую запись servinfo
struct sockaddr_storage clinfo;			//информация о клиенте
socklen_t clinfo_size=sizeof clinfo;
/*размер информации о клиенте. инициализация здесь жизненно важна, иначе возникают ошибки и
проблемы с accept()!*/
struct sockaddr_in *s;		//временная запись для добычи IP-адреса и порта клиента из clinfo
char datetime_str[50]; 		//текущие дата и время в строке

printf("Launching server on %i port...\n",serv_port);

//настройка параметров сокета
memset(&hints, 0, sizeof hints);		//обнуляем запись с параметрами сокета
hints.ai_family = mode;					//используем IPv4 либо IPv6 в зависимости от режима
hints.ai_socktype = SOCK_STREAM;		//используем потоковый сокет и протокол TCP
hints.ai_flags = AI_PASSIVE;			//автоматическое заполнение IP-адреса текущего устройства

//перевод номера порта сервера из int в char, необходимый для функции getaddrinfo()
if (snprintf(serv_port_str, 10, "%d", serv_port)<0) {
	fprintf(stderr,"snprintf(serv_port) error\n");
	return 1;
	}

/*создаём запись servinfo с заданными настройками: IP-адрес - IP текущего устройства, порт -
заданный ранее, настройки заданы в записи hints*/
if ((fresult = getaddrinfo(NULL, serv_port_str, &hints, &servinfo)) != 0) {
	fprintf(stderr, "getaddrinfo() error: %s\n", gai_strerror(fresult));
	//очищаем информацию о сервере, чтобы избежать утечек памяти; в дальнейшем поступаем так же
	freeaddrinfo(servinfo);
	return 1;
}

//проходим по всем результатам и осуществляем привязку к первому возможному
for(p = servinfo; p != NULL; p = p->ai_next) {

	//создаём сокет, который будет ожидать подключения
	if ((listensock = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol)) == -1) {
		perror("socket() error");
		continue;
		}

	/*разрешаем повторное использование порта, чтобы избежать ошибки "bind() error: Address
	already in use". она появляется при попытке перезапуске сервера спустя (примерно) менее минуты
	после его закрытия. ошибка здесь не будет критичной, так что не завершаем работу. при
	параноидальной заботе о приватности стоит убрать этот код.*/
	if (setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) != 0) {
		perror("setsockopt() error");
		continue;
		}

	//привязываем созданный сокет к заданному ранее порту на нашем устройстве
	if ((bind(listensock, servinfo->ai_addr, servinfo->ai_addrlen)) != 0) {
		perror("bind() error);
		//напоследок закрываем открытый сокет
		if (close(listensock) != 0) perror("close(listensock) error");
		continue;
		}//if bind()
		
	break;

	}//for()

//если нам не удалось осуществить привязку, выдаём об этом сообщение и завершаем программу
if (p == NULL)  {
	fprintf(stderr, "Error: can't bind to that port.\n");
	freeaddrinfo(servinfo);
	return 1;
	}

//нам больше не понадобится запись servinfo, очищаем её
freeaddrinfo(servinfo);

//ожидаем одного входящего соединения
if ((listen(listensock, 1)) != 0) {
	perror("listen() error");
	if (close(listensock) != 0) perror("close(listensock) error");
	return 1;
	}

//принимаем входящее соединение, получая новый сокет для общения с клиентом
if ((sock = accept(listensock, (struct sockaddr *)&clinfo, &clinfo_size)) == -1) {
	perror("accept() error");
	if (close(listensock) != 0) perror("close(listensock) error");
	return 1;
	}

/*закрываем сокет, ожидавший соединения, так как общение происходит через другой сокет. ошибка
здесь не будет критичной, так что не завершаем работу. при повышенной заботе о приватности стоит
изменить код: в случае ошибки закрыть новый сокет sock и завершить программу возвратом 1.*/
if (close(listensock) != 0) perror("close(listensock) error");

//вытаскиваем из записи clinfo IP-адрес и порт подключившегося устройства для вывода на экран
s = (struct sockaddr_in *)&clinfo;
cliport = ntohs(s->sin_port);
inet_ntop(clinfo.ss_family, get_in_addr((struct sockaddr *)&clinfo), cliaddr, sizeof cliaddr);

//выясняем временя и дату начала беседы для вывода
//ошибки здесь некритичны, так что не останавливаем работу программы при их появлении
datetime(datetime_str);

printf("Клиент %s порт %i успешно подключился в %s", cliaddr, cliport, datetime_str);

return sock;
}

//--MAKE CONNECION AS CLIENT-----------------------------------------------------------------------

int go_client (const char *server_address, unsigned int serv_port, int mode)
{

int fresult;			//результат выполнения функции
struct sockaddr_in6 sa;	//запись для проверки и хранения IP-адреса сервера

//переводим IP-адрес на входе в понятный компьютеру формат
fresult = inet_pton(mode, server_address, &(sa.sin6_addr));
switch(fresult)
	{case 0: {
		fprintf(stderr, "inet_pton() error: invalid IP address.\n");
		return 1;};
	case -1: {
		perror("inet_pton() error");
		return 1;};
	}

//--подключение к серверу--------------------------------------------------------------------------

char serv_port_str[10];				//строка-номер порта сервера
int sock;							//сокет для общения
struct addrinfo *servinfo, hints, *p;
//массив информации о сервере, параметры сокета, указатель на текущую запись servinfo
char datetime_str[50]; 				//текущие дата и время в строке

printf("Соединение с сервером %s порт %i...\n", server_address, serv_port);

//настройка параметров сокета
memset(&hints, 0, sizeof hints);		//обнуляем запись с параметрами сокета
hints.ai_family = mode;					//используем IPv4 либо IPv6 в зависимости от режима
hints.ai_socktype = SOCK_STREAM;		//используем потоковый сокет и протокол TCP

//перевод из int в char, необходимый для функции getaddrinfo()
if (snprintf(serv_port_str, 10, "%d", serv_port)<0)
	{fprintf(stderr,"snprintf(serv_port) error\n");
	return 1;
	}

/*создаём запись servinfo с заданными настройками: IP-адрес - IP сервера, порт - заданный ранее,
настройки заданы в записи hints*/
if ((fresult = getaddrinfo(server_address, serv_port_str, &hints, &servinfo)) != 0) {
	fprintf(stderr, "getaddrinfo() error: %s\n", gai_strerror(fresult));
	//напоследок очищаем информацию о сервере, чтобы избежать утечек памяти
	freeaddrinfo(servinfo);
	return 1;
	}


//проходим по всем результатам и осуществляем подключение к первому возможному
for(p = servinfo; p != NULL; p = p->ai_next) {

	//создаём сокет для последующей работы с ним, используя запись servinfo
	if ((sock = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol)) == -1) {
		perror("socket() error");
		freeaddrinfo(servinfo);
		continue;
		}

	//устанавливаем соединение с сервером по заданному адресу и порту
	if ((connect(sock, servinfo->ai_addr, servinfo->ai_addrlen)) != 0) {
		perror("connect() error");
		freeaddrinfo(servinfo);
		//напоследок закрываем открытый сокет
		if (close(sock) != 0) perror("close() error");
		continue;
		}//if connect()
		
	break;
	
	}//for()
	
//если нам не удалось осуществить подключение, выдаём об этом сообщение и завершаем программу
if (p == NULL)  {
	fprintf(stderr, "Error: cannot connect to server.\n");
	return 1;
	}

//нам больше не понадобится запись servinfo, очищаем её
freeaddrinfo(servinfo);

//выясняем время и дату начала беседы для вывода
//ошибки здесь некритичны, так что не останавливаем работу программы при их появлении
datetime(datetime_str);

printf("Подключение успешно выполенено в %s",datetime_str);

return sock;
}

//--SEND THE WHOLE MESSAGE-----------------------------------------------------------------------

/*эта функция заставляет функцию send() попытаться передать всё сообщение, что не предусмотрено по
умолчанию*/
int sendall (int sock, char *buf, int len)
{

//количество отправленных байтов, количество байтов в очереди, возвращаемое send() значение
int total = 0, bytesleft = len, fresult;

while(total < len) {
	fresult = send(sock, buf+total, bytesleft, 0);
	if (fresult == -1) break;	//произошла ошибка, выходим из цикла
	total = total + fresult;
	bytesleft = bytesleft - fresult;
	}

    return fresult==-1?-1:0;	//возвращаем -1 при ошибке, 0 при успешном выполнении
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
