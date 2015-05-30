/* 
poison.h - заголовочный файл, запрещающий использовать уязвимые функции, с дополнениями и изменениями
Лицензия: общественное достояние

Оригинал: https://github.com/leafsr/gcc-poison, версия 04.12.2013
*/

//макрозащита, запрещающая подключать этот файл более одного раза
#ifndef __POISON_H__
#define __POISON_H__
#ifdef __GNUC__

/* Работа со строками */
#	pragma GCC poison strcpy wcscpy stpcpy wcpcpy
#	pragma GCC poison scanf sscanf vscanf fwscanf swscanf wscanf
#	pragma GCC poison gets puts
#	pragma GCC poison strcat wcscat
#	pragma GCC poison wcrtomb wctob
#	pragma GCC poison sprintf vsprintf vfprintf
#	pragma GCC poison asprintf vasprintf
#	pragma GCC poison strncpy wcsncpy
#	pragma GCC poison strtok wcstok
#	pragma GCC poison strdupa strndupa

/* Относящиеся к сигналам */
#	pragma GCC poison longjmp siglongjmp
#	pragma GCC poison setjmp sigsetjmp

/* Выделение памяти */
/*закомментированно, так как иначе выдаётся предупреждение "warning: poisoning existing macro
"alloca" [enabled by default]"*/
//#	pragma GCC poison alloca
#	pragma GCC poison mallopt

/* Файловое API */
#	pragma GCC poison remove
#	pragma GCC poison mktemp tmpnam tempnam
#	pragma GCC poison getwd

/* Разное */
#	pragma GCC poison getlogin getpass cuserid
#	pragma GCC poison rexec rexec_af

/* Выполнение команд/запуск программ */
//использование этого семейства функций часто небезопасно и неоправдано
#	pragma GCC poison system exec execl execlp execle execv execvp execvpe execve fexecve

/* Устаревшие сетевые функции */
#	pragma GCC poison gethostbyname gethostbyaddr inet_ntoa inet_aton

#endif
#endif
