/*
main.c - Osteria GUI organization
License: BSD 2-Clause
*/

#include "crypto.h"

//все эти переменные объявлены глобальными для удобного применения в обработчиках
GtkWidget *server_address_txt, *companion_name_txt, *net_role_combo, *keys_combo,
*net_protocol_combo, *port_spin;	//указатели на элементы управления
GtkTextView *out_view;				//указатель на выходное текстовое представление
GtkTextBuffer *in_buf, *out_buf;	//указатели на текстовые буферы
//указатель на строку, считанную из полей ввода
const gchar *companion_name = NULL;
/*сокет для общения, результат проверки на существование сохранённых постоянных ключей: 0 -
продолжить запись, 2 - прервать её*/
int sock, keys_exist = 2;

//ЭП, мы: сеансовый секретный ключ, постоянные публичный и секретный ключи
unsigned char m_ss[crypto_sign_SECRETKEYBYTES], Mm_sp[crypto_sign_PUBLICKEYBYTES],
Mm_ss[crypto_sign_SECRETKEYBYTES],
//ЭП, собеседник: сеансовый публичный ключ, постоянный публичный ключ
x_sp[crypto_sign_PUBLICKEYBYTES], Mx_sp[crypto_sign_PUBLICKEYBYTES],
//ЭП, обе стороны: сообщение с ЭП, его длина
sm[varmlen];

//шифрование, мы: постоянные публичный и секретный ключи, нонс
unsigned char Mm_cp[crypto_box_PUBLICKEYBYTES], Mm_cs[crypto_box_SECRETKEYBYTES],
m_n[crypto_box_NONCEBYTES],
//шифрование, собеседник: постоянный публичный ключ, нонс, временный нонс
Mx_cp[crypto_box_PUBLICKEYBYTES], x_n[crypto_box_NONCEBYTES], x_n_tmp[crypto_box_NONCEBYTES],
/*шифрование, обе стороны: зашифрованное и временное сообщения, комбинация (сеансовых и постоянных)
секретного нашего и публичного ключа собеседника, хеш для генерации нонса*/
cm[varmlen], tm[varmlen], ckey[crypto_box_BEFORENMBYTES], M_ckey[crypto_box_BEFORENMBYTES],
h[crypto_hash_BYTES];

//хеши от постоянных и сеансовых публичных ключей для защиты от атаки "человек посередине"
unsigned char Mh[crypto_hash_BYTES], Sh[crypto_hash_BYTES];

/*длины сообщений: изначального, подписанного, зашифрованного, временного (в обычном формате и в
формате для передачи по сети), финального, число фактически переданных/полученных байт*/
unsigned long long mlen, smlen, cmlen, tmlen, fmlen, bytes_real;
uint16_t tmlen_network;

//--НАЧАТЬ И ЗАВЕРШИТЬ ВЫВОД В ВЫХОДНОЙ БУФЕР------------------------------------------------------

void begin_insert ()
{
	GtkTextIter end_iter;	//конечный итератор

	//установить курсор в конец выходного буфера
	gtk_text_buffer_get_end_iter(out_buf, &end_iter);
	gtk_text_buffer_place_cursor(out_buf, &end_iter);
}

void end_insert ()
{
	GtkTextMark *mk_end;	//позиция в буфере для его прокрутки при вставке

	//прокрутить выходное представление до конца
	mk_end = gtk_text_buffer_get_mark(out_buf, "insert");
	gtk_text_view_scroll_to_mark(out_view, mk_end, 0.0, FALSE, 0.0, 0.0);
}

//--ПРОВЕРКА НА СУЩЕСТВОВАНИЕ СОХРАНЁННЫХ ПОСТОЯННЫХ КЛЮЧЕЙ----------------------------------------

//считывание выбора пользователя в диалоговом окне
void check_user_choice (GtkDialog *dialog, gint response_id)
{
	//если пользователь нажал "да", то перезаписываем ключи
	if (response_id == GTK_RESPONSE_YES)
		keys_exist = 0;
	//иначе (если нажата кнопка "нет" или окно закрыто) прерываем операцию
	else keys_exist = 2;
}

//собственно проверка с диалогом
int is_keys_exist (GtkWidget *parent_window)
{
	//переменные для создания диалогового сообщения
	GtkWidget *dialog;
	GtkDialogFlags flags = GTK_DIALOG_DESTROY_WITH_PARENT;

	char path[200] = "keys/";	//текущий путь к папке

	//при отсуствии папки keys в каталоге с программой создаём её
	if (mkdir("keys", 0700) == -1)
		if (errno != EEXIST) {
    		perror("mkdir(keys) error");
    		return 1;
		   	}

	//получаем путь вида "keys/user"
	strncat(path, companion_name, 30);

	//папка для собеседника с таким именем уже существует?
	if (mkdir(path, 0700) == -1) {

		//папки для собеседника не было, при попытке её создания произошла ошибка - выходим из процедуры
		if (errno != EEXIST) {
			perror("mkdir(user) error");
			return 1;
			}

		//папка уже создана, спрашиваем пользователя о дальнейших действиях
		else {
	
			dialog = gtk_message_dialog_new(GTK_WINDOW(parent_window), flags, GTK_MESSAGE_QUESTION,
											GTK_BUTTONS_YES_NO,
    	                          			"Найдены файлы постоянных ключей для этого собеседника. Перезаписать?");
			g_signal_connect(dialog, "response", G_CALLBACK (check_user_choice), NULL);
			gtk_dialog_run(GTK_DIALOG(dialog));
			gtk_widget_destroy(dialog);
			
			return keys_exist;	//возвращаем выбор пользователя в диалоге
		
   			}	//else
   		
   		}	//if mkdir()
   		
   	return 0;	//создание папки прошло успешно, туда можно писать

}

//--ВЫВОД ХЕША ОТ ПУБЛИЧНЫХ КЛЮЧЕЙ---------------------------------------------------------------

void show_pubkeys_hash (unsigned char h[crypto_hash_BYTES])
{

char temp[10];	//буфер для промежуточного вывода
int i;			//переменная для цикла

for (i=0; i < crypto_hash_BYTES; i++) {
	snprintf(temp, 2, "%02x", h[i]);	//выводим данные в шестнадцатеричном коде
	gtk_text_buffer_insert_at_cursor(out_buf, temp, -1);
	
	//после вывода байтов с номерами, кратными 32, вставляем пустую строку
	if ((i+1) % 32 == 0) {
		snprintf(temp, 2, "\n");
		gtk_text_buffer_insert_at_cursor(out_buf, temp, -1);
		}

	//после вывода байтов с номерами, кратными 4 и не кратными 32, вставляем пробел
	else if ((i+1) % 4 == 0) {
		snprintf(temp, 2, " ");
		gtk_text_buffer_insert_at_cursor(out_buf, temp, -1);
		}
		
    };	//for

}

//--ОКНО "О ПРОГРАММЕ"-----------------------------------------------------------------------------

void show_about ()
{

GtkBuilder *builder;	//указатель на служебную структуру (после работы очистить)
GtkWidget *about_win;	//указатель на создаваемое окно

//загрузка окна "о программе"
builder = gtk_builder_new();
gtk_builder_add_from_file(builder, "gui/about.glade", NULL);

//закрываем окно при нажатии на кнопку "закрыть"
about_win = GTK_WIDGET(gtk_builder_get_object(builder, "about_window"));
g_signal_connect(G_OBJECT(about_win), "response", G_CALLBACK(gtk_widget_destroy), about_win);

g_object_unref(G_OBJECT(builder));	//освобождаем память

//настройка окна завершена, показать его
gtk_widget_show_all(about_win);

}

//--СЧИТЫВАНИЕ ИЗ ВХОДНОГО БУФЕРА И ОТПРАВКА СООБЩЕНИЯ---------------------------------------------

void send_message ()
{

GtkTextIter start_iter, end_iter;	//итераторы начальный и конечный
gchar *m = NULL;					//пользовательское сообщение (после работы очистить)

char time_str[15];					//текущее время

unsigned char fm[sizeof(uint16_t)+crypto_box_NONCEBYTES+varmlen];
//финальное (передаваемое по сети) сообщения

//устанавливаем считываем пользовательское сообщение с начала входного буфера до его конца
gtk_text_buffer_get_start_iter(in_buf, &start_iter);
gtk_text_buffer_get_end_iter(in_buf, &end_iter);
//gtk_text_buffer_get_iter_at_line_offset(in_buf, &end_iter, 1, 0);
m = gtk_text_buffer_get_text(in_buf, &start_iter, &end_iter, FALSE);
mlen = strlen(m);

//если сообщение имеет слишком большой размер, то обрезаем его до максимально допустимого размера
if (mlen > maxmlen)	mlen = maxmlen;

//обрабатываем и посылаем cообщение, если сокет для общения ещё не закрыт
if ((sock != 0) && (mlen > 0)) {

	//очищаем входной буфер
	gtk_text_buffer_set_text(in_buf, "", -1);
	
	time_talk(time_str);

	//выдаём сообщение в конец выходного буфера и прокручиваем текстовое представление до конца
	begin_insert();
	gtk_text_buffer_insert_at_cursor(out_buf, "\nВы", -1);
	gtk_text_buffer_insert_at_cursor(out_buf, time_str, -1);
	gtk_text_buffer_insert_at_cursor(out_buf, m, -1);
	end_insert();

    //подписываем сообщение нашим секретным ключом
	crypto_sign(sm, &smlen, (const unsigned char *)m, mlen, m_ss);
	//перед шифрованием первые 32 байта сообщения должны быть заполнены нулями, добавляем их
	bzero(&tm, crypto_box_ZEROBYTES);
	memcpy(tm+crypto_box_ZEROBYTES, sm, smlen);
	cmlen = smlen+crypto_box_ZEROBYTES;
	crypto_box_afternm(cm, tm, cmlen, m_n, ckey);	//шифрование cообщения
	//после шифрования первые 16 байтов сообщения заполнены нулями, удаляем их
	tmlen = cmlen-crypto_box_BOXZEROBYTES;
	memcpy(tm,cm+crypto_box_BOXZEROBYTES,tmlen);

	//записываем в первые 2 байта финального сообщения длину его информационной части
	tmlen_network = htons(tmlen);
	memcpy(fm, &tmlen_network, sizeof(uint16_t));
	//а после и само сообщение
	memcpy(fm+sizeof(uint16_t), tm, tmlen);
	//считаем его длину финального сообщения
	fmlen = sizeof(uint16_t)+tmlen;

	//пишем результирующее сообщение в сокет для общения
	if (sendall(sock, (char *)fm, fmlen) == -1) {
			
			perror("sendall(m) error");
			if (close(sock) != 0)
				perror("close(sock) error");
			sock = 0;
			
			//выдаём сообщение в конец выходного буфера и прокручиваем текстовое представление до конца
			begin_insert();
			gtk_text_buffer_insert_at_cursor(out_buf, "\nНе удалось передать сообщение из-за критической ошибки."
											"Соединение будет закрыто.", -1);
			end_insert();
			
			return;
			}

	/*считаем нонс для следующего сообщения как первые 24 байта от хеша подписанного и
	зашифрованного сообщения*/
	crypto_hash(h, tm, tmlen);
	memcpy(m_n, h, crypto_box_NONCEBYTES);

	}	//else

g_free(m);	//освобождаем память

return;

}

//--ОБРАБОТЧИК СОБЫТИЯ "В СОКЕТЕ ДЛЯ ОБЩЕНИЯ ЕСТЬ ДАННЫЕ ДЛЯ СЧИТЫВАНИЯ"---------------------------

gboolean sock_GIO_handler(GIOChannel *source, GIOCondition condition, gpointer data)
{

unsigned char m[varmlen];	//сообщение от собеседника
//длины зашифрованного и временного сообщений (в обычном формате и в формате для передачи по сети)
unsigned long long mlen, cmlen, tmlen;
uint16_t tmlen_network;

char time_str[15];			//текущее время

if (sock == 0) return FALSE;

//принимаем размер зашифрованного сообщения собеседника
bytes_real = recv(sock, &tmlen_network, sizeof(uint16_t), MSG_WAITALL);
switch(bytes_real) {
	case 0: {
	
		if (close(sock) != 0) perror("close(sock) error");
		sock = 0;
		
		//выдаём сообщение в конец выходного буфера и прокручиваем текстовое представление до конца
		begin_insert();
		gtk_text_buffer_insert_at_cursor(out_buf, "\nCompanion closed the connection.", -1);
		end_insert();
		
		return FALSE;
		};
	case -1: {

		perror("recv(tmlen) error");
		if (close(sock) != 0) perror("close(sock) error");
		sock = 0;
		
		//выдаём сообщение в конец выходного буфера и прокручиваем текстовое представление до конца
		begin_insert();
		gtk_text_buffer_insert_at_cursor(out_buf, "\nПроизошла критическая ошибка. Соединение будет закрыто.", -1);
		end_insert();
		
		return FALSE;
		};
	}
		
//переводим его в формат, подходящий для обработки на данном устройстве
tmlen = ntohs(tmlen_network);
//простейшая защита от неправильного размера входного сообщения - требует серьёзной доработки
if (tmlen > varmlen)
	tmlen = varmlen;

//принимаем сообщение с известным размером, расшифровываем его, проверяем его ЭП и выводим на экран
bytes_real = recv(sock, tm, tmlen, MSG_WAITALL);
switch(bytes_real)
	{case 0: {
		
		if (close(sock) != 0) perror("close(sock) error");
		sock = 0;
		
		//выдаём сообщение в конец выходного буфера и прокручиваем текстовое представление до конца
		begin_insert();
		gtk_text_buffer_insert_at_cursor(out_buf, "\nCompanion closed the connection.", -1);
		end_insert();
		
		return FALSE;
		};
	case -1: {
		
		perror("recv(m) error");
		if (close(sock) != 0) perror("close(sock) error");
		sock = 0;
		
		//выдаём сообщение в конец выходного буфера и прокручиваем текстовое представление до конца
		begin_insert();
		gtk_text_buffer_insert_at_cursor(out_buf, "\nПроизошла критическая ошибка. Соединение будет закрыто.", -1);
		end_insert();
		
		return FALSE;
		};
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
if (crypto_box_open_afternm(tm, cm, cmlen, x_n, ckey) == -1) {

	//выдаём сообщение в конец выходного буфера и прокручиваем текстовое представление до конца
	begin_insert();
	gtk_text_buffer_insert_at_cursor(out_buf, "\nОшибка: не удалось расшифровать сообщение.", -1);
	end_insert();

	}
else {
	/*сообщение успешно расшифровано, теперь удаляем из него 32 начальных нуля, добавленных нами
	для функции шифрования*/
	memcpy(sm, tm+crypto_box_ZEROBYTES, bytes_real-crypto_box_BOXZEROBYTES);

	//проверяем электронную подпись сообщения
	if (crypto_sign_open(tm, &mlen, sm, bytes_real-crypto_box_BOXZEROBYTES, x_sp) == -1) {
	
		//выдаём сообщение в конец выходного буфера и прокручиваем текстовое представление до конца
		begin_insert();
		gtk_text_buffer_insert_at_cursor(out_buf, "\nОшибка: поступило сообщение с неверной электронной подписью.", -1);
		end_insert();

		}
	else {
		
		//если оно прошло проверку, то наконец выводим его
		memcpy(m, tm, mlen);
		//перестрахуемся, записав в последний символ сообщения символ конца строки
		m[mlen] = '\0';
		
		time_talk(time_str);

		//выдаём сообщение в конец выходного буфера и прокручиваем текстовое представление до конца
		begin_insert();
		gtk_text_buffer_insert_at_cursor(out_buf, "\n", -1);
		gtk_text_buffer_insert_at_cursor(out_buf, companion_name, -1);
		gtk_text_buffer_insert_at_cursor(out_buf, time_str, -1);
		gtk_text_buffer_insert_at_cursor(out_buf, (const gchar *)m, -1);
		end_insert();
					
		/*сообщение успешно прошло проверку, а значит, записываем ранее	сгенерированный нонс на
		место использованного*/
		memcpy(x_n, x_n_tmp, crypto_box_NONCEBYTES);
							
		}	//else memcpy(m)
				
	}	//else memcpy(sm)

return TRUE;
	
}

//--ОКНО БЕСЕДЫ------------------------------------------------------------------------------------

//обработчик пункта меню "сохранить ключи"
int save_handler (GtkWidget *talk_win)
{
	int fresult;	//результат выполнения функции
	
	//выдаём сообщение в конец выходного буфера и прокручиваем текстовое представление до конца
	begin_insert();
	
	//проверяем, существуют ли на диске постоянные ключи для общения с этим пользователем
	fresult = is_keys_exist(talk_win);
	if (fresult == 1) {
		gtk_text_buffer_insert_at_cursor(out_buf,
										"\nОшибка: не удалось сохранить в файлы постоянные ключи текущего сеанса.", -1);
		end_insert();
		return 1;
		}
	else if (fresult == 2) {
		gtk_text_buffer_insert_at_cursor(out_buf,
										"\nПерезапись постоянных ключей отменена.", -1);
		end_insert();
		return 0;
		}
	
	//если ключей для этого пользователя раньше не было или их можно перезаписать, то сохраняем их
	if (save_current_keys(companion_name, Mm_sp, Mm_ss, Mx_sp, Mm_cp, Mm_cs, Mx_cp) == 1)
		gtk_text_buffer_insert_at_cursor(out_buf,
										"\nОшибка: не удалось сохранить в файлы постоянные ключи текущего сеанса.", -1);
	else
		gtk_text_buffer_insert_at_cursor(out_buf, "\nПостоянные ключи текущего сеанса успешно сохранены.", -1);

	end_insert();

	return 0;
}

//обработчик пункта меню "закрыть соединение"
void close_handler ()
{
	//если сокет для общения ещё не закрыт, то закрываем его и выдаём сообщение
	if (sock != 0) {
	
		if (close(sock) != 0)
			perror("close(sock) error");

		sock = 0;

		//выдаём сообщение в конец выходного буфера и прокручиваем текстовое представление до конца
		begin_insert();
		gtk_text_buffer_insert_at_cursor(out_buf, "\nВы закрыли соединение.", -1);
		end_insert();

		}	//if sock
}

//обработчик пункта меню "выход"/закрытия окна через системное меню
void quit_handler ()
{
	//если сокет для общения ещё не закрыт, то закрываем его
	if (sock != 0)
		if (close(sock) != 0)
			perror("close(sock) error");

	//выходим из главного цикла GTK
	gtk_main_quit();
}

//обработчик нажатия клавиш для обнаружения нажатия на кнопку Enter
gboolean talk_keypress (GtkWidget *widget, GdkEventKey *event, gpointer user_data)
{
	//если она нажата клавиша Enter, то считаем, что была нажата кнопка "отправить"
	if (event->keyval == GDK_KEY_Return)
		send_message();

	return FALSE;
}

//обработчик кнопки "отправить"
void send_button_handler ()
{
	GtkTextIter end_iter;	//конечный итератор

	/*добавляем в конец буфера ввода символ перевода строки для одинакового отображения при нажатии
	на Enter и при нажатии на кнопку "отправить"*/
	gtk_text_buffer_get_end_iter(in_buf, &end_iter);
	gtk_text_buffer_place_cursor(in_buf, &end_iter);
	gtk_text_buffer_insert_at_cursor(in_buf, "\n", -1);

	send_message();
}

//-------------------------------------------------------------------------------------------------

//cоздание окна беседы
void show_talk ()
{
	GtkBuilder *builder;				//указатель на служебную структуру (после работы очистить)
	GtkWidget *talk_win = NULL, *curr_widget;	//указатели на окно и на текущий настраиваемый виджет
	GtkTextView *in_view;				//указатель на входное текстовое представление
	GIOChannel *sock_GIO;				//канал для неблокирующего чтения из сокета для общения

	char datetime_str[50]; 				//текущие дата и время в строке

	//загрузка окна "беседа"
	builder = gtk_builder_new();
	gtk_builder_add_from_file(builder, "gui/talk.glade", NULL);

	//завершаем всё приложение при закрытии этого окна через системное меню
	talk_win = GTK_WIDGET(gtk_builder_get_object(builder, "talk_window"));
	g_signal_connect_swapped(G_OBJECT(talk_win), "destroy", G_CALLBACK(quit_handler), NULL);

	//вызываем обработчик при нажатии клавиш в этом окне для отлова нажатия кнопки Enter
	gtk_widget_add_events(talk_win, GDK_KEY_RELEASE_MASK);
	g_signal_connect(G_OBJECT(talk_win), "key_release_event", G_CALLBACK(talk_keypress), NULL);

	//устанавливаем связь между буферами и представлениями входного и выходного потоков данных
	in_buf = GTK_TEXT_BUFFER(gtk_builder_get_object(builder, "input_buffer"));
	out_buf = GTK_TEXT_BUFFER(gtk_builder_get_object(builder, "output_buffer"));
	in_view = GTK_TEXT_VIEW(gtk_builder_get_object(builder, "input_view"));
	out_view = GTK_TEXT_VIEW(gtk_builder_get_object(builder, "output_view"));
	gtk_text_view_set_buffer(in_view, in_buf);
	gtk_text_view_set_buffer(out_view, out_buf);

	//вызвываем обработчик при нажатии на кнопку "отправить"
	curr_widget = GTK_WIDGET(gtk_builder_get_object(builder, "send_button"));
	g_signal_connect(G_OBJECT(curr_widget), "clicked", G_CALLBACK(send_button_handler), NULL);

	//вызываем обработчик при выборе в меню пункта "сохранить ключи"
	curr_widget = GTK_WIDGET(gtk_builder_get_object(builder, "save-keys_menuitem"));
	g_signal_connect_swapped(G_OBJECT(curr_widget), "activate", G_CALLBACK(save_handler), talk_win);
	//"разорвать соединение"
	curr_widget = GTK_WIDGET(gtk_builder_get_object(builder, "close-connection_menuitem"));
	g_signal_connect(G_OBJECT(curr_widget), "activate", G_CALLBACK(close_handler), NULL);
	//"выход"
	curr_widget = GTK_WIDGET(gtk_builder_get_object(builder, "quit_menuitem"));
	g_signal_connect(G_OBJECT(curr_widget), "activate", G_CALLBACK(quit_handler), NULL);
	//"о программе"
	curr_widget = GTK_WIDGET(gtk_builder_get_object(builder, "about_menuitem"));
	g_signal_connect(G_OBJECT(curr_widget), "activate", G_CALLBACK(show_about), NULL);

	g_object_unref(G_OBJECT(builder));	//освобождаем память

	//создаём канал для неблокирующего чтения из сокета для общения
	sock_GIO = g_io_channel_unix_new(sock);

	//устанавливаем его кодировку в NULL, поскольку мы работаем с двоичными данными
	if (g_io_channel_set_encoding(sock_GIO, NULL, NULL) != G_IO_STATUS_NORMAL)
		fprintf(stderr, "g_io_channel_set_encoding() error.\n");

	//активируем обработчик в тех случаях, когда из сокета есть что прочитать или соединение разорвано
	g_io_add_watch(sock_GIO, G_IO_IN || G_IO_HUP, sock_GIO_handler, NULL);

	gtk_widget_show_all(talk_win);		//настройка окна завершена, показать его

	//выясняем время и дату начала беседы для вывода
	datetime(datetime_str);

	//выдаём сообщение в конец выходного буфера и прокручиваем текстовое представление до конца
	begin_insert();
	gtk_text_buffer_insert_at_cursor(out_buf, "Подключение успешно выполенено в ", -1);
	gtk_text_buffer_insert_at_cursor(out_buf, datetime_str, -1);
	gtk_text_buffer_insert_at_cursor(out_buf, "\nХеш от постоянных публичных ключей:\n", -1);
	show_pubkeys_hash(Mh);
	gtk_text_buffer_insert_at_cursor(out_buf, "\nХеш от сеансовых публичных ключей:\n", -1);
	show_pubkeys_hash(Sh);
	end_insert();
}

//--ОБРАБОТЧИК КНОПКИ "ЗАПУСК" ОКНА НАСТРОЕК СОЕДИНЕНИЯ--------------------------------------------

int launch_handler (GtkWidget *settings_win)
{

//переменные для создания диалогового сообщения
GtkWidget *dialog;
GtkDialogFlags flags = GTK_DIALOG_DESTROY_WITH_PARENT;

//указатель на строку, считанную из поля ввода
const gchar *server_address = NULL;

//указатели на строки, считанные из комбобоксов (после работы очистить)
gchar *net_role = NULL, *keys = NULL, *net_protocol = NULL;

int mode, fresult;		//используемый сетевой протокол, результат выполнения функции
unsigned int serv_port;	//порт сервера

//считываем данные из комбобокса с режимом работы с ключами
keys = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(keys_combo));

//считываем данные из поля ввода с имененм собеседника
companion_name = gtk_entry_get_text(GTK_ENTRY(companion_name_txt));
//если имя собеседника не введено, то назначаем ему значение по умолчанию
if (strcmp(companion_name, "") == 0) companion_name = "Собеседник";

//желаемый режим работы - генерация файлов с ключами? если да, запускаем его
if (strcmp(keys, "записать на диск") == 0) {

	//освобождаем память от данных из комбобокса с режимом работы с ключами
	g_free(keys);
	
	//проверяем, существуют ли на диске постоянные ключи для общения с этим пользователем
	fresult = is_keys_exist(settings_win);
	if (fresult == 1) {
		//если произошла ошибка, сообщаем об этом пользователю
		dialog = gtk_message_dialog_new(GTK_WINDOW(settings_win), flags, GTK_MESSAGE_WARNING,
                                		GTK_BUTTONS_OK,
                                 		"Ошибка: не удалось сгенерировать постоянные ключи для общения с %s.",
										companion_name);
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return 1;
		}
	else if (fresult == 2) {
		//если пользователь отменил перезапись, сообщаем ему об успешной отмене
		dialog = gtk_message_dialog_new(GTK_WINDOW(settings_win), flags, GTK_MESSAGE_INFO,
                                		GTK_BUTTONS_OK,
                                 		"Перезапись постоянных ключей для общения с %s отменена.",
										companion_name);
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return 0;
		}
	
	//вызываем функцию генерации файлов с постоянными ключами
	if (generate_key_files(companion_name) == -1) {
	
		//если произошла ошибка, сообщаем об этом пользователю
		dialog = gtk_message_dialog_new(GTK_WINDOW(settings_win), flags, GTK_MESSAGE_WARNING,
                                		GTK_BUTTONS_OK,
                                 		"Ошибка: не удалось сгенерировать постоянные ключи для общения с %s.",
										companion_name);
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		
		}	//generate_key_files
	else {
	
		//операция прошла успешно, сообщаем об этом пользователю
		dialog = gtk_message_dialog_new(GTK_WINDOW(settings_win), flags, GTK_MESSAGE_INFO,
                                		GTK_BUTTONS_OK,
                                 		"Постоянные ключи для общения с %s успешно сохранены.\n\n"
										"Обменяйтесь с ним публичными ключами по защищённому каналу.",
										companion_name);
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		
		}	//else dialog

	}	//strcmp(записать на диск)

//если выбран другой режим работы с ключами
else {

	//считываем данные из оставшихся полей ввода
	server_address = gtk_entry_get_text(GTK_ENTRY(server_address_txt));
	serv_port = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(port_spin));

	//считываем данные из оставшихся комбобоксов
	net_role = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(net_role_combo));
	net_protocol = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(net_protocol_combo));

	//если задан соответствующий режим, запускаем загрузку ключей из файлов
	if (strcmp(keys, "загрузить с диска") == 0) {
	
		if (load_key_files(companion_name, (unsigned char **)&Mm_sp, (unsigned char **)&Mm_ss,
							(unsigned char **)&Mx_sp, (unsigned char **)&Mm_cp,
							(unsigned char **)&Mm_cs, (unsigned char **)&Mx_cp,
							(unsigned char **)&Mh) == 1) {
							
			//если произошла ошибка, то сообщаем об	этом пользователю и завершаем работу обработчика
			dialog = gtk_message_dialog_new(GTK_WINDOW(settings_win), flags, GTK_MESSAGE_WARNING,
        	                        		GTK_BUTTONS_OK,
        	                        		"Ошибка: не удалось загрузить с диска постоянные ключи для общения с %s.",
											companion_name);
			gtk_dialog_run(GTK_DIALOG(dialog));
			gtk_widget_destroy(dialog);
			
			return 1;
			}	//load_key_files
				
		}	//strcmp(загрузить с диска)
		
		
	//устанавливаем указанный пользователем сетевой протокол
	if (strcmp(net_protocol, "IPv4") == 0)
		mode = AF_INET;
	else
		mode = AF_INET6;
		
	//освобождаем память от данных в соответсвующем комбобоксе
	g_free(net_protocol);
		
	//запускаем установку соединения для сетевой роли, указанной пользователем
	if (strcmp(net_role, "сервер") == 0)
		sock = go_server(serv_port, mode);
	else
		sock = go_client(server_address, serv_port, mode);
		
	//освобождаем память от данных в соответсвующем комбобоксе
	g_free(net_role);
		
	/*если по каким-либо причинам на этапе соединения произошла критическая ошибка, то сообщаем об
	этом пользователю и завершаем работу обработчика*/
	if (sock == 1) {
		dialog = gtk_message_dialog_new(GTK_WINDOW(settings_win), flags, GTK_MESSAGE_WARNING,
                                		GTK_BUTTONS_OK,
                                		"Ошибка: не удалось установить соединение с %s.",
										companion_name);
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
	
		//освобождаем память от данных в соответсвующем комбобоксе
		g_free(keys);
		
		return 1;
		}

	//если задан соответствующий режим, запускаем обмен ключами по сети
	if (strcmp(keys, "обменяться по сети") == 0) {
		if (net_key_exchange(sock, (unsigned char **)&Mm_sp, (unsigned char **)&Mm_ss,
							(unsigned char **)&Mx_sp, (unsigned char **)&Mm_cp,
							(unsigned char **)&Mm_cs, (unsigned char **)&Mx_cp,
							(unsigned char **)&Mh) == 1) {

			//если произошла ошибка, то сообщаем об	этом пользователю и завершаем работу обработчика
			dialog = gtk_message_dialog_new(GTK_WINDOW(settings_win), flags, GTK_MESSAGE_WARNING,
        	                        		GTK_BUTTONS_OK,
        	                        		"Ошибка: не удалось осуществить обмен постоянными ключами с %s по сети.",
											companion_name);
			gtk_dialog_run(GTK_DIALOG(dialog));
			gtk_widget_destroy(dialog);
			
			//освобождаем память от данных в соответсвующем комбобоксе
			g_free(keys);
			
			return 1;
			}	//net_key_exchange
				
		}	//strcmp(обменяться по сети)
	
	//освобождаем память от данных в соответсвующем комбобоксе
	g_free(keys);
	
	//производим генерацию и обмен сеансовыми ключами, подготовив общий ключ шифрования
	crypto_box_beforenm(M_ckey, Mx_cp, Mm_cs);
	if (create_session_keys(sock, Mm_ss, Mx_sp, M_ckey, (unsigned char **)&m_ss,
							(unsigned char **)&x_sp, (unsigned char **)&ckey,
							(unsigned char **)&m_n,	(unsigned char **)&x_n,
							(unsigned char **)Sh) == 1) {
		
		//если произошла ошибка, то сообщаем об	этом пользователю и завершаем работу обработчика
		dialog = gtk_message_dialog_new(GTK_WINDOW(settings_win), flags, GTK_MESSAGE_WARNING,
        	                        	GTK_BUTTONS_OK,
        	                        	"Ошибка: не удалось осуществить обмен сеансовыми ключами с %s по сети.",
										companion_name);
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		
		return 1;
		}	//create_session_keys
		
	//если защищённое соединение установлено, скрываем окно настроек и вызываем окно беседы
	gtk_widget_hide(settings_win);
	show_talk();

	}	//else (режим работы с ключами отличен от "генерации файлов с ключами")

return 0;

}

//--ОКНО НАСТРОЕК СОЕДИНЕНИЯ-----------------------------------------------------------------------

//обработчик изменения сетевой роли
void net_role_changed ()
{
	//указатель на строку, считанную из комбобокса (после работы очистить)
	gchar *net_role = NULL;

	//считываем данные из комбобокса
	net_role = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(net_role_combo));

	//если выбран режим "сервер", то делаем поле ввода адреса сервера неактивным
	if (strcmp(net_role, "сервер") == 0) gtk_widget_set_sensitive(server_address_txt, FALSE);
	//если выбран режим "клиент", то делаем поле ввода адреса сервера активным
	else gtk_widget_set_sensitive(server_address_txt, TRUE);

	g_free(net_role);	//освобождаем память от данных из комбобокса
}

//обработчик изменения режима работы с ключами
void keys_changed ()
{
	//указатель на строку, считанную из комбобокса (после работы очистить)
	gchar *keys = NULL;

	//считываем данные из комбобокса
	keys = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(keys_combo));

	/*если выбран режим "записать на диск", то делаем все элементы управления кроме режима работы с
	ключами и имени собеседника неактивными*/
	if (strcmp(keys, "записать на диск") == 0) {
		gtk_widget_set_sensitive(server_address_txt, FALSE);
		gtk_widget_set_sensitive(net_role_combo, FALSE);
		gtk_widget_set_sensitive(net_protocol_combo, FALSE);
		gtk_widget_set_sensitive(port_spin, FALSE);
		}
	/*если выбран другой режим, то делаем все потенциально неактивные элементы управления кроме
	адреса сервера активными (активность поля адреса сервера определяется вызовом обработчика
	изменения сетевой роли)*/
	else {
		gtk_widget_set_sensitive(net_role_combo, TRUE);
		gtk_widget_set_sensitive(net_protocol_combo, TRUE);
		gtk_widget_set_sensitive(port_spin, TRUE);
	
		/*вызываем обработчик изменения сетевой роли в этом окне, чтобы сделать активным/неактивным
		поле ввода адреса сервера*/
		net_role_changed();
		}

	g_free(keys);	//освобождаем память от данных из комбобокса
}

//-------------------------------------------------------------------------------------------------

int main(int argc, char *argv[])
{
	GtkBuilder *builder;	//указатель на служебную структуру (после работы очистить)
	GtkWidget *settings_win = NULL, *button;	//указатели на создаваемое окно и кнопку

	printf("Osteria %s, debug output\n\n", version);

	/*пытаемся сделать программу восприимчивой ко всем локалям; ошибка здесь не будет критичной,
	поэтому не завершаем работу при её появлении*/
	if (setlocale(LC_ALL, "") == NULL) fprintf(stderr, "setlocale() error\n");

	//инициализация GTK+
	gtk_init(&argc, &argv);

	//загрузка окна "настройка соединения"
	builder = gtk_builder_new();
	gtk_builder_add_from_file(builder, "gui/settings.glade", NULL);

	//завершаем всё приложение при закрытии окна через системное меню
	settings_win = GTK_WIDGET(gtk_builder_get_object(builder, "settings_window"));
	g_signal_connect_swapped(G_OBJECT(settings_win), "destroy", G_CALLBACK(gtk_main_quit), NULL);

	//и при нажатии на кнопку "выход"
	button = GTK_WIDGET(gtk_builder_get_object(builder, "exit_button"));
	g_signal_connect(G_OBJECT(button), "clicked", G_CALLBACK(gtk_main_quit), NULL);

	//при нажатии на кнопку "о программе" показать соответствующее окно
	button = GTK_WIDGET(gtk_builder_get_object(builder, "about_button"));
	g_signal_connect(G_OBJECT(button), "clicked", G_CALLBACK(show_about), NULL);

	//при нажатии на кнопку "запуск" показать соответствующее окно
	button = GTK_WIDGET(gtk_builder_get_object(builder, "launch_button"));
	g_signal_connect_swapped(G_OBJECT(button), "clicked", G_CALLBACK(launch_handler), settings_win);

	//присваиваем глобальным переменным адреса элементов управления этого окна
	server_address_txt = GTK_WIDGET(gtk_builder_get_object(builder, "server-address_text"));
	companion_name_txt = GTK_WIDGET(gtk_builder_get_object(builder, "companion-name_text"));
	net_role_combo = GTK_WIDGET(gtk_builder_get_object(builder, "net-role_combobox"));
	keys_combo = GTK_WIDGET(gtk_builder_get_object(builder, "keys_combobox"));
	net_protocol_combo = GTK_WIDGET(gtk_builder_get_object(builder, "net-protocol_combobox"));
	port_spin = GTK_WIDGET(gtk_builder_get_object(builder, "server-port_spin"));

	g_object_unref(G_OBJECT(builder));	//освобождаем память

	//при изменении сетевой роли или режима работы с ключами запускаем соответствующие обработчики
	g_signal_connect(G_OBJECT(net_role_combo), "changed", G_CALLBACK(net_role_changed), NULL);
	g_signal_connect(G_OBJECT(keys_combo), "changed", G_CALLBACK(keys_changed), NULL);

	//настройка окна завершена, показать его и начать обрабатывать события окон в целом
	gtk_widget_show_all(settings_win);

	gtk_main();

	return 0;
}
