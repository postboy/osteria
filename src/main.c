/*
main.c - Osteria GUI organization
License: BSD 2-Clause
*/

#include "crypto.h"

//all that variables are declared as global for easy using in handlers
static GtkWidget *server_address_txt, *companion_name_txt, *net_role_combo, *keys_combo,
*net_protocol_combo, *port_spin;	//pointers to GUI elements
static GtkTextView *out_view;				//pointer to output view
static GtkTextBuffer *in_buf, *out_buf;	//pointers to text buffers
//pointer to string from input field
static const gchar *companion_name = NULL;
/*socket for data exchange, does persistent keys for that companion exists: 0 - continue writing,
2 - abort it*/
static int sock, keys_exist = 2;

//signatures, we: session secret key, persistent public and secret keys
static unsigned char m_ss[crypto_sign_SECRETKEYBYTES], Mm_sp[crypto_sign_PUBLICKEYBYTES],
Mm_ss[crypto_sign_SECRETKEYBYTES],
//signatures, companion: session public key, persistent public key
x_sp[crypto_sign_PUBLICKEYBYTES], Mx_sp[crypto_sign_PUBLICKEYBYTES],
//signatures, both sides: signed message
sm[varmlen];

//encryption, we: persistent public and secret keys, nonce
static unsigned char Mm_cp[crypto_box_PUBLICKEYBYTES], Mm_cs[crypto_box_SECRETKEYBYTES],
m_n[crypto_box_NONCEBYTES],
//encryption, companion: persistent public key, nonce, unverified nonce
Mx_cp[crypto_box_PUBLICKEYBYTES], x_n[crypto_box_NONCEBYTES], x_n_tmp[crypto_box_NONCEBYTES],
/*encryption, both sides: encrypted and temporary messages, combination of (session and persistent)
our secret and companion's public keys, hash for nonce generation*/
cm[varmlen], tm[varmlen], ckey[crypto_box_BEFORENMBYTES], M_ckey[crypto_box_BEFORENMBYTES],
h[crypto_hash_BYTES];

//hashes of persistent and session public keys for protection against "man-in-the-middle" attack
static unsigned char Mh[crypto_hash_BYTES], Sh[crypto_hash_BYTES];

/*lengths of messages: original, signed, encrypted, temporary (in usual format and in format for
network sending), final; number of really recieved bytes*/
static unsigned long long mlen, smlen, cmlen, tmlen, fmlen, really_recvieved;
static uint16_t tmlen_network;

//--BEGIN AND END INSERTION IN OUTPUT BUFFER-------------------------------------------------------

static void begin_insert ()
{
	GtkTextIter end_iter;	//end iterator

	//move cursor to the end of output buffer
	gtk_text_buffer_get_end_iter(out_buf, &end_iter);
	gtk_text_buffer_place_cursor(out_buf, &end_iter);
}

static void end_insert ()
{
	GtkTextMark *mk_end;	//position in buffer for it's scrolling after insert

	//scroll output view to bottom
	mk_end = gtk_text_buffer_get_mark(out_buf, "insert");
	gtk_text_view_scroll_to_mark(out_view, mk_end, 0.0, FALSE, 0.0, 0.0);
}

//--CHECK FOR EXISTENCE OF SAVED PERMANENT KEYS----------------------------------------------------

//reading user's choice in dialog window
static void check_user_choice (GtkDialog *dialog, gint response_id)
{
	//if user pressed "yes" then rewrite keys
	if (response_id == GTK_RESPONSE_YES)
		keys_exist = 0;
	//if user pressed "no" or closed dialog window then break this operation
	else keys_exist = 2;
}

//existence check with a dialog window
static int is_keys_exist (GtkWidget *parent_window)
{
	//variables for dialog window creation
	GtkWidget *dialog;
	GtkDialogFlags flags = GTK_DIALOG_DESTROY_WITH_PARENT;

	char path[200] = "keys/";	//current path to folder

	//if there's no "keys" folder near the program then create it
	if (mkdir("keys", 0700) == -1)
		if (errno != EEXIST) {
    		perror("mkdir(keys) error");
    		return 1;
		   	}

	//get a path like "keys/user"
	strncat(path, companion_name, 30);

	//if folder for current companion already exists?
	if (mkdir(path, 0700) == -1) {

		//there wasn't such folder, then when we tried to create it and an error occured
		if (errno != EEXIST) {
			perror("mkdir(user) error");
			return 1;
			}

		//folder already exists, ask a user for following actions
		else {
	
			dialog = gtk_message_dialog_new(GTK_WINDOW(parent_window), flags, GTK_MESSAGE_QUESTION,
											GTK_BUTTONS_YES_NO,
    	                          			"Previously saved keys for current companion has been found. Rewrite?");
			g_signal_connect(dialog, "response", G_CALLBACK (check_user_choice), NULL);
			gtk_dialog_run(GTK_DIALOG(dialog));
			gtk_widget_destroy(dialog);
			
			return keys_exist;	//return user's choice in dialog window
		
   			}	//else
   		
   		}	//if mkdir()
   		
   	return 0;	//folder was successfully created, we can write there

}

//--PRINT A HASH OF PUBLIC KEYS--------------------------------------------------------------------

static void show_pubkeys_hash (unsigned char h[crypto_hash_BYTES])
{

	char temp[10];	//buffer for temporary output
	int i;			//variable for cycle

	for (i=0; i < crypto_hash_BYTES; i++) {
		snprintf(temp, 4, "%02x", h[i]);	//output format of hash is HEX-code
		gtk_text_buffer_insert_at_cursor(out_buf, temp, -1);
	
		//place a line feed every 16 bytes
		if ((i+1) % 16 == 0) {
			snprintf(temp, 2, "\n");
			gtk_text_buffer_insert_at_cursor(out_buf, temp, -1);
			}

		//place a space every 2 bytes
		else if ((i+1) % 2 == 0) {
			snprintf(temp, 2, " ");
			gtk_text_buffer_insert_at_cursor(out_buf, temp, -1);
			}
		
    	};	//for

}

//--ABOUT WINDOW-----------------------------------------------------------------------------------

static void show_about ()
{

	GtkBuilder *builder;	//pointer to service structure (free after work)
	GtkWidget *about_win;	//pointer to window

	//load "about" window
	builder = gtk_builder_new();
	gtk_builder_add_from_file(builder, "gui/about.glade", NULL);

	//close window if "close" button is pressed
	about_win = GTK_WIDGET(gtk_builder_get_object(builder, "about_window"));
	g_signal_connect(G_OBJECT(about_win), "response", G_CALLBACK(gtk_widget_destroy), about_win);

	g_object_unref(G_OBJECT(builder));

	gtk_widget_show_all(about_win);

}

//--READING FROM INPUT BUFFER AND MESSAGE SENDING--------------------------------------------------

static void send_message ()
{

GtkTextIter start_iter, end_iter;	//start and end iterators
gchar *m = NULL;					//user message (free after work)

char time_str[15];					//current time

unsigned char fm[sizeof(uint16_t)+crypto_box_NONCEBYTES+varmlen];
//final message for sending via network

//read user message from beginning of input buffer to it's end
gtk_text_buffer_get_start_iter(in_buf, &start_iter);
gtk_text_buffer_get_end_iter(in_buf, &end_iter);
//gtk_text_buffer_get_iter_at_line_offset(in_buf, &end_iter, 1, 0);
m = gtk_text_buffer_get_text(in_buf, &start_iter, &end_iter, FALSE);
mlen = strlen(m);

//if message is too big then cut it
if (mlen > maxmlen)	mlen = maxmlen;

//if socket for data exchange isn't closed, send a message
if ((sock != 0) && (mlen > 0)) {

	//clear input buffer
	gtk_text_buffer_set_text(in_buf, "", -1);
	
	time_talk(time_str);

	begin_insert();
	gtk_text_buffer_insert_at_cursor(out_buf, "\nYou", -1);
	gtk_text_buffer_insert_at_cursor(out_buf, time_str, -1);
	gtk_text_buffer_insert_at_cursor(out_buf, m, -1);
	end_insert();

    //sign a message with our secret key
	crypto_sign(sm, &smlen, (const unsigned char *)m, mlen, m_ss);
	//first 32 bytes of message should be cleared before encryption, add 32 zero bytes
	bzero(&tm, crypto_box_ZEROBYTES);
	memcpy(tm+crypto_box_ZEROBYTES, sm, smlen);
	cmlen = smlen+crypto_box_ZEROBYTES;
	crypto_box_afternm(cm, tm, cmlen, m_n, ckey);	//message encryption
	//first 16 bytes of message are zero bytes, remove them
	tmlen = cmlen-crypto_box_BOXZEROBYTES;
	memcpy(tm,cm+crypto_box_BOXZEROBYTES,tmlen);

	//write a length of encrypted message to first 2 bytes of final message
	tmlen_network = htons(tmlen);
	memcpy(fm, &tmlen_network, sizeof(uint16_t));
	memcpy(fm+sizeof(uint16_t), tm, tmlen);	//then add to the encrypted message itself
	fmlen = sizeof(uint16_t)+tmlen;			//get final message length

	//write final message in socket for data exchange
	if (sendall(sock, (char *)fm, fmlen) == -1) {
			
			perror("sendall(m) error");
			if (close(sock) != 0)
				perror("close(sock) error");
			sock = 0;
			
			begin_insert();
			gtk_text_buffer_insert_at_cursor(out_buf, "\nFailed to send a message - critical error occured."
											"Connection will be closed.\n", -1);
			end_insert();
			
			return;
			}

	//get a nonce for our next message as first 24 bytes of hash of encrypted message
	crypto_hash(h, tm, tmlen);
	memcpy(m_n, h, crypto_box_NONCEBYTES);

	}	//else

g_free(m);

return;

}

//--"THERE'S AN INPUT DATA IN SOCKET" EVENT HANDLER------------------------------------------------

static gboolean sock_GIO_handler(GIOChannel *source, GIOCondition condition, gpointer data)
{

	unsigned char m[varmlen];	//message from companion
	/*lengths of encrypted and temporary messages (in usual format and in format for network
	exchange*/
	unsigned long long mlen, cmlen, tmlen;
	uint16_t tmlen_network;

	char time_str[15];			//current time

	if (sock == 0) return FALSE;

	//recieve a size of companion's encrypted message
	really_recvieved = recv(sock, &tmlen_network, sizeof(uint16_t), MSG_WAITALL);
	switch(really_recvieved) {
		case 0: {
	
			if (close(sock) != 0) perror("close(sock) error");
			sock = 0;
		
			begin_insert();
			gtk_text_buffer_insert_at_cursor(out_buf, "\nCompanion closed the connection.\n", -1);
			end_insert();
		
			return FALSE;
			};
		case -1: {

			perror("recv(tmlen) error");
			if (close(sock) != 0) perror("close(sock) error");
			sock = 0;
		
			begin_insert();
			gtk_text_buffer_insert_at_cursor(out_buf, "\nCritical error occured. Connection will be closed.\n", -1);
			end_insert();
		
			return FALSE;
			};
		}
		
	//convert it to format suitable for processing on current computer
	tmlen = ntohs(tmlen_network);
	//simplest protection against wrong size of incoming message, needs serious improvement
	if (tmlen > varmlen)
		tmlen = varmlen;

	//recieve a message with known length, decrypt it, check it's signature and print it
	really_recvieved = recv(sock, tm, tmlen, MSG_WAITALL);
	switch(really_recvieved) {
		case 0: {
		
			if (close(sock) != 0) perror("close(sock) error");
			sock = 0;
		
			begin_insert();
			gtk_text_buffer_insert_at_cursor(out_buf, "\nCompanion closed the connection.\n", -1);
			end_insert();
		
			return FALSE;
			};
		case -1: {
		
			perror("recv(m) error");
			if (close(sock) != 0) perror("close(sock) error");
			sock = 0;
		
			begin_insert();
			gtk_text_buffer_insert_at_cursor(out_buf, "\nCritical error occured. Connection will be closed.\n", -1);
			end_insert();
		
			return FALSE;
			};
		}

	/*get a nonce for companion's next message as first 24 bytes of hash of encrypted message (we
	will overwrite an old nonce if this message will be successfully authentificated)*/
	crypto_hash(h, tm, tmlen);
	memcpy(x_n_tmp, h, crypto_box_NONCEBYTES);

	//first 16 bytes should be zero bytes for successful decryption, add them
	bzero(&cm, crypto_box_BOXZEROBYTES);
	cmlen = really_recvieved+crypto_box_BOXZEROBYTES;
	memcpy(cm+crypto_box_BOXZEROBYTES, tm, really_recvieved);

	//try to decrypt message
	if (crypto_box_open_afternm(tm, cm, cmlen, x_n, ckey) == -1) {

		begin_insert();
		gtk_text_buffer_insert_at_cursor(out_buf, "\nError: failed to decrypt recieved message.\n", -1);
		end_insert();

		}
	else {
		//message has been successfully decrypted, delete first 32 zero bytes in the beginning
		memcpy(sm, tm+crypto_box_ZEROBYTES, really_recvieved-crypto_box_BOXZEROBYTES);

		//check a signature of decrypted message
		if (crypto_sign_open(tm, &mlen, sm, really_recvieved-crypto_box_BOXZEROBYTES, x_sp) == -1) {
	
			begin_insert();
			gtk_text_buffer_insert_at_cursor(out_buf, "\nError: recieved message has wrong signature.\n", -1);
			end_insert();

			}
		else {
		
			//message was successfully authentificated, print it
			memcpy(m, tm, mlen);
			//let's be sure that there's at least one end of line symbol in message
			m[mlen] = '\0';
		
			time_talk(time_str);

			begin_insert();
			gtk_text_buffer_insert_at_cursor(out_buf, "\n", -1);
			gtk_text_buffer_insert_at_cursor(out_buf, companion_name, -1);
			gtk_text_buffer_insert_at_cursor(out_buf, time_str, -1);
			gtk_text_buffer_insert_at_cursor(out_buf, (const gchar *)m, -1);
			end_insert();
					
			//message was successfully authentificated, rewrite the nonce
			memcpy(x_n, x_n_tmp, crypto_box_NONCEBYTES);
							
			}	//else memcpy(m)
				
		}	//else memcpy(sm)

	return TRUE;
	
}

//--TALK WINDOW------------------------------------------------------------------------------------

//"save keys" menu item handler
static int save_handler (GtkWidget *talk_win)
{
	int fresult;	//return of called function
	
	begin_insert();
	
	//does persistent keys for current companion already exists on disk?
	fresult = is_keys_exist(talk_win);
	if (fresult == 1) {
		gtk_text_buffer_insert_at_cursor(out_buf,
										"\nError: failed to save persistent keys of current session.\n", -1);
		end_insert();
		return 1;
		}
	else if (fresult == 2) {
		gtk_text_buffer_insert_at_cursor(out_buf,
										"\nRewriting of persistent keys has been aborted.\n", -1);
		end_insert();
		return 0;
		}
	
	//if there wasn't keys for current companion or we should rewrite them then save them
	if (save_current_keys(companion_name, Mm_sp, Mm_ss, Mx_sp, Mm_cp, Mm_cs, Mx_cp) == 1)
		gtk_text_buffer_insert_at_cursor(out_buf,
										"\nError: failed to save persistent keys of current session.\n", -1);
	else
		gtk_text_buffer_insert_at_cursor(out_buf, "\nPersistent keys of current session successfully saved.\n", -1);

	end_insert();

	return 0;
}

//"close connection" menu item handler
static void close_handler ()
{
	//if socket for data exchange isn't closed then close it
	if (sock != 0) {
	
		if (close(sock) != 0)
			perror("close(sock) error");

		sock = 0;

		begin_insert();
		gtk_text_buffer_insert_at_cursor(out_buf, "\nYou closed the connection.\n", -1);
		end_insert();

		}	//if sock
}

//"exit" menu item handler (called also if user press "close" button of window)
static void quit_handler ()
{
	//if socket for data exchange isn't closed then close it
	if (sock != 0)
		if (close(sock) != 0)
			perror("close(sock) error");

	//leave main GTK cycle
	gtk_main_quit();
}

//key pressing handler for catching "enter" press
static gboolean talk_keypress (GtkWidget *widget, GdkEventKey *event, gpointer user_data)
{
	//if user hit "enter" then read and send message
	if (event->keyval == GDK_KEY_Return)
		send_message();

	return FALSE;
}

static void send_button_handler ()
{
	GtkTextIter end_iter;	//end iterator

	//add a line feed for same output after pressing "enter" key and "send" button
	gtk_text_buffer_get_end_iter(in_buf, &end_iter);
	gtk_text_buffer_place_cursor(in_buf, &end_iter);
	gtk_text_buffer_insert_at_cursor(in_buf, "\n", -1);

	send_message();
}

//-------------------------------------------------------------------------------------------------

//creation of talk window
static void show_talk ()
{
	GtkBuilder *builder;	//pointer to service structure (free after work)
	GtkWidget *talk_win = NULL, *curr_widget;
	//pointers to window and current widget for seting up
	GtkTextView *in_view;	//pointer to input view
	GIOChannel *sock_GIO;	//channel for unblocking reading from socket for data exchange

	char datetime_str[50]; 	//date and time as string

	//load "talk" window
	builder = gtk_builder_new();
	gtk_builder_add_from_file(builder, "gui/talk.glade", NULL);

	//close a program if that window was closed by user
	talk_win = GTK_WIDGET(gtk_builder_get_object(builder, "talk_window"));
	g_signal_connect_swapped(G_OBJECT(talk_win), "destroy", G_CALLBACK(quit_handler), NULL);

	//call a handler if some key was pressed to catch "enter" key press
	gtk_widget_add_events(talk_win, GDK_KEY_RELEASE_MASK);
	g_signal_connect(G_OBJECT(talk_win), "key_release_event", G_CALLBACK(talk_keypress), NULL);

	//connect input and output buffers and views with each other
	in_buf = GTK_TEXT_BUFFER(gtk_builder_get_object(builder, "input_buffer"));
	out_buf = GTK_TEXT_BUFFER(gtk_builder_get_object(builder, "output_buffer"));
	in_view = GTK_TEXT_VIEW(gtk_builder_get_object(builder, "input_view"));
	out_view = GTK_TEXT_VIEW(gtk_builder_get_object(builder, "output_view"));
	gtk_text_view_set_buffer(in_view, in_buf);
	gtk_text_view_set_buffer(out_view, out_buf);

	//call a handler after "send" button was pressed
	curr_widget = GTK_WIDGET(gtk_builder_get_object(builder, "send_button"));
	g_signal_connect(G_OBJECT(curr_widget), "clicked", G_CALLBACK(send_button_handler), NULL);

	//call a handler after "save keys" menu item was selected
	curr_widget = GTK_WIDGET(gtk_builder_get_object(builder, "save-keys_menuitem"));
	g_signal_connect_swapped(G_OBJECT(curr_widget), "activate", G_CALLBACK(save_handler), talk_win);
	//same with "close connection"
	curr_widget = GTK_WIDGET(gtk_builder_get_object(builder, "close-connection_menuitem"));
	g_signal_connect(G_OBJECT(curr_widget), "activate", G_CALLBACK(close_handler), NULL);
	//"exit"
	curr_widget = GTK_WIDGET(gtk_builder_get_object(builder, "quit_menuitem"));
	g_signal_connect(G_OBJECT(curr_widget), "activate", G_CALLBACK(quit_handler), NULL);
	//"about"
	curr_widget = GTK_WIDGET(gtk_builder_get_object(builder, "about_menuitem"));
	g_signal_connect(G_OBJECT(curr_widget), "activate", G_CALLBACK(show_about), NULL);

	g_object_unref(G_OBJECT(builder));

	//create a channel for unblocking reading from socket for data exchange
	
	#ifdef WIN32
		sock_GIO = g_io_channel_win32_new_socket (sock);
	#else
		sock_GIO = g_io_channel_unix_new(sock);
	#endif
	

	//set it's encoding to NULL which means "data type - binary data"
	if (g_io_channel_set_encoding(sock_GIO, NULL, NULL) != G_IO_STATUS_NORMAL)
		fprintf(stderr, "g_io_channel_set_encoding() error.\n");

	//activate a handler if there's some data to read or if connection was closed
	g_io_add_watch(sock_GIO, G_IO_IN || G_IO_HUP, sock_GIO_handler, NULL);

	gtk_widget_show_all(talk_win);

	//get date and time of connection
	datetime(datetime_str);

	begin_insert();
	gtk_text_buffer_insert_at_cursor(out_buf, "Connection established at ", -1);
	gtk_text_buffer_insert_at_cursor(out_buf, datetime_str, -1);
	gtk_text_buffer_insert_at_cursor(out_buf, "\nHash of persistent public keys:\n", -1);
	show_pubkeys_hash(Mh);
	gtk_text_buffer_insert_at_cursor(out_buf, "\nHash of session public keys:\n", -1);
	show_pubkeys_hash(Sh);
	end_insert();
}

//--"LAUNCH" BUTTON (CONNECTION SETTINGS WINDOW) HANDLER-------------------------------------------

static int launch_handler (GtkWidget *settings_win)
{

	//variables for dialog window creation
	GtkWidget *dialog;
	GtkDialogFlags flags = GTK_DIALOG_DESTROY_WITH_PARENT;

	//pointer to string readed from input field
	const gchar *server_address = NULL;

	//pointers to strings readed from comboboxes (free after work)
	gchar *net_role = NULL, *keys = NULL, *net_protocol_char = NULL;

	int net_protocol_int, fresult;	//network protocol, return of called function
	unsigned int serv_port;		//server port

	//get data from combobox that sets a mode of work with persistent keys
	keys = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(keys_combo));

	//get data from input field with companion's name
	companion_name = gtk_entry_get_text(GTK_ENTRY(companion_name_txt));
	//if companion's name wasn't entered then use default value
	if (strcmp(companion_name, "") == 0) companion_name = "Companion";

	/*selected mode of work with persistent keys is a generation of files with persistent keys?
	call a procedure for it*/
	if (strcmp(keys, "write to files") == 0) {

		g_free(keys);
	
		//does persistent keys for current companion already exists on disk?
		fresult = is_keys_exist(settings_win);
		if (fresult == 1) {

			dialog = gtk_message_dialog_new(GTK_WINDOW(settings_win), flags, GTK_MESSAGE_WARNING,
                                			GTK_BUTTONS_OK,
                                 			"Error: failed to generate persistent keys for talking with %s.",
											companion_name);
			gtk_dialog_run(GTK_DIALOG(dialog));
			gtk_widget_destroy(dialog);
			return 1;

			}
		else if (fresult == 2) {
		
			dialog = gtk_message_dialog_new(GTK_WINDOW(settings_win), flags, GTK_MESSAGE_INFO,
    	                            		GTK_BUTTONS_OK,
    	                             		"Rewriting of persistent keys for talking with %s has been aborted.",
											companion_name);
			gtk_dialog_run(GTK_DIALOG(dialog));
			gtk_widget_destroy(dialog);
			return 0;
		
			}
	
		//call a function for generation of files with persistent keys
		if (generate_key_files(companion_name) == -1) {
	
			dialog = gtk_message_dialog_new(GTK_WINDOW(settings_win), flags, GTK_MESSAGE_WARNING,
                                			GTK_BUTTONS_OK,
                                 			"Error: failed to generate persistent keys for talking with %s.",
											companion_name);
			gtk_dialog_run(GTK_DIALOG(dialog));
			gtk_widget_destroy(dialog);
		
			}	//generate_key_files
		else {
	
			dialog = gtk_message_dialog_new(GTK_WINDOW(settings_win), flags, GTK_MESSAGE_INFO,
                               		 		GTK_BUTTONS_OK,
                               				"Persistent keys for talking with %s successfully saved.\n\n"
											"Make an exchange of public keys via trusted channel.",
											companion_name);
			gtk_dialog_run(GTK_DIALOG(dialog));
			gtk_widget_destroy(dialog);
		
			}	//else dialog

	}	//strcmp(write to files)

	//if another mode of work with persistent keys was choosen
	else {

		//get data from input fields
		server_address = gtk_entry_get_text(GTK_ENTRY(server_address_txt));
		serv_port = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(port_spin));

		//get data from another comboboxes
		net_role = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(net_role_combo));
		net_protocol_char = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(net_protocol_combo));

		//load persistent keys for talking with current companion from files if user choosed that
		if (strcmp(keys, "load from files") == 0) {
	
			if (load_key_files(companion_name, (unsigned char **)&Mm_sp, (unsigned char **)&Mm_ss,
								(unsigned char **)&Mx_sp, (unsigned char **)&Mm_cp,
								(unsigned char **)&Mm_cs, (unsigned char **)&Mx_cp,
								(unsigned char **)&Mh) == 1) {
							
				dialog = gtk_message_dialog_new(GTK_WINDOW(settings_win), flags, GTK_MESSAGE_WARNING,
    	    	                        		GTK_BUTTONS_OK,
    	    	                        		"Error: failed to load persistent keys for talking with %s from files.",
												companion_name);
				gtk_dialog_run(GTK_DIALOG(dialog));
				gtk_widget_destroy(dialog);
			
				return 1;
				}	//load_key_files
				
			}	//strcmp(load from files)
		
		
		//use a network protocol choosen by user
		if (strcmp(net_protocol_char, "IPv4") == 0)
			net_protocol_int = AF_INET;
		else
			net_protocol_int = AF_INET6;
		
		g_free(net_protocol_char);
		
		//make a connection as a server or client depending on user's choice
		if (strcmp(net_role, "server") == 0)
			sock = go_server(serv_port, net_protocol_int);
		else
			sock = go_client(server_address, serv_port, net_protocol_int);
		
		g_free(net_role);
		
		//if a critical error occured then stop this handler
		if (sock == 1) {
			dialog = gtk_message_dialog_new(GTK_WINDOW(settings_win), flags, GTK_MESSAGE_WARNING,
    	                            		GTK_BUTTONS_OK,
    	                            		"Error: failed to make connection with %s.",
											companion_name);
			gtk_dialog_run(GTK_DIALOG(dialog));
			gtk_widget_destroy(dialog);
	
			g_free(keys);
		
			return 1;
			}

		//make an exchange of persistent keys via network if user choosed that
		if (strcmp(keys, "exchange via network") == 0) {
			if (net_key_exchange(sock, (unsigned char **)&Mm_sp, (unsigned char **)&Mm_ss,
								(unsigned char **)&Mx_sp, (unsigned char **)&Mm_cp,
								(unsigned char **)&Mm_cs, (unsigned char **)&Mx_cp,
								(unsigned char **)&Mh) == 1) {

				dialog = gtk_message_dialog_new(GTK_WINDOW(settings_win), flags, GTK_MESSAGE_WARNING,
    	    	                        		GTK_BUTTONS_OK,
    	    	                        		"Error: failed to make an exchange of persistent keys with %s via network.",
												companion_name);
				gtk_dialog_run(GTK_DIALOG(dialog));
				gtk_widget_destroy(dialog);
			
				g_free(keys);
			
				return 1;
				}	//net_key_exchange
				
			}	//strcmp(exchange via network)
	
		g_free(keys);
	
		//generate session keys and exchange them
		crypto_box_beforenm(M_ckey, Mx_cp, Mm_cs);
		if (create_session_keys(sock, Mm_ss, Mx_sp, M_ckey, (unsigned char **)&m_ss,
								(unsigned char **)&x_sp, (unsigned char **)&ckey,
								(unsigned char **)&m_n,	(unsigned char **)&x_n,
								(unsigned char **)Sh) == 1) {
		
			dialog = gtk_message_dialog_new(GTK_WINDOW(settings_win), flags, GTK_MESSAGE_WARNING,
    	    	                        	GTK_BUTTONS_OK,
    	    	                        	"Error: failed to make exchange of session keys with %s via network.",
											companion_name);
			gtk_dialog_run(GTK_DIALOG(dialog));
			gtk_widget_destroy(dialog);
		
			return 1;
			}	//create_session_keys
		
		//if secure connection was established then hide this window and show talk window instead
		gtk_widget_hide(settings_win);
		show_talk();

		}	//else (mode of wirk with persistent keys is not "write to files")

	return 0;

}

//--CONNECTION SETTINGS WINDOW---------------------------------------------------------------------

//'value in "network role" combobox has changed' event handler
static void net_role_changed ()
{
	//pointer to string readed from combobox (free after work)
	gchar *net_role = NULL;

	//get data from "network role" combobox
	net_role = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(net_role_combo));

	//if "server" mode selected then make "server address" input field inactive
	if (strcmp(net_role, "server") == 0) gtk_widget_set_sensitive(server_address_txt, FALSE);
	//if "client" mode selected then make "server address" input field active
	else gtk_widget_set_sensitive(server_address_txt, TRUE);

	g_free(net_role);
}

//'value in "keys" combobox has changed' event handler
static void keys_changed ()
{
	//pointer to string readed from combobox (free after work)
	gchar *keys = NULL;

	//get data from "keys" combobox
	keys = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(keys_combo));

	/*if "write to files" mode selected then make all widgets except "keys" and "companion's name"
	inactive*/
	if (strcmp(keys, "write to files") == 0) {
		gtk_widget_set_sensitive(server_address_txt, FALSE);
		gtk_widget_set_sensitive(net_role_combo, FALSE);
		gtk_widget_set_sensitive(net_protocol_combo, FALSE);
		gtk_widget_set_sensitive(port_spin, FALSE);
		}
	//else make all potentially inactive widgets excepts "server address" active
	else {
		gtk_widget_set_sensitive(net_role_combo, TRUE);
		gtk_widget_set_sensitive(net_protocol_combo, TRUE);
		gtk_widget_set_sensitive(port_spin, TRUE);
	
		//call a handler of "network role" changing to make "server address" widget active or inactive
		net_role_changed();
		}

	g_free(keys);
}

//--PROGRAM INITIALIZATION-------------------------------------------------------------------------

extern int main(int argc, char *argv[])
{
	GtkBuilder *builder;						//pointer to service structure (free after work)
	GtkWidget *settings_win = NULL, *button;	//pointers to window and button

	printf("Osteria %s, debug output\n\n", version);

	//Windows-only
	#ifdef WIN32
    	WSADATA x;
    	WORD wVersionRequested;
    	int err;
    	
    	//use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h
    	wVersionRequested = MAKEWORD(2, 2);

		err = WSAStartup(wVersionRequested, &wsaData);
  	  	if (err != 0) {
  	    	//tell the user that we could not find a usable Winsock DLL
	        fprintf(stderr, "WSAStartup(2,2) failed with error: %d\n", err);
    	    return 1;
    		}

		//confirm that the WinSock DLL supports 2.2
    	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
    	    //tell the user that we could not find a usable WinSock DLL
    	    fprintf(stderr, "Could not find a usable version of Winsock.dll\n");
    	    WSACleanup();
    	    return 1;
    		}
   		else
        	printf("The Winsock 2.2 dll was found okay\n");        	
	#endif

	//try to make a program able to understand all locales
	if (setlocale(LC_ALL, "") == NULL) fprintf(stderr, "setlocale() error\n");

	//GTK initialization
	gtk_init(&argc, &argv);

	//load "connection settings" window
	builder = gtk_builder_new();
	gtk_builder_add_from_file(builder, "gui/settings.glade", NULL);

	//close a program if that window was closed by user
	settings_win = GTK_WIDGET(gtk_builder_get_object(builder, "settings_window"));
	g_signal_connect_swapped(G_OBJECT(settings_win), "destroy", G_CALLBACK(gtk_main_quit), NULL);

	//and if "exit" button was pressed
	button = GTK_WIDGET(gtk_builder_get_object(builder, "exit_button"));
	g_signal_connect(G_OBJECT(button), "clicked", G_CALLBACK(gtk_main_quit), NULL);

	//if "about" button was pressed then show "about" window
	button = GTK_WIDGET(gtk_builder_get_object(builder, "about_button"));
	g_signal_connect(G_OBJECT(button), "clicked", G_CALLBACK(show_about), NULL);

	//if "launch" button was pressed then call a handler of this event
	button = GTK_WIDGET(gtk_builder_get_object(builder, "launch_button"));
	g_signal_connect_swapped(G_OBJECT(button), "clicked", G_CALLBACK(launch_handler), settings_win);

	//initialize a global variables pointing to widgets in this window
	server_address_txt = GTK_WIDGET(gtk_builder_get_object(builder, "server-address_text"));
	companion_name_txt = GTK_WIDGET(gtk_builder_get_object(builder, "companion-name_text"));
	net_role_combo = GTK_WIDGET(gtk_builder_get_object(builder, "net-role_combobox"));
	keys_combo = GTK_WIDGET(gtk_builder_get_object(builder, "keys_combobox"));
	net_protocol_combo = GTK_WIDGET(gtk_builder_get_object(builder, "net-protocol_combobox"));
	port_spin = GTK_WIDGET(gtk_builder_get_object(builder, "server-port_spin"));

	g_object_unref(G_OBJECT(builder));

	//if a value in "network role" or "keys" combobox has changed then call a handler of this event
	g_signal_connect(G_OBJECT(net_role_combo), "changed", G_CALLBACK(net_role_changed), NULL);
	g_signal_connect(G_OBJECT(keys_combo), "changed", G_CALLBACK(keys_changed), NULL);

	gtk_widget_show_all(settings_win);

	//begin handling of windows events
	gtk_main();

	#ifdef WIN32
		//in Windows we are done with Winsock and CryptoAPI
		WSACleanup();
		if (CryptReleaseContext(hCryptProv,0) == 0) {
			fprintf(stderr, "CryptReleaseContext() error: %x\n", GetLastError());
			return 1;
			}
	#endif

	return 0;
}
