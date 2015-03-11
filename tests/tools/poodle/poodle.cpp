#include <signal.h>
#include <sys/types.h>		/* standard system types 	*/
#include <netinet/in.h>		/* Internet address structures 	*/
#include <netdb.h>		/* host to IP resolution 	*/
#include <sys/stat.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/socket.h>
#ifdef USE_PP
#include <sys/socketvar.h>
#endif
#include <arpa/inet.h>
#include <arpa/inet.h>        /*  inet (3) funtions         */
#include <unistd.h>           /*  misc. UNIX functions      */
#include <pthread.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/sysctl.h>

#define MAX_FDS 300000
#define min(a,b) (((a) < (b)) ? (a) : (b))

class  reporter_c;

reporter_c* p_reporter_for_sig_handling;

bool report = false;

unsigned long total_system_conns;
unsigned long total_system_bytes;
unsigned long total_system_closed;
bool is_server = false; 
bool is_client = false; 
char* g_buf;
unsigned long g_bandwidth_in_bytes = 1024;
bool is_PP_throttle = false;
#define G_BUF_SIZE 1024*1024
time_t sys_start;
int old_somaxconn = 0;
size_t old_somaxconn_size = sizeof(old_somaxconn);
size_t new_somaxconn_new_size = 20000;

double Time()
{
	double res;
	struct timeval t;
	gettimeofday(&t, NULL);
	res = t.tv_sec;
	res *= 1000000;
	res += t.tv_usec;
	return res;
}

bool should_run = true;

class connection_group_thread_c;



class one_connection_c {
	friend class connection_group_thread_c;
	public:
	int init(int id, char* server_address, int server_port);
	int send(int send_size);
	int connect();
	void zero_per_second_counters();
	int shut_down();


	private:
	int socket;
	time_t last_active;
	time_t m_created;
	int send_size;
	int m_sent;
	int m_id;
	char* m_buf;
	bool m_is_active;
	struct    sockaddr_in servaddr;  /*  socket address structure  */
	int m_server_port;
	char m_server_address[96];
	int m_bytes_sent_this_second;
	unsigned long m_byte_to_send_per_second;
};

class connection_group_thread_c {
	public:
		int init(int id, int load, int send_time_out, char* server_address, int server_port, 
				int conns_per_second, unsigned long conn_active_time);
		int run();
		void* (*m_f)(void* arg);
		static void* thread_func(void* arg);
		void main_loop();
		int get_last_second_sent() { return m_last_second_sent; }
		unsigned long get_conns_created() { return m_conns_created; }
		unsigned long get_conns_closed() { return m_conns_closed; }

	private:

		int m_send_time_out;
		int m_id;
		int m_load;
		one_connection_c *conns;
		pthread_t the_thread;
		int m_conns_per_second;
		unsigned long  m_conn_active_time;
		int  m_last_second_sent;
		unsigned long m_conns_created;
		unsigned long m_conns_closed;

};

void connection_group_thread_c::main_loop()
{
	int conns_left_this_sec;
	int handled;
	int closed;
	time_t now;
	double second_start;
	int rc;
	int sent_this_second;
	int rounds=0;


	printf("loader_id=%d thread=%p conns_per_sec=%d bandwidth_per_conn=%lu\n", m_id, pthread_self(), m_conns_per_second, g_bandwidth_in_bytes);

	/*
	 * while (1)
	 * 	zero times and per conncounters
	 * 	while(got_time_this_second)
	 * 		for(all_connections)
	 * 			transmit_if_needed
	 * 			close_if_needed
	 * 			open_if_needed
	 *
	 *
	 */

#define TIME_TO_CLOSE(i) (now>conns[i].m_created+m_conn_active_time) 
#define SECOND_NOT_OVER (Time()-second_start)<1000000
	while (should_run) {
		rounds = 0;
		second_start = Time();
		conns_left_this_sec = m_conns_per_second;
		now = time(NULL); 
		for ( int i = 0; i < m_load; i++ ) 
			conns[i].zero_per_second_counters();
		sent_this_second = 0;
		while (SECOND_NOT_OVER) {
			rounds++;
			for ( int i = 0; i < m_load; i++ ){
				if ( conns[i].m_is_active )
					sent_this_second += conns[i].send((1024*1024));
			}
			for ( int i = 0; i < m_load; i++ ){
				if (TIME_TO_CLOSE(i)) {
					if ( !conns[i].shut_down() ) 
						m_conns_closed++;
				}
				if (conns_left_this_sec && !conns[i].m_is_active) { // no need to go over all of this if the per second quota is done.
					rc = conns[i].connect();
					if ( rc != 0 ) 
						printf("Error connect!\n");
					conns_left_this_sec--;
					m_conns_created++;

				}

			}
		}
		m_last_second_sent = sent_this_second;
	}

}


void* connection_group_thread_c::thread_func(void* arg)
{
	connection_group_thread_c* t = (connection_group_thread_c*)arg;
	t->main_loop();
	return NULL;
}

int connection_group_thread_c::run()
{
	pthread_create(&the_thread, NULL, thread_func, this);
	pthread_detach(the_thread);
	return 0;
}



int connection_group_thread_c::init(int id, int load, int send_time_out, char* server_address, int server_port, 
		int conns_per_second, unsigned long  conn_active_time)
{
	m_id = id;
	m_load = load;
	m_send_time_out = send_time_out;
	m_conns_per_second = conns_per_second ? conns_per_second : load/10+load%10;
	m_conn_active_time = conn_active_time;
	m_last_second_sent = 0;
	m_conns_closed = 0;
	m_conns_created = 0;
	conns = new one_connection_c[m_load];


	for (int i=0; i<load; i++) {
		conns[i].init(id*10000+i, server_address, server_port);
	}
	return 0;
}

void one_connection_c::zero_per_second_counters()
{
	m_bytes_sent_this_second = 0;
}

int one_connection_c::init(int id, char* server_address, int server_port)
{
	m_buf = g_buf;
	m_id = id;
	m_byte_to_send_per_second = g_bandwidth_in_bytes;
	m_bytes_sent_this_second = 0;
	m_created = 0; //this is initiate a connect in the manager main loop.
	m_is_active = false;
	strcpy(m_server_address, server_address);
	m_server_port = server_port;
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_port        = htons(server_port);
	if ( inet_aton(server_address, &servaddr.sin_addr) <= 0 ) {
		printf("ERROR: Invalid remote IP address.\n");
		return -1;
	}
	return 0;

}

int one_connection_c::send(int s_size)
{
	int nwritten;
	int left_to_send;
	int send_size;

#ifdef USE_PP
	if (is_PP_throttle) {
		nwritten = write(socket, m_buf, s_size);
		return nwritten;
	}
#endif

	if  (m_bytes_sent_this_second >= m_byte_to_send_per_second)
		return 0;

	left_to_send = m_byte_to_send_per_second - m_bytes_sent_this_second;

	send_size = s_size<left_to_send ? s_size : left_to_send;
	send_size = send_size/5;


	nwritten = write(socket, m_buf, send_size);
	m_bytes_sent_this_second += nwritten;
	return nwritten;
}

int one_connection_c::connect()
{
	int rc;


	if ( (socket = ::socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
		perror("socket");
		fprintf(stderr, "Error creating listening socket.\n");
		socket = -1;
	}

	struct linger nolinger; 
	socklen_t optlen = sizeof(nolinger); 
	nolinger.l_onoff = 1; 
	nolinger.l_linger = 0; 

	// avoid long CLOSE_WAIT, we need this port in a snap.
	setsockopt(socket, SOL_SOCKET, SO_LINGER, &nolinger, optlen); 

	rc = fcntl(socket, F_SETFL, O_NONBLOCK); 

	rc = ::connect(socket, (struct sockaddr *) &servaddr, sizeof(servaddr));
	if ( (rc < 0) && (errno != EINPROGRESS)  ) {
		printf("Error calling connect()\n");
		perror("connect");
		close(socket);
		socket = -1;
		return -1;
	}
#ifdef USE_PP
	// packet pacing
	if ( is_PP_throttle ) {
		struct so_rate_ctl rate;
		rate.flags = 0;
		rate.max_pacing_rate = m_byte_to_send_per_second;
		setsockopt(socket,SOL_SOCKET, SO_MAX_PACING_RATE, &rate, sizeof(rate));
	}

#endif
	m_is_active = true;
	m_created = time(NULL);
	total_system_conns++;
	return 0;
}

int one_connection_c::shut_down()
{
	if (!m_is_active)
		return 1;
	::shutdown(socket, SHUT_RDWR);
	close(socket);
	socket = -1;
	m_is_active = false;
	return 0;
}
class reporter_c {
	public:
		void init(connection_group_thread_c* load, int num_threads);
		int run();
		static void* thread_func(void* arg);
		void main_loop();
		void summary();

	private:
		connection_group_thread_c* m_current_load;
		int m_num_threads;
		pthread_t the_thread;
};

void reporter_c::init(connection_group_thread_c* load, int num_threads)
{
	m_current_load = load;
	m_num_threads = num_threads;
}

void* reporter_c::thread_func(void* arg)
{
	reporter_c* t = (reporter_c*)arg;
	t->main_loop();
	return NULL;
}

int reporter_c::run()
{
	pthread_create(&the_thread, NULL, thread_func, this);
	pthread_detach(the_thread);
	return 0;
}

void reporter_c::summary()
{
	unsigned long system_conns_created = 0;
	unsigned long system_conns_closed = 0;
	for (int i=0; i<m_num_threads; i++) {
		system_conns_created += m_current_load[i].get_conns_created();
		system_conns_closed += m_current_load[i].get_conns_closed();
	}
	printf("Total conns created = %lu\n", system_conns_created);
	printf("Total conns closed = %lu\n", system_conns_closed);
}

void reporter_c::main_loop()
{
	unsigned long last_second_all_bytes = 0;
	while ( true ) {
		sleep(1);
		for (int i=0; i<m_num_threads; i++) {
			last_second_all_bytes += m_current_load[i].get_last_second_sent();
		}
		printf("Transmited %.2f KB per second\n", (double)last_second_all_bytes/1024);
		last_second_all_bytes = 0;
	}
}

int one_server(int server_port)
{
	int			i;
	int			rc;
	int			s; 
	int			cs; 		/* new connection's socket descriptor */
	char			buf[1024*1024];  /* buffer for incoming data */
	struct sockaddr_in	sa;
	struct sockaddr_in	csa; 		/* client's address struct */
	socklen_t         	size_csa; 	/* size of client's address struct */
	struct 			rlimit my_limit;
	int		    	all_fds[MAX_FDS];
	bool rest;
	int total;
	unsigned long reads, read_from_start;
	double start, passed, actual_bandwith;

	getrlimit (RLIMIT_NOFILE, &my_limit);
	printf ( "Current limit of open files is %ld.\n", my_limit.rlim_cur);


	for (i = 0; i < MAX_FDS; i++ ) { 
		all_fds[i] = -1;
	}


	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(server_port);
	sa.sin_addr.s_addr = INADDR_ANY;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("socket: allocation failed");
	}

	rc = fcntl(s, F_SETFL, O_NONBLOCK); 
	printf("set non_block(%d)\n", rc);

	rc = bind(s, (struct sockaddr *)&sa, sizeof(sa));
	if (rc) {
		perror("bind");
	}

	int opt = 1;
	if (setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt))<0){
		printf ("setsockopt (SO_RESUSEADDR): %s\r\n",strerror(errno));
		exit(EXIT_FAILURE);
	}


	rc = listen(s, 2048);

	printf("Listening on port %d\n", server_port);

	/* check there was no error */
	if (rc) {
		perror("listen");
	}
	total = 0;
	start = Time();
	read_from_start = 0;
	while ( 1 ) {
		cs = accept(s, (struct sockaddr *)&csa, &size_csa);
		if ( cs > 1 ) {
			total_system_conns++;
			rc = fcntl(cs, F_SETFL, O_NONBLOCK); 
			all_fds[total] = cs;
			while ( all_fds[total] != -1 ) {
				total = (total + 1)%MAX_FDS;
			}
			continue;
		}
		for (i = 0; i < total; i++ ) { 
			rc = read(all_fds[i], buf, 1024*1204);
			if ( rc == 0 ) {
				shutdown(all_fds[i], SHUT_RDWR);
				close(all_fds[i]);
				total_system_closed++;
				all_fds[i] = -1;
			}
			if ( rc > 0 ) {
				reads++;
				read_from_start += rc;
				while (rc > 0 ) {
					rc = read(all_fds[i], buf, 1024*1204);
					if ( rc > 0 )
						read_from_start += rc;
				}
			}
		}
		if ( report ) {
			passed = Time() - start;
			if ( passed > 1000000 ) {
				start = Time();
				actual_bandwith = (read_from_start*(1000000/passed)/1024);
				if (read_from_start>0)
					printf("Actual B/W = %.2f KiloBytesPerSecond \n", actual_bandwith);
				read_from_start = 0;
			}
		}
	}
	return 0;
}

void usage(char *prog)
{
	printf("Usage: %s [-s | -c host] [client(sender) options]\n where options are:\n"
			"	      -h help screen\n"
			"	      -v report statistics, otherwise be silent\n"
			"	      -p port (default 10005)\n"
			"	      -c server host address\n"
			"	      -C concurrent connections(100000 max)\n"
			"	      -P use Packet Pacing for throttling. otherwise software is used\n"
			"	      -n conn created per second\n"
			"	      -t active time per connection in seconds. The connection will be closed and a new connection will be created once time is up.\n"
			"	      -T Total run time in secs, otherwise run forever or till killed \n"
			"	      -r how many threads\n"
			"	      -b bandwidth per conn (kbps) or \n"
			"	      -B total bandwidth (kbps)\n\n"
			, prog
	      );
	exit(0);
}
void sig_pipe_handler(int s) {
	return ;
}
void shut_down_handler(int s) {
	printf("Shutting down....\n");
	sysctlbyname("kern.ipc.somaxconn", NULL, NULL, &old_somaxconn, sizeof(old_somaxconn));
	if ( report ) {
		if ( is_server ) {
			printf("Total conns created: %lu\n", total_system_conns);
			printf("Total conns closed: %lu\n", total_system_closed);
		}
		else  {
			p_reporter_for_sig_handling->summary();
		}
	}
	exit(0);
	return ;
}



int main(int argc, char* argv[])
{

	int rc;

	if ( argc < 2 ) {
		usage(argv[0]);
	}

	total_system_conns = 0;
	total_system_bytes = 0;
	total_system_closed = 0;

	sys_start = time(NULL);
	sleep(1);


	struct rlimit rlim;
	int resource =  RLIMIT_NOFILE;
	rlim.rlim_max = MAX_FDS;
	rlim.rlim_cur = MAX_FDS;
	rc =  setrlimit(resource, &rlim);
	//printf ( "sysconf() says %ld files.\n", sysconf(_SC_OPEN_MAX));
	//save the old somax and load the new
	sysctlbyname("kern.ipc.somaxconn", &old_somaxconn, &old_somaxconn_size, &new_somaxconn_new_size, sizeof(new_somaxconn_new_size));


	signal(SIGPIPE, sig_pipe_handler);
	signal(SIGINT, shut_down_handler);


	g_buf = new char[G_BUF_SIZE];
	for (int i=0; i<G_BUF_SIZE; i++)
		g_buf[i] = (i%10) + '0';

	srand(time(NULL));

	const char *optstring = "c:p:r:C:n:t:b:B:T:hvsP";
	char c;


	char* server_address;
	char* local_base_address;
	int server_port = 10005; 
	int thread_load = 1;
	int total_conns = 100;
	int threads = 1;
	unsigned long conn_active_time = 999999999;
	int total_run_time = 0;
	unsigned long bandwidth_per_conn = 10*1024;
	unsigned long total_bandwidth = 0;
	int total_conn_per_sec = 0;
	unsigned long total_cons = 0;


	while ((c = getopt(argc, argv,optstring)) != -1)
	{
		switch(c)
		{
			case 'P':
				is_PP_throttle = true;
				break;
			case 'r':
				threads = atoi(optarg);
				break;
			case 'n':
				total_conn_per_sec = atoi(optarg);
				break;
			case 'p':
				server_port = atoi(optarg);
				break;
			case 'c':
				is_client = true;
				server_address = strdup(optarg);
				break;
			case 's':
				is_server = true;
				break;
			case 'C':
				total_conns = atoi(optarg);
				break;
			case 't':
				conn_active_time = atoi(optarg);
				break;
			case 'T':
				total_run_time = atoi(optarg);
				break;
			case 'b':
				bandwidth_per_conn = atoi(optarg);
				g_bandwidth_in_bytes = bandwidth_per_conn*1024;
				break;
			case 'B':
				total_bandwidth = atoi(optarg);
				break;
			case 'v':
				report = true;
				break;
			case 'h':
				usage(argv[0]);
				break;
			default:
				break;
		}
	}

	if ( is_server ) {
		one_server(server_port);
	}

	if ( total_bandwidth ) {
		g_bandwidth_in_bytes = (total_bandwidth*1024/total_conns);
	}

	connection_group_thread_c *loader = new connection_group_thread_c[threads];
	reporter_c reporter;
	p_reporter_for_sig_handling = &reporter;
	char client_ip[96];
	int base_addr;
	char addr_3[96];
	char *t;
	char *p3;




	for (int i=0; i<threads; i++) {
		sprintf(client_ip, "%s.%d", addr_3, base_addr);
		loader[i].init(i, total_conns/threads, 5, server_address, server_port, total_conn_per_sec/threads, conn_active_time);
		loader[i].run();
	}

	if ( report ) {
		reporter.init(loader, threads);
		reporter.run();
	}

	if (total_run_time) {
		sleep(total_run_time);
		should_run = false;
		sleep(1);
		shut_down_handler(9);
		exit(0);
	}
	pause();

	return 0;
}