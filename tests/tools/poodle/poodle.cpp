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
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/sysctl.h>

#include <list>

#define MAX_FDS 300000
#define min(a,b) (((a) < (b)) ? (a) : (b))

#define KILO 1000
#define BITS_IN_BYTE 8

class  client_reporter_c;

client_reporter_c* p_reporter_for_sig_handling;

bool report = false;

unsigned long total_system_conns;
unsigned long total_system_bytes;
unsigned long total_system_closed;
bool is_server = false; 
bool is_client = false; 
char* g_buf;
bool g_modify_pace = false;
unsigned long g_bandwidth_in_bytes = 100/8; //100Kbits is PP lower mark.
bool is_PP_throttle = false;
#define G_BUF_SIZE 32*1024
time_t sys_start;
int old_somaxconn = 0;
size_t old_somaxconn_size = sizeof(old_somaxconn);
size_t new_somaxconn_new_size = 20000;

int num_CPU()
{
	int mib[4];
	int numCPU;
	size_t len = sizeof(numCPU);

	/* set the mib for hw.ncpu */
	mib[0] = CTL_HW;
	mib[1] = HW_NCPU;  

	/* get the number of CPUs from the system */
	sysctl(mib, 2, &numCPU, &len, NULL, 0);

	return numCPU;
}


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
bool close_all_sockets = false;

class connection_group_thread_c;

class pace_modify_data {
	public:
		static pace_modify_data *instance()
		{
			if (!s_instance)
				s_instance = new pace_modify_data;
			return s_instance;
		}
		int init(int modify_interval=5, int paces_size=60); //hard coded for fun
		int get_next_pace() { return m_paces[m_current_pace_idx++%m_paces_size]; }
		int get_modify_interval_in_secs() { return m_modify_interval_in_secs; }
	private:
		static pace_modify_data *s_instance;
		int* m_paces;
		int  m_paces_size;
		int  m_modify_interval_in_secs;
		int m_current_pace_idx;
		pace_modify_data() {}
};
pace_modify_data *pace_modify_data::s_instance = 0;

int pace_modify_data::init(int modify_interval, int paces_size)
{
	int start = 1*KILO;

	m_paces_size = paces_size;
	m_paces = new int[m_paces_size];
	m_current_pace_idx = 0;
	for (int i=0; i<m_paces_size; i++)
	{
		m_paces[i] = (i+1)*start;
	}
	m_modify_interval_in_secs = modify_interval;

	return 0;
}

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
		void close_all();

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

void connection_group_thread_c::close_all()
{
	for ( int i = 0; i < m_load; i++ ) {
		conns[i].shut_down();
	}
	delete[] conns;
}

void connection_group_thread_c::main_loop()
{
	int conns_left_this_sec;
	int handled;
	int closed;
	time_t now;
	time_t modify_interval_start = time(NULL);
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

#define TIME_TO_CLOSE(i) (now > conns[i].m_created+m_conn_active_time)
#define SECOND_NOT_OVER (Time()-second_start)<1000000
#define TIME_TO_MODIFY (g_modify_pace && (now - modify_interval_start) > pace_modify_data::instance()->get_modify_interval_in_secs())
	while (should_run) {
		rounds = 0;
		second_start = Time();
		conns_left_this_sec = m_conns_per_second;
		now = time(NULL); 
		// we arrive here once a sec
		for ( int i = 0; i < m_load; i++ ) 
			conns[i].zero_per_second_counters();
		sent_this_second = 0;
		if ( TIME_TO_MODIFY ) {
			modify_interval_start = time(NULL);
			unsigned int new_pace = pace_modify_data::instance()->get_next_pace();
			for (int i = 0; i < m_load; i++) {
				if ( is_PP_throttle ) {
#ifdef USE_PP
					setsockopt(conns[i].socket, SOL_SOCKET,
						   SO_MAX_PACING_RATE,
						   &new_pace, sizeof(new_pace));
#endif
				}
				else {
					conns[i].m_byte_to_send_per_second = new_pace;
				}
			}
		}
		while (SECOND_NOT_OVER) {
			rounds++;
			for ( int i = 0; i < m_load; i++ ){
				if ( conns[i].m_is_active )
					sent_this_second += conns[i].send((G_BUF_SIZE));
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

	nwritten = write(socket, m_buf, s_size);
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
		setsockopt(socket, SOL_SOCKET, SO_MAX_PACING_RATE,
                                &m_byte_to_send_per_second,
                                sizeof(m_byte_to_send_per_second));
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
	::close(socket);
	socket = -1;
	m_is_active = false;
	return 0;
}
class client_reporter_c {
	public:
		void init(connection_group_thread_c* load, int num_threads);
		int run();
		static void* thread_func(void* arg);
		void main_loop();
		void summary();
		void help_close_all();

	private:
		connection_group_thread_c* m_current_load;
		int m_num_threads;
		pthread_t the_thread;
};

void client_reporter_c::init(connection_group_thread_c* load, int num_threads)
{
	m_current_load = load;
	m_num_threads = num_threads;
}

void* client_reporter_c::thread_func(void* arg)
{
	client_reporter_c* t = (client_reporter_c*)arg;
	t->main_loop();
	return NULL;
}

int client_reporter_c::run()
{
	pthread_create(&the_thread, NULL, thread_func, this);
	pthread_detach(the_thread);
	return 0;
}

void client_reporter_c::help_close_all()
{
	for (int i=0; i<m_num_threads; i++) {
		m_current_load[i].close_all();
	}
}

void client_reporter_c::summary()
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

void client_reporter_c::main_loop()
{
	unsigned long last_second_all_bytes = 0;
	while ( true ) {
		sleep(1);
		for (int i=0; i<m_num_threads; i++) {
			last_second_all_bytes += m_current_load[i].get_last_second_sent();
		}
		printf("Wrote %.2f bits per second (%.1f Mbits/s )\n", (double)last_second_all_bytes*BITS_IN_BYTE, (double)last_second_all_bytes*BITS_IN_BYTE/(KILO*KILO));
		last_second_all_bytes = 0;
	}
}

class server_worker_c {
	public:
		void init();
		int run();
		static void* thread_func(void* arg);
		void main_loop();
		void safe_add_pending_socket(int s);
		unsigned long get_last_second_recieved() { return m_saved_last_second_received; }
		unsigned int get_num_conns() { return m_num_conns; }


	private:

		void safe_update_all_socket_list();
		pthread_mutex_t m_lock;
		pthread_t the_thread;
		std::list<int> all_socket;
		std::list<int> pending_sockets;
		unsigned int m_last_second_received;
		unsigned int m_saved_last_second_received;
		unsigned int m_num_conns;


};
void server_worker_c::safe_update_all_socket_list()
{
	int s;

	pthread_mutex_lock(&m_lock);
		while ( !pending_sockets.empty() ) {
			s = pending_sockets.front();
			all_socket.push_front(s);
			pending_sockets.pop_front();
			m_num_conns++;
		}
	pthread_mutex_unlock(&m_lock);
}

void server_worker_c::safe_add_pending_socket(int s)
{
	pthread_mutex_lock(&m_lock);
		pending_sockets.push_back(s);
	pthread_mutex_unlock(&m_lock);
}

void server_worker_c::init()
{	
	m_lock = PTHREAD_MUTEX_INITIALIZER;
	m_num_conns = 0;
	
}

void* server_worker_c::thread_func(void* arg)
{
	server_worker_c* t = (server_worker_c*)arg;
	t->main_loop();
	return NULL;
}

int server_worker_c::run()
{
	pthread_create(&the_thread, NULL, thread_func, this);
	pthread_detach(the_thread);
	return 0;
}


#define SECOND_PASSED (Time()-second_start)>1000000
void server_worker_c::main_loop()
{
	char *buf = new char[32*1024];
	int rc;
	double second_start;
	
	second_start = Time();
	while ( true ) {
		// read all active sockets
		for (std::list<int>::iterator s=all_socket.begin(); s != all_socket.end(); ++s)
		{
again:
			rc = read(*s, buf, 32*1024);
			if ( rc <= 0 && errno != EAGAIN) {
				rc = ::close(*s);
				all_socket.erase(s);
				break;
			}
			if ( rc > 0 ) {
				m_last_second_received += rc;
				goto again;
			}
		}
		safe_update_all_socket_list();
		if ( SECOND_PASSED ) {
			m_saved_last_second_received = m_last_second_received;

			m_last_second_received = 0;
			second_start = Time();
		}
	}
}

class server_reporter_c { /* XXX Todo: this class is almost the same as client_reporter - they need to be under the same class */
	public:
		void init(server_worker_c* load, int num_threads);
		int run();
		static void* thread_func(void* arg);
		void main_loop();
		void summary();

	private:
		server_worker_c* m_current_load;
		int m_num_threads;
		pthread_t the_thread;
};

void server_reporter_c::init(server_worker_c* load, int num_threads)
{
	m_current_load = load;
	m_num_threads = num_threads;
}

void* server_reporter_c::thread_func(void* arg)
{
	server_reporter_c* t = (server_reporter_c*)arg;
	t->main_loop();
	return NULL;
}

int server_reporter_c::run()
{
	pthread_create(&the_thread, NULL, thread_func, this);
	pthread_detach(the_thread);
	return 0;
}

void server_reporter_c::summary()
{
}

#define MEGA_BITS_IN_BYTES KILO*KILO/BITS_IN_BYTE
#define GIGA_BITS_IN_BYTES MEGA_BITS_IN_BYTES*KILO

void server_reporter_c::main_loop()
{
	unsigned long last_second_all_bytes = 0;
	unsigned int conns = 0;
	while ( true ) {
		sleep(1);
		conns = 0;
		last_second_all_bytes = 0;
		for (int i=0; i<m_num_threads; i++) {
			last_second_all_bytes += m_current_load[i].get_last_second_recieved();
			conns += m_current_load[i].get_num_conns();
		}
		if ( last_second_all_bytes == 0 )
			continue;
		printf("%u conns Recieved", conns);
		if ( last_second_all_bytes > GIGA_BITS_IN_BYTES )
			printf(" %.3f Gbits/sec. ", (double)last_second_all_bytes*BITS_IN_BYTE/(KILO*KILO*KILO));
		else if ( last_second_all_bytes > MEGA_BITS_IN_BYTES )
			printf(" %.2f Mbits/sec. ", (double)last_second_all_bytes*BITS_IN_BYTE/(KILO*KILO));
		else
			printf(" %lu bits. ", last_second_all_bytes*BITS_IN_BYTE);
		printf(" %.1f Kbytes per conn\n", conns > 0 ? (double)last_second_all_bytes/(conns*KILO) : 0);


		last_second_all_bytes = 0;
	}
}

int one_server(int server_port, int server_threads)
{
	int			i;
	int			rc;
	int			s; 
	int			cs; 		/* new connection's socket descriptor */
	struct sockaddr_in	sa;
	struct sockaddr_in	csa; 		/* client's address struct */
	socklen_t         	size_csa; 	/* size of client's address struct */
	struct 			rlimit my_limit;
	int		    	all_fds[MAX_FDS];
	bool rest;
	unsigned long reads, read_from_start;
	double start, passed, actual_bandwidth;
	int next_worker_thread = 0;
	int num_worker_threads = server_threads;

	getrlimit (RLIMIT_NOFILE, &my_limit);
	printf ( "Current limit of open files is %ld.\n", my_limit.rlim_cur);
	printf ( "Init server with %d threads.\n", server_threads);


	// create worker threads
	server_worker_c *server_worker_threads = new server_worker_c[num_worker_threads];
	for (int i=0; i<num_worker_threads; i++) {
		server_worker_threads[i].init();
		server_worker_threads[i].run();
	}

	if ( report ) {
		server_reporter_c reporter;
		reporter.init(server_worker_threads, num_worker_threads);
		reporter.run();

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


	rc = listen(s, 20480);

	printf("Listening on port %d\n", server_port);

	/* check there was no error */
	if (rc) {
		perror("listen");
	}
	while ( 1 ) {
		cs = accept(s, (struct sockaddr *)&csa, &size_csa);

		if ( cs > 1 ) {
			server_worker_threads[next_worker_thread++ % num_worker_threads].safe_add_pending_socket(cs);
			total_system_conns++;
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
			"	      -t active time per connection in seconds. The connection will be //closed and a new connection will be created once time is up.\n"
			"	      -T Total run time in secs, otherwise run forever or till killed \n"
			"	      -r how many client threads. (This box has %d cores available)\n"
			"	      -R how many server threads. (This box has %d cores available)\n"
			"	      -M Modify pace, currently hard-coded to 10 rates\n"
			"	      -z bandwidth per conn (bits) or \n"
			"	      -b bandwidth per conn (kbps) or \n"
			"	      -B total bandwidth (kbps)\n\n"
			, prog, num_CPU(), num_CPU()
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
	if (!is_server ) {
		should_run = false;
		sleep(3);
		p_reporter_for_sig_handling->help_close_all();
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
	sysctlbyname("kern.ipc.somaxconn", &old_somaxconn, &old_somaxconn_size, &new_somaxconn_new_size, sizeof(new_somaxconn_new_size));


	signal(SIGPIPE, sig_pipe_handler);
	signal(SIGINT, shut_down_handler);


	g_buf = new char[G_BUF_SIZE];
	for (int i=0; i<G_BUF_SIZE; i++)
		g_buf[i] = (i%10) + '0';

	srand(time(NULL));

	const char *optstring = "z:c:p:R:r:C:n:t:b:B:T:hvsPM";
	char c;


	char* server_address;
	char* local_base_address;
	int server_port = 10005; 
	int thread_load = 1;
	int total_conns = 100;
	int threads = 1;
	int server_threads = 1;
	unsigned long conn_active_time = 999999999;
	int total_run_time = 0;
	unsigned long bandwidth_per_conn = 10*KILO;
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
			case 'R':
				server_threads = atoi(optarg);
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
			case 'z':
				bandwidth_per_conn = atoi(optarg);
				g_bandwidth_in_bytes = bandwidth_per_conn/BITS_IN_BYTE;
				break;
			case 'T':
				total_run_time = atoi(optarg);
				break;
			case 'M':
				g_modify_pace = true;;
				break;
			case 'b':
				bandwidth_per_conn = atoi(optarg);
				g_bandwidth_in_bytes = bandwidth_per_conn*KILO;
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
		one_server(server_port, server_threads);
	}

	if ( g_modify_pace )
	{
		pace_modify_data::instance()->init();
		pace_modify_data::instance()->get_modify_interval_in_secs();
	}

	if ( total_bandwidth ) {
		g_bandwidth_in_bytes = (total_bandwidth*KILO)/total_conns;
	}

	connection_group_thread_c *loader = new connection_group_thread_c[threads];
	client_reporter_c reporter;
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

	reporter.init(loader, threads);

	if ( report ) {
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
