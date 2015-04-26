#include <sys/types.h>
#include <sys/param.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/dkstat.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <sys/time.h>
#include <sys/user.h>
#include <kvm.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_mib.h>
#include <curses.h>

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


struct iface_data {
	char* iface_name;
	char iface_rx_sysctl_line[256];
	char iface_tx_sysctl_line[256];
	long first_stat_rx_read;
	long second_stat_rx_read;
	long first_stat_tx_read;
	long second_stat_tx_read;
};

void usage(char *prog)
{
	printf("\nUsage: %s [-i report interval]\n" , prog);
	exit(0);
}



int main(int argc, char* argv[])
{

	int             rows;
	int             name[6] = {CTL_NET, PF_LINK, NETLINK_GENERIC, IFMIB_IFDATA, 0, IFDATA_GENERAL};
	size_t          len;
	struct ifmibdata ifmd; /* ifmibdata contains the network statistics */
	struct iface_data* ifs;
	int num_NICs = 0;
	double begin_stats, end_stats;
	double rx_bits_per_second, tx_bits_per_second;
	double factor;
	int rv;
	int interval = 1;
	int microsleep;
	char c;
	const char *optstring = "i:h";

	while ((c = getopt(argc, argv,optstring)) != -1)
	{
		switch(c)
		{
			case 'i':
				interval = atoi(optarg);
				break;
			case 'h':
				usage(argv[0]);
				break;
			default:
				break;
		}
	}

	len = sizeof(rows);
	/* get number of interfaces */
	if (sysctlbyname("net.link.generic.system.ifcount", &rows, &len, NULL, 0) == 0) {
		ifs = (struct iface_data*)calloc(rows, sizeof(struct iface_data));
		len = sizeof(ifmd);
		/* walk through all interfaces in the ifmib table from last to first */
		int t = 0;
		for ( ; rows > 0; rows--) {
			name[4] = rows; /* set the interface index */
			/* retrive the ifmibdata for the current index */
			if (sysctl(name, 6, &ifmd, &len, NULL, 0) == -1) {
				perror("read sysctl");
				break;
			}
			if ( strncmp(ifmd.ifmd_name, "mlxen", 5) == 0 ) {
				ifs[t].iface_name = strdup(ifmd.ifmd_name);
				sprintf(ifs[t].iface_rx_sysctl_line, "hw.%s.stat.rx_bytes", ifs[t].iface_name);
				sprintf(ifs[t].iface_tx_sysctl_line, "hw.%s.stat.tx_bytes", ifs[t].iface_name);
				t++;

			}
		}
		num_NICs = t;
		/* if we are here there is no interface with the given name */
	} else {
		perror("read sysctlbyname");
		return -1;
	}
	if ( num_NICs == 0 )
	{
		printf("\n Could not find any Mellanox NICs, exiting...\n\n");
		exit(0);
	}
	initscr();
	rv = refresh();
	erase();
	/* aim to a little undershoot */
	int space = 9;
	microsleep = interval*1000000 - 200;
	while ( true ) {
		begin_stats = Time();
		for (int i=0; i<num_NICs; i++)
		{
			sysctlbyname(ifs[i].iface_rx_sysctl_line, &ifs[i].first_stat_rx_read, &len, NULL, 0);
			sysctlbyname(ifs[i].iface_tx_sysctl_line, &ifs[i].first_stat_tx_read, &len, NULL, 0);
		}
		usleep(microsleep);
		for (int i=0; i<num_NICs; i++)
		{
			sysctlbyname(ifs[i].iface_rx_sysctl_line, &ifs[i].second_stat_rx_read, &len, NULL, 0);
			sysctlbyname(ifs[i].iface_tx_sysctl_line, &ifs[i].second_stat_tx_read, &len, NULL, 0);
		}
		end_stats = Time();
		space = 9;
		for (int i=0; i<num_NICs; i++) {
			factor = ((end_stats-begin_stats)/(double)(1000000));
			rx_bits_per_second = ((ifs[i].second_stat_rx_read - ifs[i].first_stat_rx_read)*8)/factor;
			tx_bits_per_second = ((ifs[i].second_stat_tx_read - ifs[i].first_stat_tx_read)*8)/factor;
			mvprintw(space+i, 30, "%s: IN: %.0f bits/s. %.02f Mbits/s. %.02f Gbits/s\n", ifs[i].iface_name, rx_bits_per_second, rx_bits_per_second/1000000, rx_bits_per_second/1000000000);
			space+=1;
			mvprintw(space+i, 30, "%s: OUT: %.0f bits/s. %.02f Mbits/s. %.02f Gbits/s\n", ifs[i].iface_name, tx_bits_per_second, tx_bits_per_second/1000000, tx_bits_per_second/1000000000);
			space+=2;
		}
		refresh();
		//exit(0);
	}

}

