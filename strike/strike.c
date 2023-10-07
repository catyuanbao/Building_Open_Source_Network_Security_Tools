#include "./strike.h"

int loop = 1;
u_long mac_count = 0;

short MAC_LEN = 6;
short IP_LEN = 20;

int main(int argc, char *argv[])
{

	int option;					// cmd line option
	pcap_t *p_fd;
	char *device;				// network device like "eth0" and so on
	pcap_if_t *alldevs, *dev;
	u_char *packet;
	int print_ip = 0;

	struct pcap_pkthdr headers;
	struct pcap_stat ps;		// the stats of pcap operation

	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter_code;
	bpf_u_int32 network, netmask;
	mac_entry *mac_table[HASH_TABLE_SIZE];

	device = NULL;

	while ((option = getopt(argc, argv, "Ii:")) != EOF) {
		switch (option) {
		case 'I':
			print_ip = 1;
			break;
		case 'i':
			device = optarg;
			break;
		default:
			exit(1);
		}
	}

	printf("strike 1.0 [passive MAC -> OUI mapping tool]\n");
	printf("Ctrl+c to quit\n");

	// check if device is not set, set a defalut one
	if (device == NULL) {
		if (pcap_findalldevs(&alldevs, errbuf) == -1) {
			fprintf(stderr, "Error for pcap_findalldevs() %s\n", errbuf);
			exit(1);
		}
		if (alldevs == NULL) {
			fprintf(stderr, "No devices found.\n");
			exit(1);
		}
		dev = alldevs;
		device = dev->name;
		if (device == NULL) {
			fprintf(stderr, "No device found!\n");
			exit(1);
		}
	}
	// open a pcap_t session
	p_fd = pcap_open_live(device, SNAPLEN, PROMISC, TIMEOUT, errbuf);
	if (p_fd == NULL) {
		fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
		pcap_freealldevs(alldevs);
		exit(1);
	}
	// find network and netmask of the divice
	if (pcap_lookupnet(device, &network, &netmask, errbuf) == -1) {
		fprintf(stderr, "pcap_lookupnet() failed: %s\n", errbuf);
		pcap_freealldevs(alldevs);
		pcap_close(p_fd);
		exit(1);
	}
	// strike only works in ethernet
	if (pcap_datalink(p_fd) != DLT_EN10MB) {
		fprintf(stderr, "strike only works in ethernet.\n");
		pcap_freealldevs(alldevs);
		pcap_close(p_fd);
		exit(1);
	}
	// complie rule
	if (pcap_compile(p_fd, &filter_code, FILTER_STR, 1, netmask) == -1) {
		fprintf(stderr, "pcap_compile() failed: %s\n", pcap_geterr(p_fd));
		pcap_freealldevs(alldevs);
		pcap_close(p_fd);
		exit(1);
	}
	// set rule
	if (pcap_setfilter(p_fd, &filter_code) == -1) {
		fprintf(stderr, "pcap_setfilter() failed: %s\n", pcap_geterr(p_fd));
		pcap_freealldevs(alldevs);
		pcap_close(p_fd);
		exit(1);
	}

	if (catch_signal(SIGINT, cleanup) == -1) {
		fprintf(stderr, "can't catch signal.\n");
		// Todo: free hash table
		pcap_freealldevs(alldevs);
		pcap_close(p_fd);
		exit(1);
	}

	hash_table_init(mac_table);
	while (loop) {
		packet = (u_char *) pcap_next(p_fd, &headers);
		if (packet == NULL) {
			continue;
		}

		if (deal_new_packet(packet, mac_table)) {
			if (print_ip) {
				printf("%s @ %s -> %s\n", mac_printf(packet),
					   ip_printf(packet + MAC_LEN + IP_LEN), binary_search(packet + MAC_LEN));
			} else {
				printf("%s -> %s\n", mac_printf(packet), binary_search(packet + MAC_LEN));
			}
		}
	}

	if (pcap_stats(p_fd, &ps) == -1) {
		fprintf(stderr, "pcap_stats() failed: %s\n", pcap_geterr(p_fd));
	} else {
		printf("\nPackets received by libpcap:\t%6d\n"
			   "Packets dropped by libpcap:\t%6d\n"
			   "Unique MAC addresses stored:\t%6ld\n", ps.ps_recv, ps.ps_drop, mac_count);
	}

	pcap_freealldevs(alldevs);
	pcap_close(p_fd);

	return 0;
}

void cleanup()
{
	loop = 0;
	printf("Interrupt signal caught... process will exit\n");
}

int catch_signal(int signum, void (*handler)())
{
	struct sigaction action;

	action.sa_handler = handler;
	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;

	if (sigaction(signum, &action, NULL) == -1) {
		return -1;
	}
	return 1;
}

void hash_table_init(mac_entry **mac_table)
{
	int i;
	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		mac_table[i] = NULL;
	}
}

char *mac_printf(u_char *packet)
{
	int n;
	static char address[18];

	n = sprintf(address, "%.2x:", packet[6]);
	n += sprintf(address + n, "%.2x:", packet[7]);
	n += sprintf(address + n, "%.2x:", packet[8]);
	n += sprintf(address + n, "%.2x:", packet[9]);
	n += sprintf(address + n, "%.2x:", packet[10]);
	n += sprintf(address + n, "%.2x", packet[11]);

	address[n] = '\0';
	return address;
}

char *ip_printf(u_char *address)
{
	static char ip[17];

	sprintf(ip, "%3d.%3d.%3d.%3d", (address[0] & 255), (address[1] & 255), (address[2] & 255), (address[3] & 255));

	return ip;
}

int deal_new_packet(u_char *pcaket, mac_entry **mac_table)
{
	u_long n;

	n = hash_table_hash(pcaket);

	// check if the entry hashed
	if (mac_table[n]) {
		if (!hash_table_dup_check(pcaket, mac_table, n)) {
			// collision add a bucket
			if (hash_table_add_entry(pcaket, mac_table, n)) {
				mac_count++;
				return 1;
			}
		} else {
			// duplicate entry, ignore it
			return 0;
		}
	} else {
		// table slot if free
		if (hash_table_add_entry(pcaket, mac_table, n)) {
			mac_count++;
			return 1;
		}

	}

	return 0;
}

u_long hash_table_hash(u_char *packet)
{
	int i;
	u_long j;

	for (i = 6, j = 0; i != 12; i++) {
		j = (j * 13) + packet[i];
	}

	return (j %= HASH_TABLE_SIZE);
}

int hash_table_add_entry(u_char *packet, mac_entry **mac_table, int index)
{
	mac_entry *p;

	if (mac_table[index] == NULL) {
		mac_table[index] = malloc(sizeof(mac_table));
		if (mac_table[index] == NULL) {
			fprintf(stderr, "malloc error\n");
			return 0;
		}
		mac_table[index]->mac[0] = packet[6];
		mac_table[index]->mac[1] = packet[7];
		mac_table[index]->mac[2] = packet[8];
		mac_table[index]->mac[3] = packet[9];
		mac_table[index]->mac[4] = packet[10];
		mac_table[index]->mac[5] = packet[11];
		mac_table[index]->next = NULL;
		return 1;
	} else {
		// find the end of a link list
		for (p = mac_table[index]; p->next; p = p->next) {

		}
		p->next = malloc(sizeof(mac_table));
		if (p->next == NULL) {
			fprintf(stderr, "malloc error\n");
			return 0;
		}

		p = p->next;
		p->mac[0] = packet[6];
		p->mac[1] = packet[7];
		p->mac[2] = packet[8];
		p->mac[3] = packet[9];
		p->mac[4] = packet[10];
		p->mac[5] = packet[11];
		p->next = NULL;
	}
	return 1;
}

int hash_table_dup_check(u_char *packet, mac_entry **mac_table, int index)
{
	mac_entry *p;
	for (p = mac_table[index]; p; p = p->next) {
		if (p->mac[0] == packet[6] && p->mac[1] == packet[7] &&
			p->mac[2] == packet[8] && p->mac[3] == packet[9] && p->mac[4] == packet[10] && p->mac[5] == packet[11]) {
			/* this MAC is already in our table */
			return (1);
		}
	}
	return 0;
}

const char *binary_search(u_char *key)
{
	struct oui *entry;
	int start, end, diff, mid;

	start = 0;
	end = sizeof(oui_table) / sizeof(oui_table[0]);

	while (end > start) {
		mid = (start + end) / 2;
		entry = &oui_table[mid];

		diff = key[0] - entry->prefix[0];
		if (diff == 0) {
			diff = key[1] - entry->prefix[1];
		}
		if (diff == 0) {
			diff = key[2] - entry->prefix[2];
		}

		if (diff == 0) {
			return entry->vendor;
		}

		if (diff < 0) {
			end = mid;
		} else {
			start = mid + 1;
		}
	}
	return "Unknown Verdor";
}
