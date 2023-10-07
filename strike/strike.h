#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <pcap.h>
#include <signal.h>
#include <netinet/in.h>
#include "./oui.h"

#define SNAPLEN         34		// enough length for Data Link Layer Header
#define PROMISC         1		// set network deivece PROMISC
#define TIMEOUT         500
#define FILTER_STR      ""
#define HASH_TABLE_SIZE 2553	// needs to be a prime number

typedef struct table_entry {
	u_char mac[6];				// holds the MAC address
	struct table_entry *next;	// pointer to the next entry
} mac_entry;

const char *binary_search(u_char * key);
char *mac_printf(u_char * packet);
char *ip_printf(u_char * address);

// deal new packet function
int deal_new_packet(u_char * pcaket, mac_entry ** mac_table);

// hash table functions
void hash_table_init(mac_entry ** mac_table);
int hash_table_dup_check(u_char * pcaket, mac_entry ** mac_table, int index);
int hash_table_add_entry(u_char * packet, mac_entry ** mac_table, int index);
void hash_table_destory(mac_entry ** mac_table);
u_long hash_table_hash(u_char * packet);

// clean up function and deal with Ctrl+C signal

void cleanup();
int catch_signal(int, void (*)());
