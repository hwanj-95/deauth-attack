#ifndef HEADER_H
#define HEADER_H

#endif // HEADER_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h> //ipv4 ip_addr
#include <arpa/inet.h> // inet_ntoa > net add change
#include <algorithm>
#include <string.h>
#include <unistd.h>

#include "mac.h"
using namespace std;

#define MAC_LEN 6
#define version 0x00        // radiotap_header -> it.version setting
#define padding 0x00        // radiotap_header -> it_pad setting
#define radio_len 0x0008     // radiotap_header -> it_len setting
#define flags 0x00000000    // radiotap_header -> flags
#define Type 0x00C0        // deauth packet type
#define duration 0x0000     // deauth_header -> dur setting
#define number 0x0000       // deauth_header -> num setting
#define reason_code 0x0007  // wireless_header -> code setting


struct radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
}__attribute__((__packed__));

struct deauth_header {
    u_int16_t type;
    u_int16_t dur;
    Mac d_addr;
    Mac s_addr;
    Mac bssid;
    u_int16_t num;
};

struct wireless_header {
    u_int16_t code;
};

#pragma pack(push, 1)
struct DeauthPacket {
    radiotap_header radio;
    deauth_header dea;
    wireless_header wir;
};
#pragma pack(pop)

