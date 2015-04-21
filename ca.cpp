#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <ifaddrs.h>

#include <net/if.h>
#ifndef __linux__
#include <net/if_dl.h>
#endif

#include <string>
#include <net/ethernet.h>

#include "common.hpp"
#include "ether.hpp"

void usage(char* prog_name)
{
    printf("cell advertisor\n");
    printf("%s [interface]\n", prog_name);
}

int
main(int argc, char** argv)
{
    debug = true;

    if (argc != 2) {
        usage(argv[0]);
        exit(EXIT_FAILURE);

    }

    uint8_t  dst_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    struct ether_addr src_mac;
    memset(&src_mac, 0, sizeof(src_mac));

    std::vector<std::string> if_list = get_ifname_list();

    char ifname[IFNAMSIZ];
    memset(ifname, 0, sizeof(ifname));
    strncpy(ifname, argv[1], strlen(argv[1]));

    bool is_loopback;
#ifndef __linux__
    is_loopback = strncmp(ifname, "lo0", strlen("lo0"));
#else
    is_loopback = strncmp(ifname, "lo", strlen("lo"));
#endif
    if (is_loopback == 0) {
        MESG("ca cant use with lo0.");
        exit(EXIT_FAILURE);
    }

    std::string str_ifname = ifname;
    if (!is_exist_if(if_list, str_ifname)) {
        MESG("A selected interface is not exist.");
        exit(EXIT_FAILURE);
    }

#ifndef __linux__
    struct ifaddrs *ifs;
    struct ifaddrs *ifp;
    struct sockaddr_dl* dl;

    if (getifaddrs(&ifs) != 0) {
        PERROR("getifaddrs");
        MESG("unabe to get interface info for %s", ifname);
        return false;
    }

    for (ifp=ifs; ifp; ifp=ifp->ifa_next) {
        int ifp_family = ifp->ifa_addr->sa_family;

        if (ifp->ifa_addr == NULL) {
            continue;
        } else if (ifp_family != AF_LINK) {
            continue;
        }

        dl = (struct sockaddr_dl*)ifp->ifa_addr;

        if (strncmp(ifname, dl->sdl_data, dl->sdl_nlen) == 0) {
            memcpy(&src_mac, LLADDR(dl), ETHER_ADDR_LEN);
            break;
        }
    }
    freeifaddrs(ifs);
#else
    {
        int fd;
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, ifname, strlen(ifname));
        ioctl(fd, SIOCGIFHWADDR, &ifr);
        close(fd);
        memcpy(&src_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    }
#endif

    printf("src:%s\n", ether_ntoa(&src_mac));
    printf("dst:%s\n", ether_ntoa(&src_mac));

    char pcapbuf[PCAP_ERRBUF_SIZE];
    memset(pcapbuf, 0, sizeof(pcapbuf));

    pcap_t* handler = pcap_create(ifname, pcapbuf);

    if (handler == NULL) {
        std::cout << "Cannot open device " << ifname << "." << std::endl;
        std::cout << pcapbuf << std::endl;
        exit(EXIT_FAILURE);
    }

    if (pcap_activate(handler) != 0) {
        pcap_perror(handler, (char*)"ERROR");
        exit(EXIT_FAILURE);
    }

    uint8_t advbuf[64];
    memset(advbuf, 0, sizeof(advbuf));
    struct ether_header* eth = (struct ether_header*)advbuf;
    memcpy(eth->ether_dhost, dst_mac, sizeof(dst_mac));
    memcpy(eth->ether_shost, &src_mac, sizeof(src_mac));
    eth->ether_type = htons(ETHERTYPE_IP);
    eth->ether_type = htons(0x0101);
    // 0101-01FF exp number

    int ret;
    while ( 1 ) {
        ret =pcap_inject(handler, advbuf, 64);
        //perror("pcap_inject");
        if(ret < 0) std::cout << "Failed to inject" << std::endl; 
        sleep(10);
    }

    return 0;
}

