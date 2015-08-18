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
#else
#include <netinet/ether.h>
#endif

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <string>
#include <net/ethernet.h>

#include "common.hpp"
#include "ether.hpp"

static inline uint16_t
checksum(const uint8_t* buf, size_t size, uint32_t adjust)
{
    uint32_t sum = 0;
    uint16_t element = 0;

    while (size>0) {
        element = (*buf)<<8;
        buf++;
        size--;
        if (size>0) {
            element |= *buf;
            buf++;
            size--;
        }
        sum += element;
    }
    sum += adjust;

    while (sum>0xFFFF) {
        sum = (sum>>16) + (sum&0xFFFF);
    }

    return (~sum) & 0xFFFF;
}

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
    printf("dst:%s\n", ether_ntoa((ether_addr*)dst_mac));

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

    struct {
        uint8_t  src[16];
        uint8_t  dst[16];
        uint32_t len;
        uint8_t  nxt[4];
    } ipv6_pseudo_hdr;

    struct {
        ether_header       eth;
        ip6_hdr            ip6h;
        nd_neighbor_advert na;
    } ipv6_na;

    memset(&ipv6_pseudo_hdr, 0, sizeof(ipv6_pseudo_hdr));
    memset(&ipv6_na, 0, sizeof(ipv6_na));

    // set ethernet header
    memcpy(&ipv6_na.eth.ether_dhost, dst_mac, sizeof(dst_mac));
    memcpy(&ipv6_na.eth.ether_shost, &src_mac, sizeof(src_mac));
    ipv6_na.eth.ether_type = htons(ETHERTYPE_IPV6);

    // set IPv6 header
    ipv6_na.ip6h.ip6_vfc  = 0x60;
    ipv6_na.ip6h.ip6_plen = ntohs(sizeof(ipv6_na.na));
    ipv6_na.ip6h.ip6_nxt  = IPPROTO_ICMPV6;
    ipv6_na.ip6h.ip6_hlim = 0xff;

    uint8_t ipv6_dst[16] = {0xff, 0x02, 0, 0,
                               0,    0, 0, 0,
                               0,    0, 0, 0,
                               0,    0, 0, 1};
    uint8_t ipv6_src[16] = {0xfe, 0x80, 0,    0,
                               0,    0, 0,    0,
                               0,    0, 0, 0xff,
                            0xfe,    0, 0,    0};

    ipv6_src[ 8] = src_mac.ether_addr_octet[0] ^ 0x02;
    ipv6_src[ 9] = src_mac.ether_addr_octet[1];
    ipv6_src[10] = src_mac.ether_addr_octet[2];
    ipv6_src[13] = src_mac.ether_addr_octet[3];
    ipv6_src[14] = src_mac.ether_addr_octet[4];
    ipv6_src[15] = src_mac.ether_addr_octet[5];

    memcpy(&ipv6_na.ip6h.ip6_dst, ipv6_dst, sizeof(ipv6_dst));
    memcpy(&ipv6_na.ip6h.ip6_src, ipv6_src, sizeof(ipv6_src));

    // set ICMPv6 Neighbor Advertisement
    ipv6_na.na.nd_na_hdr.icmp6_type = ND_NEIGHBOR_ADVERT;
    memcpy(&ipv6_na.na.nd_na_target, ipv6_dst, sizeof(ipv6_dst));

    // TODO: checksum
    memcpy(ipv6_pseudo_hdr.src, ipv6_src, sizeof(ipv6_src));
    memcpy(ipv6_pseudo_hdr.dst, ipv6_dst, sizeof(ipv6_dst));
    ipv6_pseudo_hdr.nxt[3] = IPPROTO_ICMPV6;

    uint32_t sum32;
    sum32 = checksum((uint8_t*)&ipv6_pseudo_hdr, sizeof(ipv6_pseudo_hdr), 0);
    sum32 = checksum((uint8_t*)&ipv6_na, sizeof(ipv6_na), sum32);

    ipv6_na.na.nd_na_hdr.icmp6_cksum = ntohs(sum32);

    // uint8_t advbuf[64];
    // memset(advbuf, 0, sizeof(advbuf));
    // struct ether_header* eth = (struct ether_header*)advbuf;
    // memcpy(eth->ether_dhost, dst_mac, sizeof(dst_mac));
    // memcpy(eth->ether_shost, &src_mac, sizeof(src_mac));
    // eth->ether_type = htons(ETHERTYPE_IP);
    // eth->ether_type = htons(0x0101);
    // 0101-01FF exp number

    int ret;
    while ( 1 ) {
        ret = pcap_inject(handler, &ipv6_na, sizeof(ipv6_na));
        //perror("pcap_inject");
        if(ret < 0) std::cout << "Failed to inject" << std::endl; 
        sleep(10);
    }

    return 0;
}

