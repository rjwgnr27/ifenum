//#define _GNU_SOURCE /* To get definitiions of NI_MAXSERV and NI_MAXHOST */
#include <arpa/inet.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <iostream>
#include <optional>
#include <vector>

#include "ifenum_config.h"

#define SV(STR) {#STR, STR}
struct svPair {
    std::string_view name;
    int val;
};
static constexpr svPair afLookup[] = {
    SV(AF_UNSPEC),
    SV(AF_LOCAL),
    SV(AF_UNIX),
    SV(AF_FILE),
    SV(AF_INET),
    SV(AF_AX25),
    SV(AF_IPX),
    SV(AF_APPLETALK),
    SV(AF_NETROM),
    SV(AF_BRIDGE),
    SV(AF_ATMPVC),
    SV(AF_X25),
    SV(AF_INET6),
    SV(AF_ROSE),
    SV(AF_DECnet),
    SV(AF_NETBEUI),
    SV(AF_SECURITY),
    SV(AF_KEY),
    SV(AF_NETLINK),
    SV(AF_ROUTE),
    SV(AF_PACKET),
    SV(AF_ASH),
    SV(AF_ECONET),
    SV(AF_ATMSVC),
    SV(AF_RDS),
    SV(AF_SNA),
    SV(AF_IRDA),
    SV(AF_PPPOX),
    SV(AF_WANPIPE),
    SV(AF_LLC),
    SV(AF_IB),
    SV(AF_MPLS),
    SV(AF_CAN),
    SV(AF_TIPC),
    SV(AF_BLUETOOTH),
    SV(AF_IUCV),
    SV(AF_RXRPC),
    SV(AF_ISDN),
    SV(AF_PHONET),
    SV(AF_IEEE802154),
    SV(AF_CAIF),
    SV(AF_ALG),
    SV(AF_NFC),
    SV(AF_VSOCK),
    SV(AF_KCM),
    SV(AF_QIPCRTR),
    SV(AF_SMC),
    SV(AF_XDP),
    SV(AF_MCTP),
    SV(AF_MAX),
};

static constexpr svPair ifFlagsLookup[] = {
    SV(IFF_UP),
    SV(IFF_BROADCAST),
    SV(IFF_DEBUG),
    SV(IFF_LOOPBACK),
    SV(IFF_POINTOPOINT),
    SV(IFF_RUNNING),
    SV(IFF_NOARP),
    SV(IFF_PROMISC),
    SV(IFF_NOTRAILERS),
    SV(IFF_ALLMULTI),
    SV(IFF_MASTER),
    SV(IFF_SLAVE),
    SV(IFF_MULTICAST),
    SV(IFF_PORTSEL),
    SV(IFF_AUTOMEDIA),
    SV(IFF_DYNAMIC),
//     SV(IFF_LOWER_UP),
//     SV(IFF_DORMANT),
//     SV(IFF_ECHO),
};

static std::vector<std::string> interfaces;
static std::vector<sockaddr> addrs;
static std::vector<int> families;

static bool operator ==(sockaddr const& a, sockaddr const& b)
{
    auto sz = (a.sa_family == AF_INET) ? sizeof(in_addr) : sizeof(in6_addr);
    return a.sa_family == b.sa_family && memcmp(a.sa_data, b.sa_data, sz) == 0;
}

static std::string findAf(int fam)
{
    auto it = std::find_if(std::begin(afLookup), std::end(afLookup),
        [fam]( svPair const& af){return af.val == fam;});
    if (it == std::end(afLookup))
        return "af_unkwn_" + std::to_string(fam);
    else
        return std::string(it->name);
};

static std::string addrStr(sockaddr const *const saddr)
{
    if (!saddr)
        return "-";

    char host[NI_MAXHOST];
    std::optional<int> ret;
    auto const family = saddr->sa_family;
    switch (family) {
    case AF_INET:
        ret = getnameinfo(saddr, sizeof(sockaddr_in), host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
        break;

    case AF_INET6:
        ret = getnameinfo(saddr, sizeof(sockaddr_in6), host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
        break;
    }
    if (ret) {
        if (*ret == 0)
            return host;
        else
            return gai_strerror(*ret);
    }
    return "";
}

static void enumAddresses(ifaddrs const* addr)
{
    for(; addr; addr = addr->ifa_next) {
        if (!addr->ifa_addr)
            continue;

        if ( !interfaces.empty() && std::none_of(interfaces.begin(), interfaces.end(),
             [addr](std::string const& name){return addr->ifa_name == name;}) )
            continue;

        if ( !families.empty() && std::none_of(families.begin(), families.end(),
             [addr](int fam){return addr->ifa_addr->sa_family == fam;}) )
            continue;

        if ( !addrs.empty() && std::none_of(addrs.begin(), addrs.end(),
             [addr](sockaddr const& sa){return *addr->ifa_addr == sa;}) )
            continue;

        std::cout << addr->ifa_name << ": "
                  << findAf(addr->ifa_addr->sa_family) << ' '
                  << addrStr(addr->ifa_addr) << '/' << addrStr(addr->ifa_netmask);
        std::cout << " [";
        bool first = true;
        for(auto const& sv : ifFlagsLookup) {
            if (addr->ifa_flags & sv.val) {
                if (!first)
                    std::cout << ' ';
                first = false;
                std::cout << sv.name;
            }
        }
        std::cout << ']';
        std::cout << '\n';
    }
}


enum args : int {
    argUnkown   = '?',
    argMissing  = ':',
    argDone     = -1,
    argHelp     = 'h',
    argAddr     = 'a',
    argFam      = 'f',
    argIface    = 'i',
    argVersion  = 'v',
    argHelpAf   = 0x100,
};
static constexpr option argOpts[] = {
    {"help",    no_argument,        nullptr,        argHelp},
    {"help-af", no_argument,        nullptr,        argHelpAf},
    {"addr",    required_argument,  nullptr,        argAddr},
    {"af",      required_argument,  nullptr,        argFam},
    {"iface",   required_argument,  nullptr,        argIface},
    {"version", no_argument,        nullptr,        argVersion},
    {nullptr, 0, nullptr, 0}
};

enum class argsReturn {
    ok,
    error,
    exit
};

static void printAfs()
{
    std::cerr << "Address families:";
    int col = 1000;
    for(auto const& af : afLookup) {
        col += af.name.size() + 1;
        if (col > 80) {
            std::cerr << "\n    ";
            col = 4 + af.name.size() + 1;
        }
        std::cerr << af.name << ' ';
    }
    std::cerr << '\n';
}

static argsReturn processArgs(int argc, char * const argv[])
{
    while (1) {
        int c = getopt_long(argc, argv, ":ha:f:i:v", argOpts, nullptr);
        switch (static_cast<args>(c)) {
        case argUnkown:
            break;

        case argDone:
            return argsReturn::ok;

        case argMissing:
            return argsReturn::error;

        case argHelp:
            return argsReturn::error;

        case argHelpAf:
            printAfs();
            return argsReturn::exit;

        case argIface:
            interfaces.push_back(optarg);
            break;

        case argFam: {
                std::string_view arg(optarg);
                auto it = std::find_if(std::begin(afLookup), std::end(afLookup),
                        [&arg]( svPair const& af) {return af.name == arg;});
                if (it == std::end(afLookup)) {
                    std::cerr << "unknown family '" << arg << "'\n";
                    return argsReturn::error;
                }
                families.push_back(it->val);
            }
            break;

        case argAddr: {
                addrinfo *info;
                int ret = getaddrinfo(optarg, nullptr, nullptr, &info);
                if (ret != 0) {
                    std::cerr << "Could not convert '" << optarg << "' to address: '"
                              << gai_strerror(ret) << "'\n";
                    return argsReturn::error;
                }
                for (addrinfo const *i = info; i; i = i->ai_next) {
                    if (i->ai_family == AF_INET || i->ai_family == AF_INET6) {
                        if (std::none_of(addrs.begin(), addrs.end(),
                                     [i](sockaddr const& sa){return *i->ai_addr == sa;}))
                            addrs.push_back(*i->ai_addr);
                    } else
                        std::cout << optarg << " is not AF_INET or AF_INET6\n";
                }
                freeaddrinfo(info);
            }
            break;

        case argVersion:
            std::cout << "version " << APP_VERSION_STRING << '\n';
            return argsReturn::exit;
        }
    }
}

int main(int argc, char **argv)
{
    switch(processArgs(argc, argv)) {
    case argsReturn::ok:
        break;

    case argsReturn::exit:
        return 0;

    case argsReturn::error:
        std::cerr << "Usage: " << argv[0] << " [OPTS]\n"
            "OPTS are:\n"
            "   -h, --help          Show this help.\n"
            "       --help-af       Show known address families for '--family=' option\n"
            "   -a, --addr=ADDR     Only for network address ADDR (may be given multiple times)\n"
            "   -f, --af=AF         Only for address family AF (may be given multiple times)\n"
            "   -i, --iface=IFACE   Only for interface IFACE (may be given multiple times)\n"
            "   -v, --version       Show version and quit.\n"
            "\n"
            "Filters may be combined. For example, '--af=AF_INET --af=AF_INET6 --iface=eth0'\n"
            "will display IPV4 and IPV6 addresses for interface eth0.\n"
            "\n";
        return -1;
    }

    if (!addrs.empty()) {
        std::cout << "Address filters:\n";
        for (auto const& i : addrs)
            std::cout <<  (i.sa_family == AF_INET ? "AF_INET  " : "AF_INET6 ") << addrStr(&i) << '\n';
    }
    ifaddrs *addrList;
    if (int ret = getifaddrs(&addrList); ret != 0) {
        char errString[64];
        std::cerr << "could not enumerate addresses: " << strerror_r(errno, errString, sizeof(errString)) << '\n';
        return EXIT_FAILURE;
    }

    std::sort(interfaces.begin(), interfaces.end());
    interfaces.erase(std::unique(interfaces.begin(), interfaces.end()), interfaces.end());
    enumAddresses(addrList);
    freeifaddrs(addrList);
    return EXIT_FAILURE;
}
