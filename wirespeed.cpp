// wirespeed: saturate the cable between two local NICs with raw ethernet frames.
//
// Frames are sent on <src> and counted on <dst> via npcap (https://npcap.com),
// bypassing the Windows IP stack

#define NOMINMAX
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>
#pragma comment(lib, "iphlpapi")
#pragma comment(lib, "ole32")

// libpcap API used here, resolved at runtime
struct pcap_t;
struct pcap_pkthdr { timeval ts; unsigned caplen, len; };
struct pcap_send_queue { unsigned maxlen, len; char* buffer; };
struct pcap_stat { unsigned ps_recv, ps_drop, ps_ifdrop, win32_extra[3]; };
struct bpf_insn { unsigned short code; unsigned char jt, jf; unsigned k; };
struct bpf_program { unsigned bf_len; bpf_insn* bf_insns; };
typedef void (*pcap_handler)(unsigned char*, const pcap_pkthdr*, const unsigned char*);
static pcap_t* (*pcap_open_live)(const char*, int, int, int, char*);
static int (*pcap_setfilter)(pcap_t*, bpf_program*);
static int (*pcap_setbuff)(pcap_t*, int);
static int (*pcap_dispatch)(pcap_t*, int, pcap_handler, unsigned char*);
static int (*pcap_stats)(pcap_t*, pcap_stat*);
static char* (*pcap_geterr)(pcap_t*);
static pcap_send_queue* (*pcap_sendqueue_alloc)(unsigned);
static int (*pcap_sendqueue_queue)(pcap_send_queue*, const pcap_pkthdr*, const unsigned char*);
static unsigned (*pcap_sendqueue_transmit)(pcap_t*, pcap_send_queue*, int);

static bool load_npcap() {
    wchar_t dir[MAX_PATH];
    GetSystemDirectoryW(dir, MAX_PATH);
    wcscat_s(dir, L"\\Npcap");  // for wpcap.dll/Packet.dll
    SetDllDirectoryW(dir);
    HMODULE m = LoadLibraryW(L"wpcap.dll");
#define GET(f) (f = (decltype(f))GetProcAddress(m, #f))
    return m && GET(pcap_open_live) && GET(pcap_setfilter) && GET(pcap_setbuff) && GET(pcap_dispatch) &&
           GET(pcap_stats) && GET(pcap_geterr) && GET(pcap_sendqueue_alloc) && GET(pcap_sendqueue_queue) &&
           GET(pcap_sendqueue_transmit);
#undef GET
}

static MIB_IF_TABLE2* g_nics;

static bool wired(const MIB_IF_ROW2& r) {
    return r.Type == IF_TYPE_ETHERNET_CSMACD && r.InterfaceAndOperStatusFlags.HardwareInterface &&
           !r.InterfaceAndOperStatusFlags.FilterInterface;
}

static bool up(const MIB_IF_ROW2& r) { return r.MediaConnectState == MediaConnectStateConnected; }

static const MIB_IF_ROW2* find_nic(const wchar_t* name_or_index) {
    for (ULONG i = 0; i < g_nics->NumEntries; i++) {
        const MIB_IF_ROW2& r = g_nics->Table[i];
        if (wired(r) && (!_wcsicmp(r.Alias, name_or_index) || r.InterfaceIndex == wcstoul(name_or_index, nullptr, 10)))
            return &r;
    }
    return nullptr;
}

static pcap_t* open_nic(const MIB_IF_ROW2& r) {
    wchar_t guid[40];
    StringFromGUID2(r.InterfaceGuid, guid, 40);
    char dev[64], err[256] = "";  // PCAP_ERRBUF_SIZE
    snprintf(dev, sizeof dev, "\\Device\\NPF_%ls", guid);
    pcap_t* p = pcap_open_live(dev, 64, 0, 100, err);
    if (!p) fprintf(stderr, "can't open %ls: %s\n", r.Alias, err);
    return p;
}

static HANDLE g_stop;            // ctrl+c or error
static unsigned char g_hdr[14];  // dst MAC, src MAC, EtherType of frames
static std::atomic<unsigned long long> g_sent, g_recv;

static void count(unsigned char*, const pcap_pkthdr* h, const unsigned char* pkt) {
    if (h->caplen >= 14 && !memcmp(pkt, g_hdr, 14)) g_recv++;
}

int wmain(int argc, wchar_t** argv) {
    if (GetIfTable2(&g_nics) != NO_ERROR) return 1;
    const MIB_IF_ROW2* src = argc > 2 ? find_nic(argv[1]) : nullptr;
    const MIB_IF_ROW2* dst = argc > 2 ? find_nic(argv[2]) : nullptr;
    if (!src || !dst || src == dst) {
        puts("usage: wirespeed <src> <dst> [frame_bytes]\n"
             "Send raw frames from <src>, counts/receives on <dst>. Ctrl+C to stop.\n\n"
             "wired NICs (name or index):");
        for (ULONG i = 0; i < g_nics->NumEntries; i++) {
            const MIB_IF_ROW2& r = g_nics->Table[i];
            const unsigned char* m = r.PhysicalAddress;
            if (!wired(r)) continue;
            printf("  %4lu  %-20ls %02X-%02X-%02X-%02X-%02X-%02X  ", r.InterfaceIndex, r.Alias, m[0], m[1], m[2], m[3],
                   m[4], m[5]);
            if (up(r)) printf("%llu Mbit/s\n", r.ReceiveLinkSpeed / 1000000);
            else puts("no link");
        }
        return 1;
    }
    if (!up(*src) || !up(*dst)) {
        fputs("both NICs need a link: plug the cable in\n", stderr);
        return 1;
    }
    unsigned maxlen = 14 + std::min(src->Mtu, dst->Mtu);
    unsigned n = argc > 3 ? wcstoul(argv[3], nullptr, 10) : maxlen;
    if (n < 60 || n > maxlen) {
        fprintf(stderr, "frame_bytes must be 60..%u (MTU + 14; enable jumbo frames on both NICs for more)\n", maxlen);
        return 1;
    }
    if (!load_npcap()) {
        fputs("`npcap` not found: install it from https://npcap.com\n", stderr);
        return 1;
    }

    // unicast to dst's MAC so the NIC accepts the frames without promiscuous mode.
    // EtherType 0x88B5= IEEE "local experimental"
    std::vector<unsigned char> frame(n);
    for (auto& c : frame) c = (unsigned char)rand();
    memcpy(&frame[0], dst->PhysicalAddress, 6);
    memcpy(&frame[6], src->PhysicalAddress, 6);
    frame[12] = 0x88;
    frame[13] = 0xB5;
    memcpy(g_hdr, frame.data(), 14);

    // each send batch blocks until the NIC completes it,
    // a second sender keeps the wire busy meanwhile.
    pcap_t* rx = open_nic(*dst);
    pcap_t* tx[2] = {open_nic(*src), open_nic(*src)};
    if (!rx || !tx[0] || !tx[1]) return 1;
    pcap_setbuff(rx, 32 << 20);
    bpf_insn ret0{6, 0, 0, 0};  // BPF "ret #0", the sending handles
    bpf_program capture_nothing{1, &ret0};
    for (pcap_t* p : tx) pcap_setfilter(p, &capture_nothing);

    g_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler([](DWORD) -> BOOL { SetEvent(g_stop); return TRUE; }, TRUE);
    std::atomic<bool> capturing{true};
    std::thread receiver([&] {
        while (capturing)
            if (pcap_dispatch(rx, -1, count, nullptr) < 0) {
                fprintf(stderr, "capture failed: %s\n", pcap_geterr(rx));
                SetEvent(g_stop);
                break;
            }
    });
    std::vector<std::thread> senders;
    for (pcap_t* p : tx)
        senders.emplace_back([&, p] {
            pcap_send_queue* q = pcap_sendqueue_alloc(4 << 20);
            pcap_pkthdr h{{0, 0}, n, n};
            while (pcap_sendqueue_queue(q, &h, frame.data()) == 0) {}  // fill 4 MB with copies of the frame
            while (WaitForSingleObject(g_stop, 0) == WAIT_TIMEOUT) {
                unsigned bytes = pcap_sendqueue_transmit(p, q, 0);
                g_sent += bytes / (sizeof h + n);
                if (bytes < q->len) {
                    fprintf(stderr, "send failed: %s\n", pcap_geterr(p));
                    SetEvent(g_stop);
                }
            }
        });

    double line_bps = (double)std::min(src->TransmitLinkSpeed, dst->ReceiveLinkSpeed);
    printf("%ls -> %ls, %u-byte frames, %.0f Mbit/s link. Ctrl+C to stop.\n", src->Alias, dst->Alias, n, line_bps / 1e6);
    auto t0 = std::chrono::steady_clock::now(), last = t0;
    unsigned long long seen = 0;
    while (WaitForSingleObject(g_stop, 1000) == WAIT_TIMEOUT) {
        auto now = std::chrono::steady_clock::now();
        unsigned long long total = g_recv;
        double fps = (total - seen) / std::chrono::duration<double>(now - last).count();
        // on the wire every frame also costs 24 bytes: preamble+SFD 8, FCS 4, inter-frame gap 12
        printf("%6.0fs %9.1f Mbit/s %8.1f kpps %6.1f%% of line\n", std::chrono::duration<double>(now - t0).count(),
               fps * n * 8 / 1e6, fps / 1e3, fps * (n + 24) * 8 / line_bps * 100);
        fflush(stdout);
        seen = total;
        last = now;
    }

    for (auto& s : senders) s.join();
    double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    Sleep(200);  // let the last frames land
    capturing = false;
    receiver.join();
    pcap_stat st{};
    pcap_stats(rx, &st);
    unsigned long long sent = g_sent, recv = g_recv;
    printf("\nsent %llu frames, received %llu, lost %lld (%.4f%%), avg %.1f Mbit/s over %.1f s\n", sent, recv,
           (long long)(sent - recv), sent ? 100.0 * (sent - recv) / sent : 0.0, recv * n * 8 / secs / 1e6, secs);
    if (st.ps_drop) printf("(%u of those were the capture on %ls falling behind, not the wire)\n", st.ps_drop, dst->Alias);
    return 0;
}
