/*
 * wdfilter: WinDivert's own filter compiler/evaluator built for the host
 * (Linux/macOS) against the WinDivert 2.2.2 sources, so filter strings can
 * be checked without Windows. See build.sh.
 *
 *   wdfilter compile <filter> [layer]      -> "OK" or "ERR <msg> at <pos>"
 *   wdfilter eval <filter> <hex-packet> <outbound 0|1> [loopback 0|1] -> "1" or "0"
 */
#include <windows.h>
#include <stdio.h>
#define WINDIVERTEXPORT
#include "windivert.h"
#include "windivert_device.h"
#define WINDIVERT_GET_DATA(p, l, mi, ma, i, d, s) 0
#include "protos.c"
#include "windivert_shared.c"
#include "windivert_helper.c"
#include "strfuncs.c"

static int unhex(const char *s, unsigned char *out, int max) {
    int n = 0;
    for (; s[0] && s[1] && n < max; s += 2) {
        unsigned v; sscanf(s, "%2x", &v); out[n++] = (unsigned char)v;
    }
    return n;
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "compile") == 0) {
        static char obj[65536]; const char *err = NULL; UINT pos = 0;
        int layer = argc > 3 ? atoi(argv[3]) : 0;
        if (WinDivertHelperCompileFilter(argv[2], (WINDIVERT_LAYER)layer, obj, sizeof(obj), &err, &pos)) {
            printf("OK\n"); return 0;
        }
        printf("ERR %s at %u\n", err ? err : "?", pos); return 1;
    }
    if (argc >= 5 && strcmp(argv[1], "eval") == 0) {
        static unsigned char pkt[65536];
        int n = unhex(argv[3], pkt, sizeof(pkt));
        WINDIVERT_ADDRESS addr; memset(&addr, 0, sizeof(addr));
        addr.Layer = WINDIVERT_LAYER_NETWORK;
        addr.Outbound = atoi(argv[4]) != 0;
        addr.Loopback = argc > 5 && atoi(argv[5]) != 0;
        addr.IPv6 = (pkt[0] >> 4) == 6;
        SetLastError(0);
        BOOL r = WinDivertHelperEvalFilter(argv[2], pkt, n, &addr);
        if (!r && GetLastError() != 0) { printf("ERR %u\n", GetLastError()); return 2; }
        printf("%d\n", r ? 1 : 0); return 0;
    }
    fprintf(stderr, "usage: wdfilter compile <filter> | eval <filter> <hex> <outbound>\n");
    return 2;
}
