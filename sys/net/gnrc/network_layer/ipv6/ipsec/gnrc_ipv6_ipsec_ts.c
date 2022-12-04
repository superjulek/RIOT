#include "net/gnrc/ipv6/ipsec/ipsec_ts.h"


int ipsec_ts_from_pkt(gnrc_pktsnip_t *pkt, ipsec_ts_t *ts)
{
    (void) pkt;

    ts->a = 1;
    return 0;
}
