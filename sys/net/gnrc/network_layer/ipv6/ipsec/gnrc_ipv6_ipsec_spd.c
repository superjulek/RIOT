#include "net/gnrc/ipv6/ipsec/ipsec_spd.h"


ipsec_sp_rule_t ipsec_get_policy_rule(ipsec_ts_t *ts)
{
    (void)ts;
    return IPSEC_SP_RULE_PROTECT;
}
