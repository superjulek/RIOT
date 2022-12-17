#ifndef IPSECNET_GNRC_IPV6_IPSEC_ENUMS_H
#define IPSECNET_GNRC_IPV6_IPSEC_ENUMS_H


#ifdef __cplusplus
extern "C" {
#endif


typedef enum {
    IPSEC_SP_RULE_PROTECT,
    IPSEC_SP_RULE_BYPASS,
    IPSEC_SP_RULE_DROP,
    IPSEC_SP_RULE_ERROR,
} ipsec_sp_rule_t;

typedef enum {
    TRAFFIC_DIR_OUT,
    TRAFFIC_DIR_IN,
} traffic_dir_t;

#ifdef __cplusplus
}
#endif

#endif /* IPSECNET_GNRC_IPV6_IPSEC_ENUMS_H */
