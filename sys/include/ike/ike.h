/*
 * Copyright (C) 2022 Juliusz Neuman
 */

/**
 * @defgroup    sys_ps IKE
 * @ingroup     sys
 * @brief       Control IKE daemon
 * @{
 *
 * @file
 * @brief       IKE
 *
 * @author      Juliusz Neuman <neuman.juliusz@gmail.com>
 */

#ifndef IKE_H
#define IKE_H

#ifdef __cplusplus
extern "C"
{
#endif

#define HASH_SIZE_SHA1 20
#define HMAC_SIZE_SHA1_96 12
#define KEY_SIZE_SHA1 20

#define countof(t) sizeof(t)/sizeof(*t)

    typedef enum
    {
        IKE_STATE_OFF = 0,
        IKE_STATE_NEGOTIATION = 1,
        IKE_STATE_ESTABLISHED = 2,
    } ike_state_t;

    int ike_init(char *addr_str);

    /**
     * @brief IKE.
     */
    void ikectrl(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* IKE_H */
/** @} */
