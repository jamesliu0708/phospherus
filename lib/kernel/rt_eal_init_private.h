#ifndef _RT_EAL_INIT_H
#define _RT_EAL_INIT_H

struct eal_config {
    char lcores[2048];
    int megabytes;
    int nchannels;
    int nranks;
    char loglevel[64];
    char socket_mem[64];
};

/**
 *  Initialize the eal
 * 
 * @param eal_config 
 * @return int 
 */
int init_eal(struct eal_config* eal_config);

#endif // _RT_EAL_INIT_H