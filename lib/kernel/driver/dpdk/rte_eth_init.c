#include <driver/pss_port.h>
#include <rte_memzone.h>
#include <rte_ethdev.h>
#include "rte_eth_core.h"
#include "rte_eth_config.h"

bool pss_ethlayer_prepare(void)
{
    int ret;
    char ethpath[100];

    if (rte_eal_process_type() != RTE_PROC_PRIMARY) 
        return false;

    rte_rst_config(RTE_PORT_ALL);
    snprintf(ethpath, sizeof(ethpath), "%s/%s", RTE_ETHERNET_DIR, RTE_ETHERDEV_ENV_NAME);
    ret = rte_gcfg_setup(ethpath);
    if (ret < 0) {
        fprintf(stderr, "rt_ethdev: Cannot load cfgfile\n");
		return false;
    }

    return true;
}

struct pss_port* pss_port_setup(const char* ifname)
{
    int ret, portid;
    unsigned int socketid;
    struct rte_memzone* mz;
    struct pss_port* port;

    int ret = rte_eth_dev_get_port_by_name(ifname, &portid);
    if (ret < 0) {
        fprintf(stderr, "Ethdev does not exist\n");
        return NULL;
    }

    socketid = rte_eth_dev_socket_id(portid);
    mz = rte_memzone_reserve_aligned(ifname, sizeof(struct pss_port) + sizeof(struct rte_port), socketid, 
                                        0, RTE_CACHE_LINE_SIZE);
    if (mz == NULL) {
        fprintf(stderr, "Failed to allocate pss port\n");
        return NULL;
    }

    port = mz->addr;
    port->mz = mz;
    port->data = (struct rte_port*)((const char*)port + sizeof(struct pss_port));
    port->port_id = portid;
    port->socket_id = socketid;
    memcpy(port->name, ifname, sizeof(ifname));

    ret = rte_eth_setup(port);
    if (ret)
        goto failed;

    return port;
failed:
    rte_rst_config(portid);
    rte_memzone_free(mz);
    return NULL;
}

struct pss_port *pss_port_lookup(const char* ifname)
{
    struct rte_memzone *mz = rte_memzone_lookup(ifname);
    if (mz == NULL)
        return NULL;
    return (struct rte_memzone*)mz->addr;
}

void pss_port_cleanup(struct pss_port* port) 
{
    rte_eth_cleanup((struct rte_port*)port->data);
    rte_memzone_free(port->mz);
}