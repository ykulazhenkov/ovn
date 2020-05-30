/* Copyright (c) 2015, 2016, 2017 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "binding.h"
#include "ha-chassis.h"
#include "lflow.h"
#include "lport.h"
#include "patch.h"

#include "lib/bitmap.h"
#include "openvswitch/poll-loop.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "lib/netdev.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "lib/chassis-index.h"
#include "lib/ovn-sb-idl.h"
#include "ovn-controller.h"

VLOG_DEFINE_THIS_MODULE(binding);

#define OVN_QOS_TYPE "linux-htb"

struct qos_queue {
    struct hmap_node node;
    uint32_t queue_id;
    uint32_t max_rate;
    uint32_t burst;
};

void
binding_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_bridges);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_ports);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_port);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_qos);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_external_ids);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_bfd);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_bfd_status);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_status);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_qos);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_qos_col_type);
}

static void
add_local_datapath__(struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                     struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
                     struct ovsdb_idl_index *sbrec_port_binding_by_name,
                     const struct sbrec_datapath_binding *datapath,
                     bool has_local_l3gateway, int depth,
                     struct hmap *local_datapaths)
{
    uint32_t dp_key = datapath->tunnel_key;
    struct local_datapath *ld = get_local_datapath(local_datapaths, dp_key);
    if (ld) {
        if (has_local_l3gateway) {
            ld->has_local_l3gateway = true;
        }
        return;
    }

    ld = xzalloc(sizeof *ld);
    hmap_insert(local_datapaths, &ld->hmap_node, dp_key);
    ld->datapath = datapath;
    ld->localnet_port = NULL;
    ld->has_local_l3gateway = has_local_l3gateway;

    if (depth >= 100) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "datapaths nested too deep");
        return;
    }

    struct sbrec_port_binding *target =
        sbrec_port_binding_index_init_row(sbrec_port_binding_by_datapath);
    sbrec_port_binding_index_set_datapath(target, datapath);

    const struct sbrec_port_binding *pb;
    SBREC_PORT_BINDING_FOR_EACH_EQUAL (pb, target,
                                       sbrec_port_binding_by_datapath) {
        if (!strcmp(pb->type, "patch") || !strcmp(pb->type, "l3gateway")) {
            const char *peer_name = smap_get(&pb->options, "peer");
            if (peer_name) {
                const struct sbrec_port_binding *peer;

                peer = lport_lookup_by_name(sbrec_port_binding_by_name,
                                            peer_name);

                if (peer && peer->datapath) {
                    if (!strcmp(pb->type, "patch")) {
                        /* Add the datapath to local datapath only for patch
                         * ports. For l3gateway ports, since gateway router
                         * resides on one chassis, we don't need to add.
                         * Otherwise, all other chassis might create patch
                         * ports between br-int and the provider bridge. */
                        add_local_datapath__(sbrec_datapath_binding_by_key,
                                             sbrec_port_binding_by_datapath,
                                             sbrec_port_binding_by_name,
                                             peer->datapath, false,
                                             depth + 1, local_datapaths);
                    }
                    ld->n_peer_ports++;
                    if (ld->n_peer_ports > ld->n_allocated_peer_ports) {
                        ld->peer_ports =
                            x2nrealloc(ld->peer_ports,
                                       &ld->n_allocated_peer_ports,
                                       sizeof *ld->peer_ports);
                    }
                    ld->peer_ports[ld->n_peer_ports - 1].local = pb;
                    ld->peer_ports[ld->n_peer_ports - 1].remote = peer;
                }
            }
        }
    }
    sbrec_port_binding_index_destroy_row(target);
}

static void
add_local_datapath(struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                   struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
                   struct ovsdb_idl_index *sbrec_port_binding_by_name,
                   const struct sbrec_datapath_binding *datapath,
                   bool has_local_l3gateway, struct hmap *local_datapaths)
{
    add_local_datapath__(sbrec_datapath_binding_by_key,
                         sbrec_port_binding_by_datapath,
                         sbrec_port_binding_by_name,
                         datapath, has_local_l3gateway, 0, local_datapaths);
}

static void
get_qos_params(const struct sbrec_port_binding *pb, struct hmap *queue_map)
{
    uint32_t max_rate = smap_get_int(&pb->options, "qos_max_rate", 0);
    uint32_t burst = smap_get_int(&pb->options, "qos_burst", 0);
    uint32_t queue_id = smap_get_int(&pb->options, "qdisc_queue_id", 0);

    if ((!max_rate && !burst) || !queue_id) {
        /* Qos is not configured for this port. */
        return;
    }

    struct qos_queue *node = xzalloc(sizeof *node);
    hmap_insert(queue_map, &node->node, hash_int(queue_id, 0));
    node->max_rate = max_rate;
    node->burst = burst;
    node->queue_id = queue_id;
}

static const struct ovsrec_qos *
get_noop_qos(struct ovsdb_idl_txn *ovs_idl_txn,
             const struct ovsrec_qos_table *qos_table)
{
    const struct ovsrec_qos *qos;
    OVSREC_QOS_TABLE_FOR_EACH (qos, qos_table) {
        if (!strcmp(qos->type, "linux-noop")) {
            return qos;
        }
    }

    if (!ovs_idl_txn) {
        return NULL;
    }
    qos = ovsrec_qos_insert(ovs_idl_txn);
    ovsrec_qos_set_type(qos, "linux-noop");
    return qos;
}

static bool
set_noop_qos(struct ovsdb_idl_txn *ovs_idl_txn,
             const struct ovsrec_port_table *port_table,
             const struct ovsrec_qos_table *qos_table,
             struct sset *egress_ifaces)
{
    if (!ovs_idl_txn) {
        return false;
    }

    const struct ovsrec_qos *noop_qos = get_noop_qos(ovs_idl_txn, qos_table);
    if (!noop_qos) {
        return false;
    }

    const struct ovsrec_port *port;
    size_t count = 0;

    OVSREC_PORT_TABLE_FOR_EACH (port, port_table) {
        if (sset_contains(egress_ifaces, port->name)) {
            ovsrec_port_set_qos(port, noop_qos);
            count++;
        }
        if (sset_count(egress_ifaces) == count) {
            break;
        }
    }
    return true;
}

static void
set_qos_type(struct netdev *netdev, const char *type)
{
    int error = netdev_set_qos(netdev, type, NULL);
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "%s: could not set qdisc type \"%s\" (%s)",
                     netdev_get_name(netdev), type, ovs_strerror(error));
    }
}

static void
setup_qos(const char *egress_iface, struct hmap *queue_map)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
    struct netdev *netdev_phy;

    if (!egress_iface) {
        /* Queues cannot be configured. */
        return;
    }

    int error = netdev_open(egress_iface, NULL, &netdev_phy);
    if (error) {
        VLOG_WARN_RL(&rl, "%s: could not open netdev (%s)",
                     egress_iface, ovs_strerror(error));
        return;
    }

    /* Check current qdisc. */
    const char *qdisc_type;
    struct smap qdisc_details;

    smap_init(&qdisc_details);
    if (netdev_get_qos(netdev_phy, &qdisc_type, &qdisc_details) != 0 ||
        qdisc_type[0] == '\0') {
        smap_destroy(&qdisc_details);
        netdev_close(netdev_phy);
        /* Qos is not supported. */
        return;
    }
    smap_destroy(&qdisc_details);

    /* If we're not actually being requested to do any QoS:
     *
     *     - If the current qdisc type is OVN_QOS_TYPE, then we clear the qdisc
     *       type to "".  Otherwise, it's possible that our own leftover qdisc
     *       settings could cause strange behavior on egress.  Also, QoS is
     *       expensive and may waste CPU time even if it's not really in use.
     *
     *       OVN isn't the only software that can configure qdiscs, and
     *       physical interfaces are shared resources, so there is some risk in
     *       this strategy: we could disrupt some other program's QoS.
     *       Probably, to entirely avoid this possibility we would need to add
     *       a configuration setting.
     *
     *     - Otherwise leave the qdisc alone. */
    if (hmap_is_empty(queue_map)) {
        if (!strcmp(qdisc_type, OVN_QOS_TYPE)) {
            set_qos_type(netdev_phy, "");
        }
        netdev_close(netdev_phy);
        return;
    }

    /* Configure qdisc. */
    if (strcmp(qdisc_type, OVN_QOS_TYPE)) {
        set_qos_type(netdev_phy, OVN_QOS_TYPE);
    }

    /* Check and delete if needed. */
    struct netdev_queue_dump dump;
    unsigned int queue_id;
    struct smap queue_details;
    struct qos_queue *sb_info;
    struct hmap consistent_queues;

    smap_init(&queue_details);
    hmap_init(&consistent_queues);
    NETDEV_QUEUE_FOR_EACH (&queue_id, &queue_details, &dump, netdev_phy) {
        bool is_queue_needed = false;

        HMAP_FOR_EACH_WITH_HASH (sb_info, node, hash_int(queue_id, 0),
                                 queue_map) {
            is_queue_needed = true;
            if (sb_info->max_rate ==
                smap_get_int(&queue_details, "max-rate", 0)
                && sb_info->burst == smap_get_int(&queue_details, "burst", 0)) {
                /* This queue is consistent. */
                hmap_insert(&consistent_queues, &sb_info->node,
                            hash_int(queue_id, 0));
                break;
            }
        }

        if (!is_queue_needed) {
            error = netdev_delete_queue(netdev_phy, queue_id);
            if (error) {
                VLOG_WARN_RL(&rl, "%s: could not delete queue %u (%s)",
                             egress_iface, queue_id, ovs_strerror(error));
            }
        }
    }

    /* Create/Update queues. */
    HMAP_FOR_EACH (sb_info, node, queue_map) {
        if (hmap_contains(&consistent_queues, &sb_info->node)) {
            hmap_remove(&consistent_queues, &sb_info->node);
            continue;
        }

        smap_clear(&queue_details);
        smap_add_format(&queue_details, "max-rate", "%d", sb_info->max_rate);
        smap_add_format(&queue_details, "burst", "%d", sb_info->burst);
        error = netdev_set_queue(netdev_phy, sb_info->queue_id,
                                 &queue_details);
        if (error) {
            VLOG_WARN_RL(&rl, "%s: could not configure queue %u (%s)",
                         egress_iface, sb_info->queue_id, ovs_strerror(error));
        }
    }
    smap_destroy(&queue_details);
    hmap_destroy(&consistent_queues);
    netdev_close(netdev_phy);
}

static void
destroy_qos_map(struct hmap *qos_map)
{
    struct qos_queue *qos_queue;
    HMAP_FOR_EACH_POP (qos_queue, node, qos_map) {
        free(qos_queue);
    }

    hmap_destroy(qos_map);
}

static void
update_local_lport_ids(struct sset *local_lport_ids,
                       const struct sbrec_port_binding *binding_rec)
{
        char buf[16];
        snprintf(buf, sizeof(buf), "%"PRId64"_%"PRId64,
                 binding_rec->datapath->tunnel_key,
                 binding_rec->tunnel_key);
        sset_add(local_lport_ids, buf);
}

/*
 * Get the encap from the chassis for this port. The interface
 * may have an external_ids:encap-ip=<encap-ip> set; if so we
 * get the corresponding encap from the chassis.
 * If "encap-ip" external-ids is not set, we'll not bind the port
 * to any specific encap rec. and we'll pick up a tunnel port based on
 * the chassis name alone for the port.
 */
static struct sbrec_encap *
sbrec_get_port_encap(const struct sbrec_chassis *chassis_rec,
                     const struct ovsrec_interface *iface_rec)
{

    if (!iface_rec) {
        return NULL;
    }

    const char *encap_ip = smap_get(&iface_rec->external_ids, "encap-ip");
    if (!encap_ip) {
        return NULL;
    }

    struct sbrec_encap *best_encap = NULL;
    uint32_t best_type = 0;
    for (int i = 0; i < chassis_rec->n_encaps; i++) {
        if (!strcmp(chassis_rec->encaps[i]->ip, encap_ip)) {
            uint32_t tun_type = get_tunnel_type(chassis_rec->encaps[i]->type);
            if (tun_type > best_type) {
                best_type = tun_type;
                best_encap = chassis_rec->encaps[i];
            }
        }
    }
    return best_encap;
}

static bool
is_our_chassis(const struct sbrec_chassis *chassis_rec,
               const struct sbrec_port_binding *binding_rec,
               const struct sset *active_tunnels,
               const struct sset *local_lports)
{
    bool our_chassis = false;
    if (binding_rec->parent_port && binding_rec->parent_port[0] &&
        sset_contains(local_lports, binding_rec->parent_port)) {
        /* This port is in our chassis unless it is a localport. */
        our_chassis = strcmp(binding_rec->type, "localport");
    } else if (!strcmp(binding_rec->type, "l2gateway")) {
        const char *chassis_id = smap_get(&binding_rec->options,
                                          "l2gateway-chassis");
        our_chassis = chassis_id && !strcmp(chassis_id, chassis_rec->name);
    } else if (!strcmp(binding_rec->type, "chassisredirect") ||
               !strcmp(binding_rec->type, "external")) {
        our_chassis = ha_chassis_group_contains(binding_rec->ha_chassis_group,
                                                chassis_rec) &&
                      ha_chassis_group_is_active(binding_rec->ha_chassis_group,
                                                 active_tunnels, chassis_rec);
    } else if (!strcmp(binding_rec->type, "l3gateway")) {
        const char *chassis_id = smap_get(&binding_rec->options,
                                          "l3gateway-chassis");
        our_chassis = chassis_id && !strcmp(chassis_id, chassis_rec->name);
    }

    return our_chassis;
}

static void
add_localnet_egress_interface_mappings(
        const struct sbrec_port_binding *port_binding,
        struct shash *bridge_mappings, struct sset *egress_ifaces)
{
    const char *network = smap_get(&port_binding->options, "network_name");
    if (!network) {
        return;
    }

    struct ovsrec_bridge *br_ln = shash_find_data(bridge_mappings, network);
    if (!br_ln) {
        return;
    }

    /* Add egress-ifaces from the connected bridge */
    for (size_t i = 0; i < br_ln->n_ports; i++) {
        const struct ovsrec_port *port_rec = br_ln->ports[i];

        for (size_t j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec;

            iface_rec = port_rec->interfaces[j];
            bool is_egress_iface = smap_get_bool(&iface_rec->external_ids,
                                                 "ovn-egress-iface", false);
            if (!is_egress_iface) {
                continue;
            }
            sset_add(egress_ifaces, iface_rec->name);
        }
    }
}

static bool
is_network_plugged(const struct sbrec_port_binding *binding_rec,
                   struct shash *bridge_mappings)
{
    const char *network = smap_get(&binding_rec->options, "network_name");
    return network ? !!shash_find_data(bridge_mappings, network) : false;
}

static void
consider_localnet_port(const struct sbrec_port_binding *binding_rec,
                       struct shash *bridge_mappings,
                       struct sset *egress_ifaces,
                       struct hmap *local_datapaths)
{
    /* Ignore localnet ports for unplugged networks. */
    if (!is_network_plugged(binding_rec, bridge_mappings)) {
        return;
    }

    add_localnet_egress_interface_mappings(binding_rec,
            bridge_mappings, egress_ifaces);

    struct local_datapath *ld
        = get_local_datapath(local_datapaths,
                             binding_rec->datapath->tunnel_key);
    if (!ld) {
        return;
    }

    if (ld->localnet_port && strcmp(ld->localnet_port->logical_port,
                                    binding_rec->logical_port)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "localnet port '%s' already set for datapath "
                     "'%"PRId64"', skipping the new port '%s'.",
                     ld->localnet_port->logical_port,
                     binding_rec->datapath->tunnel_key,
                     binding_rec->logical_port);
        return;
    }
    ld->localnet_port = binding_rec;
}

enum local_binding_type {
    BT_VIF,
    BT_CHILD,
    BT_VIRTUAL
};

struct local_binding {
    struct ovs_list node;       /* In parent if any. */
    char *name;
    enum local_binding_type type;
    const struct ovsrec_interface *iface;
    const struct sbrec_port_binding *pb;

    struct ovs_list children;
};

static struct local_binding *
local_binding_create(const char *name, const struct ovsrec_interface *iface,
                     const struct sbrec_port_binding *pb,
                     enum local_binding_type type)
{
    struct local_binding *lbinding = xzalloc(sizeof *lbinding);
    lbinding->name = xstrdup(name);
    lbinding->type = type;
    lbinding->pb = pb;
    lbinding->iface = iface;
    ovs_list_init(&lbinding->children);
    return lbinding;
}

static void
local_binding_add(struct shash *local_bindings, struct local_binding *lbinding)
{
    shash_add(local_bindings, lbinding->name, lbinding);
}

static struct local_binding *
local_binding_find(struct shash *local_bindings, const char *name)
{
    return shash_find_data(local_bindings, name);
}

static void
local_binding_destroy(struct local_binding *lbinding)
{
    struct local_binding *c, *next;
    LIST_FOR_EACH_SAFE (c, next, node, &lbinding->children) {
        ovs_list_remove(&c->node);
        free(c->name);
        free(c);
    }
    free(lbinding->name);
    free(lbinding);
}

void
local_bindings_destroy(struct shash *local_bindings)
{
    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE (node, next, local_bindings) {
        struct local_binding *lbinding = node->data;
        struct local_binding *c, *n;
        LIST_FOR_EACH_SAFE (c, n, node, &lbinding->children) {
            ovs_list_remove(&c->node);
            free(c->name);
            free(c);
        }
    }

    shash_destroy(local_bindings);
}

static void
local_binding_add_child(struct local_binding *lbinding,
                        struct local_binding *child)
{
    struct local_binding *l;
    LIST_FOR_EACH (l, node, &lbinding->children) {
        if (l == child) {
            return;
        }
    }

    ovs_list_push_back(&lbinding->children, &child->node);
}

static struct local_binding *
local_binding_find_child(struct local_binding *lbinding,
                         const char *child_name)
{
    struct local_binding *l;
    LIST_FOR_EACH (l, node, &lbinding->children) {
        if (!strcmp(l->name, child_name)) {
            return l;
        }
    }

    return NULL;
}

void
binding_add_vport_to_local_bindings(struct shash *local_bindings,
                                    const struct sbrec_port_binding *parent,
                                    const struct sbrec_port_binding *vport)
{
    struct local_binding *lbinding = local_binding_find(local_bindings,
                                                        parent->logical_port);
    ovs_assert(lbinding);
    struct local_binding *vbinding =
        local_binding_find_child(lbinding, vport->logical_port);
    if (!vbinding) {
        vbinding = local_binding_create(vport->logical_port, lbinding->iface,
                                        vport, BT_VIRTUAL);
        local_binding_add_child(lbinding, vbinding);
    } else {
        vbinding->type = BT_VIRTUAL;
    }
}

static void
claim_lport(const struct sbrec_port_binding *pb,
            const struct sbrec_chassis *chassis_rec,
            const struct ovsrec_interface *iface_rec)
{
    if (pb->chassis != chassis_rec) {
        if (pb->chassis) {
            VLOG_INFO("Changing chassis for lport %s from %s to %s.",
                    pb->logical_port, pb->chassis->name,
                    chassis_rec->name);
        } else {
            VLOG_INFO("Claiming lport %s for this chassis.", pb->logical_port);
        }
        for (int i = 0; i < pb->n_mac; i++) {
            VLOG_INFO("%s: Claiming %s", pb->logical_port, pb->mac[i]);
        }

        sbrec_port_binding_set_chassis(pb, chassis_rec);
    }

    /* Check if the port encap binding, if any, has changed */
    struct sbrec_encap *encap_rec =
        sbrec_get_port_encap(chassis_rec, iface_rec);
    if (encap_rec && pb->encap != encap_rec) {
        sbrec_port_binding_set_encap(pb, encap_rec);
    }
}

static void
release_lport(const struct sbrec_port_binding *pb)
{
    VLOG_INFO("Releasing lport %s from this chassis.", pb->logical_port);
    if (pb->encap) {
        sbrec_port_binding_set_encap(pb, NULL);
    }
    sbrec_port_binding_set_chassis(pb, NULL);

    if (pb->virtual_parent) {
        sbrec_port_binding_set_virtual_parent(pb, NULL);
    }
}

static void
consider_port_binding_for_vif(const struct sbrec_port_binding *pb,
                              struct binding_ctx_in *b_ctx_in,
                              enum local_binding_type binding_type,
                              struct local_binding *lbinding,
                              struct binding_ctx_out *b_ctx_out,
                              struct hmap *qos_map)
{
    const char *vif_chassis = smap_get(&pb->options, "requested-chassis");
    bool can_bind = !vif_chassis || !vif_chassis[0]
                    || !strcmp(vif_chassis, b_ctx_in->chassis_rec->name)
                    || !strcmp(vif_chassis, b_ctx_in->chassis_rec->hostname);

    /* Ports of type "virtual" should never be explicitly bound to an OVS
     * port in the integration bridge. If that's the case, ignore the binding
     * and log a warning.
     */
    if (!strcmp(pb->type, "virtual") && lbinding && lbinding->iface &&
        binding_type == BT_VIF) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl,
                     "Virtual port %s should not be bound to OVS port %s",
                     pb->logical_port, lbinding->iface->name);
        lbinding->pb = NULL;
        return;
    }

    if (lbinding && lbinding->pb && can_bind) {
        claim_lport(pb, b_ctx_in->chassis_rec, lbinding->iface);

        switch (binding_type) {
        case BT_VIF:
            lbinding->pb = pb;
            break;
        case BT_CHILD:
        case BT_VIRTUAL:
        {
            /* Add child logical port to the set of all local ports. */
            sset_add(b_ctx_out->local_lports, pb->logical_port);
            struct local_binding *child =
                local_binding_find_child(lbinding, pb->logical_port);
            if (!child) {
                child = local_binding_create(pb->logical_port, lbinding->iface,
                                             pb, binding_type);
                local_binding_add_child(lbinding, child);
            } else {
                ovs_assert(child->type == BT_CHILD ||
                           child->type == BT_VIRTUAL);
                child->pb = pb;
                child->iface = lbinding->iface;
            }
            break;
        }
        default:
            OVS_NOT_REACHED();
        }

        add_local_datapath(b_ctx_in->sbrec_datapath_binding_by_key,
                           b_ctx_in->sbrec_port_binding_by_datapath,
                           b_ctx_in->sbrec_port_binding_by_name,
                           pb->datapath, false, b_ctx_out->local_datapaths);
        update_local_lport_ids(b_ctx_out->local_lport_ids, pb);
        if (lbinding->iface && qos_map && b_ctx_in->ovs_idl_txn) {
            get_qos_params(pb, qos_map);
        }
    } else if (lbinding && lbinding->pb && !can_bind) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_INFO_RL(&rl,
                         "Not claiming lport %s, chassis %s "
                         "requested-chassis %s",
                         pb->logical_port,
                         b_ctx_in->chassis_rec->name,
                         vif_chassis);
    }

    if (pb->chassis == b_ctx_in->chassis_rec) {
        if (!lbinding || !lbinding->pb || !can_bind) {
            release_lport(pb);
        }
    }
}

static void
consider_port_binding(const struct sbrec_port_binding *pb,
                      struct binding_ctx_in *b_ctx_in,
                      struct binding_ctx_out *b_ctx_out,
                      struct hmap *qos_map)
{

    bool our_chassis = is_our_chassis(b_ctx_in->chassis_rec, pb,
                                      b_ctx_in->active_tunnels,
                                      b_ctx_out->local_lports);

    if (!strcmp(pb->type, "l2gateway")) {
        if (our_chassis) {
            sset_add(b_ctx_out->local_lports, pb->logical_port);
            add_local_datapath(b_ctx_in->sbrec_datapath_binding_by_key,
                               b_ctx_in->sbrec_port_binding_by_datapath,
                               b_ctx_in->sbrec_port_binding_by_name,
                               pb->datapath, false,
                               b_ctx_out->local_datapaths);
        }
    } else if (!strcmp(pb->type, "chassisredirect")) {
        if (ha_chassis_group_contains(pb->ha_chassis_group,
                                      b_ctx_in->chassis_rec)) {
            add_local_datapath(b_ctx_in->sbrec_datapath_binding_by_key,
                               b_ctx_in->sbrec_port_binding_by_datapath,
                               b_ctx_in->sbrec_port_binding_by_name,
                               pb->datapath, false,
                               b_ctx_out->local_datapaths);
        }
    } else if (!strcmp(pb->type, "l3gateway")) {
        if (our_chassis) {
            add_local_datapath(b_ctx_in->sbrec_datapath_binding_by_key,
                               b_ctx_in->sbrec_port_binding_by_datapath,
                               b_ctx_in->sbrec_port_binding_by_name,
                               pb->datapath, true, b_ctx_out->local_datapaths);
        }
    } else if (!strcmp(pb->type, "localnet")) {
        /* Add all localnet ports to local_lports so that we allocate ct zones
         * for them. */
        sset_add(b_ctx_out->local_lports, pb->logical_port);
        if (qos_map && b_ctx_in->ovs_idl_txn) {
            get_qos_params(pb, qos_map);
        }
    } else if (!strcmp(pb->type, "external")) {
        if (ha_chassis_group_contains(pb->ha_chassis_group,
                                      b_ctx_in->chassis_rec)) {
            add_local_datapath(b_ctx_in->sbrec_datapath_binding_by_key,
                               b_ctx_in->sbrec_port_binding_by_datapath,
                               b_ctx_in->sbrec_port_binding_by_name,
                               pb->datapath, false,
                               b_ctx_out->local_datapaths);
        }
    }

    if (our_chassis || !strcmp(pb->type, "localnet")) {
        update_local_lport_ids(b_ctx_out->local_lport_ids, pb);
    }

    ovs_assert(b_ctx_in->ovnsb_idl_txn);
    if (our_chassis) {
        claim_lport(pb, b_ctx_in->chassis_rec, NULL);
    } else if (pb->chassis == b_ctx_in->chassis_rec) {
        release_lport(pb);
    }
}

static void
build_local_bindings_from_local_ifaces(struct binding_ctx_in *b_ctx_in,
                                       struct binding_ctx_out *b_ctx_out)
{
    int i;
    for (i = 0; i < b_ctx_in->br_int->n_ports; i++) {
        const struct ovsrec_port *port_rec = b_ctx_in->br_int->ports[i];
        const char *iface_id;
        int j;

        if (!strcmp(port_rec->name, b_ctx_in->br_int->name)) {
            continue;
        }

        for (j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec;

            iface_rec = port_rec->interfaces[j];
            iface_id = smap_get(&iface_rec->external_ids, "iface-id");
            int64_t ofport = iface_rec->n_ofport ? *iface_rec->ofport : 0;

            if (iface_id && ofport > 0) {
                const struct sbrec_port_binding *pb
                    = lport_lookup_by_name(
                        b_ctx_in->sbrec_port_binding_by_name, iface_id);
                struct local_binding *lbinding =
                    local_binding_find(b_ctx_out->local_bindings, iface_id);
                if (!lbinding) {
                    lbinding = local_binding_create(iface_id, iface_rec, pb,
                                                    BT_VIF);
                    local_binding_add(b_ctx_out->local_bindings, lbinding);
                } else {
                    lbinding->type = BT_VIF;
                    lbinding->pb = pb;
                }
                sset_add(b_ctx_out->local_lports, iface_id);
            }

            /* Check if this is a tunnel interface. */
            if (smap_get(&iface_rec->options, "remote_ip")) {
                const char *tunnel_iface
                    = smap_get(&iface_rec->status, "tunnel_egress_iface");
                if (tunnel_iface) {
                    sset_add(b_ctx_out->egress_ifaces, tunnel_iface);
                }
            }
        }
    }

    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE (node, next, b_ctx_out->local_bindings) {
        struct local_binding *lbinding = node->data;
        if (!sset_contains(b_ctx_out->local_lports, lbinding->name)) {
            local_binding_destroy(lbinding);
            shash_delete(b_ctx_out->local_bindings, node);
        }
    }
}

void
binding_run(struct binding_ctx_in *b_ctx_in, struct binding_ctx_out *b_ctx_out)
{
    if (!b_ctx_in->chassis_rec) {
        return;
    }

    const struct sbrec_port_binding *binding_rec;
    struct shash bridge_mappings = SHASH_INITIALIZER(&bridge_mappings);
    struct hmap qos_map;

    hmap_init(&qos_map);
    if (b_ctx_in->br_int) {
        build_local_bindings_from_local_ifaces(b_ctx_in, b_ctx_out);
    }

    struct hmap *qos_map_ptr =
        !sset_is_empty(b_ctx_out->egress_ifaces) ? &qos_map : NULL;

    /* Run through each binding record to see if it is resident on this
     * chassis and update the binding accordingly.  This includes both
     * directly connected logical ports and children of those ports
     * (which also includes virtual ports).
     */
    SBREC_PORT_BINDING_TABLE_FOR_EACH (binding_rec,
                                       b_ctx_in->port_binding_table) {
        if (!strcmp(binding_rec->type, "patch") ||
            !strcmp(binding_rec->type, "localport") ||
            !strcmp(binding_rec->type, "vtep")) {
            update_local_lport_ids(b_ctx_out->local_lport_ids, binding_rec);
            continue;
        }

        bool consider_for_vif = false;
        struct local_binding *lbinding = NULL;
        enum local_binding_type binding_type = BT_VIF;
        if (!binding_rec->type[0]) {
            if (!binding_rec->parent_port || !binding_rec->parent_port[0]) {
                lbinding = local_binding_find(b_ctx_out->local_bindings,
                                              binding_rec->logical_port);
            } else {
                lbinding = local_binding_find(b_ctx_out->local_bindings,
                                              binding_rec->parent_port);
                binding_type = BT_CHILD;
            }

            consider_for_vif = true;
        } else if (!strcmp(binding_rec->type, "virtual") &&
                   binding_rec->virtual_parent &&
                   binding_rec->virtual_parent[0]) {
            lbinding = local_binding_find(b_ctx_out->local_bindings,
                                          binding_rec->virtual_parent);
            consider_for_vif = true;
            binding_type = BT_VIRTUAL;
        }

        if (consider_for_vif) {
            consider_port_binding_for_vif(binding_rec, b_ctx_in,
                                          binding_type, lbinding, b_ctx_out,
                                          qos_map_ptr);
        } else {
            consider_port_binding(binding_rec, b_ctx_in, b_ctx_out,
                                  qos_map_ptr);
        }
    }

    add_ovs_bridge_mappings(b_ctx_in->ovs_table, b_ctx_in->bridge_table,
                            &bridge_mappings);

    /* Run through each binding record to see if it is a localnet port
     * on local datapaths discovered from above loop, and update the
     * corresponding local datapath accordingly. */
    SBREC_PORT_BINDING_TABLE_FOR_EACH (binding_rec,
                                       b_ctx_in->port_binding_table) {
        if (!strcmp(binding_rec->type, "localnet")) {
            consider_localnet_port(binding_rec, &bridge_mappings,
                                   b_ctx_out->egress_ifaces,
                                   b_ctx_out->local_datapaths);
        }
    }
    shash_destroy(&bridge_mappings);

    if (!sset_is_empty(b_ctx_out->egress_ifaces)
        && set_noop_qos(b_ctx_in->ovs_idl_txn, b_ctx_in->port_table,
                        b_ctx_in->qos_table, b_ctx_out->egress_ifaces)) {
        const char *entry;
        SSET_FOR_EACH (entry, b_ctx_out->egress_ifaces) {
            setup_qos(entry, &qos_map);
        }
    }

    destroy_qos_map(&qos_map);
}

/* Returns true if port-binding changes potentially require flow changes on
 * the current chassis. Returns false if we are sure there is no impact. */
bool
binding_evaluate_port_binding_changes(struct binding_ctx_in *b_ctx_in,
                                      struct binding_ctx_out *b_ctx_out)
{
    if (!b_ctx_in->chassis_rec) {
        return true;
    }

    bool changed = false;

    const struct sbrec_port_binding *binding_rec;
    SBREC_PORT_BINDING_TABLE_FOR_EACH_TRACKED (binding_rec,
                                               b_ctx_in->port_binding_table) {
        /* XXX: currently OVSDB change tracking doesn't support getting old
         * data when the operation is update, so if a port-binding moved from
         * this chassis to another, there is no easy way to find out the
         * change. To workaround this problem, we just makes sure if
         * any port *related to* this chassis has any change, then trigger
         * recompute.
         *
         * - If a regular VIF is unbound from this chassis, the local ovsdb
         *   interface table will be updated, which will trigger recompute.
         *
         * - If the port is not a regular VIF, always trigger recompute. */
        if (binding_rec->chassis == b_ctx_in->chassis_rec) {
            changed = true;
            break;
        }

        if (strcmp(binding_rec->type, "")) {
            changed = true;
            break;
        }

        struct local_binding *lbinding = NULL;
        if (!binding_rec->parent_port || !binding_rec->parent_port[0]) {
            lbinding = local_binding_find(b_ctx_out->local_bindings,
                                          binding_rec->logical_port);
        } else {
            lbinding = local_binding_find(b_ctx_out->local_bindings,
                                          binding_rec->parent_port);
        }

        if (lbinding) {
            changed = true;
            break;
        }
    }

    return changed;
}

/* Returns true if the database is all cleaned up, false if more work is
 * required. */
bool
binding_cleanup(struct ovsdb_idl_txn *ovnsb_idl_txn,
                const struct sbrec_port_binding_table *port_binding_table,
                const struct sbrec_chassis *chassis_rec)
{
    if (!ovnsb_idl_txn) {
        return false;
    }
    if (!chassis_rec) {
        return true;
    }

    const struct sbrec_port_binding *binding_rec;
    bool any_changes = false;
    SBREC_PORT_BINDING_TABLE_FOR_EACH (binding_rec, port_binding_table) {
        if (binding_rec->chassis == chassis_rec) {
            if (binding_rec->encap)
                sbrec_port_binding_set_encap(binding_rec, NULL);
            sbrec_port_binding_set_chassis(binding_rec, NULL);
            any_changes = true;
        }
    }

    if (any_changes) {
        ovsdb_idl_txn_add_comment(
            ovnsb_idl_txn,
            "ovn-controller: removing all port bindings for '%s'",
            chassis_rec->name);
    }

    return !any_changes;
}
