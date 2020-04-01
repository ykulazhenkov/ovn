/* Copyright (c) 2015, 2016 Nicira, Inc.
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


#ifndef OVN_BINDING_H
#define OVN_BINDING_H 1

#include <stdbool.h>
#include "openvswitch/shash.h"
#include "openvswitch/hmap.h"
#include "openvswitch/uuid.h"
#include "openvswitch/list.h"

struct hmap;
struct ovsdb_idl;
struct ovsdb_idl_index;
struct ovsdb_idl_txn;
struct ovsrec_bridge;
struct ovsrec_port_table;
struct ovsrec_qos_table;
struct ovsrec_bridge_table;
struct ovsrec_open_vswitch_table;
struct sbrec_chassis;
struct sbrec_port_binding_table;
struct sset;
struct sbrec_port_binding;
struct shash;

struct binding_ctx_in {
    struct ovsdb_idl_txn *ovnsb_idl_txn;
    struct ovsdb_idl_txn *ovs_idl_txn;
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key;
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    const struct ovsrec_port_table *port_table;
    const struct ovsrec_qos_table *qos_table;
    const struct sbrec_port_binding_table *port_binding_table;
    const struct ovsrec_bridge *br_int;
    const struct sbrec_chassis *chassis_rec;
    const struct sset *active_tunnels;
    const struct ovsrec_bridge_table *bridge_table;
    const struct ovsrec_open_vswitch_table *ovs_table;
    const struct ovsrec_interface_table *iface_table;
};

struct binding_ctx_out {
    struct hmap *local_datapaths;
    struct shash *local_bindings;
    struct sset *local_lports;
    struct sset *local_lport_ids;
    struct sset *egress_ifaces;
    struct smap *local_iface_ids;
    struct hmap *tracked_dp_bindings;
    bool *local_lports_changed;
};

enum local_binding_type {
    BT_VIF,
    BT_CONTAINER,
    BT_VIRTUAL
};

struct local_binding {
    char *name;
    enum local_binding_type type;
    const struct ovsrec_interface *iface;
    const struct sbrec_port_binding *pb;

    /* shash of 'struct local_binding' representing children. */
    struct shash children;
};

static inline struct local_binding *
local_binding_find(struct shash *local_bindings, const char *name)
{
    return shash_find_data(local_bindings, name);
}

/* Represents a tracked binding logical port. */
struct tracked_binding_lport {
    const struct sbrec_port_binding *pb;
    struct ovs_list list_node;
    bool deleted;
};

/* Represent a tracked binding datapath. */
struct tracked_binding_datapath {
    struct hmap_node node;
    const struct sbrec_datapath_binding *dp;
    bool is_new;
    struct ovs_list lports_head; /* List of struct tracked_binding_lport. */
};

void binding_register_ovs_idl(struct ovsdb_idl *);
void binding_run(struct binding_ctx_in *, struct binding_ctx_out *);
bool binding_cleanup(struct ovsdb_idl_txn *ovnsb_idl_txn,
                     const struct sbrec_port_binding_table *,
                     const struct sbrec_chassis *);

void local_bindings_init(struct shash *local_bindings);
void local_bindings_destroy(struct shash *local_bindings);
bool binding_handle_ovs_interface_changes(struct binding_ctx_in *,
                                          struct binding_ctx_out *,
                                          bool *changed);
bool binding_handle_port_binding_changes(struct binding_ctx_in *,
                                         struct binding_ctx_out *,
                                         bool *changed);
void binding_tracked_dp_destroy(struct hmap *tracked_datapaths);
#endif /* controller/binding.h */
