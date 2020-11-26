/*
 * Copyright (c) 2020 Red Hat, Inc.
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

#ifndef OVN_MAC_LEARN_H
#define OVN_MAC_LEARN_H 1

#include <sys/types.h>
#include <netinet/in.h>

/* Includes from Open vSwitch. */
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "lib/ovs-atomic.h"
#include "lib/ovs-thread.h"

struct ovn_desired_flow_table;
struct mac_binding;

/* Default maximum size of a MAC Binding table, in entries. */
#define MAC_BINDING_DEFAULT_MAX 8192

struct mac_binding_entry {
    struct hmap_node hmap_node; /* Node in a mac_binding hmap. */
    time_t expires;             /* Expiration time. */

    uint32_t dp_key;
    uint32_t port_key; /* Port from where this mac_binding is learnt. */
    struct in6_addr ip;

    /* Value. */
    struct eth_addr mac;

    /* The following are marked guarded to prevent users from iterating over or
     * accessing a mac_entry without holding the parent mac_learning rwlock. */
    struct ovs_list lru_node OVS_GUARDED; /* Element in 'lrus' list. */

    struct ovs_list update_node OVS_GUARDED; /* Element in 'updated' list. */
    struct ovs_list expire_node OVS_GUARDED; /* Element in 'exired' list. */
};

struct mac_binding {
    struct hmap table;          /* Learning table. */
    struct ovs_list lrus OVS_GUARDED; /* In-use entries, LRU at front. */
    struct ovs_list updated OVS_GUARDED;  /* Recently added/updated entries. */
    struct ovs_list expired OVS_GUARDED;  /* Recently removed entries. */

    unsigned int idle_time;     /* Max age before deleting an entry. */
    size_t max_entries;         /* Max number of learned bindings. */
    struct ovs_refcount ref_cnt;
    struct ovs_rwlock rwlock;
    bool need_revalidate;

    /* Statistics */
    uint64_t total_learned;
    uint64_t total_expired;
    uint64_t total_evicted;
};

/* Basics. */
struct mac_binding *mac_binding_create(unsigned int idle_time);
struct mac_binding *mac_binding_ref(const struct mac_binding *);
void mac_binding_unref(struct mac_binding *);
bool mac_binding_run(struct mac_binding *mb) OVS_REQ_WRLOCK(mb->rwlock);
void mac_binding_wait(struct mac_binding *mb)
    OVS_REQ_RDLOCK(mb->rwlock);

/* Configuration. */
void mac_binding_set_idle_time(struct mac_binding *mb, unsigned int idle_time)
    OVS_REQ_WRLOCK(mb->rwlock);
void mac_binding_set_max_entries(struct mac_binding *mb, size_t max_entries)
    OVS_REQ_WRLOCK(mb->rwlock);

/* Learning. */
struct mac_binding_entry *mac_binding_insert(
    struct mac_binding *mb, uint32_t dp_key,
    uint32_t port_key, struct in6_addr *ip,
    struct eth_addr mac) OVS_REQ_WRLOCK(mb->rwlock);
bool mac_binding_update(struct mac_binding *mb, uint32_t dp_key,
                        uint32_t port_key, struct in6_addr *ip,
                        struct eth_addr mac)
    OVS_EXCLUDED(mb->rwlock);

/* Lookup. */
struct mac_binding_entry *mac_binding_lookup(const struct mac_binding *mb,
                                             uint32_t dp_key,
                                             uint32_t port_key,
                                             struct in6_addr *ip)
    OVS_REQ_RDLOCK(mb->rwlock);

/* Flushing. */
void mac_binding_expire(struct mac_binding *mb, struct mac_binding_entry *e)
    OVS_REQ_WRLOCK(mb->rwlock);
void mac_binding_flush(struct mac_binding *mb) OVS_REQ_WRLOCK(mb->rwlock);

void mac_binding_compute_lflows(struct mac_binding *mb,
                                const struct hmap *local_datapaths,
                                bool recompute,
                                struct ovn_desired_flow_table *)
                                OVS_REQ_WRLOCK(mb->rwlock);
#endif /* OVN_MAC_LEARN_H */