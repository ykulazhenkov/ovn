/* Copyright (c) 2020, Red Hat, Inc.
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

#include "mac-binding.h"
#include "lflow.h"
#include "ovn-controller.h"
#include "ofctrl.h"

/* OpenvSwitch lib includes. */
#include "include/openvswitch/match.h"
#include "include/openvswitch/ofp-actions.h"
#include "include/openvswitch/ofpbuf.h"
#include "include/openvswitch/vlog.h"
#include "lib/uuid.h"
#include "lib/coverage.h"
#include "lib/smap.h"
#include "lib/timeval.h"

VLOG_DEFINE_THIS_MODULE(mac_binding);

COVERAGE_DEFINE(mac_binding_learned);
COVERAGE_DEFINE(mac_binding_expired);
COVERAGE_DEFINE(mac_binding_evicted);

static unsigned int
normalize_idle_time(unsigned int idle_time)
{
    return (idle_time < 15 ? 15
            : idle_time > 3600 ? 3600
            : idle_time);
}

/* Creates and returns a new MAC Binding table with an initial MAC aging
 * timeout of 'idle_time' seconds and an initial maximum of MAC_DEFAULT_MAX
 * entries. */
struct mac_binding *
mac_binding_create(unsigned int idle_time)
{
    struct mac_binding *mb;

    mb = xmalloc(sizeof *mb);
    ovs_list_init(&mb->lrus);
    ovs_list_init(&mb->updated);
    ovs_list_init(&mb->expired);
    hmap_init(&mb->table);
    mb->idle_time = normalize_idle_time(idle_time);
    mb->max_entries = MAC_BINDING_DEFAULT_MAX;
    mb->need_revalidate = false;
    ovs_refcount_init(&mb->ref_cnt);
    ovs_rwlock_init(&mb->rwlock);

    return mb;
}

struct mac_binding *
mac_binding_ref(const struct mac_binding *mb_)
{
    struct mac_binding *mb = CONST_CAST(struct mac_binding *, mb_);
    if (mb) {
        ovs_refcount_ref(&mb->ref_cnt);
    }
    return mb;
}

static void
mac_binding_entry_delete(struct mac_binding_entry *e)
{
    ovs_list_remove(&e->expire_node);
    free(e);
}

/* Unreferences (and possibly destroys) MAC binding table 'mb'. */
void
mac_binding_unref(struct mac_binding *mb)
{
    if (mb && ovs_refcount_unref(&mb->ref_cnt) == 1) {
        struct mac_binding_entry *e, *next;

        ovs_rwlock_wrlock(&mb->rwlock);
        HMAP_FOR_EACH_SAFE (e, next, hmap_node, &mb->table) {
            mac_binding_expire(mb, e);
            mac_binding_entry_delete(e);
        }
        hmap_destroy(&mb->table);
        ovs_rwlock_unlock(&mb->rwlock);
        ovs_rwlock_destroy(&mb->rwlock);
        free(mb);
    }
}

/* Expires 'e' from the 'mb' hash table. */
void
mac_binding_expire(struct mac_binding *mb, struct mac_binding_entry *e)
{
    mb->need_revalidate = true;
    hmap_remove(&mb->table, &e->hmap_node);
    ovs_list_remove(&e->lru_node);
    ovs_list_push_back(&mb->expired, &e->expire_node);
}


/* Expires all the mac-binding entries in 'mb'. */
void
mac_binding_flush(struct mac_binding *mb OVS_UNUSED)
{

}

/* Does periodic work required by 'mB'.  Returns true if something changed. */
bool
mac_binding_run(struct mac_binding *mb)
{
    return mb->need_revalidate;
}

void
mac_binding_wait(struct mac_binding *mb OVS_UNUSED)
{

}

static void
evict_mac_binding_entry_fairly(struct mac_binding *mb)
    OVS_REQ_WRLOCK(mb->rwlock)
{
    struct mac_binding_entry *e;

    e = CONTAINER_OF(ovs_list_front(&mb->lrus),
                     struct mac_binding_entry, lru_node);
    COVERAGE_INC(mac_binding_evicted);
    mac_binding_expire(mb, e);
}

static size_t
mac_binding_hash(uint32_t dp_key, uint32_t port_key, struct in6_addr *ip)
{
    return hash_bytes(ip, sizeof *ip, hash_2words(dp_key, port_key));
}

struct mac_binding_entry *
mac_binding_lookup(const struct mac_binding *mb, uint32_t dp_key,
                   uint32_t port_key, struct in6_addr *ip)
{
    uint32_t hash = mac_binding_hash(dp_key, port_key, ip);

    struct mac_binding_entry *e;
    HMAP_FOR_EACH_WITH_HASH (e, hmap_node, hash, &mb->table) {
        if (e->dp_key == dp_key && e->port_key == port_key &&
            IN6_ARE_ADDR_EQUAL(&e->ip, ip)) {
            return e;
        }
    }

    return NULL;
}

struct mac_binding_entry *
mac_binding_insert(struct mac_binding *mb, uint32_t dp_key,
                   uint32_t port_key, struct in6_addr *ip,
                   struct eth_addr mac)
{
    struct mac_binding_entry *e;

    e = mac_binding_lookup(mb, dp_key, port_key, ip);
    if (!e) {
        uint32_t hash = mac_binding_hash(dp_key, port_key, ip);

        if (hmap_count(&mb->table) >= mb->max_entries) {
            evict_mac_binding_entry_fairly(mb);
        }

        e = xmalloc(sizeof *e);
        hmap_insert(&mb->table, &e->hmap_node, hash);
        e->dp_key = dp_key;
        e->port_key = port_key;
        e->ip = *ip;
        e->mac = mac;
        COVERAGE_INC(mac_binding_learned);
        mb->total_learned++;
    } else {
        ovs_list_remove(&e->lru_node);
    }

    /* Mark 'e' as recently used. */
    ovs_list_push_back(&mb->lrus, &e->lru_node);
    ovs_list_push_back(&mb->updated, &e->update_node);
    e->expires = time_now() + mb->idle_time;

    mb->need_revalidate = true;
    return e;
}

static void
mac_binding_entry_uuid(struct mac_binding_entry *e, struct uuid *mac_uuid)
{
    uuid_zero(mac_uuid);
    mac_uuid->parts[0] = e->dp_key;
    mac_uuid->parts[1] = e->port_key;
}

static void
put_load(const uint8_t *data, size_t len,
         enum mf_field_id dst, int ofs, int n_bits,
         struct ofpbuf *ofpacts)
{
    struct ofpact_set_field *sf = ofpact_put_set_field(ofpacts,
                                                       mf_from_id(dst), NULL,
                                                       NULL);
    bitwise_copy(data, len, 0, sf->value, sf->field->n_bytes, ofs, n_bits);
    bitwise_one(ofpact_set_field_mask(sf), sf->field->n_bytes, ofs, n_bits);
}

static void
mac_binding_entry_add_flow(struct mac_binding_entry *e,
                           const struct hmap *local_datapaths,
                           struct ovn_desired_flow_table *flow_table)
{
    if (!get_local_datapath(local_datapaths, e->dp_key)) {
        return;
    }

    struct match get_arp_match = MATCH_CATCHALL_INITIALIZER;
    struct match lookup_arp_match = MATCH_CATCHALL_INITIALIZER;

    if (IN6_IS_ADDR_V4MAPPED(&e->ip)) {
        ovs_be32 ip4 = in6_addr_get_mapped_ipv4(&e->ip);
        match_set_reg(&get_arp_match, 0, ntohl(ip4));
        match_set_reg(&lookup_arp_match, 0, ntohl(ip4));
        match_set_dl_type(&lookup_arp_match, htons(ETH_TYPE_ARP));
    } else {
        ovs_be128 value;
        memcpy(&value, &e->ip, sizeof(value));

        match_set_xxreg(&get_arp_match, 0, ntoh128(value));
        match_set_xxreg(&lookup_arp_match, 0, ntoh128(value));
        match_set_dl_type(&lookup_arp_match, htons(ETH_TYPE_IPV6));
        match_set_nw_proto(&lookup_arp_match, 58);
        match_set_icmp_code(&lookup_arp_match, 0);
    }

    match_set_metadata(&get_arp_match, htonll(e->dp_key));
    match_set_reg(&get_arp_match, MFF_LOG_OUTPORT - MFF_REG0, e->port_key);

    match_set_metadata(&lookup_arp_match, htonll(e->dp_key));
    match_set_reg(&lookup_arp_match, MFF_LOG_INPORT - MFF_REG0,
                  e->port_key);

    uint64_t stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(stub);
    uint8_t value = 1;
    put_load(e->mac.ea, sizeof e->mac.ea, MFF_ETH_DST, 0, 48, &ofpacts);
    put_load(&value, sizeof value, MFF_LOG_FLAGS, MLF_LOOKUP_MAC_BIT, 1,
             &ofpacts);

    struct uuid mac_uuid;
    mac_binding_entry_uuid(e, &mac_uuid);

    ofctrl_add_flow(flow_table, OFTABLE_MAC_BINDING, 100,
                    0, &get_arp_match, &ofpacts, &mac_uuid);

    ofpbuf_clear(&ofpacts);
    put_load(&value, sizeof value, MFF_LOG_FLAGS, MLF_LOOKUP_MAC_BIT, 1,
             &ofpacts);
    match_set_dl_src(&lookup_arp_match, e->mac);
    ofctrl_add_flow(flow_table, OFTABLE_MAC_LOOKUP, 100,
                    0, &lookup_arp_match,
                    &ofpacts, &mac_uuid);

    ofpbuf_uninit(&ofpacts);
}

static void
mac_binding_entry_remove_flow(struct mac_binding_entry *e,
                              struct ovn_desired_flow_table *flow_table)
{
    struct uuid mb_uuid;
    mac_binding_entry_uuid(e, &mb_uuid);
    ofctrl_remove_flows(flow_table, &mb_uuid);
}

void
mac_binding_compute_lflows(struct mac_binding *mb,
                           const struct hmap *local_datapaths,
                           bool recompute,
                           struct ovn_desired_flow_table *flow_table)
{
    if (recompute) {
        ovs_rwlock_rdlock(&mb->rwlock);
        struct mac_binding_entry *e;
        LIST_FOR_EACH (e, lru_node, &mb->lrus) {
            mac_binding_entry_add_flow(e, local_datapaths, flow_table);
        }
        ovs_rwlock_unlock(&mb->rwlock);
    } else {
        ovs_rwlock_wrlock(&mb->rwlock);
        struct mac_binding_entry *e;
        LIST_FOR_EACH_POP (e, expire_node, &mb->expired) {
            mac_binding_entry_remove_flow(e, flow_table);
        }

        LIST_FOR_EACH_POP (e, update_node, &mb->updated) {
            mac_binding_entry_remove_flow(e, flow_table);
            mac_binding_entry_add_flow(e, local_datapaths, flow_table);
        }
        ovs_rwlock_unlock(&mb->rwlock);
    }
}
