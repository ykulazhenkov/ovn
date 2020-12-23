/* Copyright (c) 2021 Red Hat, Inc.
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

#include "dp-flow-mgr.h"
#include "ofctrl.h"
#include "lflow.h"

/* ovs includes. */
#include "lib/byte-order.h"
#include "lib/uuid.h"
#include "lib/hash.h"
#include "lib/hmapx.h"
#include "lib/ovs-atomic.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-flow.h"
#include "openvswitch/ofp-group.h"
#include "openvswitch/ofp-match.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-meter.h"
#include "openvswitch/ofp-packet.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"


VLOG_DEFINE_THIS_MODULE(dpflowmgr);

static void dp_flow_table_destroy__(struct dp_flow_table *dp_table);

static struct hmap dp_flow_tables = HMAP_INITIALIZER(&dp_flow_tables);

#define CONJ_ACT_COOKIE UINT64_MAX

/* Flow handling. */
struct ovn_flow;

/* An ovn_flow action. */
struct ovn_flow_action {
    struct ovs_list flow_uuid_action_node;

    struct ofpact *ofpacts;
    size_t ofpacts_len;
    uint64_t cookie;
    struct uuid flow_uuid;

    struct ovs_list list_node;
    struct ovn_flow *flow;
};

/* An OpenFlow flow. */
struct ovn_flow {
    struct hmap_node hmap_node;
    struct hmap *match_flow_table;
    struct hmap *uuid_action_flow_table;

    /* Key. */
    uint8_t table_id;
    uint16_t priority;
    struct minimatch match;

    /* Hash. */
    uint32_t hash;

    /* Data. */
    struct ovn_flow_action *normal_act;

    /* For ACL flows. */
    struct ovs_list allow_act_list;
    struct ovs_list drop_act_list;
    struct ovs_list conj_act_list;

    uint64_t active_cookie;
    bool installed;
};

struct flow_uuid_to_acts {
    struct hmap_node hmap_node; /* Node in
                                 *  ovn_flow_table.uuid_flow_table. */
    struct uuid flow_uuid;
    struct ovs_list acts; /* A list of struct ovn_flow_action nodes that
                           * are referenced by the sb_uuid. */
};

struct ovn_flow_table {
    /* Hash map of flow table using flow match conditions as hash key.*/
    struct hmap match_flow_table[OFTABLE_MAX_TABLE_IDS];

    /* Hash map of ovn_flow_action list table using uuid as hash key.*/
    struct hmap uuid_action_flow_table;
};

struct dp_flow_table {
    struct hmap_node hmap_node;
    uint32_t dp_key;

    struct ovn_flow_table lflow_table[2];
    struct ovn_flow_table pflow_table[2];

    struct ovn_flow_table *active_lflow_table;
    struct ovn_flow_table *old_lflow_table;

    struct ovn_flow_table *active_pflow_table;
    struct ovn_flow_table *old_pflow_table;

    struct hmapx modified_lflows;
    struct hmapx modified_pflows;
};

static void dp_flow_switch_lflow_table__(struct dp_flow_table *);
static void dp_flow_switch_pflow_table__(struct dp_flow_table *);
static void dp_flow_table_destroy__(struct dp_flow_table *);

static void dp_flow_add_openflow__(struct dp_flow_table *, bool lflow_table,
                                   uint8_t table_id, uint16_t priority,
                                   uint64_t cookie, const struct match *match,
                                   const struct ofpbuf *actions,
                                   const struct uuid *flow_uuid);
static void dp_flows_remove(struct dp_flow_table *, bool lflow_table,
                            const struct uuid *flow_uuid);

static void ovn_flow_table_init(struct ovn_flow_table *);
static void ovn_flow_table_clear(struct ovn_flow_table *);
static void ovn_flow_table_destroy(struct ovn_flow_table *);

static uint32_t ovn_flow_match_hash(const struct ovn_flow *);

static void ovn_flow_init(struct ovn_flow *, uint8_t table_id,
                          uint16_t priority, const struct match *);
static void ovn_flow_uninit(struct ovn_flow *);
static struct ovn_flow *ovn_flow_alloc(uint8_t table_id, uint16_t priority,
                                       const struct match *);
static void ovn_flow_destroy(struct ovn_flow *);

static struct ovn_flow_action *ovn_flow_action_alloc(const struct ofpbuf *,
                                                     uint64_t cookie,
                                                     const struct uuid *);
static void ovn_flow_action_init(struct ovn_flow_action *,
                                 const struct ofpbuf *, uint64_t cookie,
                                 const struct uuid *);
static void ovn_flow_action_destroy(struct ovn_flow_action *);
static struct ovn_flow *ovn_flow_lookup(struct ovn_flow_table *,
                                        const struct ovn_flow *target);
static void ovn_flow_clear_actions_from_list(struct ovs_list *act_list);
static void ovn_flow_clear_actions(struct ovn_flow *);

static bool ovn_flow_action_is_normal(const struct ovn_flow_action *);
static bool ovn_flow_action_is_allow(const struct ovn_flow_action *);
static bool ovn_flow_action_is_drop(const struct ovn_flow_action *);
static bool ovn_flow_action_is_conj(const struct ovn_flow_action *);

static bool ovn_flow_has_action(struct ovn_flow *, struct ovn_flow_action *);
static struct flow_uuid_to_acts *flow_uuid_to_acts_lookup(
    struct hmap *uuid_action_table, const struct uuid *flow_uuid);
static void ovn_flow_action_link_to_flow_uuid(
    struct hmap *uuid_action_table, struct ovn_flow_action *);
static void ovn_flow_unref_action__(struct ovn_flow *,
                                    struct ovn_flow_action *);
static struct ovn_flow_action * ovn_flow_action_get_matching_in_list(
    struct ovs_list *act_list, struct ovn_flow_action *a);
static void ovn_flow_unref_action(struct ovn_flow *, struct ovn_flow_action *);
static struct ovn_flow_action *ovn_flow_get_matching_action(
    struct ovn_flow *, struct ovn_flow_action *);
static bool ovn_flow_has_active_actions(struct ovn_flow *);

static void
ovn_flow_add_to_dp_flow_table(struct ovn_flow_table *, struct ovn_flow *,
                              struct ovn_flow_action *);
static bool ovn_flow_update_actions(struct ovn_flow_table *,
                                    struct ovn_flow *,
                                    struct ovn_flow_action *);
static bool ovn_flow_table_is_empty(struct ovn_flow_table *, uint8_t table_id);

static void ovn_flow_prepare_ofmsg(struct ovn_flow *, struct ovs_list *msgs);
static void dp_flow_populate_oflow_msgs__(struct dp_flow_table *,
                                          struct ovs_list *msgs);

static struct ofpbuf *encode_flow_mod(struct ofputil_flow_mod *);
static void add_flow_mod(struct ofputil_flow_mod *, struct ovs_list *msgs);
static void ovn_flow_add_oflow(struct ovn_flow *, struct ovn_flow_action *,
                               struct ovs_list *msgs);
static void ovn_flow_mod_oflow(struct ovn_flow *, struct ovn_flow_action *,
                               struct ovs_list *msgs);
static void ovn_flow_del_oflow(struct ovn_flow *, struct ovs_list *msgs);
static void ovn_flow_log(const struct ovn_flow *f);
static void dp_flow_print_oflows__(struct dp_flow_table *, FILE *stream);

void
dp_flow_tables_init(void)
{

}

void
dp_flow_tables_destroy(void)
{
    struct dp_flow_table *dp_table;
    HMAP_FOR_EACH_POP (dp_table, hmap_node, &dp_flow_tables) {
        dp_flow_table_destroy__(dp_table);
    }

    hmap_destroy(&dp_flow_tables);
}

struct dp_flow_table *
dp_flow_table_get(uint32_t dp_key)
{
    struct dp_flow_table *dp_table;
    HMAP_FOR_EACH_WITH_HASH (dp_table, hmap_node, dp_key, &dp_flow_tables) {
        if (dp_table->dp_key == dp_key) {
            return dp_table;
        }
    }

    return NULL;
}

struct dp_flow_table *
dp_flow_table_alloc(uint32_t dp_key)
{
    struct dp_flow_table *dp_table = xzalloc(sizeof *dp_table);
    ovn_flow_table_init(&dp_table->lflow_table[0]);
    ovn_flow_table_init(&dp_table->lflow_table[1]);
    ovn_flow_table_init(&dp_table->pflow_table[0]);
    ovn_flow_table_init(&dp_table->pflow_table[1]);
    hmapx_init(&dp_table->modified_lflows);
    hmapx_init(&dp_table->modified_pflows);

    dp_table->active_lflow_table = &dp_table->lflow_table[0];
    dp_table->old_lflow_table = &dp_table->lflow_table[1];
    dp_table->active_pflow_table = &dp_table->pflow_table[0];
    dp_table->old_pflow_table = &dp_table->pflow_table[1];

    dp_table->dp_key = dp_key;
    hmap_insert(&dp_flow_tables, &dp_table->hmap_node, dp_key);
    return dp_table;
}

void dp_flow_table_destroy(uint32_t dp_key)
{
    struct dp_flow_table *dp_table = dp_flow_table_get(dp_key);
    if (dp_table) {
        hmap_remove(&dp_flow_tables, &dp_table->hmap_node);
        dp_flow_table_destroy__(dp_table);
    }
}

void
dp_flow_switch_logical_oflow_tables(void)
{
    struct dp_flow_table *dp_ftable;
    HMAP_FOR_EACH (dp_ftable, hmap_node, &dp_flow_tables) {
        dp_flow_switch_lflow_table__(dp_ftable);
    }
}

void
dp_flow_switch_logical_oflow_table(uint32_t dp_key)
{
    struct dp_flow_table *dp_ftable;
    dp_ftable = dp_flow_table_get(dp_key);
    if (dp_ftable) {
        dp_flow_switch_lflow_table__(dp_ftable);
    }
}

void
dp_flow_switch_physical_oflow_tables(void)
{
    struct dp_flow_table *dp_ftable;
    HMAP_FOR_EACH (dp_ftable, hmap_node, &dp_flow_tables) {
        dp_flow_switch_pflow_table__(dp_ftable);
    }
}

void
dp_flow_switch_physical_oflow_table(uint32_t dp_key)
{
    struct dp_flow_table *dp_ftable;
    dp_ftable = dp_flow_table_get(dp_key);
    if (dp_ftable) {
        dp_flow_switch_pflow_table__(dp_ftable);
    }
}

void
dp_flow_add_logical_oflow(uint32_t dp_key, uint8_t table_id,
                          uint16_t priority, uint64_t cookie,
                          const struct match *match,
                          const struct ofpbuf *actions,
                          const struct uuid *flow_uuid)
{
    struct dp_flow_table *dp_ftable = dp_flow_table_get(dp_key);
    if (!dp_ftable) {
        dp_ftable = dp_flow_table_alloc(dp_key);
    }

    dp_flow_add_openflow__(dp_ftable, true, table_id, priority, cookie, match,
                           actions, flow_uuid);
}

void
dp_flow_add_physical_oflow(uint32_t dp_key, uint8_t table_id,
                           uint16_t priority, uint64_t cookie,
                           const struct match *match,
                           const struct ofpbuf *actions,
                           const struct uuid *flow_uuid)
{
    struct dp_flow_table *dp_ftable = dp_flow_table_get(dp_key);
    if (!dp_ftable) {
        dp_ftable = dp_flow_table_alloc(dp_key);
    }

    dp_flow_add_openflow__(dp_ftable, false, table_id, priority, cookie, match,
                           actions, flow_uuid);
}

void
dp_flow_remove_logical_oflows_all(const struct uuid *flow_uuid)
{
    struct dp_flow_table *dp_ftable;
    HMAP_FOR_EACH (dp_ftable, hmap_node, &dp_flow_tables) {
        dp_flows_remove(dp_ftable, true, flow_uuid);
    }
}

void
dp_flow_remove_logical_oflows(uint32_t dp_key, const struct uuid *flow_uuid)
{
    struct dp_flow_table *dp_ftable = dp_flow_table_get(dp_key);
    if (dp_ftable) {
        dp_flows_remove(dp_ftable, true, flow_uuid);
    }
}

void
dp_flow_remove_physical_oflows(uint32_t dp_key, const struct uuid *flow_uuid)
{
    struct dp_flow_table *dp_ftable = dp_flow_table_get(dp_key);
    if (dp_ftable) {
        dp_flows_remove(dp_ftable, false, flow_uuid);
    }
}                                       

void
dp_flow_flush_logical_oflows(uint32_t dp_key)
{
    dp_flow_switch_logical_oflow_table(dp_key);
}

void
dp_flow_flush_physical_oflows(uint32_t dp_key)
{
    dp_flow_switch_physical_oflow_table(dp_key);
}

void
dp_flow_populate_oflow_msgs(struct ovs_list *msgs)
{
    struct dp_flow_table *dp_ftable;
    HMAP_FOR_EACH (dp_ftable, hmap_node, &dp_flow_tables) {
        dp_flow_populate_oflow_msgs__(dp_ftable, msgs);
    }
}

void
dp_flow_print_oflows(uint32_t dp_key, FILE *stream)
{
    struct dp_flow_table *dp_ftable = dp_flow_table_get(dp_key);
    if (dp_ftable) {
        dp_flow_print_oflows__(dp_ftable, stream);
    }
}
/* Static functions. */

static void
dp_flow_switch_lflow_table__(struct dp_flow_table *dp_ftable)
{
    struct ovn_flow_table *t = dp_ftable->active_lflow_table;
    dp_ftable->active_lflow_table = dp_ftable->old_lflow_table;
    dp_ftable->old_lflow_table = t;

    hmapx_clear(&dp_ftable->modified_lflows);
}

static void
dp_flow_switch_pflow_table__(struct dp_flow_table *dp_ftable)
{
    struct ovn_flow_table *t = dp_ftable->active_pflow_table;
    dp_ftable->active_pflow_table = dp_ftable->old_pflow_table;
    dp_ftable->old_pflow_table = t;

    hmapx_clear(&dp_ftable->modified_pflows);
}

static void
dp_flow_table_destroy__(struct dp_flow_table *dp_ftable)
{
    hmapx_clear(&dp_ftable->modified_lflows);
    hmapx_destroy(&dp_ftable->modified_lflows);
    hmapx_clear(&dp_ftable->modified_pflows);
    hmapx_destroy(&dp_ftable->modified_pflows);
    ovn_flow_table_destroy(&dp_ftable->lflow_table[0]);
    ovn_flow_table_destroy(&dp_ftable->lflow_table[1]);
    ovn_flow_table_destroy(&dp_ftable->pflow_table[0]);
    ovn_flow_table_destroy(&dp_ftable->pflow_table[1]);
    free(dp_ftable);
}

static void
dp_flow_add_openflow__(struct dp_flow_table *dp_ftable, bool lflow_table,
                       uint8_t table_id, uint16_t priority,
                       uint64_t cookie, const struct match *match,
                       const struct ofpbuf *actions,
                       const struct uuid *flow_uuid)
{
    ovs_assert(table_id < OFTABLE_MAX_TABLE_IDS);

    struct ovn_flow_table *active_ftable;
    struct ovn_flow_table *old_ftable;
    struct hmapx *modified_flows;

    if (lflow_table) {
        active_ftable = dp_ftable->active_lflow_table;
        old_ftable = dp_ftable->old_lflow_table;
        modified_flows = &dp_ftable->modified_lflows;
    } else {
        active_ftable = dp_ftable->active_pflow_table;
        old_ftable = dp_ftable->old_pflow_table;
        modified_flows = &dp_ftable->modified_pflows;
    }

    struct ovn_flow *f = ovn_flow_alloc(table_id, priority, match);
    f->match_flow_table = &active_ftable->match_flow_table[table_id];
    f->uuid_action_flow_table = &active_ftable->uuid_action_flow_table;

    struct ovn_flow_action *a = ovn_flow_action_alloc(actions, cookie,
                                                      flow_uuid);

    struct ovn_flow *existing_f = ovn_flow_lookup(active_ftable, f);
    if (existing_f && ovn_flow_has_action(existing_f, a)) {
        /* The flow-action pair already exists. Nothing to be done. */
        ovn_flow_destroy(f);
        ovn_flow_action_destroy(a);
        return;
    }

    bool push_flow_to_switch = true;

    if (!existing_f) {
        ovn_flow_add_to_dp_flow_table(active_ftable, f, a);
    } else {
        ovn_flow_destroy(f);
        f = existing_f;
        push_flow_to_switch = ovn_flow_update_actions(active_ftable, f, a);
    }

    ovn_flow_log(f);

    if (!ovn_flow_table_is_empty(old_ftable, table_id)) {
        existing_f = ovn_flow_lookup(old_ftable, f);
        if (existing_f) {
            f->installed = existing_f->installed;
            struct ovn_flow_action *existing_f_a =
                ovn_flow_get_matching_action(existing_f, a);
            if (existing_f_a) {
                ovn_flow_unref_action(existing_f, existing_f_a);
                if (!ovn_flow_has_active_actions(existing_f)) {
                    hmap_remove(&old_ftable->match_flow_table[table_id],
                                &existing_f->hmap_node);
                    if (existing_f->installed) {
                        push_flow_to_switch = false;
                    }
                    ovn_flow_destroy(existing_f);
                }
            }
        }
    }

    if (push_flow_to_switch) {
        hmapx_add(modified_flows, (void *) f);
    }
}

static void
dp_flows_remove(struct dp_flow_table *dp_ftable, bool lflow_table,
                const struct uuid *flow_uuid)
{
    struct ovn_flow_table *flow_table;
    struct hmapx *modified_flows;

    if (lflow_table) {
        flow_table = dp_ftable->active_lflow_table;
        modified_flows = &dp_ftable->modified_lflows;
    } else {
        flow_table = dp_ftable->active_pflow_table;
        modified_flows = &dp_ftable->modified_pflows;
    }

    struct flow_uuid_to_acts *f_uuid_to_acts =
        flow_uuid_to_acts_lookup(&flow_table->uuid_action_flow_table,
                                 flow_uuid);

    if (!f_uuid_to_acts) {
        return;
    }

    struct ovn_flow_action *a;
    LIST_FOR_EACH_POP (a, flow_uuid_action_node, &f_uuid_to_acts->acts) {
        struct ovn_flow *f = a->flow;
        ovn_flow_unref_action__(a->flow, a);
        ovn_flow_action_destroy(a);
        hmapx_add(modified_flows, (void *) f);
    }

    hmap_remove(&flow_table->uuid_action_flow_table,
                &f_uuid_to_acts->hmap_node);
}

/* ovn flow table functions. */
static void
ovn_flow_table_init(struct ovn_flow_table *flow_table)
{
    for (uint8_t i = 0 ; i < OFTABLE_MAX_TABLE_IDS; i++) {
        hmap_init(&flow_table->match_flow_table[i]);
    }

    hmap_init(&flow_table->uuid_action_flow_table);
}

static void
ovn_flow_table_clear(struct ovn_flow_table *flow_table)
{
    struct flow_uuid_to_acts *f_uuid_to_acts;
    HMAP_FOR_EACH_POP (f_uuid_to_acts, hmap_node,
                       &flow_table->uuid_action_flow_table) {
        struct ovn_flow_action *a;
        LIST_FOR_EACH_POP (a, flow_uuid_action_node,
                           &f_uuid_to_acts->acts) {
            ovn_flow_unref_action__(a->flow, a);
            ovn_flow_action_destroy(a);
        }

        free(f_uuid_to_acts);
    }

    struct ovn_flow *f;
    for (uint8_t i = 0 ; i < OFTABLE_MAX_TABLE_IDS; i++) {
        HMAP_FOR_EACH_POP (f, hmap_node, &flow_table->match_flow_table[i]) {
            ovn_flow_destroy(f);
        }
    }
}

static void
ovn_flow_table_destroy(struct ovn_flow_table *flow_table)
{
    ovn_flow_table_clear(flow_table);
    for (uint8_t i = 0 ; i < OFTABLE_MAX_TABLE_IDS; i++) {
        hmap_destroy(&flow_table->match_flow_table[i]);
    }
    hmap_destroy(&flow_table->uuid_action_flow_table);
}


/* Returns a hash of the match key in 'f'. */
static uint32_t
ovn_flow_match_hash(const struct ovn_flow *f)
{
    return hash_2words((f->table_id << 16) | f->priority,
                       minimatch_hash(&f->match, 0));
}

static void
ovn_flow_action_init(struct ovn_flow_action *a, const struct ofpbuf *actions,
                     uint64_t cookie, const struct uuid *flow_uuid)
{
    a->ofpacts = xmemdup(actions->data, actions->size);
    a->ofpacts_len = actions->size;
    a->cookie = cookie;
    a->flow_uuid = *flow_uuid;
    ovs_list_init(&a->list_node);
}

static void
ovn_flow_action_destroy(struct ovn_flow_action *a)
{
    free(a->ofpacts);
    free(a);
}

static void
ovn_flow_init(struct ovn_flow *f, uint8_t table_id, uint16_t priority,
              const struct match *match)
{
    f->table_id = table_id;
    f->priority = priority;
    minimatch_init(&f->match, match);

    f->hash = ovn_flow_match_hash(f);

    ovs_list_init(&f->allow_act_list);
    ovs_list_init(&f->drop_act_list);
    ovs_list_init(&f->conj_act_list);

    f->active_cookie = 0;
}

static struct ovn_flow *
ovn_flow_alloc(uint8_t table_id, uint16_t priority,
               const struct match *match)
{
    struct ovn_flow *f = xzalloc(sizeof *f);
    ovn_flow_init(f, table_id, priority, match);

    return f;
}

static struct ovn_flow_action *
ovn_flow_action_alloc(const struct ofpbuf *actions,
                      uint64_t cookie, const struct uuid *flow_uuid)
{
    struct ovn_flow_action *a = xzalloc(sizeof *a);
    ovn_flow_action_init(a, actions, cookie, flow_uuid);

    return a;
}

/* Finds and returns a ovn_flow in 'flow_table' whose key is identical to
 * 'target''s key, or NULL if there is none.
 */
static struct ovn_flow *
ovn_flow_lookup(struct ovn_flow_table *flow_table,
                const struct ovn_flow *target)
{
    struct ovn_flow *f;
    HMAP_FOR_EACH_WITH_HASH (f, hmap_node, target->hash,
                             &flow_table->match_flow_table[target->table_id]) {
        if (f->priority == target->priority
            && minimatch_equal(&f->match, &target->match)) {

            return f;
        }
    }
    return NULL;
}

static void
ovn_flow_clear_actions_from_list(struct ovs_list *act_list)
{
    struct ovn_flow_action *a;
    LIST_FOR_EACH_POP (a, list_node, act_list) {
        ovs_list_remove(&a->flow_uuid_action_node);
        ovn_flow_action_destroy(a);
    }
}

static void
ovn_flow_clear_actions(struct ovn_flow *f)
{
    if (f->normal_act) {
        ovs_list_remove(&f->normal_act->flow_uuid_action_node);
        ovn_flow_action_destroy(f->normal_act);
        f->normal_act = NULL;
    }

    if (!ovs_list_is_empty(&f->allow_act_list)) {
        ovn_flow_clear_actions_from_list(&f->allow_act_list);
    }

    if (!ovs_list_is_empty(&f->drop_act_list)) {
        ovn_flow_clear_actions_from_list(&f->drop_act_list);
    }

    if (!ovs_list_is_empty(&f->conj_act_list)) {
        ovn_flow_clear_actions_from_list(&f->conj_act_list);
    }
}

static void
ovn_flow_uninit(struct ovn_flow *f)
{
    minimatch_destroy(&f->match);
    ovn_flow_clear_actions(f);
}

static void
ovn_flow_destroy(struct ovn_flow *f)
{
    if (f) {
        ovn_flow_uninit(f);
        free(f);
    }
}

static bool
ovn_flow_action_is_drop(const struct ovn_flow_action *f)
{
    return f->ofpacts_len == 0;
}

static bool
ovn_flow_action_is_conj(const struct ovn_flow_action *f)
{
    const struct ofpact *a = NULL;

    OFPACT_FOR_EACH (a, f->ofpacts, f->ofpacts_len) {
        if (a->type == OFPACT_CONJUNCTION) {
            return true;
        }
    }
    return false;
}

static bool
ovn_flow_action_is_allow(const struct ovn_flow_action *f)
{
    if (ovn_flow_action_is_drop(f)) {
        return false;
    }

    const struct ofpact *a = f->ofpacts;
    return (a->type == OFPACT_RESUBMIT &&
            ofpact_last(a, f->ofpacts, f->ofpacts_len));
}

static bool
ovn_flow_action_is_normal(const struct ovn_flow_action *f)
{
    return (!ovn_flow_action_is_allow(f) && !ovn_flow_action_is_drop(f) &&
            !ovn_flow_action_is_conj(f));
}

static struct ovn_flow_action *
ovn_flow_action_get_matching_in_list(struct ovs_list *act_list,
                                     struct ovn_flow_action *a)
{
    struct ovn_flow_action *act_in_list;
    LIST_FOR_EACH (act_in_list, list_node, act_list) {
        if (ofpacts_equal(act_in_list->ofpacts,
                          act_in_list->ofpacts_len,
                          a->ofpacts,
                          a->ofpacts_len)) {
            return act_in_list;
        }
    }

    return NULL;
}

static struct ovn_flow_action *
ovn_flow_get_matching_action(struct ovn_flow *f, struct ovn_flow_action *a)
{
    if (f->normal_act && ovn_flow_action_is_normal(a)) {
        if(ofpacts_equal(f->normal_act->ofpacts,
                         f->normal_act->ofpacts_len,
                         a->ofpacts,
                         a->ofpacts_len)) {
            return f->normal_act;
        }
    }

    if (ovn_flow_action_is_allow(a)) {
        return ovn_flow_action_get_matching_in_list(&f->allow_act_list, a);
    }

    if (ovn_flow_action_is_drop(a)) {
        return ovn_flow_action_get_matching_in_list(&f->drop_act_list, a);
    }

    if (ovn_flow_action_is_conj(a)) {
        return ovn_flow_action_get_matching_in_list(&f->conj_act_list, a);
    }

    return NULL;
}

static bool
ovn_flow_has_action(struct ovn_flow *f, struct ovn_flow_action *a)
{
    struct ovn_flow_action *ma = ovn_flow_get_matching_action(f, a);

    if (ovn_flow_action_is_normal(a)) {
        return ma ? true: false;
    }

    return ma ? uuid_equals(&ma->flow_uuid, &a->flow_uuid) : false;
}

static bool
ovn_flow_has_active_actions(struct ovn_flow *f)
{
    if (f->normal_act) {
        return true;
    }

    if (!ovs_list_is_empty(&f->allow_act_list)) {
        return true;
    }

    if (!ovs_list_is_empty(&f->drop_act_list)) {
        return true;
    }

    return !ovs_list_is_empty(&f->allow_act_list);
}

static struct flow_uuid_to_acts *
flow_uuid_to_acts_lookup(struct hmap *uuid_action_table,
                         const struct uuid *flow_uuid)
{
    struct flow_uuid_to_acts *f_uuid_to_acts;
    HMAP_FOR_EACH_WITH_HASH (f_uuid_to_acts, hmap_node, uuid_hash(flow_uuid),
                             uuid_action_table) {
        if (uuid_equals(flow_uuid, &f_uuid_to_acts->flow_uuid)) {
            return f_uuid_to_acts;
        }
    }
    return NULL;
}

static void
ovn_flow_action_link_to_flow_uuid(struct hmap *uuid_action_table,
                                  struct ovn_flow_action *a)
{
    struct flow_uuid_to_acts *f_uuid_to_acts;
    f_uuid_to_acts = flow_uuid_to_acts_lookup(uuid_action_table, &a->flow_uuid);
    if (!f_uuid_to_acts) {
        f_uuid_to_acts = xzalloc(sizeof *f_uuid_to_acts);
        f_uuid_to_acts->flow_uuid = a->flow_uuid;
        ovs_list_init(&f_uuid_to_acts->acts);
        hmap_insert(uuid_action_table, &f_uuid_to_acts->hmap_node,
                    uuid_hash(&a->flow_uuid));
    }

    ovs_list_push_back(&f_uuid_to_acts->acts, &a->flow_uuid_action_node);
}

static void
ovn_flow_unref_action__(struct ovn_flow *f, struct ovn_flow_action *a)
{
    if(f->normal_act == a) {
        f->normal_act = NULL;
    } else if (!ovs_list_is_empty(&a->list_node)) {
        ovs_list_remove(&a->list_node);
    }
}

static void
ovn_flow_unref_action(struct ovn_flow *f, struct ovn_flow_action *a)
{
    ovs_list_remove(&a->flow_uuid_action_node);
    ovn_flow_unref_action__(f, a);
    ovn_flow_action_destroy(a);
}

static void
ovn_flow_add_to_dp_flow_table(struct ovn_flow_table *ftable,
                              struct ovn_flow *f, struct ovn_flow_action *a)
{
    hmap_insert(&ftable->match_flow_table[f->table_id], &f->hmap_node,
                f->hash);
    ovn_flow_update_actions(ftable, f, a);
}

static bool
ovn_flow_update_actions(struct ovn_flow_table *ftable,
                        struct ovn_flow *f, struct ovn_flow_action *a)
{
    bool flow_updated = true;
    if (ovn_flow_action_is_normal(a)) {
        if (f->normal_act) {
            ovn_flow_unref_action(f, f->normal_act);
        }
        f->normal_act = a;
    } else if (ovn_flow_action_is_allow(a)) {
        flow_updated = ovs_list_is_empty(&f->allow_act_list);
        ovs_list_push_back(&f->allow_act_list, &a->list_node);
    } else if (ovn_flow_action_is_drop(a)) {
        flow_updated = ovs_list_is_empty(&f->drop_act_list);
        ovs_list_push_back(&f->drop_act_list, &a->list_node);
    } else {
        /* conj action. */
        ovs_list_is_empty(&f->conj_act_list);
        ovs_list_push_back(&f->conj_act_list, &a->list_node);
    }
    
    a->flow = f;

    ovn_flow_action_link_to_flow_uuid(&ftable->uuid_action_flow_table, a);

    return flow_updated;
}

static bool
ovn_flow_table_is_empty(struct ovn_flow_table *ftable, uint8_t table_id)
{
    return hmap_is_empty(&ftable->match_flow_table[table_id]);
}

static void
ovn_flow_prepare_ofmsg(struct ovn_flow *f, struct ovs_list *msgs)
{
    struct ovn_flow_action *a = NULL;
    struct ovn_flow_action *conj_act = NULL;

    if (f->normal_act) {
        a = f->normal_act;
    } else if (!ovs_list_is_empty(&f->allow_act_list)) {
        a = CONTAINER_OF(ovs_list_front(&f->allow_act_list),
                         struct ovn_flow_action,
                         list_node);
    } else if (!ovs_list_is_empty(&f->drop_act_list)) {
        a = CONTAINER_OF(ovs_list_front(&f->drop_act_list),
                         struct ovn_flow_action,
                         list_node);
    } else if (!ovs_list_is_empty(&f->conj_act_list)) {
        struct ovn_flow_action *c;
        uint64_t ofpacts_stub[1024 / 8];
        struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);        

        LIST_FOR_EACH (c, list_node, &f->conj_act_list) {
            ofpbuf_put(&ofpacts, c->ofpacts, c->ofpacts_len);
        }
        conj_act = xzalloc(sizeof *conj_act);
        conj_act->cookie = CONJ_ACT_COOKIE;
        conj_act->ofpacts = xmemdup(ofpacts.data, ofpacts.size);
        conj_act->ofpacts_len = ofpacts.size;
        ofpbuf_uninit(&ofpacts);
        a = conj_act;
    }

    if (a) {
        if (f->active_cookie == 0) {
            ovn_flow_add_oflow(f, a, msgs);
        } else {
            ovn_flow_mod_oflow(f, a, msgs);
        }
    } else {
        ovn_flow_del_oflow(f, msgs);
    }
        
    if (conj_act) {
        free(conj_act->ofpacts);
        free(conj_act);
    }
}

static void
dp_flow_populate_oflow_msgs__(struct dp_flow_table *dp_ftable,
                               struct ovs_list *msgs)
{
    struct ovn_flow *f;

    for (uint8_t i = 0; i < OFTABLE_MAX_TABLE_IDS; i++) {
        HMAP_FOR_EACH_POP (f, hmap_node,
                           &dp_ftable->old_lflow_table->match_flow_table[i]) {
            ovn_flow_clear_actions(f);
            ovn_flow_prepare_ofmsg(f, msgs);
            hmapx_find_and_delete(&dp_ftable->modified_lflows, f);
            ovn_flow_destroy(f);
        }

        HMAP_FOR_EACH_POP (f, hmap_node,
                           &dp_ftable->old_pflow_table->match_flow_table[i]) {
            ovn_flow_clear_actions(f);
            ovn_flow_prepare_ofmsg(f, msgs);
            hmapx_find_and_delete(&dp_ftable->modified_pflows, f);
            ovn_flow_destroy(f);
        }
    }

    struct hmapx_node *node;
    HMAPX_FOR_EACH (node, &dp_ftable->modified_lflows) {
        f = node->data;
        ovn_flow_prepare_ofmsg(f, msgs);
        f->installed = true;
    }

    hmapx_clear(&dp_ftable->modified_lflows);

    HMAPX_FOR_EACH (node, &dp_ftable->modified_pflows) {
        f = node->data;
        ovn_flow_prepare_ofmsg(f, msgs);
        f->installed = true;
    }

    hmapx_clear(&dp_ftable->modified_pflows);
}

/* Flow table update. */

static struct ofpbuf *
encode_flow_mod(struct ofputil_flow_mod *fm)
{
    fm->buffer_id = UINT32_MAX;
    fm->out_port = OFPP_ANY;
    fm->out_group = OFPG_ANY;
    return ofputil_encode_flow_mod(fm, OFPUTIL_P_OF15_OXM);
}

static void
add_flow_mod(struct ofputil_flow_mod *fm, struct ovs_list *msgs)
{
    struct ofpbuf *msg = encode_flow_mod(fm);
    ovs_list_push_back(msgs, &msg->list_node);
}

static void
ovn_flow_add_oflow(struct ovn_flow *f, struct ovn_flow_action *a,
                   struct ovs_list *msgs)
{
    /* Send flow_mod to add flow. */
    struct ofputil_flow_mod fm = {
        .match = f->match,
        .priority = f->priority,
        .table_id = f->table_id,
        .ofpacts = a->ofpacts,
        .ofpacts_len = a->ofpacts_len,
        .new_cookie = htonll(a->cookie),
        .command = OFPFC_ADD,
    };
    add_flow_mod(&fm, msgs);
    f->active_cookie = a->cookie;
}

static void
ovn_flow_mod_oflow(struct ovn_flow *f, struct ovn_flow_action *a,
                   struct ovs_list *msgs)
{
    /* Update actions in installed flow. */
    struct ofputil_flow_mod fm = {
        .match = f->match,
        .priority = f->priority,
        .table_id = f->table_id,
        .ofpacts = a->ofpacts,
        .ofpacts_len = a->ofpacts_len,
        .command = OFPFC_MODIFY_STRICT,
    };
    /* Update cookie if it is changed. */
    if (f->active_cookie != a->cookie) {
        fm.modify_cookie = true;
        fm.new_cookie = htonll(a->cookie);
        /* Use OFPFC_ADD so that cookie can be updated. */
        fm.command = OFPFC_ADD;
    }
    add_flow_mod(&fm, msgs);
    f->active_cookie = a->cookie;
}

static void
ovn_flow_del_oflow(struct ovn_flow *f, struct ovs_list *msgs)
{
    struct ofputil_flow_mod fm = {
        .match = f->match,
        .priority = f->priority,
        .table_id = f->table_id,
        .command = OFPFC_DELETE_STRICT,
    };
    add_flow_mod(&fm, msgs);
    f->active_cookie = 0;
}

static char *
ovn_flow_to_string(const struct ovn_flow *f)
{
    struct ds s = DS_EMPTY_INITIALIZER;

    struct ovn_flow_action *a = NULL;
    struct ovn_flow_action *conj_act = NULL;

    if (f->normal_act) {
        a = f->normal_act;
    } else if (!ovs_list_is_empty(&f->allow_act_list)) {
        a = CONTAINER_OF(ovs_list_front(&f->allow_act_list),
                         struct ovn_flow_action,
                         list_node);
    } else if (!ovs_list_is_empty(&f->drop_act_list)) {
        a = CONTAINER_OF(ovs_list_front(&f->drop_act_list),
                         struct ovn_flow_action,
                         list_node);
    } else if (!ovs_list_is_empty(&f->conj_act_list)) {
        struct ovn_flow_action *c;
        uint64_t ofpacts_stub[1024 / 8];
        struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);        

        LIST_FOR_EACH (c, list_node, &f->conj_act_list) {
            ofpbuf_put(&ofpacts, c->ofpacts, c->ofpacts_len);
        }
        conj_act = xzalloc(sizeof *conj_act);
        conj_act->cookie = CONJ_ACT_COOKIE;
        conj_act->ofpacts = xmemdup(ofpacts.data, ofpacts.size);
        conj_act->ofpacts_len = ofpacts.size;
        ofpbuf_uninit(&ofpacts);
        a = conj_act;
    }

    if (a) {
        ds_put_format(&s, "cookie=%"PRIx64", ", a->cookie);
    }
    ds_put_format(&s, "table_id=%"PRIu8", ", f->table_id);
    ds_put_format(&s, "priority=%"PRIu16", ", f->priority);
    minimatch_format(&f->match, NULL, NULL, &s, OFP_DEFAULT_PRIORITY);
    ds_put_cstr(&s, ", actions=");
    struct ofpact_format_params fp = { .s = &s };
    if (a) {
        ofpacts_format(a->ofpacts, a->ofpacts_len, &fp);
    } else {
        ds_put_cstr(&s, "<EMPTY>");
    }

    if (conj_act) {
        free(conj_act->ofpacts);
        free(conj_act);
    }
    return ds_steal_cstr(&s);
}

static void
ovn_flow_log(const struct ovn_flow *f)
{
    if (VLOG_IS_DBG_ENABLED()) {
        char *s = ovn_flow_to_string(f);
        VLOG_DBG("flow: %s", s);
        free(s);
    }
}

static void
dp_flow_print_flow_table__(struct ovn_flow_table *ftable, FILE *stream)
{
    bool is_empty = true;
    struct ovn_flow *f;
    for (uint8_t i = 0 ; i < OFTABLE_MAX_TABLE_IDS; i++) {
        is_empty = (is_empty && hmap_is_empty(&ftable->match_flow_table[i]));

        HMAP_FOR_EACH (f, hmap_node, &ftable->match_flow_table[i]) {
            char *s = ovn_flow_to_string(f);
            if (s) {
                fputs(s, stream);
                free(s);
                fputc('\n', stream);
            }
        }
    }

    if (is_empty) {
        fputs("empty\n", stream);
    }
}

static void
dp_flow_print_oflows__(struct dp_flow_table *dp_ftable, FILE *stream)
{
    fprintf(stream, "Flow table dump for datapath [%u]\n", dp_ftable->dp_key);
    fputs("Active logical flows: ", stream);

    dp_flow_print_flow_table__(dp_ftable->active_lflow_table, stream);

    fputc('\n', stream);
    fputs("Old logical flows: ", stream);
    dp_flow_print_flow_table__(dp_ftable->old_lflow_table, stream);

    fputs("Active physical flows: ", stream);
    dp_flow_print_flow_table__(dp_ftable->active_pflow_table, stream);

    fputs("Old physical flows: ", stream);
    dp_flow_print_flow_table__(dp_ftable->old_pflow_table, stream);

    fputs("\n\n", stream);
}

#if 0
void
dp_flow_dump_stats(void)
{
    VLOG_INFO("NUMS : %s : %s : %d entered : No of dptables = [%lu]",  __FILE__, __FUNCTION__, __LINE__, hmap_count(&dp_flow_tables));

    struct dp_flow_table *dp_ftable;
    HMAP_FOR_EACH (dp_ftable, hmap_node, &dp_flow_tables) {
        VLOG_INFO("NUMS :  %s : %d : dp table key = [%u] : No of lflows - [%lu] : No of old lflows - [%lu]"
                  " No of pflows - [%lu] : No of old pflows - [%lu]",
                  __FUNCTION__, __LINE__, dp_ftable->dp_key,
                  hmap_count(&dp_ftable->active_lflow_table->match_flow_table),
                  hmap_count(&dp_ftable->old_lflow_table->match_flow_table),
                  hmap_count(&dp_ftable->active_pflow_table->match_flow_table),
                  hmap_count(&dp_ftable->old_pflow_table->match_flow_table));
    }

    VLOG_INFO(" **** NUMS : %s : %s : %d exiting ******",  __FILE__, __FUNCTION__, __LINE__);
}
#endif
