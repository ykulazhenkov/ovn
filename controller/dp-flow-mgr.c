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
    bool stale;

    struct ovs_list list_node;
    struct ovn_flow *flow;
};

/* An OpenFlow flow. */
struct ovn_flow {
    struct hmap_node hmap_node;
    struct hmap *match_flow_table; /* Points to the match flow table hmap for
                                    * easy access. */
    struct hmap *uuid_action_flow_table; /* Points to the uuid action flow
                                          * table hmap for easy access. */
    struct ovs_list flow_list_node; /* List node in dp_flow_table.lflows_list[]
                                     * or dp_flow_table.pflows_list[]. */

    /* Flow list in which this 'ovn_flow.flow_list_node' is present
     * (for easy access). */
    struct ovs_list *flow_list;

    /* Key. */
    uint8_t table_id;
    uint16_t priority;
    struct minimatch match;

    /* Hash. */
    uint32_t hash;

    /* Actions associated with the flow.
     * An ovn_flow can have
     *   - A normal action - has precendence over all the other below actions
     *                       if set.
     *   - a list of allow actions - has precedence over drop and conjuctive
     *                               actions.
     *   - a list of drop actions  - has precedence over conjuctive actions.
     *   - a list of conjuctive actions.
     */
    struct ovn_flow_action *normal_act;
    struct ovs_list allow_act_list;
    struct ovs_list drop_act_list;
    struct ovs_list conj_act_list;

    /* Presently installed ofpacts. */
    struct ofpact *installed_ofpacts;
    size_t installed_ofpacts_len;

    /* Cookie of the ovn_action which is presently active. */
    uint64_t active_cookie;
};

/* Represents a list of 'ovn flow actions' associated with
 * a flow uuid. */
struct flow_uuid_to_acts {
    struct hmap_node hmap_node; /* Node in
                                 *  ovn_flow_table.uuid_flow_table. */
    struct uuid flow_uuid;
    struct ovs_list acts; /* A list of struct ovn_flow_action nodes that
                           * are referenced by the sb_uuid. */
};

/* Represents a flow table. */
struct ovn_flow_table {
    /* Hash map of flow table using flow match conditions as hash key.*/
    struct hmap match_flow_table;

    /* Hash map of ovn_flow_action list table using uuid as hash key.*/
    struct hmap uuid_action_flow_table;
};

/* Represents a datapath flow table.
 *
 * We maintain 2 lists for logical flows list. One represents an active flow
 * list and the other represents an old flow list.  When a flow is added to
 * the dp flow table, it is always added to the active flow list. If that flow
 * is present in the old flow list, it is removed from the old one.
 *
 * The function dp_flow_populate_oflow_msgs() clears all the
 * flows present in the old flow list.
 *
 * User can swap the lists by calling dp_flow_switch_logical_oflow_tables().
 *
 * The same goes for the physical flow lists.
 */
struct dp_flow_table {
    struct hmap_node hmap_node;
    uint32_t dp_key;

    struct ovn_flow_table lflow_table; /* For logical flows. */
    struct ovn_flow_table pflow_table; /* For physical flows. */

    struct ovs_list lflows_list[2];
    struct ovs_list pflows_list[2];

    struct ovs_list *active_lflows; /* Points to one of the element in
                                     * lflows_list. */
    struct ovs_list *old_lflows; /* Points to other element in
                                  * lflows_list. */

    struct ovs_list *active_pflows;
    struct ovs_list *old_pflows;

    struct hmapx modified_lflows;
    struct hmapx modified_pflows;
};

/* Static functions. */
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

static uint32_t ovn_flow_match_hash__(uint8_t table_id, uint16_t priority,
                                      const struct minimatch *);
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
                                        uint8_t table_id, uint16_t priority,
                                        const struct minimatch *);
static void ovn_flow_invalidate_all_actions(struct ovn_flow *f);
static void ovn_flow_clear_actions_from_list(struct ovs_list *act_list);
static void ovn_flow_invalidate_actions_from_list(struct ovs_list *act_list);
static void ovn_flow_clear_actions(struct ovn_flow *);
static bool ovn_flow_has_active_actions(struct ovn_flow *);

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

static bool ovn_flow_update_actions(struct ovn_flow_table *,
                                    struct ovn_flow *,
                                    struct ovn_flow_action *);

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
static void ovn_flow_log(const struct ovn_flow *);
static char * ovn_flow_to_string(const struct ovn_flow *);

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
    ovn_flow_table_init(&dp_table->lflow_table);
    ovn_flow_table_init(&dp_table->pflow_table);

    ovs_list_init(&dp_table->lflows_list[0]);
    ovs_list_init(&dp_table->lflows_list[1]);
    ovs_list_init(&dp_table->pflows_list[0]);
    ovs_list_init(&dp_table->pflows_list[1]);

    hmapx_init(&dp_table->modified_lflows);
    hmapx_init(&dp_table->modified_pflows);

    dp_table->active_lflows = &dp_table->lflows_list[0];
    dp_table->old_lflows = &dp_table->lflows_list[1];
    dp_table->active_pflows = &dp_table->pflows_list[0];
    dp_table->old_pflows = &dp_table->pflows_list[1];

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
dp_flow_flush_all_oflows(void)
{
    struct dp_flow_table *dp_table;
    HMAP_FOR_EACH_POP (dp_table, hmap_node, &dp_flow_tables) {
        dp_flow_table_destroy__(dp_table);
    }

    hmap_destroy(&dp_flow_tables);
    hmap_init(&dp_flow_tables);
}

void
dp_flow_populate_oflow_msgs(struct ovs_list *msgs)
{
    struct dp_flow_table *dp_ftable;
    HMAP_FOR_EACH (dp_ftable, hmap_node, &dp_flow_tables) {
        dp_flow_populate_oflow_msgs__(dp_ftable, msgs);
    }
}

/* Static functions. */

static void
dp_flow_switch_lflow_table__(struct dp_flow_table *dp_ftable)
{
    struct ovs_list *t = dp_ftable->active_lflows;
    dp_ftable->active_lflows = dp_ftable->old_lflows;
    dp_ftable->old_lflows = t;

    hmapx_clear(&dp_ftable->modified_lflows);
}

static void
dp_flow_switch_pflow_table__(struct dp_flow_table *dp_ftable)
{
    struct ovs_list *t = dp_ftable->active_pflows;
    dp_ftable->active_pflows = dp_ftable->old_pflows;
    dp_ftable->old_pflows = t;

    hmapx_clear(&dp_ftable->modified_pflows);
}

static void
dp_flow_table_destroy__(struct dp_flow_table *dp_ftable)
{
    hmapx_clear(&dp_ftable->modified_lflows);
    hmapx_destroy(&dp_ftable->modified_lflows);
    hmapx_clear(&dp_ftable->modified_pflows);
    hmapx_destroy(&dp_ftable->modified_pflows);

    ovn_flow_table_destroy(&dp_ftable->lflow_table);
    ovn_flow_table_destroy(&dp_ftable->pflow_table);

    free(dp_ftable);
}

/* This function
 *   - Looks up in the datapath flow table if the flow F
 *     with the provided (match, table_id, priority) is already
 *     present or not.
 *
 *   - If not present it creates an ovn_flow 'F' with the provided
 *     (match, table_id, priority) and inserts into the flow table.
 *
 *   - Allocates ovn_flow_action 'A' with the given -
 *     (actions, cookie, flow_uuid).
 *
 *   - If 'F' already has 'A' it does nothing and returns. Otherwise
 *     it associates 'A' to the 'F' actions.
 *
 *   - Adds 'F' to the active flow list.
 */
static void
dp_flow_add_openflow__(struct dp_flow_table *dp_ftable, bool lflow_table,
                       uint8_t table_id, uint16_t priority,
                       uint64_t cookie, const struct match *match,
                       const struct ofpbuf *actions,
                       const struct uuid *flow_uuid)
{
    struct ovn_flow_table *ftable;
    struct hmapx *modified_flows;
    struct ovs_list *active_flows;

    if (lflow_table) {
        ftable = &dp_ftable->lflow_table;
        modified_flows = &dp_ftable->modified_lflows;
        active_flows = dp_ftable->active_lflows;
    } else {
        ftable = &dp_ftable->pflow_table;
        modified_flows = &dp_ftable->modified_pflows;
        active_flows = dp_ftable->active_pflows;
    }

    struct minimatch minimatch;
    minimatch_init(&minimatch, match);

    struct ovn_flow *f = ovn_flow_lookup(ftable, table_id, priority,
                                         &minimatch);

    minimatch_destroy(&minimatch);

    bool active_flow_list_changed = false;
    bool flow_exists = true;

    if (!f) {
        f = ovn_flow_alloc(table_id, priority, match);
        f->match_flow_table = &ftable->match_flow_table;
        f->uuid_action_flow_table = &ftable->uuid_action_flow_table;
        ovs_list_init(&f->flow_list_node);
        flow_exists = false;
        hmap_insert(&ftable->match_flow_table, &f->hmap_node,
                    f->hash);
    } else {
        ovs_list_remove(&f->flow_list_node);
        active_flow_list_changed = (active_flows != f->flow_list);
    }

    f->flow_list = active_flows;
    ovs_list_push_back(active_flows, &f->flow_list_node);

    struct ovn_flow_action *a = ovn_flow_action_alloc(actions, cookie,
                                                      flow_uuid);

    if (active_flow_list_changed) {
        ovn_flow_invalidate_all_actions(f);
    }

    bool push_flow_to_switch = true;
    if (flow_exists && ovn_flow_has_action(f, a)) {
        struct ovn_flow_action *existing_a =
            ovn_flow_get_matching_action(f, a);
        if (uuid_equals(&existing_a->flow_uuid, flow_uuid)) {
            existing_a->stale = false;
        }
        if (!active_flow_list_changed) {
            /* The flow-action pair already exists. Nothing to be done. */
            push_flow_to_switch = false;
        }
        ovn_flow_action_destroy(a);
    } else {
        ovn_flow_update_actions(ftable, f, a);
    }

    ovn_flow_log(f);
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
        flow_table = &dp_ftable->lflow_table;
        modified_flows = &dp_ftable->modified_lflows;
    } else {
        flow_table = &dp_ftable->pflow_table;
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
    hmap_init(&flow_table->match_flow_table);
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
    HMAP_FOR_EACH_POP (f, hmap_node, &flow_table->match_flow_table) {
            ovn_flow_destroy(f);
    }
}

static void
ovn_flow_table_destroy(struct ovn_flow_table *flow_table)
{
    ovn_flow_table_clear(flow_table);
    hmap_destroy(&flow_table->match_flow_table);
    hmap_destroy(&flow_table->uuid_action_flow_table);
}

static uint32_t
ovn_flow_match_hash__(uint8_t table_id, uint16_t priority,
                       const struct minimatch *match)
{
    return hash_2words((table_id << 16) | priority,
                       minimatch_hash(match, 0));
}

/* Returns a hash of the match key in 'f'. */
static uint32_t
ovn_flow_match_hash(const struct ovn_flow *f)
{
    return ovn_flow_match_hash__(f->table_id, f->priority, &f->match);
}

static void
ovn_flow_action_init(struct ovn_flow_action *a, const struct ofpbuf *actions,
                     uint64_t cookie, const struct uuid *flow_uuid)
{
    a->ofpacts = xmemdup(actions->data, actions->size);
    a->ofpacts_len = actions->size;
    a->cookie = cookie;
    a->flow_uuid = *flow_uuid;
    a->stale = false;
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

    f->installed_ofpacts = NULL;
    f->installed_ofpacts_len = 0;

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
                uint8_t table_id, uint16_t priority,
                const struct minimatch *match)
{
    size_t hash = ovn_flow_match_hash__(table_id, priority, match);

    struct ovn_flow *f;
    HMAP_FOR_EACH_WITH_HASH (f, hmap_node, hash,
                             &flow_table->match_flow_table) {
        if (f->priority == priority
            && minimatch_equal(&f->match, match)) {

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
ovn_flow_invalidate_actions_from_list(struct ovs_list *act_list)
{
    struct ovn_flow_action *a;
    LIST_FOR_EACH (a, list_node, act_list) {
        a->stale = true;
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
ovn_flow_invalidate_all_actions(struct ovn_flow *f)
{
    if (f->normal_act) {
        f->normal_act->stale = true;
    }

    if (!ovs_list_is_empty(&f->allow_act_list)) {
        ovn_flow_invalidate_actions_from_list(&f->allow_act_list);
    }

    if (!ovs_list_is_empty(&f->drop_act_list)) {
        ovn_flow_invalidate_actions_from_list(&f->drop_act_list);
    }

    if (!ovs_list_is_empty(&f->conj_act_list)) {
        ovn_flow_invalidate_actions_from_list(&f->conj_act_list);
    }
}

static void
ovn_flow_delete_stale_actions_from_list(struct ovs_list *act_list)
{
    struct ovn_flow_action *a, *next;
    LIST_FOR_EACH_SAFE (a, next, list_node, act_list) {
        if (a->stale) {
            ovn_flow_unref_action(a->flow, a);
        }
    }
}

static void
ovn_flow_delete_stale_actions(struct ovn_flow *f)
{
    if (f->normal_act && f->normal_act->stale) {
        ovn_flow_unref_action(f, f->normal_act);
        f->normal_act = NULL;
    }

    if (!ovs_list_is_empty(&f->allow_act_list)) {
        ovn_flow_delete_stale_actions_from_list(&f->allow_act_list);
    }

    if (!ovs_list_is_empty(&f->drop_act_list)) {
        ovn_flow_delete_stale_actions_from_list(&f->drop_act_list);
    }

    if (!ovs_list_is_empty(&f->conj_act_list)) {
        ovn_flow_delete_stale_actions_from_list(&f->conj_act_list);
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
        free(f->installed_ofpacts);
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
        if (ofpacts_equal(f->normal_act->ofpacts,
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

    return !ovs_list_is_empty(&f->conj_act_list);
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
    if (f->normal_act == a) {
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
        ovs_list_push_back(&f->conj_act_list, &a->list_node);
    }

    a->flow = f;
    a->stale = false;

    ovn_flow_action_link_to_flow_uuid(&ftable->uuid_action_flow_table, a);

    return flow_updated;
}

static bool
ovn_flow_needs_flow_mod(struct ovn_flow *f, struct ovn_flow_action *a)
{
    if (f->installed_ofpacts_len != a->ofpacts_len) {
        return true;
    }

    if (f->installed_ofpacts_len && a->ofpacts_len) {
        return !ofpacts_equal(f->installed_ofpacts,
                              f->installed_ofpacts_len,
                              a->ofpacts,
                              a->ofpacts_len);
    }

    return f->active_cookie ? false : true;
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
        /* check if there is really a need to install or not. */
        if (ovn_flow_needs_flow_mod(f, a)) {
            if (f->active_cookie == 0) {
                ovn_flow_add_oflow(f, a, msgs);
            } else {
                ovn_flow_mod_oflow(f, a, msgs);
            }
            free(f->installed_ofpacts);
            if (a->ofpacts_len) {
                f->installed_ofpacts = xmemdup(a->ofpacts, a->ofpacts_len);
                f->installed_ofpacts_len = a->ofpacts_len;
            } else {
                f->installed_ofpacts = NULL;
                f->installed_ofpacts_len = 0;
            }
        }
    } else {
        ovn_flow_del_oflow(f, msgs);
        free(f->installed_ofpacts);
        f->installed_ofpacts = NULL;
        f->installed_ofpacts_len = 0;
        f->active_cookie = 0;
    }

    if (conj_act) {
        free(conj_act->ofpacts);
        free(conj_act);
    }
}

static void
ovn_flow_handle_modified(struct ovn_flow *f, struct ovs_list *msgs)
{
    ovn_flow_delete_stale_actions(f);
    ovn_flow_prepare_ofmsg(f, msgs);
    if (!ovn_flow_has_active_actions(f)) {
        hmap_remove(f->match_flow_table, &f->hmap_node);
        ovs_list_remove(&f->flow_list_node);
        ovn_flow_destroy(f);
    }
}

static void
dp_flow_populate_oflow_msgs__(struct dp_flow_table *dp_ftable,
                              struct ovs_list *msgs)
{
    struct ovn_flow *f;

    LIST_FOR_EACH_POP (f, flow_list_node, dp_ftable->old_lflows) {
        ovn_flow_clear_actions(f);
        ovn_flow_prepare_ofmsg(f, msgs);
        hmap_remove(f->match_flow_table, &f->hmap_node);
        hmapx_find_and_delete(&dp_ftable->modified_lflows, f);
        ovn_flow_destroy(f);
    }

    LIST_FOR_EACH_POP (f, flow_list_node, dp_ftable->old_pflows) {
        ovn_flow_clear_actions(f);
        ovn_flow_prepare_ofmsg(f, msgs);
        hmap_remove(f->match_flow_table, &f->hmap_node);
        hmapx_find_and_delete(&dp_ftable->modified_pflows, f);
        ovn_flow_destroy(f);
    }

    struct hmapx_node *node;
    HMAPX_FOR_EACH (node, &dp_ftable->modified_lflows) {
        f = node->data;
        ovn_flow_handle_modified(f, msgs);
    }

    hmapx_clear(&dp_ftable->modified_lflows);

    HMAPX_FOR_EACH (node, &dp_ftable->modified_pflows) {
        f = node->data;
        ovn_flow_handle_modified(f, msgs);
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

#if 0
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

#endif
