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


#ifndef OVN_LIB_LB_H
#define OVN_LIB_LB_H 1

#include "openvswitch/hmap.h"

struct nbrec_load_balancer;
struct sbrec_load_balancer;
struct ovn_port;
struct uuid;

struct ovn_lb {
    struct hmap_node hmap_node;

    bool nb_lb; /* NB load balancer or SB load balancer. */
    union {
        struct {
            const struct nbrec_load_balancer *nlb; /* May be NULL. */
            char *selection_fields;
        };
        const struct sbrec_load_balancer *slb; /* May be NULL. */
    };

    struct lb_vip *vips;
    size_t n_vips;
};

struct lb_vip {
    char *vip;
    uint16_t vip_port;
    int addr_family;
    char *vip_port_str;

    /* Backend information. */
    char *backend_ips;
    struct lb_vip_backend *backends;
    size_t n_backends;

    /* Valid only for NB load balancer. */
    struct nbrec_load_balancer_health_check *lb_health_check;
};

struct lb_vip_backend {
    char *ip;
    uint16_t port;
    int addr_family;

    /* Valid only for NB load balancer. */
    struct ovn_port *op; /* Logical port to which the ip belong to. */
    bool health_check;
    char *svc_mon_src_ip; /* Source IP to use for monitoring. */
    const struct sbrec_service_monitor *sbrec_monitor;
};

struct ovn_lb *ovn_nb_lb_create(
    const struct nbrec_load_balancer *nbrec_lb,
    struct hmap *ports, struct hmap *lbs,
    void * (*ovn_port_find)(const struct hmap *ports, const char *name));
struct ovn_lb *ovn_sb_lb_create(const struct sbrec_load_balancer *sbrec_lb);
struct ovn_lb * ovn_lb_find(struct hmap *lbs, struct uuid *uuid);
void ovn_lb_destroy(struct ovn_lb *lb);
void ovn_lbs_destroy(struct hmap *lbs);

#endif /* OVN_LIB_LB_H 1 */
