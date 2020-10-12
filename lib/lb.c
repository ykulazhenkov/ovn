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

#include "lb.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"

/* OpenvSwitch lib includes. */
#include "openvswitch/vlog.h"
#include "lib/smap.h"

VLOG_DEFINE_THIS_MODULE(lb);

static struct ovn_northd_lb *
ovn_northd_lb_create_(const struct smap *vips)
{
    struct ovn_northd_lb *lb = xzalloc(sizeof *lb);

    lb->n_vips = smap_count(vips);
    lb->vips = xcalloc(lb->n_vips, sizeof *lb->vips);
    struct smap_node *node;
    size_t n_vips = 0;

    SMAP_FOR_EACH (node, vips) {
        char *vip;
        uint16_t port;
        int addr_family;

        if (!ip_address_and_port_from_lb_key(node->key, &vip, &port,
                                             &addr_family)) {
            continue;
        }

        lb->vips[n_vips].vip = vip;
        lb->vips[n_vips].vip_port = port;
        lb->vips[n_vips].addr_family = addr_family;
        lb->vips[n_vips].vip_port_str = xstrdup(node->key);
        lb->vips[n_vips].backend_ips = xstrdup(node->value);

        char *tokstr = xstrdup(node->value);
        char *save_ptr = NULL;
        char *token;
        size_t n_backends = 0;
        /* Format for a backend ips : IP1:port1,IP2:port2,...". */
        for (token = strtok_r(tokstr, ",", &save_ptr);
            token != NULL;
            token = strtok_r(NULL, ",", &save_ptr)) {
            n_backends++;
        }

        free(tokstr);
        tokstr = xstrdup(node->value);
        save_ptr = NULL;

        lb->vips[n_vips].n_backends = n_backends;
        lb->vips[n_vips].backends = xcalloc(n_backends,
                                            sizeof *lb->vips[n_vips].backends);
        n_backends = 0;
        for (token = strtok_r(tokstr, ",", &save_ptr);
            token != NULL;
            token = strtok_r(NULL, ",", &save_ptr)) {
            char *backend_ip;
            uint16_t backend_port;
            int backend_addr_family;
            if (!ip_address_and_port_from_lb_key(token, &backend_ip,
                                                 &backend_port,
                                                 &backend_addr_family)) {
                continue;
            }

            if (addr_family != backend_addr_family) {
                continue;
            }

            lb->vips[n_vips].backends[n_backends].ip = backend_ip;
            lb->vips[n_vips].backends[n_backends].port = backend_port;
            lb->vips[n_vips].backends[n_backends].addr_family = addr_family;
            n_backends++;
        }

        lb->vips[n_vips].n_backends = n_backends;
        free(tokstr);
        n_vips++;
    }

    /* Its possible that ip_address_and_port_from_lb_key() may fail.
     * Update the lb->n_vips to the correct value. */
    lb->n_vips = n_vips;
    return lb;
}

struct ovn_northd_lb *
ovn_northd_lb_create(const struct nbrec_load_balancer *nbrec_lb,
                     struct hmap *ports, struct hmap *lbs,
                     void * (*ovn_port_find)(const struct hmap *ports,
                                         const char *name))
{
    struct ovn_northd_lb *lb = ovn_northd_lb_create_(&nbrec_lb->vips);
    hmap_insert(lbs, &lb->hmap_node, uuid_hash(&nbrec_lb->header_.uuid));
    lb->nlb = nbrec_lb;

    for (size_t i = 0; i < lb->n_vips; i++) {
        struct ovn_northd_lb_vip *lb_vip = &lb->vips[i];

        struct nbrec_load_balancer_health_check *lb_health_check = NULL;
        if (nbrec_lb->protocol && !strcmp(nbrec_lb->protocol, "sctp")) {
            if (nbrec_lb->n_health_check > 0) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl,
                             "SCTP load balancers do not currently support "
                             "health checks. Not creating health checks for "
                             "load balancer " UUID_FMT,
                             UUID_ARGS(&nbrec_lb->header_.uuid));
            }
        } else {
            for (size_t j = 0; j < nbrec_lb->n_health_check; j++) {
                if (!strcmp(nbrec_lb->health_check[j]->vip,
                            lb_vip->vip_port_str)) {
                    lb_health_check = nbrec_lb->health_check[i];
                    break;
                }
            }
        }

        lb_vip->lb_health_check = lb_health_check;

        for (size_t j = 0; j < lb_vip->n_backends; j++) {
            struct ovn_northd_lb_vip_backend *backend = &lb_vip->backends[j];

            struct ovn_port *op = NULL;
            char *svc_mon_src_ip = NULL;
            const char *s = smap_get(&nbrec_lb->ip_port_mappings,
                                     backend->ip);
            if (s) {
                char *port_name = xstrdup(s);
                char *p = strstr(port_name, ":");
                if (p) {
                    *p = 0;
                    p++;
                    op = ovn_port_find(ports, port_name);
                    svc_mon_src_ip = xstrdup(p);
                }
                free(port_name);
            }

            backend->op = op;
            backend->svc_mon_src_ip = svc_mon_src_ip;
        }
    }

    if (nbrec_lb->n_selection_fields) {
        char *proto = NULL;
        if (nbrec_lb->protocol && nbrec_lb->protocol[0]) {
            proto = nbrec_lb->protocol;
        }

        struct ds sel_fields = DS_EMPTY_INITIALIZER;
        for (size_t i = 0; i < lb->nlb->n_selection_fields; i++) {
            char *field = lb->nlb->selection_fields[i];
            if (!strcmp(field, "tp_src") && proto) {
                ds_put_format(&sel_fields, "%s_src,", proto);
            } else if (!strcmp(field, "tp_dst") && proto) {
                ds_put_format(&sel_fields, "%s_dst,", proto);
            } else {
                ds_put_format(&sel_fields, "%s,", field);
            }
        }
        ds_chomp(&sel_fields, ',');
        lb->selection_fields = ds_steal_cstr(&sel_fields);
    }

    return lb;
}

struct ovn_northd_lb *
ovn_northd_lb_find(struct hmap *lbs, const struct uuid *uuid)
{
    struct ovn_northd_lb *lb;
    size_t hash = uuid_hash(uuid);
    HMAP_FOR_EACH_WITH_HASH (lb, hmap_node, hash, lbs) {
        if (uuid_equals(&lb->nlb->header_.uuid, uuid)) {
            return lb;
        }
    }

    return NULL;
}

void
ovn_northd_lb_add_datapath(struct ovn_northd_lb *lb,
                           const struct sbrec_datapath_binding *sb)
{
    if (lb->n_allocated_dps == lb->n_dps) {
        lb->dps = x2nrealloc(lb->dps, &lb->n_allocated_dps, sizeof *lb->dps);
    }
    lb->dps[lb->n_dps++] = sb;
}

void
ovn_northd_lb_destroy(struct ovn_northd_lb *lb)
{
    for (size_t i = 0; i < lb->n_vips; i++) {
        free(lb->vips[i].vip);
        free(lb->vips[i].backend_ips);
        free(lb->vips[i].vip_port_str);

        for (size_t j = 0; j < lb->vips[i].n_backends; j++) {
            free(lb->vips[i].backends[j].ip);
            free(lb->vips[i].backends[j].svc_mon_src_ip);
        }

        free(lb->vips[i].backends);
    }
    free(lb->vips);
    free(lb->selection_fields);
    free(lb->dps);
    free(lb);
}

void
ovn_northd_lbs_destroy(struct hmap *lbs)
{
    struct ovn_northd_lb *lb;
    HMAP_FOR_EACH_POP (lb, hmap_node, lbs) {
        ovn_northd_lb_destroy(lb);
    }
    hmap_destroy(lbs);
}

struct ovn_controller_lb *
ovn_controller_lb_create(const struct sbrec_load_balancer *sbrec_lb)
{
    struct ovn_controller_lb *lb = xzalloc(sizeof *lb);

    lb->slb = sbrec_lb;
    lb->n_vips = smap_count(&sbrec_lb->vips);
    lb->vips = xcalloc(lb->n_vips, sizeof *lb->vips);

    struct smap_node *node;
    size_t n_vips = 0;

    SMAP_FOR_EACH (node, &sbrec_lb->vips) {
        char *vip;
        uint16_t port;
        int addr_family;

        if (!ip_address_and_port_from_lb_key(node->key, &vip, &port,
                                             &addr_family)) {
            continue;
        }

        if (addr_family == AF_INET) {
            ovs_be32 vip4;
            ip_parse(vip, &vip4);
            in6_addr_set_mapped_ipv4(&lb->vips[n_vips].vip, vip4);
        } else {
            ipv6_parse(vip, &lb->vips[n_vips].vip);
        }

        lb->vips[n_vips].vip_port = port;
        lb->vips[n_vips].addr_family = addr_family;

        char *tokstr = xstrdup(node->value);
        char *save_ptr = NULL;
        char *token;
        size_t n_backends = 0;
        /* Format for a backend ips : IP1:port1,IP2:port2,...". */
        for (token = strtok_r(tokstr, ",", &save_ptr);
            token != NULL;
            token = strtok_r(NULL, ",", &save_ptr)) {
            n_backends++;
        }

        free(tokstr);
        tokstr = xstrdup(node->value);
        save_ptr = NULL;

        lb->vips[n_vips].n_backends = n_backends;
        lb->vips[n_vips].backends = xcalloc(n_backends,
                                            sizeof *lb->vips[n_vips].backends);
        n_backends = 0;
        for (token = strtok_r(tokstr, ",", &save_ptr);
            token != NULL;
            token = strtok_r(NULL, ",", &save_ptr)) {
            char *backend_ip;
            uint16_t backend_port;
            int backend_addr_family;

            if (!ip_address_and_port_from_lb_key(token, &backend_ip,
                                                 &backend_port,
                                                 &backend_addr_family)) {
                continue;
            }

            if (addr_family != backend_addr_family) {
                continue;
            }

            if (addr_family == AF_INET) {
                ovs_be32 ip4;
                ip_parse(backend_ip, &ip4);
                in6_addr_set_mapped_ipv4(
                    &lb->vips[n_vips].backends[n_backends].ip, ip4);
            } else {
                ipv6_parse(backend_ip,
                           &lb->vips[n_vips].backends[n_backends].ip);
            }

            lb->vips[n_vips].backends[n_backends].port = backend_port;
            lb->vips[n_vips].backends[n_backends].addr_family = addr_family;
            n_backends++;
        }

        lb->vips[n_vips].n_backends = n_backends;
        free(tokstr);
        n_vips++;
    }

    /* Its possible that ip_address_and_port_from_lb_key() may fail.
     * Update the lb->n_vips to the correct value. */
    lb->n_vips = n_vips;
    return lb;
}

void
ovn_controller_lb_destroy(struct ovn_controller_lb *lb)
{
    for (size_t i = 0; i < lb->n_vips; i++) {
        free(lb->vips[i].backends);
    }
    free(lb->vips);
    free(lb);
}
