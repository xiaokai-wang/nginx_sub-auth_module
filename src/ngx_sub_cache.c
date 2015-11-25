#include "ngx_http_oauth_service_module.h"


#define CHECK_TIMEOUT  3 * 1000

static void *ngx_http_memcache_get_peer(void *data, ngx_int_t flag);

static ngx_int_t ngx_http_memcache_get_keepalive_peer(ngx_http_oauth_keepalive_peer_data_t *mkp);

static void ngx_http_memcache_send_handler(ngx_event_t *event);
static void ngx_http_memcache_recv_handler(ngx_event_t *event);
static void ngx_http_memcache_parse_value(ngx_http_request_t *r);
static void ngx_http_memcache_free_keepalive_peer(ngx_http_oauth_keepalive_peer_data_t *mkp);
static void ngx_http_memcache_keepalive_close_handler(ngx_event_t *ev);
static void ngx_http_memcache_check_timeout_handler(ngx_event_t *event);
static void ngx_http_memcache_clear_event(ngx_http_oauth_keepalive_peer_data_t *mkp);

static void ngx_http_memcache_add_check_timer(ngx_http_memcache_peer_t *memcache_peer);
static void ngx_http_check_memcache_send(ngx_event_t *event);
static void ngx_http_check_memcache_recv(ngx_event_t *event);

static ngx_int_t ngx_http_oauth_service_memcached_parse(ngx_http_request_t *r, u_char *data);


ngx_uint_t ngx_http_oauth_check_shm_generation = 0;


ngx_int_t
ngx_http_memcache_peers_init_process(ngx_cycle_t *cycle)
{
    ngx_uint_t                             i;
    ngx_http_memcache_peer_t              *memcache_peer;
    ngx_http_memcache_peers_t             *memcache_peers;
    ngx_http_oauth_service_main_conf_t    *osmcf;

    osmcf = sub_ctx;

    ngx_log_debug0(NGX_LOG_DEBUG, cycle->log, 0,
                   " oauth service memcache_peers init process ");

    memcache_peers = osmcf->memcache_peers;
    memcache_peer  = memcache_peers->peers;

    for (i = 0; i < memcache_peers->count; i++) {
        memcache_peer[i].check_ev.handler = ngx_http_memcache_check_handler;
        memcache_peer[i].check_ev.log = cycle->log;
        memcache_peer[i].check_ev.data = &memcache_peer[i];
        memcache_peer[i].check_ev.timer_set = 0;

        memcache_peer[i].check_timeout_ev.handler = ngx_http_check_memcache_timeout;
        memcache_peer[i].check_timeout_ev.log = cycle->log;
        memcache_peer[i].check_timeout_ev.data = &memcache_peer[i];
        memcache_peer[i].check_timeout_ev.timer_set = 0;

        ngx_memzero(&memcache_peer[i].pc, sizeof(ngx_peer_connection_t));

        memcache_peer[i].pc.sockaddr = (struct sockaddr *)memcache_peer[i].sockaddr;
        memcache_peer[i].pc.socklen = memcache_peer[i].socklen;
        memcache_peer[i].pc.name = ngx_pcalloc(cycle->pool, sizeof(ngx_str_t));
        memcache_peer[i].pc.name->data = memcache_peer[i].name;
        memcache_peer[i].pc.name->len = ngx_strlen(memcache_peer[i].name);

        memcache_peer[i].pc.get = ngx_event_get_peer;
        memcache_peer[i].pc.log = cycle->log;
        memcache_peer[i].pc.log_error = NGX_ERROR_ERR;

        memcache_peer[i].pc.cached = 0;
        memcache_peer[i].pc.connection = NULL;

    }

    return NGX_OK;
}


void *
ngx_http_memcache_peers_init(ngx_conf_t *cf, void *conf)
{
    ngx_url_t                                   u;
    ngx_uint_t                                  i, j, n;
    ngx_http_memcache_peer_t                   *memcache_peer;
    ngx_http_memcache_peers_t                  *memcache_peers;
    ngx_http_oauth_service_main_conf_t         *osmcf = conf;
    ngx_http_oauth_service_keepalive_cache_t   *cached;

    memcache_peers = osmcf->memcache_peers;

    u.host = osmcf->memcache_host;
    u.port = (in_port_t)osmcf->memcache_port;

    memcache_peers->peers = ngx_pcalloc(cf->pool, 5 * sizeof(ngx_http_memcache_peer_t));
    if (memcache_peers->peers == NULL) {
        return NGX_CONF_ERROR;
    }
    memcache_peer = memcache_peers->peers;

    for (i = 0; i < 5; i++) {
        ngx_queue_init(&memcache_peer[i].free);
        ngx_queue_init(&memcache_peer[i].cache);

        cached = ngx_pcalloc(cf->pool,
                sizeof(ngx_http_oauth_service_keepalive_cache_t) * osmcf->memcache_keepalive);

        if (cached == NULL) {
            return NGX_CONF_ERROR;
        }
        for (j = 0; j < osmcf->memcache_keepalive; j++) {
            cached[j].connection = NULL;
        }

        for (j = 0; j < osmcf->memcache_keepalive; j++) {
            cached[j].data = &memcache_peer[i];
            ngx_queue_insert_head(&memcache_peer[i].free, &cached[j].queue);
        }
    }

    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                          "%s in upstream \"%s\" ", u.err, u.host.data);
        }

        return NGX_CONF_ERROR;
    }

    n = u.naddrs;
    memcache_peers->count = n;
    memcache_peers->updating_times = 0;

    for (i = 0; i < n; i++) {
        ngx_memcpy(&memcache_peer[i].sockaddr, u.addrs[i].sockaddr, u.addrs[i].socklen);

        memcache_peer[i].socklen     = u.addrs[i].socklen;

        ngx_memcpy(&memcache_peer[i].name, u.addrs[i].name.data, u.addrs[i].name.len);

        memcache_peer[i].current_weight = 0;
        memcache_peer[i].effective_weight = 1;
        memcache_peer[i].weight = 1;

        memcache_peer[i].down = 0;
        memcache_peer[i].check_times = 0;

        memcache_peer[i].check_interval = osmcf->check_interval;
        memcache_peer[i].check_up_times = osmcf->check_times;

        memcache_peer[i].free_connection = 0;
        memcache_peer[i].using_connection = 0;
    }

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_memcache_connect_handler(ngx_http_oauth_keepalive_peer_data_t *mkp)
{
    ngx_int_t                               rc;
    ngx_connection_t                       *c;
    ngx_http_request_t                     *r;
    ngx_peer_connection_t                  *pc;
    ngx_http_memcache_peer_t               *memcache_peer;
    ngx_http_memcache_peers_t              *memcache_peers;
    ngx_http_oauth_service_main_conf_t     *omcf;

    r = mkp->request;
    pc = &mkp->pc;

    omcf = ngx_http_get_module_main_conf(r, ngx_http_oauth_service_module);

    memcache_peers = omcf->memcache_peers;

    if (mkp->state == NGX_TCP_CONNECT_DONE) {
        return NGX_OK;
    }

    if (memcache_peers->count == 1) {
        memcache_peer = &memcache_peers->peers[0];

    } else {
        memcache_peer = ngx_http_memcache_get_peer(memcache_peers, 0);
    }

    if (memcache_peer == NULL) {
        return NGX_ERROR;
    }

    mkp->pc.sockaddr = (struct sockaddr *)memcache_peer->sockaddr;
    mkp->pc.socklen = memcache_peer->socklen;
    mkp->pc.name = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    mkp->pc.name->data = memcache_peer->name;
    mkp->pc.name->len = ngx_strlen(memcache_peer->name);

    mkp->check_timeout_ev.handler = ngx_http_memcache_check_timeout_handler;
    mkp->check_timeout_ev.log = r->pool->log;
    mkp->check_timeout_ev.timer_set = 0;

    mkp->conf = memcache_peer;

    if (ngx_http_memcache_get_keepalive_peer(mkp) == NGX_OK) {
        mkp->check_timeout_ev.data = mkp->pc.connection;

        c = mkp->pc.connection;
        c->data = mkp;
        c->write->handler = ngx_http_memcache_send_handler;
        c->read->handler = ngx_http_memcache_recv_handler;

        ngx_add_timer(&mkp->check_timeout_ev, omcf->memcache_timeout);
        c->write->handler(c->write);

        return NGX_OK;
    }

    rc = ngx_event_connect_peer(pc);

    if (rc == NGX_ERROR || rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                        "memcache_connect cannt connet to %*s", NAME_LEN, memcache_peer->name);

        pc->connection = NULL;
        memcache_peer->down = 1;
        ngx_add_timer(&memcache_peer->check_ev, memcache_peer->check_interval);

        return NGX_ERROR;
    }

    if (rc == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                        "memcache_connect busy connet to %*s", NAME_LEN, memcache_peer->name);
        pc->connection = NULL;
        return NGX_ERROR;
    }

    mkp->check_timeout_ev.data = pc->connection;

    /* NGX_OK or NGX_AGAIN */
    c = pc->connection;
    c->data = mkp;
    c->log = pc->log;
    c->sendfile = 0;
    c->read->log = c->log;
    c->write->log = c->log;
    c->pool = NULL;

    mkp->pc.connection = c;

    c->write->handler = ngx_http_memcache_send_handler;
    c->read->handler = ngx_http_memcache_recv_handler;

    mkp->state = NGX_TCP_CONNECT_DONE;

    ngx_add_timer(&mkp->check_timeout_ev, omcf->memcache_timeout);

    if (rc == NGX_OK) {
        c->write->handler(c->write);
    }

    return NGX_OK;
}


static void *
ngx_http_memcache_get_peer(void *data, ngx_int_t flag)
{
    ngx_int_t                     total = 0;
    ngx_uint_t                    i;
    ngx_http_memcache_peer_t     *peer = NULL, *best = NULL;
    ngx_http_memcache_peers_t    *memcache_peers = data;

    for (i = 0; i < memcache_peers->count; i++) {

        peer = &memcache_peers->peers[i];

        if (peer->down) {
            continue;
        }

        peer->current_weight += peer->effective_weight;
        total += peer->effective_weight;

        if (peer->effective_weight < peer->weight) {
            peer->effective_weight++;
        }

        if (best == NULL || peer->current_weight > best->current_weight) {
            best = peer;
        }
    }

    if (best == NULL) {
        return NULL;
    }

    best->current_weight -= total;

    return best;
}


static ngx_int_t
ngx_http_memcache_get_keepalive_peer(ngx_http_oauth_keepalive_peer_data_t *mkp)
{
    ngx_http_memcache_peer_t                      *memcache_peer;
    ngx_http_oauth_service_keepalive_cache_t      *item;

    ngx_queue_t       *q, *cache;
    ngx_connection_t  *c;

    memcache_peer = mkp->conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mkp->pc.log, 0,
                   "oauth memcache get keepalive peer");

    /* search cache for suitable connection */

    cache = &memcache_peer->cache;

    for (q = ngx_queue_head(cache);
        q != ngx_queue_sentinel(cache);
        q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_oauth_service_keepalive_cache_t, queue);
        c = item->connection;

        if (ngx_memn2cmp((u_char *) &item->sockaddr, (u_char *) mkp->pc.sockaddr,
                         item->socklen, mkp->pc.socklen) == 0)
        {
            ngx_queue_remove(q);
            ngx_queue_insert_head(&memcache_peer->free, q);

            if (c == NULL) {
                continue;
            }

            if (ngx_http_oauth_service_test_connect(c) != NGX_OK) {
                ngx_close_connection(c);
                item->connection = NULL;

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mkp->pc.log, 0, "memcache_get_keepalive_closed");

                if (memcache_peer->free_connection != 0) {
                    memcache_peer->free_connection--;
                }
                continue;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mkp->pc.log, 0,
                           "memcache get keepalive peer: using connection %p", c);

            c->idle = 0;
            c->log = mkp->pc.log;
            c->read->log = mkp->pc.log;
            c->write->log = mkp->pc.log;

            mkp->pc.connection = c;
            mkp->pc.cached = 1;

            item->data = memcache_peer;

            memcache_peer->using_connection++;
            if (memcache_peer->free_connection != 0) {
                memcache_peer->free_connection--;
            }

            return NGX_OK;
        } else {
            ngx_queue_remove(q);
            ngx_queue_insert_head(&memcache_peer->free, q);

            ngx_log_debug0(NGX_LOG_DEBUG, mkp->pc.log, 0,
                        "memcache get keepalive peer, item->sockaddr differ mkp->pc.sockaddr");

            if (c) {
                ngx_close_connection(c);
                item->connection = NULL;
            }
            return NGX_ERROR;
        }
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_http_memcache_make_key(ngx_http_request_t *r, u_char *data)
{
    u_char                                *temp = data;
    ngx_int_t                              len;
    ngx_http_oauth_service_ctx_t          *ctx;

    if (data == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_service_module);

    ctx->ctime.len = 4;
    ctx->ctime.data = ngx_palloc(r->pool, 4);
    if (ctx->ctime.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(ctx->ctime.data, temp, ctx->ctime.len);
    temp += 7;
    if (temp == NULL) {
        return NGX_ERROR;
    }

    ctx->uid.len = *temp & 0xff;
    ctx->uid.data = ngx_palloc(r->pool, ctx->uid.len);
    if (ctx->uid.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(ctx->uid.data, temp + 1, ctx->uid.len);
    temp = temp + ctx->uid.len + 1;
    if (temp == NULL) {
        return NGX_ERROR;
    }

    len = *temp & 0xff;     //login name
    temp = temp + len + 1;
    if (temp == NULL) {
        return NGX_ERROR;
    }

    len = *temp & 0xff;     //source from
    temp = temp + len + 1;
    if (temp == NULL) {
        return NGX_ERROR;
    }

    len = *temp & 0xff;     //expire time
    temp = temp + len + 1;
    if (temp == NULL) {
        return NGX_ERROR;
    }

    ctx->domain.len = *temp & 0xff;
    ctx->domain.data = ngx_palloc(r->pool, ctx->domain.len);
    if (ctx->domain.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(ctx->domain.data, temp + 1, ctx->domain.len);
    temp = temp + ctx->domain.len + 1;
    if (temp == NULL) {
        return NGX_ERROR;
    }

    len = *temp & 0xff;     //save state
    temp = temp + len + 1;
    if (temp == NULL) {
        return NGX_ERROR;
    }

    len = *temp & 0xff;     //login type
    temp = temp + len + 1;
    if (temp == NULL) {
        return NGX_ERROR;
    }

    temp += 2;                 //idc
    if (temp == NULL) {
        return NGX_ERROR;
    }

    ctx->rand.len = *temp & 0xff;
    ctx->rand.data = ngx_palloc(r->pool, ctx->rand.len);
    if (ctx->rand.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(ctx->rand.data, temp + 1, ctx->rand.len);

    return NGX_OK;
}


static void
ngx_http_memcache_send_handler(ngx_event_t *event)
{
    u_char                                    *data;
    ssize_t                                    temp_send = 0, send_num = 0, len;
    ngx_int_t                                  tcp_nodelay;
    ngx_connection_t                          *c;
    ngx_http_request_t                        *r;
    ngx_http_core_loc_conf_t                  *clcf;
    ngx_http_memcache_peer_t                  *memcache_peer;
    ngx_http_oauth_service_ctx_t              *ctx;
    ngx_http_oauth_keepalive_peer_data_t      *mkp;

    c = event->data;
    mkp = c->data;
    r = mkp->request;
    memcache_peer = mkp->conf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (mkp->state == NGX_TCP_SEND_DONE) {
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_service_module);

    if (ngx_http_oauth_service_need_exit()) {
        return;
    }

    if (clcf->tcp_nodelay && c->tcp_nodelay == NGX_TCP_NODELAY_UNSET) {

        tcp_nodelay = 1;
        if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
                               (const void *) &tcp_nodelay, sizeof(int)) == -1)
        {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "setsockopt(TCP_NODELAY) failed");
            goto memcache_send_fail;
        }
        c->tcp_nodelay = NGX_TCP_NODELAY_SET;

    }

    len = ctx->memcache_key.len + ngx_strlen("get \r\n");
    data = ngx_pcalloc(r->pool, len + 1);
    ngx_sprintf(data, "get %V\r\n", &ctx->memcache_key);
    *(data + len) = '\0';

    ngx_log_debug2(NGX_LOG_DEBUG, c->log, 0, "auth for memcache_send data: %*s", len, data);

    while (send_num < len) {

        temp_send = c->send(c, data + temp_send, len - send_num);

#if (NGX_DEBUG)
        {
        ngx_err_t  err;

        err = (temp_send >=0) ? 0 : ngx_socket_errno;
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, err,
                       "oauth memcache send size: %z, total: %z",
                       temp_send, len);

        if (temp_send > 0) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, err,
                        "oauth memcache send content: %*s ", temp_send, data);
        }
        }
#endif

        if (temp_send > 0) {
            send_num += temp_send;

        } else if (temp_send == 0 || temp_send == NGX_AGAIN) {
            return;

        } else {
            c->error = 1;
            goto memcache_send_fail;
        }
    }

    mkp->state = NGX_TCP_SEND_DONE;

    if (send_num == len) {
        c->write->handler = ngx_http_oauth_service_keepalive_dummy_handler;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "oauth memcache send done.");
    }

    return;

memcache_send_fail:

    ngx_http_memcache_add_check_timer(memcache_peer);
    ngx_http_memcache_clear_event(mkp);
}


static void
ngx_http_memcache_recv_handler(ngx_event_t *event)
{
    u_char                                     new_buf[512] = {'\0'};
    u_char                                    *data, *p;
    ssize_t                                    size = 0, len;
    ngx_int_t                                  rc;
    ngx_connection_t                          *c;
    ngx_http_request_t                        *r;
    ngx_http_memcache_peer_t                  *memcache_peer;
    ngx_http_oauth_service_ctx_t              *ctx;
    ngx_http_oauth_keepalive_peer_data_t   *mkp;

    c = event->data;
    mkp = c->data;
    r = mkp->request;
    memcache_peer = mkp->conf;

    if (mkp->state == NGX_TCP_RECV_DONE) {
        ngx_http_memcache_clear_event(mkp);

        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_service_module);

    ctx->memcache_content.len = 0;

    if (ngx_http_oauth_service_need_exit()) {
        return;
    }

    data = new_buf;

    while (1) {

        size = c->recv(c, data, 512 - size);

#if (NGX_DEBUG)
        {
        ngx_err_t  err;

        err = (size >= 0) ? 0 : ngx_socket_errno;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, err,
                       "oauth memcache recv size: %z ", size);

        if (size > 0) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, err,
                       "oauth memcache recv content: %*s ", size, data);
        }
        }
#endif

        if (size > 0) {
            data += size;
            continue;
        } else if (size == 0 || size == NGX_AGAIN) {
            break;
        } else {
            c->error = 1;
            goto memcache_recv_fail;
        }
    }

    len = data - new_buf;

    if (size == 0) {
        c->close = 1;
    }

    if (len != 0) {
        p = new_buf;
        rc = ngx_http_oauth_service_memcached_parse(r, p);
        if (rc == NGX_AGAIN) {
            return;
        }
        if (rc == NGX_ERROR) {
            goto memcache_recv_fail;
        }
        if (rc == MEMCACHE_NOT_FOUND) {
            ctx->memcache_flag = 1;

        } else {

            ngx_http_memcache_parse_value(r);
        }
    }

    mkp->state = NGX_TCP_RECV_DONE;

    ngx_http_memcache_clear_event(mkp);
    return;

memcache_recv_fail:

    ngx_http_memcache_add_check_timer(memcache_peer);
    ngx_http_memcache_clear_event(mkp);
}


static void
ngx_http_memcache_parse_value(ngx_http_request_t *r)
{
    u_char                               *data;
    ngx_int_t                             len, version;
    ngx_int_t                             index, i, value_len = 0;
    ngx_uint_t                            etime = 0;
    ngx_http_oauth_service_ctx_t         *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_service_module);

    ctx->etime = 0;
    len = (ngx_int_t)ctx->memcache_content.len;
    data = ctx->memcache_content.data;

    if (ctx->memcache_content.len == 0) {
        return;
    }

    if (data != NULL) {           //version and create time
        data = data + 5;
    }

    version = *data++ & 0xff;
    if (version != 1) {
        return;
    }

    while(len > 0) {

        index = *data++ & 0xff;
        if (index > INDEX_NUM) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                "memcache_parse_value index:%d excceed", index);
            break;
        }

        if(index != 7) {

            if (data != NULL) {           //serach etime

                value_len = *data++ & 0xff;
                if (value_len > len) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                "memcache_parse_value value_len:%d too big", value_len);
                    break;
                }
                data = data + value_len;

                len = len - value_len;

            } else {
                break;
            }

            continue;

        } else {

            value_len = *data++ & 0xff;
            for(i = value_len; i != 0; i--) {
                etime |= (data[i-1] << (value_len - i) * 8) & (0xff << (value_len - i) * 8);
            }

            ctx->etime = etime;

            break;
        }
    }

    return;
}


static void
ngx_http_memcache_free_keepalive_peer(ngx_http_oauth_keepalive_peer_data_t *mkp)
{
    ngx_http_memcache_peer_t                      *memcache_peer;
    ngx_http_oauth_service_keepalive_cache_t      *item;

    ngx_queue_t          *q;
    ngx_connection_t     *c;

    memcache_peer = mkp->conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mkp->pc.log, 0,
                   "memcache free keepalive peer");

    /* cache valid connections */

    c = mkp->pc.connection;

    if (c == NULL) {
        goto invalid;
    }

    if (c->error == 1 || c->close == 1) {
        goto invalid;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mkp->pc.log, 0,
                   "free keepalive peer: saving connection %p", c);

    if (ngx_queue_empty(&memcache_peer->free)) {

        q = ngx_queue_last(&memcache_peer->cache);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_oauth_service_keepalive_cache_t, queue);

        ngx_http_oauth_service_keepalive_close(item->connection);

    } else {
        q = ngx_queue_head(&memcache_peer->free);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_oauth_service_keepalive_cache_t, queue);

        memcache_peer->free_connection++;
        if (memcache_peer->using_connection != 0) {
            memcache_peer->using_connection--;
        }
    }

    item->connection = c;
    ngx_queue_insert_head(&memcache_peer->cache, q);

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    mkp->pc.connection = NULL;

    c->data = item;
    c->idle = 1;
    c->log = ngx_cycle->log;
    c->read->log = ngx_cycle->log;
    c->write->log = ngx_cycle->log;

    c->write->handler = ngx_http_oauth_service_keepalive_dummy_handler;
    c->read->handler = ngx_http_memcache_keepalive_close_handler;

    item->socklen = mkp->pc.socklen;
    ngx_memcpy(&item->sockaddr, mkp->pc.sockaddr, mkp->pc.socklen);

    if (c->read->ready) {
        ngx_http_memcache_keepalive_close_handler(c->read);
    }

    return;

invalid:

    ngx_http_oauth_service_keepalive_close(c);
}


static void
ngx_http_memcache_keepalive_close_handler(ngx_event_t *event)
{
    ngx_http_memcache_peer_t                       *memcache_peer;
    ngx_http_oauth_service_keepalive_cache_t       *item;


    int                n;
    char               buf[1];
    ngx_connection_t  *c;

    c = event->data;
    item = c->data;
    memcache_peer = item->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "memcache keepalive close handler");

    if (c->close) {
        goto close;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        /* stale event */

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto close;
        }

        return;
    }

close:

    item = c->data;

    ngx_http_oauth_service_keepalive_close(c);
    item->connection = NULL;

    ngx_queue_remove(&item->queue);
    ngx_queue_insert_head(&memcache_peer->free, &item->queue);

    if (memcache_peer->free_connection != 0) {
        memcache_peer->free_connection--;
    }
}


static void
ngx_http_memcache_check_timeout_handler(ngx_event_t *event)
{
    ngx_connection_t                            *c;
    ngx_http_memcache_peer_t                    *memcache_peer;
    ngx_http_oauth_keepalive_peer_data_t        *mkp;

    c = event->data;
    mkp = c->data;
    memcache_peer = mkp->conf;

    c->write->handler = ngx_http_oauth_service_keepalive_dummy_handler;
    c->read->handler = ngx_http_oauth_service_keepalive_dummy_handler;

    if (c) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0, 
                        "memcache server timeout: %*s", NAME_LEN, memcache_peer->name);

        ngx_close_connection(c);
        mkp->pc.connection = NULL;
    }

    if (mkp->check_timeout_ev.timer_set) {
        ngx_del_timer(&mkp->check_timeout_ev);
    }

    memcache_peer->down = 1;
    ngx_add_timer(&memcache_peer->check_ev, memcache_peer->check_interval);

    ngx_http_finalize_request_success(mkp);

    return;
}


static void
ngx_http_memcache_clear_event(ngx_http_oauth_keepalive_peer_data_t *mkp)
{
    ngx_connection_t                          *c;
    ngx_http_request_t                        *r;
    ngx_http_memcache_peer_t                  *memcache_peer;
    ngx_http_oauth_service_ctx_t              *ctx;

    r = mkp->request;
    memcache_peer = mkp->conf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_service_module);

    if (mkp->check_timeout_ev.timer_set) {
        ngx_del_timer(&mkp->check_timeout_ev);
    }

    c = mkp->pc.connection;
    if (c) {
        ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                    "clear memcache event on %*s ", NAME_LEN, memcache_peer->name);

        ngx_http_memcache_free_keepalive_peer(mkp);
    }

    if (ctx->memcache_content.len != 0) {

        if (ngx_strncmp(ctx->memcache_content.data + 5, "deleted", 7) == 0) {
            ngx_http_finalize_request_failed(mkp);

            return;

        } else if (ctx->etime != 0 && ctx->etime < (ngx_current_msec / 1000)) {
            ngx_http_finalize_request_failed(mkp);

            return;
        }

        ngx_http_finalize_request_success(mkp);

        return;

    } else if (ctx->memcache_flag) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "connect to http_server");

        mkp->state = 0;
        if (ngx_http_http_connect_handler(mkp) != NGX_OK) {
            ngx_http_finalize_request_success(mkp);

            return;
        }

    } else {
        ngx_http_finalize_request_success(mkp);
    }

    return;
}


void
ngx_http_memcache_check_handler(ngx_event_t *event)
{
    ngx_int_t                              rc;
    ngx_connection_t                      *c;
    ngx_http_memcache_peer_t              *memcache_peer;

    memcache_peer = event->data;

    if (ngx_http_oauth_service_need_exit()) {
        return;
    }

    if (memcache_peer->check_ev.timer_set) {
        ngx_del_timer(&memcache_peer->check_ev);
    }

    rc = ngx_event_connect_peer(&memcache_peer->pc);

    ngx_log_debug0(NGX_LOG_DEBUG, ngx_cycle->log, 0, "oauth_memcache_check_handler");

    if (rc == NGX_ERROR || rc == NGX_DECLINED) {
        ngx_http_memcache_add_check_timer(memcache_peer);
        return;
    }

    c = memcache_peer->pc.connection;
    c->data = memcache_peer;
    c->log = ngx_cycle->log;
    c->sendfile = 0;
    c->read->log = c->log;
    c->write->log = c->log;
    c->pool = NULL;

    c->write->handler = ngx_http_check_memcache_send;
    c->read->handler = ngx_http_check_memcache_recv;

    ngx_log_debug2(NGX_LOG_DEBUG, ngx_cycle->log, 0, 
        "check memcache server %*s again", NAME_LEN, memcache_peer->name);

    ngx_add_timer(&memcache_peer->check_timeout_ev, CHECK_TIMEOUT);

    if (rc == NGX_OK) {
        c->write->handler(c->write);
    }

    return;
}


static void
ngx_http_memcache_add_check_timer(ngx_http_memcache_peer_t *memcache_peer)
{
    ngx_msec_t                              t;
    ngx_connection_t                       *c;

    c = memcache_peer->pc.connection;
    memcache_peer->down = 1;
    memcache_peer->check_times += 1;

    if (memcache_peer->check_times <= memcache_peer->check_up_times) {
        t = memcache_peer->check_times * 3 * 1000;

    } else {
        t = memcache_peer->check_interval;
    }

    if (memcache_peer->check_timeout_ev.timer_set) {
        ngx_del_timer(&memcache_peer->check_timeout_ev);
    }

    if (c) {
        ngx_close_connection(c);
        memcache_peer->pc.connection = NULL;
    }

    ngx_log_debug4(NGX_LOG_DEBUG, ngx_cycle->log, 0, 
                "memcache_add_checktimer:%*s, check_times:%d, cost:%M", 
                NAME_LEN, memcache_peer->name, memcache_peer->check_times, t);

    ngx_add_timer(&memcache_peer->check_ev, t);
}


static void
ngx_http_check_memcache_send(ngx_event_t *event)
{
    u_char                                  data[8];
    ssize_t                                 temp_send = 0, send_num = 0, len;
    ngx_connection_t                       *c;
    ngx_http_memcache_peer_t               *memcache_peer;

    c = event->data;
    memcache_peer = c->data;

    if (ngx_http_oauth_service_need_exit()) {
        return;
    }

    len = ngx_strlen("get 1\r\n");
    ngx_sprintf(data, "get 1\r\n\0");

    ngx_log_debug2(NGX_LOG_DEBUG, c->log, 0, "check_memcache_send data: %*s", len, data);

    while (send_num < len) {

        temp_send = c->send(c, data + temp_send, len - send_num);

#if (NGX_DEBUG)
        {
        ngx_err_t  err;

        err = (temp_send >=0) ? 0 : ngx_socket_errno;
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, err,
                       "check memcache send size: %z, total: %z",
                       temp_send, len);

        if (temp_send > 0) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, err,
                        "check memcache send content: %*s ", temp_send, data);
        }
        }
#endif

        if (temp_send > 0) {
            send_num += temp_send;

        } else if (temp_send == 0 || temp_send == NGX_AGAIN) {
            return;

        } else {
            goto check_memcache_fail;
        }
    }

    if (send_num == len) {
        c->write->handler = ngx_http_oauth_service_keepalive_dummy_handler;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "check memcache send done.");
    }

    return;

check_memcache_fail:

    ngx_http_memcache_add_check_timer(memcache_peer);
}


static void
ngx_http_check_memcache_recv(ngx_event_t *event)
{
    u_char                                    *data, new_buf[10] = {'\0'};
    ssize_t                                    size = 0, len = 0;
    ngx_connection_t                          *c;
    ngx_http_memcache_peer_t                  *memcache_peer;

    c = event->data;
    memcache_peer = c->data;

    if (ngx_http_oauth_service_need_exit()) {
        return;
    }

    data = new_buf;

    while (1) {

        size = c->recv(c, data, 10 - size);

#if (NGX_DEBUG)
        {
        ngx_err_t  err;

        err = (size >= 0) ? 0 : ngx_socket_errno;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, err,
                       "oauth memcache recv size: %z ", size);

        if (size > 0) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, err,
                       "oauth memcache recv content: %*s ", size, data);
        }
        }
#endif

        if (size > 0) {
            data += size;
            continue;

        } else if (size == 0 || size == NGX_AGAIN) {
            break;

        } else {
            goto check_memcache_fail;
        }
    }

    len = data - new_buf;

    if (len >= 5 && ngx_strncmp(new_buf, "END\r\n", 5) == 0) {
        memcache_peer->down = 0;
        memcache_peer->check_times = 0;

        ngx_log_debug2(NGX_LOG_DEBUG, c->log, 0,
                       "memcache: %*s wake up (live)", NAME_LEN, memcache_peer->name);

        ngx_close_connection(c);
        memcache_peer->pc.connection = NULL;
        c->read->handler = ngx_http_oauth_service_keepalive_dummy_handler;

        if (memcache_peer->check_ev.timer_set) {
            ngx_del_timer(&memcache_peer->check_ev);
        }
    }

    if (memcache_peer->check_timeout_ev.timer_set) {
        ngx_del_timer(&memcache_peer->check_timeout_ev);
    }

    ngx_close_connection(c);
    return;

check_memcache_fail:

    ngx_http_memcache_add_check_timer(memcache_peer);
}


void
ngx_http_check_memcache_timeout(ngx_event_t *event)
{
    ngx_connection_t                            *c;
    ngx_http_memcache_peer_t                    *memcache_peer;

    memcache_peer = event->data;
    c = memcache_peer->pc.connection;

    if (ngx_http_oauth_service_need_exit()) {
        return;
    }

    if (c) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0, 
                        "check memcache timeout: %*s", NAME_LEN, memcache_peer->name);

        c->write->handler = ngx_http_oauth_service_keepalive_dummy_handler;
        c->read->handler = ngx_http_oauth_service_keepalive_dummy_handler;

        ngx_close_connection(c);
        memcache_peer->pc.connection = NULL;
    }

    if (memcache_peer->check_timeout_ev.timer_set) {
        ngx_del_timer(&memcache_peer->check_timeout_ev);
    }

    ngx_add_timer(&memcache_peer->check_ev, memcache_peer->check_interval);

    return;
}


static ngx_int_t
ngx_http_oauth_service_memcached_parse(ngx_http_request_t *r, u_char *data)
{
    u_char                               *p, *temp;
    ngx_int_t                             len, value_len;
    ngx_str_t                             line;
    ngx_http_oauth_service_ctx_t         *ctx;

    len = ngx_strlen(data);

    for (p = data; p < data + len; p++) {
        if (*p == LF) {
            goto found;
        }
    }

    return NGX_AGAIN;

found:

    *p = '\0';

    line.len = p - data - 1;
    line.data = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oauth memcached: \"%V\"", &line);

    p = data;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_service_module);

    if (ngx_strncmp(p, "VALUE ", sizeof("VALUE ") - 1) == 0) {

        p += sizeof("VALUE ") - 1;

        if (ngx_strncmp(p, ctx->memcache_key.data, ctx->memcache_key.len) != 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oauth memcached sent invalid key in response \"%V\" "
                          "for key \"%V\"", &line, &ctx->memcache_key);

            return NGX_ERROR;
        }

        p += ctx->memcache_key.len;

        if (*p++ != ' ') {
            goto no_valid;
        }


        while (*p) {
            if (*p++ == ' ') {
                goto length;
            }
        }

        goto no_valid;

    length:

        temp = p;

        while (*p && *p++ != CR) { }

        value_len = ngx_atoof(temp, p - temp - 1);
        if (value_len == -1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oauth memcached sent invalid length in response \"%V\" "
                          "for key \"%V\"", &line, &ctx->memcache_key);
            return NGX_ERROR;
        }

        data = p + 1;
        *(data + value_len) = '\0';

        ctx->memcache_content.len = value_len;
        ctx->memcache_content.data = ngx_pcalloc(r->pool, value_len + 1);
        ngx_memcpy(ctx->memcache_content.data, data, value_len + 1);

        return NGX_OK;
    }

    if (ngx_strcmp(p, "END\x0d") == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "key: \"%V\" was not found by oauth memcached", &ctx->memcache_key);

        return MEMCACHE_NOT_FOUND;
    }

no_valid:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "oauth memcached sent invalid response: \"%V\"", &line);

    return NGX_ERROR;
}

