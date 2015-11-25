#include "ngx_http_oauth_service_module.h"
#include "ngx_http_json.h"


static ngx_int_t ngx_http_http_get_keepalive_peer(ngx_http_oauth_keepalive_peer_data_t *mkp);

static void *ngx_http_http_get_peer(void *data, ngx_int_t flag);
static void ngx_http_http_send_handler(ngx_event_t *event);
static void ngx_http_http_recv_header_handler(ngx_event_t *event);
static void ngx_http_http_recv_body_handler(ngx_event_t *event);
static void ngx_http_http_json_parse(ngx_http_oauth_keepalive_peer_data_t *mkp);
static void ngx_http_http_free_keepalive_peer(ngx_http_oauth_keepalive_peer_data_t *mkp);
static void ngx_http_http_check_timeout_handler(ngx_event_t *event);
static void ngx_http_http_keepalive_close_handler(ngx_event_t *event);
static void ngx_http_http_parse_header(ngx_connection_t *c);
static void ngx_http_http_clear_event(ngx_http_oauth_keepalive_peer_data_t *mkp);


void *
ngx_http_http_peers_init(ngx_conf_t *cf, void *conf)
{
    ngx_uint_t                                   i, j, n;
    ngx_url_t                                   u;
    ngx_http_http_peer_t                       *http_peer;
    ngx_http_http_peers_t                      *http_peers;
    ngx_http_oauth_service_main_conf_t         *osmcf = conf;
    ngx_http_oauth_service_keepalive_cache_t   *cached;

    http_peers = osmcf->http_peers;

    u.host = osmcf->http_host;
    u.port = (in_port_t)osmcf->http_port;

    http_peers->peers = ngx_pcalloc(cf->pool, 5 * sizeof(ngx_http_http_peer_t));

    if (http_peers->peers == NULL) {
        return NGX_CONF_ERROR;
    }
    http_peer = http_peers->peers;

    for (i = 0; i < 5; i++) {
        ngx_queue_init(&http_peer[i].free);
        ngx_queue_init(&http_peer[i].cache);

        cached = ngx_pcalloc(cf->pool,
                      sizeof(ngx_http_oauth_service_keepalive_cache_t) * osmcf->http_keepalive);

        if (cached == NULL) {
            return NGX_CONF_ERROR;
        }
        for (j = 0; j < osmcf->http_keepalive; j++) {
            cached[j].connection = NULL;
        }

        for (j = 0; j < osmcf->http_keepalive; j++) {
            cached[j].data = &http_peer[i];
            ngx_queue_insert_head(&http_peer[i].free, &cached[j].queue);
        }
    }

    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                          "http_peers_init %s in upstream \"%V\"", u.err, &u.host);
        }

        return NGX_CONF_ERROR;
    }

    n = u.naddrs;
    http_peers->count = n;

    for (i = 0; i < n; i++) {
        ngx_memcpy(&http_peer[i].sockaddr, u.addrs[i].sockaddr, u.addrs[i].socklen);

        http_peer[i].socklen     = u.addrs[i].socklen;

        ngx_memcpy(&http_peer[i].name, u.addrs[i].name.data, u.addrs[i].name.len);

        http_peer[i].current_weight = 0;
        http_peer[i].effective_weight = 1;
        http_peer[i].weight = 1;

        http_peer[i].down = 0;

        http_peer[i].http_idc = &osmcf->idc;
    }

    return NGX_CONF_OK;
}


void
ngx_http_http_peers_init_process(ngx_cycle_t *cycle)
{
    ngx_uint_t                             i;
    ngx_http_http_peer_t                  *http_peer;
    ngx_http_http_peers_t                 *http_peers;
    ngx_http_oauth_service_main_conf_t    *osmcf;

    osmcf = sub_ctx;

    ngx_log_debug0(NGX_LOG_DEBUG, cycle->log, 0,
                   " oauth service http_peers init process ");

    http_peers = osmcf->http_peers;
    http_peer  = http_peers->peers;

    for (i = 0; i < http_peers->count; i++) {
        http_peer[i].check_timeout_ev.handler = ngx_http_http_check_handler;
        http_peer[i].check_timeout_ev.log = cycle->log;
        http_peer[i].check_timeout_ev.data = &http_peer[i];
        http_peer[i].check_timeout_ev.timer_set = 0;

        ngx_memzero(&http_peer[i].pc, sizeof(ngx_peer_connection_t));

        http_peer[i].pc.sockaddr = (struct sockaddr *)http_peer[i].sockaddr;
        http_peer[i].pc.socklen = http_peer[i].socklen;
        http_peer[i].pc.name = ngx_pcalloc(cycle->pool, sizeof(ngx_str_t));
        http_peer[i].pc.name->data = http_peer[i].name;
        http_peer[i].pc.name->len = ngx_strlen(http_peer[i].name);

        http_peer[i].pc.get = ngx_event_get_peer;
        http_peer[i].pc.log = cycle->log;
        http_peer[i].pc.log_error = NGX_ERROR_ERR;

        http_peer[i].pc.cached = 0;
        http_peer[i].pc.connection = NULL;
    }
    
    return;
}


ngx_int_t
ngx_http_http_connect_handler(ngx_http_oauth_keepalive_peer_data_t *mkp)
{
    ngx_int_t                               rc;
    ngx_connection_t                       *c;
    ngx_http_request_t                     *r;
    ngx_peer_connection_t                  *pc;
    ngx_http_http_peer_t                   *http_peer;
    ngx_http_http_peers_t                  *http_peers;
    ngx_http_oauth_service_main_conf_t     *osmcf;

    r = mkp->request;
    pc = &mkp->pc;

    if (mkp->state == NGX_TCP_CONNECT_DONE) {
        return NGX_OK;
    }

    osmcf = ngx_http_get_module_main_conf(r, ngx_http_oauth_service_module);

    http_peers = osmcf->http_peers;
    if (http_peers->count == 1) {
        http_peer = &http_peers->peers[0];

    } else {
        http_peer = ngx_http_http_get_peer(http_peers, 1);
    }

    if (http_peer == NULL) {
        return NGX_ERROR;
    }
    http_peer->data = mkp;

    mkp->pc.sockaddr = (struct sockaddr *)http_peer->sockaddr;
    mkp->pc.socklen = http_peer->socklen;
    mkp->pc.name->data = http_peer->name;
    mkp->pc.name->len = ngx_strlen(http_peer->name);

    mkp->check_timeout_ev.handler = ngx_http_http_check_timeout_handler;
    mkp->check_timeout_ev.log = r->pool->log;
    mkp->check_timeout_ev.timer_set = 0;

    mkp->conf = http_peer;

    if (ngx_http_http_get_keepalive_peer(mkp) == NGX_OK) {
        mkp->check_timeout_ev.data = mkp->pc.connection;

        c = mkp->pc.connection;
        c->data = mkp;
        c->write->handler = ngx_http_http_send_handler;
        c->read->handler = ngx_http_http_recv_header_handler;

        ngx_add_timer(&mkp->check_timeout_ev, osmcf->http_timeout);
        c->write->handler(c->write);

        return NGX_OK;
    }

    rc = ngx_event_connect_peer(pc);

    if (rc == NGX_ERROR || rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "http_connect connect to %*s failed", NAME_LEN, http_peer->name);

        pc->connection = NULL;
//        http_peer->down = 1;
//        ngx_add_timer(&http_peer->check_ev, CHECK_TIME);

        return NGX_ERROR;
    }

    if (rc == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                        "http_connect busy connet to %*s", NAME_LEN, http_peer->name);
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

    c->write->handler = ngx_http_http_send_handler;
    c->read->handler = ngx_http_http_recv_header_handler;

    mkp->state = NGX_TCP_CONNECT_DONE;

    ngx_add_timer(&mkp->check_timeout_ev, osmcf->http_timeout);

    if (rc == NGX_OK) {
        c->write->handler(c->write);
    }

    return NGX_OK;
}


static void *
ngx_http_http_get_peer(void *data, ngx_int_t flag)
{
    ngx_int_t                     total = 0;
    ngx_uint_t                    i;
    ngx_http_http_peer_t         *peer = NULL, *best = NULL;
    ngx_http_http_peers_t        *http_peers = data;

    for (i = 0; i < http_peers->count; i++) {

        peer = &http_peers->peers[i];

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
ngx_http_http_get_keepalive_peer(ngx_http_oauth_keepalive_peer_data_t *mkp)
{
    ngx_http_http_peer_t                          *http_peer;
    ngx_http_oauth_service_keepalive_cache_t      *item;

    ngx_queue_t       *q, *cache;
    ngx_connection_t  *c;

    http_peer = mkp->conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mkp->pc.log, 0,
                                       "oauth http get keepalive peer");

    /* search cache for suitable connection */

    cache = &http_peer->cache;

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
            ngx_queue_insert_head(&http_peer->free, q);

            if (c == NULL) {
                continue;
            }

            if (ngx_http_oauth_service_test_connect(c) != NGX_OK) {
                ngx_close_connection(c);
                item->connection = NULL;

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mkp->pc.log, 0, "http_get_keepalive_closed");

                continue;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mkp->pc.log, 0,
                           "http get keepalive peer: using connection %p", c);

            c->idle = 0;
            c->log = mkp->pc.log;
            c->read->log = mkp->pc.log;
            c->write->log = mkp->pc.log;

            mkp->pc.connection = c;
            mkp->pc.cached = 1;

            item->data = http_peer;

            return NGX_OK;
        } else {
            ngx_queue_remove(q);
            ngx_queue_insert_head(&http_peer->free, q);

            ngx_log_debug0(NGX_LOG_DEBUG, mkp->pc.log, 0,
                        "http get keepalive peer, item->sockaddr differ mkp->pc.sockaddr");

            if (c) {
                ngx_close_connection(c);
                item->connection = NULL;
            }
            return NGX_ERROR;
        }
    }

    return NGX_ERROR;
}


static void
ngx_http_http_send_handler(ngx_event_t *event)
{
    u_char                                     request[ngx_pagesize / 2], *m_key;
    u_char                                    *data, low[16], *data_end, m[32];
    ssize_t                                    temp_send = 0, send_num = 0, len;
    ngx_int_t                                  tcp_nodelay;
    ngx_uint_t                                 key, ip_len;
    ngx_connection_t                          *c;
    ngx_http_request_t                        *r;
    ngx_http_http_peer_t                      *http_peer;
    ngx_http_core_loc_conf_t                  *clcf;
    ngx_http_variable_value_t                 *IP;
    ngx_http_oauth_service_ctx_t              *ctx;
    ngx_http_oauth_keepalive_peer_data_t      *mkp;

    c = event->data;
    mkp = c->data;
    r = mkp->request;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (mkp->state == NGX_TCP_SEND_DONE) {
        return;
    }

    if (clcf->tcp_nodelay && c->tcp_nodelay == NGX_TCP_NODELAY_UNSET) {

        tcp_nodelay = 1;
        if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
                                (const void *) &tcp_nodelay, sizeof(int)) == -1)
        {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "setsockopt(TCP_NODELAY) failed");
            goto http_send_fail;
        }
        c->tcp_nodelay = NGX_TCP_NODELAY_SET;

    }

    ngx_http_oauth_sub_shm_t *sub_peers_ctx = sub_ctx->sub_shm;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_service_module);

    m_key = ngx_pcalloc(r->pool, (ctx->sub.len +ngx_strlen(H_DOMAIN) +ngx_strlen(PIN) +1));
    ngx_sprintf(m_key, "%V%s%s\0", &ctx->sub, H_DOMAIN, PIN);

    ngx_memset(m, '\0', 32);
    if (ngx_md5_m(m, m_key) == NGX_ERROR) {
        goto http_send_fail;
    }

    ngx_str_t   *remote_addr;

    remote_addr = (ngx_str_t *)ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    remote_addr->len = ngx_strlen("remote_addr");
    remote_addr->data = ngx_pcalloc(r->pool, ngx_strlen("remote_addr"));
    ngx_sprintf(remote_addr->data, "remote_addr");

    key = ngx_hash_strlow(low, remote_addr->data, remote_addr->len);
    IP = ngx_http_get_variable(r, remote_addr, key);

    if (IP == NULL) {
        goto http_send_fail;
    }
    ip_len = IP->len;

    http_peer = mkp->conf;

    if (ngx_http_oauth_service_need_exit()) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "auth for http send.");

    ngx_memset(request, '\0', ngx_pagesize / 2);

    data_end = ngx_sprintf(request, 
            "GET %s?%s&%s&m=%*s&sub=%V&ip=%*s&idc=%V HTTP/1.0\r\nHost: %s\r\n"
            "Connection: keep-alive\r\nAccept: */*\r\n\r\n", 
            HTTP_SERVER_URL, HTTP_ENTRY, HTTP_DOMAIN, HTTP_M_LEN, m, &ctx->sub, ip_len, IP->data,
            http_peer->http_idc, sub_peers_ctx->res->http->host);

    data = request;
    len = data_end - data;

    ngx_log_debug2(NGX_LOG_DEBUG, c->log, 0, 
                                "http_send request content %*s", len, request);

    while (send_num < len) {

        temp_send = c->send(c, data + temp_send, len - send_num);

#if (NGX_DEBUG)
        {
        ngx_err_t  err;

        err = (temp_send >=0) ? 0 : ngx_socket_errno;

        if (temp_send > 0) {
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, err,
                            "oauth http send size: %z, content: %*s",
                            temp_send, temp_send, data);
        }
        }
#endif

        if (temp_send > 0) {
            send_num += temp_send;

        } else if (temp_send == 0 || temp_send == NGX_AGAIN) {
            return;

        } else {
            c->error = 1;
            goto http_send_fail;
        }
    }

    mkp->state = NGX_TCP_SEND_DONE;

    if (send_num == len) {
        c->write->handler = ngx_http_oauth_service_keepalive_dummy_handler;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "oauth http send done.");
    }

    return;

http_send_fail:

    ngx_http_http_clear_event(mkp);
    ngx_http_finalize_request_success(mkp);
}


static void
ngx_http_http_recv_header_handler(ngx_event_t *event)
{
    ssize_t                                    size, recv_size = 0;
    ngx_int_t                                  code, rc = 0;
    ngx_connection_t                          *c;
    ngx_http_status_t                          status;
    ngx_http_request_t                        *r;
    ngx_http_http_peer_t                      *http_peer;
    ngx_http_oauth_keepalive_peer_data_t      *mkp;

    c = event->data;
    mkp = c->data;
    r = mkp->request;
    http_peer = mkp->conf;

    status.code = 0;
    status.count = 0;

    if (ngx_http_oauth_service_need_exit()) {
        return;
    }

    if (mkp->state == NGX_OAUTH_PARSE_HEADER_DONE) {
        c->read->handler = ngx_http_http_recv_body_handler;

        return;
    }

    if (mkp->state < NGX_OAUTH_PARSE_LINE_DONE) {
         http_peer->buf.start = ngx_pcalloc(r->pool, ngx_pagesize * 2);
        if (http_peer->buf.start == NULL) {
            goto http_recv_fail;
        }

        http_peer->buf.end = http_peer->buf.start + ngx_pagesize * 2;
        http_peer->buf.pos = http_peer->buf.start;
        http_peer->buf.last = http_peer->buf.start;
    }

    while (1) {

        size = c->recv(c, http_peer->buf.last, ngx_pagesize * 2 - recv_size);

#if (NGX_DEBUG)
        {
        ngx_err_t  err;

        err = (size >= 0) ? 0 : ngx_socket_errno;
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, err,
                       "http_recv_header size: %z, peer: %*s ",
                       size, NAME_LEN, http_peer->name);

        if (size > 0) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                        "http_recv_header content: %*s ", size, http_peer->buf.pos);
        }
        }
#endif

        if (size > 0) {
            http_peer->buf.last += size;
            recv_size += size;
            continue;

        } else if (size == 0 || size == NGX_AGAIN) {
            break;

        } else {
            c->error = 1;
            goto http_recv_fail;
        }
    }

    *(http_peer->buf.last) = '\0';

    if (size == 0) {
        c->close = 1;
    }

    if (recv_size > 0) {

        if (mkp->state != NGX_OAUTH_PARSE_LINE_DONE) {
            rc = ngx_http_parse_status_line(r, &http_peer->buf, &status);

            if (rc == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "parse http server status line error with peer: %*s ", NAME_LEN, http_peer->name);

                goto http_recv_fail;
            }
            if (rc == NGX_AGAIN) {
                return;
            }

            code = status.code;
            if (code == 200) {
                mkp->state = NGX_OAUTH_PARSE_LINE_DONE;
            } else {
                goto http_recv_fail;
            }

        } else if (mkp->state == NGX_OAUTH_PARSE_LINE_DONE) {
            ngx_http_http_parse_header(c);
            return;
        }

    } else {
        goto http_recv_fail;
    }

    if (mkp->state == NGX_OAUTH_PARSE_LINE_DONE) {
        ngx_http_http_parse_header(c);
    }
    return;

http_recv_fail:

    ngx_http_http_clear_event(mkp);
    ngx_http_finalize_request_success(mkp);
}


static void
ngx_http_http_recv_body_handler(ngx_event_t *event)
{
    ssize_t                                    size, len, recv_size = 0;
    ngx_connection_t                          *c;
    ngx_http_http_peer_t                      *http_peer;
    ngx_http_oauth_keepalive_peer_data_t      *mkp;

    c = event->data;
    mkp = c->data;
    http_peer = mkp->conf;

    if (ngx_http_oauth_service_need_exit()) {
        return;
    }

    if (mkp->state == NGX_TCP_RECV_DONE) {
        ngx_http_http_json_parse(mkp);

        return;
    }

    len = http_peer->buf.end - http_peer->buf.last;

    while (1) {

        size = c->recv(c, http_peer->buf.last, len - recv_size);

#if (NGX_DEBUG)
        {
        ngx_err_t  err;

        err = (size >= 0) ? 0 : ngx_socket_errno;
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, err,
                       "oauth recv http server body size: %z, peer: %*s ",
                       size, NAME_LEN, http_peer->name);

        if (size > 0) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "oauth recv http server content: %*s ", size, http_peer->buf.pos);
        }
        }
#endif

        if (size > 0) {
            http_peer->buf.last += size;
            recv_size += size;
            continue;

        } else if (size == 0 || size == NGX_AGAIN) {
            break;

        } else {
            c->error = 1;
            goto http_recv_fail;
        }
    }

    *(http_peer->buf.last) = '\0';

    if (size == 0) {
        c->close = 1;
    }

    if (size == NGX_AGAIN) {
        if (json_extract_text(http_peer->buf.pos, 
                            http_peer->buf.last - http_peer->buf.pos) != 0) {

            ngx_http_http_json_parse(mkp);
            return;
        }

        return;
    }

    mkp->state = NGX_TCP_RECV_DONE;

    c->read->handler = ngx_http_oauth_service_keepalive_dummy_handler;

    if (recv_size == 0) {
        if (http_peer->buf.pos == NULL) {
            goto http_recv_fail;
        }

        ngx_http_http_json_parse(mkp);
        return;
    }

    ngx_http_http_json_parse(mkp);

    return;

http_recv_fail:

    ngx_http_http_clear_event(mkp);
    ngx_http_finalize_request_success(mkp);
}


static void
ngx_http_http_parse_header(ngx_connection_t *c)
{
    ngx_int_t                                  rc = 0;
    ngx_buf_t                                 *buf;
    ngx_http_request_t                        *r;
    ngx_http_http_peer_t                      *http_peer;
    ngx_http_oauth_keepalive_peer_data_t      *mkp;

    mkp = c->data;
    r = mkp->request;
    http_peer = mkp->conf;

    buf = &http_peer->buf;

    if (buf->pos == buf->last) {
        return;
    }

    for ( ; ; ) {
        rc = ngx_http_parse_header_line(r, buf, 1);

        if (rc == NGX_OK) {
            continue;
        }

        if (rc == NGX_AGAIN) {
            return;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            mkp->state = NGX_OAUTH_PARSE_HEADER_DONE;

            if ((buf->last - buf->pos) > 0) {

                if (json_extract_text(buf->pos, buf->last - buf->pos) != 0) {
                    mkp->state = NGX_TCP_RECV_DONE;

                    c->read->handler = ngx_http_oauth_service_keepalive_dummy_handler;
                    ngx_http_http_json_parse(mkp);

                    return;
                }
            }

            c->read->handler = ngx_http_http_recv_body_handler;

            return;
        }
    }

    return;
}


static void
ngx_http_http_json_parse(ngx_http_oauth_keepalive_peer_data_t *mkp)
{
    json_t                         *root = NULL, *temp = NULL;
    u_char                         *data;
    ngx_int_t                       etime;
    ngx_http_request_t             *r;
    ngx_http_http_peer_t           *http_peer;

    r = mkp->request;
    http_peer = mkp->conf;
    data = http_peer->buf.pos;

    if (json_parse_document(&root, (char *)data) != JSON_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                         "http_json_parse failed: %*s ", NAME_LEN, http_peer->name);

        goto http_parse_fail;
    }

    temp = json_find_first_label(root, "retcode");
    if (temp != NULL && temp->child->text != NULL) {
        if (ngx_strncmp(temp->child->text, "50111309", 8) == 0) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                                "http_json_parse retcode failed: %s ", temp->child->text);

            json_free_value(&root);

            ngx_http_http_clear_event(mkp);
            ngx_http_finalize_request_failed(mkp);
            return;
        }

    } else {
        goto http_parse_fail;
    }
    temp = NULL;

    temp = json_find_first_label(root, "data");
    if (temp != NULL && temp->child != NULL) {

        json_t *temp1 = json_find_first_label((json_t *)temp->child, "session");
        if (temp1 != NULL && temp1->child != NULL) {

            json_t *temp2 = json_find_first_label((json_t *)temp1->child, "etime");
            if (temp2 != NULL && temp2->child->text != NULL) {
                etime = ngx_atoi((u_char *)temp2->child->text, ngx_strlen(temp2->child->text));

                if ((ngx_current_msec / 1000) > (ngx_uint_t)etime) {
                    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                                                "http_json_parse etime out: %d ", etime);

                    json_free_value(&root);

                    ngx_http_http_clear_event(mkp);
                    ngx_http_finalize_request_failed(mkp);
                    return;
                }
            }
            temp2 = NULL;
        }
        temp1 = NULL;
    }
    temp = NULL;
    json_free_value(&root);

    ngx_http_http_clear_event(mkp);
    ngx_http_finalize_request_success(mkp);
    return;

http_parse_fail:

    ngx_http_http_clear_event(mkp);
    ngx_http_finalize_request_success(mkp);
}


static void
ngx_http_http_free_keepalive_peer(ngx_http_oauth_keepalive_peer_data_t *mkp)
{
    ngx_http_http_peer_t                          *http_peer;
    ngx_http_oauth_service_keepalive_cache_t      *item;

    ngx_queue_t          *q;
    ngx_connection_t     *c;

    http_peer = mkp->conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mkp->pc.log, 0,
                                     "http free keepalive peer");

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

    if (ngx_queue_empty(&http_peer->free)) {

        q = ngx_queue_last(&http_peer->cache);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_oauth_service_keepalive_cache_t, queue);

        ngx_http_oauth_service_keepalive_close(item->connection);

    } else {
        q = ngx_queue_head(&http_peer->free);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_oauth_service_keepalive_cache_t, queue);
    }

    item->connection = c;
    ngx_queue_insert_head(&http_peer->cache, q);

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
    c->read->handler = ngx_http_http_keepalive_close_handler;

    item->socklen = mkp->pc.socklen;
    ngx_memcpy(&item->sockaddr, mkp->pc.sockaddr, mkp->pc.socklen);

    if (c->read->ready) {
        ngx_http_http_keepalive_close_handler(c->read);
    }

    return;

invalid:

    ngx_http_oauth_service_keepalive_close(c);
}


static void
ngx_http_http_check_timeout_handler(ngx_event_t *event)
{
    ngx_connection_t                            *c;
//    ngx_http_http_peer_t                        *http_peer;
    ngx_http_oauth_keepalive_peer_data_t     *mkp;

    ngx_log_debug0(NGX_LOG_DEBUG, event->log, 0, "http_check_timeout ");

    c = event->data;
    mkp = c->data;

    if (c) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                       "ngx_http_http_check_timeout_handler : fd: %d", c->fd);

        ngx_close_connection(c);
        mkp->pc.connection = NULL;
    }

//    http_peer = mkp->pc.connection->data;

//    http_peer->down = 1;
//    ngx_add_timer(&http_peer->check_ev, CHECK_TIME);

    c->read->handler = ngx_http_oauth_service_keepalive_dummy_handler;
    c->write->handler = ngx_http_oauth_service_keepalive_dummy_handler;

    ngx_http_finalize_request_success(mkp);

    return;
}


static void
ngx_http_http_keepalive_close_handler(ngx_event_t *event)
{
    ngx_http_http_peer_t                           *http_peer;
    ngx_http_oauth_service_keepalive_cache_t       *item;


    int                n;
    char               buf[1];
    ngx_connection_t  *c;

    c = event->data;
    item = c->data;
    http_peer = item->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http keepalive close handler");

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
    ngx_queue_insert_head(&http_peer->free, &item->queue);
}


void
ngx_http_http_check_handler(ngx_event_t *event)
{
    ngx_connection_t                         *c;
    ngx_http_http_peer_t                     *http_peer;
    ngx_http_oauth_keepalive_peer_data_t     *mkp;

    http_peer = event->data;
    c = http_peer->pc.connection;

    c->read->handler = ngx_http_oauth_service_keepalive_dummy_handler;
    c->write->handler = ngx_http_oauth_service_keepalive_dummy_handler;

    if (c) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                    "oauth_http_check_timeout_handler clean event: index:%V, fd: %d",
                    &http_peer->name, c->fd);

        ngx_close_connection(c);
        http_peer->pc.connection = NULL;
    }

    if (http_peer->check_timeout_ev.timer_set) {
        ngx_del_timer(&http_peer->check_timeout_ev);
    }

    mkp = http_peer->data;

    ngx_http_finalize_request_success(mkp);

    return;
}


static void
ngx_http_http_clear_event(ngx_http_oauth_keepalive_peer_data_t *mkp)
{
    ngx_connection_t                          *c;
    ngx_http_http_peer_t                      *http_peer;

    http_peer = mkp->conf;

    c = mkp->pc.connection;

    if (c) {
        ngx_log_debug(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                    "oauth_service_clear_http_event on %*s ", NAME_LEN, http_peer->name);

        ngx_http_http_free_keepalive_peer(mkp);
        mkp->pc.connection = NULL;
    }

    if (mkp->check_timeout_ev.timer_set) {
        ngx_del_timer(&mkp->check_timeout_ev);
    }

    http_peer->buf.pos = NULL;
    http_peer->buf.last = NULL;
    http_peer->buf.start = NULL;
    http_peer->buf.end = NULL;

    http_peer->data = NULL;

    return;
}

