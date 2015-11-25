#include "ngx_http_oauth_service_module.h"
#include "ngx_http_json.h"
#include "ngx_sub_config.h"


static void ngx_http_config_send_handler(ngx_event_t *event);
static void ngx_http_config_recv_header_handler(ngx_event_t *event);
static void ngx_http_config_recv_body_handler(ngx_event_t *event);
static void ngx_http_config_json_parse(ngx_http_config_peer_t *config_peer);
static void ngx_http_config_parse_header(ngx_connection_t *c);

static ngx_int_t ngx_http_config_parse_status_line(ngx_buf_t *buf, ssize_t len);
static ngx_int_t ngx_http_config_sub_shm_update(json_t *root);
static ngx_int_t ngx_http_config_update_peers();

static void ngx_http_config_delete_memcache_timers(ngx_http_memcache_peers_t *memcache_peers);
static void ngx_http_config_update_memcache_peer(ngx_http_memcache_peers_t *memcache_peers);
static void ngx_http_config_delete_http_timers(ngx_http_http_peers_t *http_peers);
static void ngx_http_config_update_http_peer(ngx_http_http_peers_t *http_peers);
static void ngx_http_config_timeout_handler(ngx_event_t *event);
static void ngx_http_config_read_dummy_handler(ngx_event_t *event);
static void ngx_http_config_write_dummy_handler(ngx_event_t *event);
static void ngx_http_config_clear_event(ngx_http_config_peer_t *config_peer);


void
ngx_http_config_add_timers(ngx_cycle_t *cycle)
{
    ngx_msec_t                           t, delay;
    ngx_http_config_peer_t              *config_peer;
    ngx_http_oauth_service_main_conf_t  *osmcf;

    osmcf = sub_ctx;

    config_peer = osmcf->config_peer;

    ngx_log_debug2(NGX_LOG_DEBUG, cycle->log, 0,
                   "oauth service_add_timers, name: %*s ", NAME_LEN, config_peer->name);

    srandom(ngx_pid);

    config_peer->check_timer_ev.handler   = ngx_http_config_begin_handler;
    config_peer->check_timer_ev.log       = cycle->log;
    config_peer->check_timer_ev.data      = config_peer;
    config_peer->check_timer_ev.timer_set = 0;

    config_peer->check_timeout_ev.handler   = ngx_http_config_timeout_handler;
    config_peer->check_timeout_ev.log       = cycle->log;
    config_peer->check_timeout_ev.data      = config_peer;
    config_peer->check_timeout_ev.timer_set = 0;

    config_peer->send_handler = ngx_http_config_send_handler;
    config_peer->recv_handler = ngx_http_config_recv_header_handler;

    /*
     * We add a random start time here, since we want to trigger
     * the check events much quickly to updata the sub shm at the beginning.
     */
    delay = config_peer->config_interval < 1000 ? config_peer->config_interval : 1000;
    t = ngx_random() % delay;

    ngx_add_timer(&config_peer->check_timer_ev, t);
}


void *
ngx_http_config_peer_init(ngx_conf_t *cf, void *conf)
{
    u_char                              *m_key;
    ngx_int_t                            len;
    ngx_url_t                            u;
    ngx_http_config_peer_t              *config_peer;
    ngx_http_oauth_service_main_conf_t  *osmcf = conf;

    config_peer = osmcf->config_peer;

    config_peer->state = 0;

    len = config_peer->config_idc->len + ngx_strlen(C_DOMAIN) + ngx_strlen(PIN);
    m_key = ngx_pcalloc(config_peer->pool, len + 1);
    ngx_sprintf(m_key, "%V%s%s\0", config_peer->config_idc, C_DOMAIN, PIN);

    if (ngx_md5_m(config_peer->m.data, m_key) == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }
    ngx_reset_pool(config_peer->pool);

    u.host.len = osmcf->config_host.len;
    u.host.data = osmcf->config_host.data;

    u.port = (in_port_t)config_peer->config_port;

    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                          "%s in upstream \"%V\" ", u.err, &u.host);
        }

        return NGX_CONF_ERROR;
    }

    ngx_memcpy(&config_peer->sockaddr, u.addrs[0].sockaddr, u.addrs[0].socklen);
    config_peer->socklen   = u.addrs[0].socklen;
    ngx_memcpy(&config_peer->name, u.addrs[0].name.data, u.addrs[0].name.len);

    return NGX_CONF_OK;
}


void
ngx_http_config_begin_handler(ngx_event_t *event)
{
    ngx_url_t                            u;
    ngx_msec_t                           interval;
    ngx_http_config_peer_t              *config_peer;

    config_peer = event->data;

    if (ngx_http_oauth_service_need_exit()) {
        return;
    }

    ngx_add_timer(event, config_peer->config_interval);

    /* This process is processing this peer now. */
    if (config_peer->owner == ngx_pid ||
        config_peer->pc.connection != NULL ||
        config_peer->check_timeout_ev.timer_set) {

        return;
    }

    interval = ngx_current_msec - config_peer->access_time;
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, event->log, 0,
                   "oauth config begin handler owner: %P,"
                   "interval: %M, config_interval: %M",
                   ngx_pid, interval, config_peer->config_interval);

    u.host.len = sub_ctx->config_host.len;
    u.host.data = sub_ctx->config_host.data;

    u.port = (in_port_t)sub_ctx->config_port;

    if (ngx_inet_resolve_host(config_peer->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                          "%s in upstream \"%V\" ", u.err, &u.host);
        }

        return;
    }

    if (ngx_memn2cmp((u_char *)u.addrs[0].sockaddr, (u_char *)config_peer->sockaddr,
                                     u.addrs[0].socklen, config_peer->socklen) != 0) {

        ngx_memcpy(&config_peer->sockaddr, u.addrs[0].sockaddr, u.addrs[0].socklen);
        config_peer->socklen  =  u.addrs[0].socklen;
        ngx_memcpy(&config_peer->name, u.addrs[0].name.data, u.addrs[0].name.len);
    }

    if (config_peer->owner == NGX_INVALID_PID)
    {
        config_peer->owner = ngx_pid;
        config_peer->access_time = ngx_current_msec;
    }

    if (config_peer->owner == ngx_pid) {
        ngx_http_config_connect_handler(event);
    }
}


void
ngx_http_config_connect_handler(ngx_event_t *event)
{
    ngx_int_t                            rc;
    ngx_connection_t                    *c;
    ngx_http_config_peer_t              *config_peer;

    config_peer = event->data;

    if (ngx_http_oauth_service_need_exit()) {
        return;
    }

    ngx_memzero(&config_peer->pc, sizeof(ngx_peer_connection_t));

    config_peer->pc.sockaddr = (struct sockaddr *)config_peer->sockaddr;
    config_peer->pc.socklen = config_peer->socklen;
    config_peer->pc.name = ngx_pcalloc(config_peer->pool, sizeof(ngx_str_t));
    config_peer->pc.name->data = config_peer->name;
    config_peer->pc.name->len = ngx_strlen(config_peer->name);

    config_peer->pc.get = ngx_event_get_peer;
    config_peer->pc.log = event->log;
    config_peer->pc.log_error = NGX_ERROR_ERR;

    config_peer->pc.cached = 0;
    config_peer->pc.connection = NULL;

    if (config_peer->state == NGX_TCP_CONNECT_DONE){
        return;
    }

    rc = ngx_event_connect_peer(&config_peer->pc);

    if (rc == NGX_ERROR || rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_WARN, event->log, 0, "oauth_config_connection connect failed");
        config_peer->access_time = ngx_current_msec;
        return;
    }

    if (rc == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, event->log, 0, 
                        "memcache_connect busy connet to %*s", NAME_LEN, config_peer->name);
        config_peer->access_time = ngx_current_msec;
        return;
    }

    /* NGX_OK or NGX_AGAIN */
    c = config_peer->pc.connection;
    c->data = config_peer;
    c->log = config_peer->pc.log;
    c->sendfile = 0;
    c->read->log = c->log;
    c->write->log = c->log;
    c->pool = config_peer->pool;

    c->write->handler = config_peer->send_handler;
    c->read->handler = config_peer->recv_handler;

    config_peer->state = NGX_TCP_CONNECT_DONE;

    ngx_add_timer(&config_peer->check_timeout_ev, config_peer->config_timeout);

    if (rc == NGX_OK) {
        c->write->handler(c->write);
    }
}


static void
ngx_http_config_send_handler(ngx_event_t *event)
{
    u_char                          request[ngx_pagesize / 2];
    u_char                         *data, *end;
    ssize_t                         temp_send = 0, send_num = 0, len;
    ngx_connection_t               *c;
    ngx_http_config_peer_t         *config_peer;
    ngx_http_oauth_sub_shm_t       *sub_peers_ctx = sub_ctx->sub_shm;

    c = event->data;
    config_peer = c->data;

    if (ngx_http_oauth_service_need_exit()) {
        return;
    }

    if (config_peer->state == NGX_TCP_SEND_DONE) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "auth for config send.");

    if (c->pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "oauth_config_send pool NULL with peer: %*s ", NAME_LEN, config_peer->name);

        goto config_send_fail;
    }

    ngx_memset(request, '\0', ngx_pagesize / 2);

    if (ngx_http_oauth_check_shm_generation == 0) {
        end = ngx_sprintf(request, 
                "GET %s?%s&%s&m=%V&idc=%V HTTP/1.0\r\nHost: %V\r\nConnection: keep-alive\r\n"
                "Accept: */*\r\n\r\n", 
                CONFIG_SERVER_URL, CONFIG_ENTRY, CONFIG_DOMAIN, &config_peer->m,
                config_peer->config_idc, &sub_ctx->config_host);
    } else {

        end = ngx_sprintf(request, 
                "GET %s?%s&%s&idc=%V&m=%V&etag=%V HTTP/1.0\r\nHost: %V\r\nConnection: keep-alive\r\n"
                "Accept: */*\r\n\r\n", 
                CONFIG_SERVER_URL, CONFIG_ENTRY, CONFIG_DOMAIN, config_peer->config_idc, 
                &config_peer->m, &sub_peers_ctx->meta->etag, &sub_ctx->config_host);
    }

    data = request;
    len = end - data;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "oauth config send request: %*s", len, request);

    while (send_num < len) {

        temp_send = c->send(c, data + temp_send, len - send_num);

#if (NGX_DEBUG)
        {
        ngx_err_t  err;

        err = (temp_send >=0) ? 0 : ngx_socket_errno;
        
        if (temp_send > 0) {
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, err,
                        "oauth config send size: %z, total: %*s", temp_send, temp_send, data);
        }
        }
#endif

        if (temp_send > 0) {
            send_num += temp_send;

        } else if (temp_send == 0 || temp_send == NGX_AGAIN) {
            return;

        } else {
            c->error = 1;
            goto config_send_fail;
        }
    }

    config_peer->state = NGX_TCP_SEND_DONE;

    if (send_num == len) {
        c->write->handler = ngx_http_config_write_dummy_handler;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "oauth config send done.");
    }

    return;

config_send_fail:

    ngx_http_config_clear_event(config_peer);
}


static ngx_int_t
ngx_http_config_parse_status_line(ngx_buf_t *buf, ssize_t len)
{
    ngx_int_t                            rc;
    ngx_uint_t                           code;
    ngx_http_status_t                    status;

    status.count = 0;
    status.code = 0;

    if (len > 0) {

        rc = ngx_http_oauth_service_parse_status_line(buf, &status);

        if (rc == NGX_AGAIN) {
            return rc;
        }

        if (rc == NGX_ERROR) {

            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                        "config server sent no valid HTTP/1.0 header");

            return rc;
        }

        code = status.code;

        if (code == 200) {
            return NGX_OK;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "oauth config status line code: %d", code);

        return NGX_ERROR;
    } else {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static void
ngx_http_config_parse_header(ngx_connection_t *c)
{
    ngx_buf_t                      *buf;
    ngx_int_t                       rc = 0;
    ngx_http_config_peer_t         *config_peer;

    config_peer = c->data;
    buf = &config_peer->buf;

    if (buf->pos == buf->last) {
        return;
    }

    for ( ; ; ) {
        rc = ngx_http_oauth_service_parse_header(buf, 1);

        if (rc == NGX_OK) {
            continue;
        }

        if (rc == NGX_AGAIN) {
            return;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            config_peer->state = NGX_OAUTH_PARSE_HEADER_DONE;

            if ((buf->last - buf->pos) > 0) {

                if (json_extract_text(buf->pos, buf->last - buf->pos) != 0) {
                    config_peer->state = NGX_TCP_RECV_DONE;

                    c->read->handler = ngx_http_config_read_dummy_handler;
                    ngx_http_config_json_parse(config_peer);

                    return;
                }
            }

            c->read->handler = ngx_http_config_recv_body_handler;

            return;
        }
    }

    return;
}


static void
ngx_http_config_recv_header_handler(ngx_event_t *event)
{
    ssize_t                         size, recv_size = 0;
    ngx_int_t                       rc = 0;
    ngx_connection_t               *c;
    ngx_http_config_peer_t         *config_peer;

    c = event->data;
    config_peer = c->data;

    if (c->close) {
        ngx_http_config_clear_event(config_peer);
    }

    if (ngx_http_oauth_service_need_exit()) {
        return;
    }

    if (config_peer->state == NGX_OAUTH_PARSE_HEADER_DONE) {
        c->read->handler = ngx_http_config_recv_body_handler;

        return;
    }

    if (config_peer->state < NGX_OAUTH_PARSE_LINE_DONE) {
        config_peer->buf.start = ngx_pcalloc(config_peer->pool, ngx_pagesize * 3);
        if (config_peer->buf.start == NULL) {
            goto config_recv_fail;
        }

        config_peer->buf.end = config_peer->buf.start + ngx_pagesize * 3;
        config_peer->buf.pos = config_peer->buf.start;
        config_peer->buf.last = config_peer->buf.start;
    }

    while (1) {

        size = c->recv(c, config_peer->buf.last, ngx_pagesize * 3 - recv_size);

#if (NGX_DEBUG)
        {
        ngx_err_t  err;

        err = (size >= 0) ? 0 : ngx_socket_errno;
        ngx_log_debug3(NGX_LOG_DEBUG, c->log, err,
                       "oauth config recv size: %z, peer: %*s ",
                       size, NAME_LEN, config_peer->name);

        if (size > 0) {
            ngx_log_debug2(NGX_LOG_DEBUG, c->log, 0,
                        "oauth config server header: %*s", size, config_peer->buf.pos);
        }
        }
#endif

        if (size > 0) {
            config_peer->buf.last += size;
            recv_size += size;
            continue;

        } else if (size == 0 || size == NGX_AGAIN) {
            break;

        } else {
            c->error = 1;
            goto config_recv_fail;
        }
    }

    *(config_peer->buf.last) = '\0';

    if (config_peer->state != NGX_OAUTH_PARSE_LINE_DONE) {
        rc = ngx_http_config_parse_status_line(&config_peer->buf, recv_size);

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "parse config server status line error with peer: %*s ", NAME_LEN, config_peer->name);

            goto config_recv_fail;
        }

        if (rc == NGX_OK) {
            config_peer->state = NGX_OAUTH_PARSE_LINE_DONE;

        } 
        if (rc == NGX_AGAIN) {
            return;
        }

    } else if (config_peer->state == NGX_OAUTH_PARSE_LINE_DONE) {
        ngx_http_config_parse_header(c);
        return;
    }

    if (config_peer->state == NGX_OAUTH_PARSE_LINE_DONE) {
        ngx_http_config_parse_header(c);
    }
    return;

config_recv_fail:

    ngx_http_config_clear_event(config_peer);
}


static void
ngx_http_config_recv_body_handler(ngx_event_t *event)
{
    ssize_t                         size, len, recv_size = 0;
    ngx_connection_t               *c;
    ngx_http_config_peer_t         *config_peer;

    c = event->data;
    config_peer = c->data;

    if (ngx_http_oauth_service_need_exit()) {
        return;
    }

    if (config_peer->state == NGX_TCP_RECV_DONE) {
        ngx_http_config_json_parse(config_peer);

        return;
    }

    len = config_peer->buf.end - config_peer->buf.last;

    while (1) {

        size = c->recv(c, config_peer->buf.last, len - recv_size);

#if (NGX_DEBUG)
        {
        ngx_err_t  err;

        err = (size >= 0) ? 0 : ngx_socket_errno;

        if (size > 0) {
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, err,
                            "oauth config recv size: %z, peer: %*s ",
                            size, NAME_LEN, config_peer->name);
        }
        }
#endif

        if (size > 0) {
            config_peer->buf.last += size;
            recv_size += size;
            continue;

        } else if (size == 0 || size == NGX_AGAIN) {
            break;

        } else {
            c->error = 1;
            goto config_recv_fail;
        }
    }

    *(config_peer->buf.last) = '\0';

    if (size == NGX_AGAIN) {
        if (json_extract_text(config_peer->buf.pos, 
                    config_peer->buf.last - config_peer->buf.pos) != 0) {

            ngx_http_config_json_parse(config_peer);
            return;
        }

        return;
    }

    config_peer->state = NGX_TCP_RECV_DONE;

    c->read->handler = ngx_http_config_read_dummy_handler;

    if (recv_size == 0) {
        if (config_peer->buf.pos == NULL) {
            goto config_recv_fail;
        }

        ngx_http_config_json_parse(config_peer);
        return;
    }

/*
    if ((config_peer->buf.end - config_peer->buf.last) > (len + 1)) {
        ngx_memcpy(config_peer->buf.last, data, len + 1);
        config_peer->buf.last += (len + 1);

    } else {
        config_peer->buf.start = ngx_pcalloc(config_peer->pool, 
                                           (config_peer->buf.last - config_peer->buf.pos) + len + 1);

        ngx_sprintf(config_peer->buf.start, "%*s%*s", (config_peer->buf.last - config_peer->buf.pos), 
                                                                config_peer->buf.pos, len + 1, data);

        config_peer->buf.last += ((config_peer->buf.last - config_peer->buf.pos) + len + 1);
        config_peer->buf.pos = config_peer->buf.start;
    }
*/
    if (recv_size > 0) {
        ngx_log_debug2(NGX_LOG_DEBUG, c->log, 0, "oauth config content: %*s", 
                                                    recv_size, config_peer->buf.pos);
    }

    ngx_http_config_json_parse(config_peer);

    return;

config_recv_fail:

    ngx_http_config_clear_event(config_peer);
}


static void
ngx_http_config_timeout_handler(ngx_event_t *event)
{
    ngx_connection_t  *c;
    ngx_http_config_peer_t  *config_peer;

    config_peer = event->data;

    if (ngx_http_oauth_service_need_exit()) {
        return;
    }

    c = config_peer->pc.connection;

    c->read->handler = ngx_http_config_read_dummy_handler;
    c->write->handler = ngx_http_config_write_dummy_handler;

    if (c) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                       "oauth_config_timeout_handler clean event: fd: %d", c->fd);

        ngx_close_connection(c);
        config_peer->pc.connection = NULL;
    }

    if (config_peer->check_timeout_ev.timer_set) {
        ngx_del_timer(&config_peer->check_timeout_ev);
    }

    config_peer->owner = NGX_INVALID_PID;
    config_peer->state = 0;

    return;
}


static void
ngx_http_config_clear_event(ngx_http_config_peer_t *config_peer)
{
    ngx_connection_t                    *c;

    c = config_peer->pc.connection;

    c->read->handler = ngx_http_config_read_dummy_handler;
    c->write->handler = ngx_http_config_write_dummy_handler;

    if (c->close && config_peer->check_timer_ev.timer_set) {
        ngx_del_timer(&config_peer->check_timer_ev);
    }

    if (c) {
        ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                    "oauth_service_clear_config_event on %P ", config_peer->owner);

        ngx_close_connection(c);
        config_peer->pc.connection = NULL;
    }

    if (config_peer->check_timeout_ev.timer_set) {
        ngx_del_timer(&config_peer->check_timeout_ev);
    }

    ngx_reset_pool(config_peer->pool);

    config_peer->owner = NGX_INVALID_PID;
    config_peer->state = 0;

    return;
}


static void
ngx_http_config_read_dummy_handler(ngx_event_t *event)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, event->log, 0,
                                  "config_read_dummy_handler");
}


static void
ngx_http_config_write_dummy_handler(ngx_event_t *event)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, event->log, 0,
                                  "config_write_dummy_handler");
}


static void
ngx_http_config_json_parse(ngx_http_config_peer_t *config_peer)
{
    json_t                         *root = NULL, *temp = NULL;
    u_char                         *data;

    data = config_peer->buf.pos;

    if (config_peer->state == NGX_TCP_ALL_DONE) {
        return;
    }

    if (json_parse_document(&root, (char *)data) != JSON_OK) {
        ngx_log_error(NGX_LOG_WARN, config_peer->pool->log, 0,
            "oauth config json parse failed: %*s ", NAME_LEN, config_peer->name);

        goto config_parse_fail;
    }

    temp = json_find_first_label(root, "retcode");
    if (temp != NULL && temp->child->text != NULL) {
        if (ngx_strcmp(temp->child->text, "20000000") != 0) {
            json_free_value(&root);

            goto config_parse_fail;
        }

    } else {
        goto config_parse_fail;
    }
    temp = NULL;

    if (ngx_http_oauth_check_shm_generation == 0) {

        if (ngx_http_config_sub_shm_update(root) == NGX_ERROR) {
            json_free_value(&root);

            goto config_parse_fail;
        }

        ngx_http_config_update_peers();
        json_free_value(&root);
        ngx_http_oauth_check_shm_generation++;

        ngx_http_config_clear_event(config_peer);
        return;
    }

    ngx_http_oauth_check_shm_generation++;
    temp = json_find_first_label(root, "data");
    if (temp != NULL && temp->child != NULL) {

        json_t *temp1 = json_find_first_label((json_t *)temp->child, "data");
        if (temp1!= NULL && temp1->child != NULL) {

            json_t *temp2 = json_find_first_label((json_t *)temp1->child, "code");
            if (temp2 != NULL && temp2->child != NULL) {
                if(ngx_strcmp(temp2->child->text, "304") != 0) {

                    if (ngx_http_config_sub_shm_update(root) == NGX_ERROR) {
                        json_free_value(&root);

                        goto config_parse_fail;
                    }

                    ngx_http_config_update_peers();
                }
            } else {
                if (ngx_http_config_sub_shm_update(root) == NGX_ERROR) {
                    json_free_value(&root);

                    goto config_parse_fail;
                }

                ngx_http_config_update_peers();
            }
            temp2 = NULL;
        }
        temp1 = NULL;

    } else {
        temp = NULL;
        json_free_value(&root);

        goto config_parse_fail;
    }
    temp = NULL;
    json_free_value(&root);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, config_peer->pool->log, 0,
                    "oauth config update successfully: %*s ", NAME_LEN, config_peer->name);

    config_peer->state = NGX_TCP_ALL_DONE;

    ngx_http_config_clear_event(config_peer);

    return;

config_parse_fail:

    config_peer->state = NGX_TCP_ALL_DONE;
    ngx_http_config_clear_event(config_peer);
}


static ngx_int_t
ngx_http_config_sub_shm_update(json_t *root)
{
    json_t *temp, *temp0, *temp1;
    json_t *cache = NULL;
    char *tmp, *tmp_temp, *unescape_text;

//    ngx_int_t                       i;
    ngx_http_sub_t                 *sub;
    ngx_http_oauth_sub_shm_t       *sub_peers_ctx = sub_ctx->sub_shm;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sub_peers_ctx->pool->log, 0, "sub_shm_update");

    temp = json_find_first_label(root, "data");
    if (temp == NULL) {
        return NGX_ERROR;
    }

    temp0 = json_find_first_label((json_t *)temp->child, "meta");
    if (temp0 != NULL && temp0->child != NULL) {

        temp1 = json_find_first_label((json_t *)temp0->child, "etag");
        if (temp1 != NULL && temp1->child != NULL) {

            ngx_memcpy(sub_peers_ctx->meta->etag.data, temp1->child->text, ETAG_LEN);
        }
        temp1 = NULL;
    }
    temp0 = NULL;

    temp0 = json_find_first_label((json_t *)temp->child, "data");
    if (temp0 != NULL && temp0->child != NULL) {

        temp1 = json_find_first_label((json_t *)temp0->child, "res");
        if (temp1 != NULL && temp1->child != NULL) {

            json_t *temp2 = json_find_first_label((json_t *)temp1->child, "cache");
            if (temp2 != NULL && temp2->child != NULL) {

                json_tree_to_string(temp2, &tmp);
                tmp_temp = tmp;
                tmp += ngx_strlen("\"cache:\"[");
                *(tmp + (ngx_strlen(tmp) - 1)) = '\0';
                if (json_parse_document(&cache, tmp) != JSON_OK) {
                    json_free_value(&cache);
                    ngx_free(tmp);
                    
                    return NGX_ERROR;
                }

                json_t *temp3 = json_find_first_label(cache, "host");
                if (temp3 != NULL && temp3->child != NULL) {
                    ngx_memzero(sub_peers_ctx->res->cache->host, NAME_LEN);
                    ngx_memcpy(sub_peers_ctx->res->cache->host, temp3->child->text, 
                                                    ngx_strlen(temp3->child->text));
                }
                temp3 = NULL;

                temp3 = json_find_first_label(cache, "port");
                if (temp3 != NULL && temp3->child != NULL) {
                    sub_peers_ctx->res->cache->port = ngx_atoi((u_char *)temp3->child->text, 
                                                            ngx_strlen(temp3->child->text));
                }
                temp3 = NULL;

                json_free_value(&cache);
                ngx_free(tmp_temp);
            }
            temp2 = NULL;

            temp2 = json_find_first_label((json_t *)temp1->child, "http");
            if (temp2 != NULL && temp2->child != NULL) {

                json_t *temp3 = json_find_first_label((json_t *)temp2->child, "validate");
                if (temp3 != NULL && temp3->child != NULL) {

                    char *data = temp3->child->text + ngx_strlen("http:\\/\\/");
                    char *data1 = data;
                    for ( ; *data != '/'; data++) { /* void */}

                    ngx_memzero(sub_peers_ctx->res->http->host, NAME_LEN);
                    ngx_memcpy(sub_peers_ctx->res->http->host, data1, data - data1 - 1);
                    ngx_memcpy(sub_peers_ctx->res->http->url, data, ngx_strlen(data));
                }
                temp3 = NULL;

                temp3 = json_find_first_label((json_t *)temp2->child, "port");
                if (temp3 != NULL && temp3->child != NULL) {
                    sub_peers_ctx->res->http->port = ngx_atoi((u_char *)temp3->child->text, 
                                                           ngx_strlen(temp3->child->text));
                } else {
                    sub_peers_ctx->res->http->port = 80;
                }
                temp3 = NULL;

            }
            temp2 = NULL;

        }
        temp1 = NULL;

        temp1 = json_find_first_label((json_t *)temp0->child, "key");
        if (temp1 != NULL && temp1->child != NULL) {

            json_t *temp2 = json_find_first_label((json_t *)temp1->child, "sub");
            if (temp2 != NULL && temp2->child != NULL) {

                sub = sub_peers_ctx->key->sub;
//                for (i = 0; i < 3; i++) {
                    json_t *temp3 = json_find_first_label((json_t *)temp2->child, "v1");
                    if (temp3 != NULL && temp3->child != NULL) {

                        json_t *temp4 = json_find_first_label((json_t *)temp3->child, "key");
                        if (temp4 != NULL && temp4->child != NULL) {
                            ngx_memcpy(sub[0].key, temp4->child->text, ngx_strlen(temp4->child->text));
                        }
                        temp4 = NULL;

                        temp4 = json_find_first_label((json_t *)temp3->child, "pub_key");
                        if (temp4 != NULL && temp4->child != NULL) {
                            unescape_text = json_unescape(temp4->child->text);
                            ngx_sprintf(sub[0].pub_key, "%*s", ngx_strlen(unescape_text), unescape_text);
                            ngx_free(unescape_text);
                        }
                        temp4 = NULL;

                    }
                    temp3 = NULL;

                    temp3 = json_find_first_label((json_t *)temp2->child, "v2");
                    if (temp3 != NULL && temp3->child != NULL) {

                        json_t *temp4 = json_find_first_label((json_t *)temp3->child, "key");
                        if (temp4 != NULL && temp4->child != NULL) {
                            ngx_memcpy(sub[1].key, temp4->child->text, ngx_strlen(temp4->child->text));
                        }
                        temp4 = NULL;

                        temp4 = json_find_first_label((json_t *)temp3->child, "pub_key");
                        tmp = temp4->child->text;
                        if (temp4 != NULL && temp4->child != NULL) {
                            unescape_text = json_unescape(temp4->child->text);
                            ngx_sprintf(sub[1].pub_key, "%*s", ngx_strlen(unescape_text), unescape_text);
                            ngx_free(unescape_text);
                        }
                        temp4 = NULL;

                    }
                    temp3 = NULL;

                    temp3 = json_find_first_label((json_t *)temp2->child, "v3");
                    if (temp3 != NULL && temp3->child != NULL) {

                        json_t *temp4 = json_find_first_label((json_t *)temp3->child, "key");
                        if (temp4 != NULL && temp4->child != NULL) {
                            ngx_memcpy(sub[2].key, temp4->child->text, ngx_strlen(temp4->child->text));
                        }
                        temp4 = NULL;

                        temp4 = json_find_first_label((json_t *)temp3->child, "pub_key");
                        if (temp4 != NULL && temp4->child != NULL) {
                            unescape_text = json_unescape(temp4->child->text);
                            ngx_sprintf(sub[2].pub_key, "%*s", ngx_strlen(unescape_text), unescape_text);
                            ngx_free(unescape_text);
                        }
                        temp4 = NULL;

                    }
                    temp3 = NULL;
//                }

            }
            temp2 = NULL;
        }
        temp1 = NULL;
    }
    temp0 = NULL;
    temp  = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_config_update_peers()
{
    ngx_url_t                      u;
    ngx_uint_t                     i, j, count = 0, flag = 0;
    ngx_http_resource_t           *peers;
    ngx_http_http_peer_t          *http_peer;
    ngx_http_http_peers_t         *http_peers;
    ngx_http_oauth_sub_shm_t      *sub_shm;
    ngx_http_memcache_peer_t      *memcache_peer;
    ngx_http_memcache_peers_t     *memcache_peers;

    sub_shm = sub_ctx->sub_shm;
    http_peers = sub_ctx->http_peers;
    memcache_peers = sub_ctx->memcache_peers;
    peers = sub_shm->res;
    memcache_peers->updating_times++;
    memcache_peer = memcache_peers->peers;

    http_peer = sub_ctx->http_peers->peers;

    ngx_log_debug0(NGX_LOG_DEBUG, sub_shm->pool->log, 0, "http_update_peers");

    u.host.data = peers->cache->host;
    u.host.len = ngx_strlen(peers->cache->host);
    u.port = (in_port_t)peers->cache->port;

    ngx_reset_pool(sub_shm->pool);

    if (ngx_inet_resolve_host(sub_shm->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, sub_shm->pool->log, 0,
                          "%s in upstream \"%V\" ", u.err, &u.host);
        }

        return NGX_ERROR;
    }

    for (i = 0; i < u.naddrs; i++) {
        for (j = 0; j < memcache_peers->count; j++) {

            if (ngx_memn2cmp((u_char *) u.addrs[i].sockaddr, (u_char *)memcache_peer[j].sockaddr,
                                            u.addrs[i].socklen, memcache_peer[j].socklen) != 0) {
                count++;
            }
        }
        if (count == memcache_peers->count) {
            flag = 1; count = 0;
            break;
        }
        count = 0;
    }

    if (flag == 1) {
        flag = 0;
        ngx_http_config_delete_memcache_timers(memcache_peers);
        memcache_peers->count = u.naddrs;

        for (i = 0; i < u.naddrs; i++) {
            ngx_memcpy(&memcache_peer[i].sockaddr, u.addrs[i].sockaddr, u.addrs[i].socklen);
            memcache_peer[i].socklen     = u.addrs[i].socklen;
            ngx_memzero(&memcache_peer[i].name, NAME_LEN);
            ngx_memcpy(&memcache_peer[i].name, u.addrs[i].name.data, u.addrs[i].name.len);
        }
        ngx_http_config_update_memcache_peer(memcache_peers);
    }

    u.host.data = peers->http->host;
    u.host.len = ngx_strlen(peers->http->host);
    u.port = (in_port_t)peers->http->port;

    if (ngx_inet_resolve_host(sub_shm->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, sub_shm->pool->log, 0,
                          "%s in upstream \"%V\" ", u.err, &u.host);
        }

        return NGX_ERROR;
    }

    for (i = 0; i < u.naddrs; i++) {
        for (j = 0; j < http_peers->count; j++) {

            if (ngx_memn2cmp((u_char *) u.addrs[i].sockaddr, (u_char *)memcache_peer[j].sockaddr,
                                            u.addrs[i].socklen, memcache_peer[j].socklen) != 0) {
                count++;
            }
        }
        if (count == http_peers->count) {
            flag = 1; count = 0;
            break;
        }
        count = 0;
    }

    if (flag == 1) {
        flag = 0;
        ngx_http_config_delete_http_timers(http_peers);
        http_peers->count = u.naddrs;

        for (i = 0; i < u.naddrs; i++) {
            ngx_memcpy(&http_peer[i].sockaddr, u.addrs[i].sockaddr, u.addrs[i].socklen);
            http_peer[i].socklen  =  u.addrs[i].socklen;
            ngx_memzero(&http_peer[i].name, NAME_LEN);
            ngx_memcpy(&http_peer[i].name, u.addrs[i].name.data, u.addrs[i].name.len);
        }
        ngx_http_config_update_http_peer(http_peers);
    }

    return NGX_OK;
}


static void
ngx_http_config_update_memcache_peer(ngx_http_memcache_peers_t *memcache_peers)
{
    ngx_uint_t                             i, count;
    ngx_http_memcache_peer_t              *memcache_peer;

    memcache_peer = memcache_peers->peers;
    count = memcache_peers->count;

    ngx_log_debug0(NGX_LOG_DEBUG, ngx_cycle->log, 0, "config_update_memcache_peer");

    for(i = 0; i < count; i++) {
        memcache_peer[i].current_weight = 0;
        memcache_peer[i].effective_weight = 1;
        memcache_peer[i].weight = 1;

        memcache_peer[i].down = 0;
        memcache_peer[i].check_times = 0;
        memcache_peer[i].free_connection = 0;
        memcache_peer[i].using_connection = 0;

        memcache_peer[i].check_ev.handler = ngx_http_memcache_check_handler;
        memcache_peer[i].check_ev.log = ngx_cycle->log;
        memcache_peer[i].check_ev.data = &memcache_peer[i];
        memcache_peer[i].check_ev.timer_set = 0;

        memcache_peer[i].check_timeout_ev.handler = ngx_http_check_memcache_timeout;
        memcache_peer[i].check_timeout_ev.log = ngx_cycle->log;
        memcache_peer[i].check_timeout_ev.data = &memcache_peer[i];
        memcache_peer[i].check_timeout_ev.timer_set = 0;

        ngx_memzero(&memcache_peer[count].pc, sizeof(ngx_peer_connection_t));

        memcache_peer[i].pc.sockaddr = (struct sockaddr *)memcache_peer[i].sockaddr;
        memcache_peer[i].pc.socklen = memcache_peer[i].socklen;

        if (memcache_peer[i].pc.name == NULL) {
            memcache_peer[i].pc.name = ngx_alloc(sizeof(ngx_str_t), ngx_cycle->log);
        }
        memcache_peer[i].pc.name->data = memcache_peer[i].name;
        memcache_peer[i].pc.name->len = ngx_strlen(memcache_peer[i].name);
        memcache_peer[i].pc.get = ngx_event_get_peer;
        memcache_peer[i].pc.log = ngx_cycle->log;
        memcache_peer[i].pc.log_error = NGX_ERROR_ERR;

        memcache_peer[i].pc.cached = 0;
        memcache_peer[i].pc.connection = NULL;
    }

    return;
}


static void
ngx_http_config_update_http_peer(ngx_http_http_peers_t *http_peers)
{
    ngx_uint_t                             i, count;
    ngx_http_http_peer_t                  *http_peer;

    http_peer = http_peers->peers;
    count = http_peers->count;

    ngx_log_debug0(NGX_LOG_DEBUG, ngx_cycle->log, 0, "config_update_http_peer");

    for(i = 0; i < count; i++) {
        http_peer[i].current_weight = 0;
        http_peer[i].effective_weight = 1;
        http_peer[i].weight = 1;
        http_peer[i].down = 0;

        http_peer[i].http_idc = &sub_ctx->idc;

        http_peer[i].check_timeout_ev.handler = ngx_http_http_check_handler;
        http_peer[i].check_timeout_ev.log = ngx_cycle->log;
        http_peer[i].check_timeout_ev.data = &http_peer[i];
        http_peer[i].check_timeout_ev.timer_set = 0;

        ngx_memzero(&http_peer[i].pc, sizeof(ngx_peer_connection_t));

        http_peer[i].pc.sockaddr = (struct sockaddr *)http_peer[i].sockaddr;
        http_peer[i].pc.socklen = http_peer[i].socklen;

        if (http_peer[i].pc.name == NULL) {
            http_peer[i].pc.name = ngx_alloc(sizeof(ngx_str_t), ngx_cycle->log);
        }
        http_peer[i].pc.name->data = http_peer[i].name;
        http_peer[i].pc.name->len = ngx_strlen(http_peer[i].name);

        http_peer[i].pc.get = ngx_event_get_peer;
        http_peer[i].pc.log = ngx_cycle->log;
        http_peer[i].pc.log_error = NGX_ERROR_ERR;

        http_peer[i].pc.cached = 0;
        http_peer[i].pc.connection = NULL;
    }

    return;
}


static void
ngx_http_config_delete_memcache_timers(ngx_http_memcache_peers_t *memcache_peers)
{
    ngx_uint_t                             i, count;
    ngx_connection_t                      *c;
    ngx_http_memcache_peer_t              *memcache_peer;

    memcache_peer = memcache_peers->peers;
    count = memcache_peers->count;

    ngx_log_debug0(NGX_LOG_DEBUG, ngx_cycle->log, 0, "config_delete_memcache_timer");

    for(i = 0; i < count; i++) {

        if (memcache_peer[i].check_timeout_ev.timer_set) {
            ngx_del_timer(&memcache_peer->check_timeout_ev);
        }

        if (memcache_peer[i].check_ev.timer_set) {
            ngx_del_timer(&memcache_peer->check_ev);
        }

        c = memcache_peer[i].pc.connection;

        if (c) {
            ngx_close_connection(c);
            memcache_peer->pc.connection = NULL;
        }
    }

    return;
}


static void
ngx_http_config_delete_http_timers(ngx_http_http_peers_t *http_peers)
{
    ngx_uint_t                             i, count;
    ngx_connection_t                      *c;
    ngx_http_http_peer_t                  *http_peer;

    http_peer = http_peers->peers;
    count = http_peers->count;

    ngx_log_debug0(NGX_LOG_DEBUG, ngx_cycle->log, 0, "config_delete_http_timer");

    for(i = 0; i < count; i++) {

        if (http_peer[i].check_timeout_ev.timer_set) {
            ngx_del_timer(&http_peer->check_timeout_ev);
        }

        c = http_peer[i].pc.connection;

        if (c) {
            ngx_close_connection(c);
            http_peer->pc.connection = NULL;
        }
    }

    return;
}

