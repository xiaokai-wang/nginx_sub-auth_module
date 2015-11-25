#include "ngx_http_oauth_service_module.h"


static ngx_int_t ngx_http_sub_shm_init_res(ngx_http_resource_t **res, ngx_pool_t *pool);
static ngx_int_t ngx_http_sub_shm_init_res_cache(ngx_http_memcache_server_t **cache, ngx_pool_t *pool);
static ngx_int_t ngx_http_sub_shm_init_res_http(ngx_http_http_server_t **http, ngx_pool_t *pool);
static ngx_int_t ngx_http_sub_shm_init_key(ngx_http_key_t **sub_key, ngx_pool_t *pool);
static ngx_int_t ngx_http_sub_shm_init_key_sub(ngx_http_sub_t **sub, ngx_pool_t *pool);
static ngx_int_t ngx_http_sub_shm_init_meta(ngx_http_meta_t **meta, ngx_pool_t *pool);


char *sub_failed = "{\"error\":\"uid invalide\"}";
char *sub_signed = "{\"error\":\"sub signed invalide\"}";


void
ngx_http_sub_auth(ngx_http_request_t *r)
{
    u_char                                   *data, *key;
    u_char                                    str[12] = {'\0'}, str1[12] = {'\0'};
    ngx_uint_t                                len = 0, i;
    ngx_str_t                                *sub;
    ngx_http_oauth_sub_shm_t                 *sub_shm;
    ngx_http_oauth_service_ctx_t             *ctx;
    ngx_http_oauth_keepalive_peer_data_t     *mkp;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_service_module);

    sub = &ctx->sub;
    sub_shm = sub_ctx->sub_shm;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "sub auth: %V", sub);

    mkp = ngx_palloc(r->pool, sizeof(ngx_http_oauth_keepalive_peer_data_t));
    mkp->request = r;
    ngx_memzero(&mkp->pc, sizeof(ngx_peer_connection_t));

    mkp->pc.get = ngx_event_get_peer;
    mkp->pc.log = r->connection->log;
    mkp->pc.log_error = NGX_ERROR_ERR;
    mkp->pc.cached = 0;
    mkp->pc.connection = NULL;

    mkp->state = 0;
    mkp->check_timeout_ev.timer_set = 0;

    if (sub->len == 0) {
        ngx_http_finalize_request_failed(mkp);
        return;
    }

    ngx_sub_validate(r, sub, &data, sub_shm->key->sub);

    if (data == NULL) {
        ctx->sub_signed_flag = 1;
        ngx_http_finalize_request_failed(mkp);
        return;
    }

    if (ngx_http_memcache_make_key(r, data + 1) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    uint64_t ctime = (uint64_t)(ctx->ctime.data[3] & 0xff);
    ctime |= (uint64_t)((ctx->ctime.data[2] << 8) & 0xff00);
    ctime |= (uint64_t)((ctx->ctime.data[1] << 16) & 0xff0000);
    ctime |= (uint64_t)((ctx->ctime.data[0] << 24) & 0xff000000);

    ctime -= FIXED_TIME;

    ngx_base62_encode(ctime, str1, 12);

    u_char *str2 = ngx_pcalloc(r->pool, ctx->domain.len * 12);
    for (i = 0; i < ctx->domain.len; i++) {
        ngx_base62_encode((uint64_t)ctx->domain.data[i], str, 12);
        ngx_sprintf(str2 + len, "%s", str);
        len = ngx_strlen(str2);
        ngx_memset(str, '\0', 12);
    }

    ctx->memcache_key.len = ctx->uid.len +ctx->rand.len +ngx_strlen(str2) +ngx_strlen(str1) +ngx_strlen("{}_");
    ctx->memcache_key.data = ngx_pcalloc(r->pool, ctx->memcache_key.len);

    key = ctx->memcache_key.data;

    ngx_sprintf(key, "{%*s}_", ctx->uid.len, ctx->uid.data);
    len = ngx_strlen(key);

    ngx_sprintf(key + len, "%*s", ctx->rand.len, ctx->rand.data);
    len = ngx_strlen(key);

    ngx_sprintf(key + len, "%s", str2);
    len = ngx_strlen(key);

    ngx_sprintf(key + len, "%s", str1);

   if (ngx_http_memcache_connect_handler(mkp) != NGX_OK) {
        ngx_http_finalize_request_success(mkp);
   }

}


void *
ngx_http_sub_shm_init(ngx_conf_t *cf, void *conf)
{
    ngx_http_oauth_service_main_conf_t     *osmcf = conf;
    ngx_http_oauth_sub_shm_t               *sub_shm;

    sub_shm = osmcf->sub_shm;

    if (ngx_http_sub_shm_init_res(&sub_shm->res,
                                        cf->pool) == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_sub_shm_init_key(&sub_shm->key,
                                        cf->pool) == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_sub_shm_init_meta(&sub_shm->meta,
                                        cf->pool) == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_sub_shm_init_res(ngx_http_resource_t **res, ngx_pool_t *pool)
{
    *res = ngx_pcalloc(pool, sizeof(ngx_http_resource_t));
    if (*res == NULL) {
        return NGX_ERROR;
    }


    if (ngx_http_sub_shm_init_res_cache(&(*res)->cache, 
                                                pool) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0, "sub_shm_init_res_cache failed");
        return NGX_ERROR;
    }


    if (ngx_http_sub_shm_init_res_http(&(*res)->http, 
                                                pool) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0, "sub_shm_init_res_http failed");
        return NGX_ERROR;
    }

    (*res)->udp = NGX_CONF_UNSET_PTR;

    return NGX_OK;
}


static ngx_int_t
ngx_http_sub_shm_init_res_cache(ngx_http_memcache_server_t **cache,
                                                       ngx_pool_t *pool)
{
    *cache = ngx_pcalloc(pool, sizeof(ngx_http_memcache_server_t));
    if (*cache == NULL) {
        return NGX_ERROR;

    }

    ngx_memset((*cache)->host, '\0', NAME_LEN);
    ngx_memset((*cache)->status, '\0', 8);

    (*cache)->port = NGX_CONF_UNSET_UINT;

    return NGX_OK;
}


static ngx_int_t
ngx_http_sub_shm_init_res_http(ngx_http_http_server_t **http,
                                                    ngx_pool_t *pool)
{
    *http = ngx_pcalloc(pool, sizeof(ngx_http_http_server_t));
    if (*http == NULL) {
        return NGX_ERROR;

    }

    ngx_memset((*http)->host, '\0', NAME_LEN);
    ngx_memset((*http)->url, '\0', NAME_LEN);
    ngx_memset((*http)->status, '\0', 8);

    ngx_memcpy((*http)->host, sub_ctx->http_host.data, sub_ctx->http_host.len);

    (*http)->port = sub_ctx->http_port;

    return NGX_OK;
}


static ngx_int_t
ngx_http_sub_shm_init_key(ngx_http_key_t **sub_key,
                                                ngx_pool_t *pool)
{
    *sub_key = ngx_pcalloc(pool, sizeof(ngx_http_key_t));
    if (*sub_key == NULL) {
        return NGX_ERROR;

    }

    if (ngx_http_sub_shm_init_key_sub(&(*sub_key)->sub, 
                                               pool) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0, "sub_shm_init_key_sub failed");
        return NGX_ERROR;

    } 

    (*sub_key)->subp        = NGX_CONF_UNSET_PTR;
    (*sub_key)->checkgsid   = NGX_CONF_UNSET_PTR;
    (*sub_key)->suesup      = NGX_CONF_UNSET_PTR;

    return NGX_OK;
}


static ngx_int_t
ngx_http_sub_shm_init_key_sub(ngx_http_sub_t **sub,
                                                ngx_pool_t *pool)
{
    ngx_int_t i;

    *sub = ngx_pcalloc(pool, sizeof(ngx_http_sub_t) * 3);
    if (*sub == NULL) {
        return NGX_ERROR;

    }

    for (i = 0; i < 3; i++) {
        ngx_memset((*sub)[i].key, '\0', 40);
        ngx_memset((*sub)[i].pub_key, '\0', 240);
    }

    ngx_sprintf((*sub)[0].key, "%V", &sub_ctx->sub_key.rc4_data_v1);
    ngx_sprintf((*sub)[1].key, "%V", &sub_ctx->sub_key.rc4_data_v2);
    ngx_sprintf((*sub)[2].key, "%V", &sub_ctx->sub_key.rc4_data_v3);

    ngx_sprintf((*sub)[0].pub_key, "%V", &sub_ctx->sub_key.rsa_key_v1);
    ngx_sprintf((*sub)[1].pub_key, "%V", &sub_ctx->sub_key.rsa_key_v2);
    ngx_sprintf((*sub)[2].pub_key, "%V", &sub_ctx->sub_key.rsa_key_v3);

    return NGX_OK;
}


static ngx_int_t
ngx_http_sub_shm_init_meta(ngx_http_meta_t **meta,
                                                ngx_pool_t *pool)
{
    *meta = ngx_pcalloc(pool, sizeof(ngx_http_meta_t));
    if (*meta == NULL) {
        return NGX_ERROR;
    }

    (*meta)->etag.data = ngx_pcalloc(pool, ETAG_LEN);
    (*meta)->etag.len = ETAG_LEN;

    ngx_memset((*meta)->etag.data, '\0', ETAG_LEN);

    (*meta)->expire  = NGX_CONF_UNSET_MSEC;
    (*meta)->ctime   = NGX_CONF_UNSET_MSEC;

    return NGX_OK;
}


void
ngx_http_finalize_request_success(ngx_http_oauth_keepalive_peer_data_t *mkp)
{
    ngx_int_t                              len;
    ngx_buf_t                             *b = NULL;
    ngx_http_request_t                    *r;
    ngx_http_variable_value_t             *oauth;
    ngx_http_oauth_service_ctx_t          *ctx;

    if (mkp->check_timeout_ev.timer_set) {
        ngx_del_timer(&mkp->check_timeout_ev);
    }

    r = mkp->request;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_service_module);

    ngx_log_debug0(NGX_LOG_DEBUG, r->connection->log, 0, "finalize_request_success");

    oauth = ngx_http_get_indexed_variable(r, oauth_index);
    oauth->data = ngx_palloc(r->pool, ngx_strlen("oauth_succeed"));
    ngx_sprintf(oauth->data, "oauth_succeed");

    r->headers_out.content_length_n = ctx->uid.len;

    len = ngx_strlen("{\"uid\":\"\"}") + ctx->uid.len;
 
    b = ngx_create_temp_buf(r->pool, ctx->uid.len);
    b->pos = ngx_pcalloc(r->pool, len);
    b->last = ngx_sprintf(b->pos, "{\"uid\":\"%V\"}", &ctx->uid);

    b->last_buf = 1;
    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
 
    r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
    ngx_int_t ret = ngx_http_send_header(r);
    ret = ngx_http_output_filter(r, &out);
 
    ngx_http_finalize_request(r, ret);
    return;
}


void
ngx_http_finalize_request_failed(ngx_http_oauth_keepalive_peer_data_t *mkp)
{
    ngx_buf_t                             *b = NULL;
    ngx_http_request_t                    *r;
    ngx_http_oauth_service_ctx_t          *ctx;

    if (mkp->check_timeout_ev.timer_set) {
        ngx_del_timer(&mkp->check_timeout_ev);
    }

    r = mkp->request;

    ngx_log_debug0(NGX_LOG_DEBUG, r->connection->log, 0, "finalize_request_failed");

    ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_service_module);

    if (ctx->sub_signed_flag == 1) {
        r->headers_out.content_length_n = ngx_strlen(sub_signed);

        b = ngx_create_temp_buf(r->pool, ngx_strlen(sub_signed));
        b->pos = (u_char *)sub_signed;
        b->last = b->pos + ngx_strlen(sub_signed);

    } else {
        r->headers_out.content_length_n = ngx_strlen(sub_failed);

        b = ngx_create_temp_buf(r->pool, ngx_strlen(sub_failed));
        b->pos = (u_char *)sub_failed;
        b->last = b->pos + ngx_strlen(sub_failed);
    }

    b->last_buf = 1;
    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    r->headers_out.status = NGX_HTTP_UNAUTHORIZED;
    r->headers_out.content_length_n = b->last - b->pos;
    ngx_str_set(&r->headers_out.content_type, "text/plain");

    r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
    ngx_int_t ret = ngx_http_send_header(r);
    ret = ngx_http_output_filter(r, &out);
 
    ngx_http_finalize_request(r, ret);
    return;
}


ngx_int_t
ngx_http_oauth_service_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        if (c->write->pending_eof || c->read->pending_eof) {
            if (c->write->pending_eof) {
                err = c->write->kq_errno;

            } else {
                err = c->read->kq_errno;
            }

            c->log->action = "oauth service connecting to upstream";
            (void) ngx_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_errno;
        }

        if (err) {
            c->log->action = "oauth_service_test_connect: connecting to memcache";
            (void) ngx_connection_error(c, err, "oauth_service_test_connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_oauth_service_parse_status_line(ngx_buf_t *b, ngx_http_status_t *status)
{
    u_char   ch;
    u_char  *p;
    enum {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_status,
        sw_space_after_status,
        sw_status_text,
        sw_almost_done
    } state;

    state = 0;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            switch (ch) {
            case 'H':
                state = sw_H;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_H:
            switch (ch) {
            case 'T':
                state = sw_HT;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_HT:
            switch (ch) {
            case 'T':
                state = sw_HTT;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_HTT:
            switch (ch) {
            case 'P':
                state = sw_HTTP;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        /* the first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return NGX_ERROR;
            }

            state = sw_major_digit;
            break;

        /* the major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            break;

        /* the first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            state = sw_minor_digit;
            break;

        /* the minor HTTP version or the end of the request line */
        case sw_minor_digit:
            if (ch == ' ') {
                state = sw_status;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            break;

        /* HTTP status code */
        case sw_status:
            if (ch == ' ') {
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            status->code = status->code * 10 + ch - '0';

            if (++status->count == 3) {
                state = sw_space_after_status;
                status->start = p - 2;
            }

            break;

        /* space or end of line */
        case sw_space_after_status:
            switch (ch) {
            case ' ':
                state = sw_status_text;
                break;
            case '.':                    /* IIS may send 403.1, 403.2, etc */
                state = sw_status_text;
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                return NGX_ERROR;
            }
            break;

        /* any text until end of line */
        case sw_status_text:
            switch (ch) {
            case CR:
                state = sw_almost_done;

                break;
            case LF:
                goto done;
            }
            break;

        /* end of status line */
        case sw_almost_done:
            status->end = p - 1;
            switch (ch) {
            case LF:
                goto done;
            default:
                return NGX_ERROR;
            }
        }
    }

    b->pos = p;

    return NGX_AGAIN;

done:

    b->pos = p + 1;
/*
    if (status->end == NULL) {
        status->end = p;
    }
*/
    return NGX_OK;

}


ngx_int_t
ngx_http_oauth_service_parse_header(ngx_buf_t *b, ngx_uint_t allow_underscores)
{
    u_char      c, ch, *p;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_ignore_line,
        sw_almost_done,
        sw_header_almost_done
    } state;

    /* the last '\0' is not needed because string is zero terminated */

    static u_char  lowcase[] =
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0" "0123456789\0\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    state = 0;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        /* first char */
        case sw_start:

            switch (ch) {
            case CR:
                state = sw_header_almost_done;
                break;
            case LF:
                goto header_done;
            default:
                state = sw_name;

                c = lowcase[ch];

                if (c) {
                    break;
                }

                if (ch == '\0') {
                    return NGX_HTTP_PARSE_INVALID_HEADER;
                }

                break;

            }
            break;

        /* header name */
        case sw_name:
            c = lowcase[ch];

            if (c) {
                break;
            }

            if (ch == '_') {
                break;
            }

            if (ch == ':') {
                state = sw_space_before_value;
                break;
            }

            if (ch == CR) {
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                goto done;
            }

            /* IIS may send the duplicate "HTTP/1.1 ..." lines */
            if (ch == '/')
            {
                state = sw_ignore_line;
                break;
            }

            if (ch == '\0') {
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }

            break;

        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            case '\0':
                return NGX_HTTP_PARSE_INVALID_HEADER;
            default:
                state = sw_value;
                break;
            }
            break;

        /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                state = sw_space_after_value;
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            case '\0':
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }
            break;

        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            case '\0':
                return NGX_HTTP_PARSE_INVALID_HEADER;
            default:
                state = sw_value;
                break;
            }
            break;

        /* ignore header line */
        case sw_ignore_line:
            switch (ch) {
            case LF:
                state = sw_start;
                break;
            default:
                break;
            }
            break;

        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            case CR:
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }
            break;

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }
        }
    }

    b->pos = p;

    return NGX_AGAIN;

done:

    b->pos = p + 1;

    return NGX_OK;

header_done:

    b->pos = p + 1;

    return NGX_HTTP_PARSE_HEADER_DONE;
}


void
ngx_http_oauth_service_keepalive_close(ngx_connection_t *c)
{
    if (c != NULL) {
        c->write->handler = ngx_http_oauth_service_keepalive_dummy_handler;
        c->read->handler = ngx_http_oauth_service_keepalive_dummy_handler;

        ngx_close_connection(c);
    }

    return;
}


void
ngx_http_oauth_service_keepalive_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                           "oauth service keepalive dummy handler");
}


ngx_int_t
ngx_http_oauth_service_need_exit()
{
    if (ngx_terminate || ngx_exiting || ngx_quit) {
        ngx_http_oauth_service_clear_all_events();
        return 1;
    }

    return 0;
}


void
ngx_http_oauth_service_clear_all_events()
{
    ngx_uint_t                             i;
    ngx_http_config_peer_t                *config_peer;
    ngx_http_oauth_sub_shm_t              *sub_peers_ctx;
    ngx_http_memcache_peer_t              *memcache_peer;
    ngx_http_memcache_peers_t             *memcache_peers;

    static ngx_flag_t                has_cleared = 0;

    sub_peers_ctx  = sub_ctx->sub_shm;
    memcache_peers = sub_ctx->memcache_peers;
    memcache_peer  = memcache_peers->peers;
    config_peer = sub_ctx->config_peer;

    if (has_cleared || sub_ctx == NULL) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                  "oauth_service_clear_all the events on %P ", ngx_pid);

    has_cleared = 1;

    if (config_peer->check_timer_ev.timer_set) {
        ngx_del_timer(&config_peer->check_timer_ev);
    }

    for (i = 0; i < memcache_peers->count; i++) {

        if (memcache_peer[i].check_ev.timer_set) {
            ngx_del_timer(&memcache_peer[i].check_ev);
        }
    }

    if (sub_peers_ctx->pool != NULL) {
        ngx_destroy_pool(sub_peers_ctx->pool);
        sub_peers_ctx->pool = NULL;
    }

    if (config_peer->pool != NULL) {
        ngx_destroy_pool(config_peer->pool);
        config_peer->pool = NULL;
    }

    return;
}


char *
ngx_http_oauth_service_set_sub_show(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_oauth_service_sub_show;

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_oauth_service_sub_show(ngx_http_request_t *r)
{
    ngx_int_t                              rc, ret;
    ngx_uint_t                             i;
    ngx_buf_t                             *b;
    ngx_chain_t                            out;
    ngx_http_sub_t                        *sub;
    ngx_http_memcache_peer_t               memcache_peer;
    ngx_http_memcache_peers_t             *memcache_peers;

    sub = sub_ctx->sub_shm->key->sub;
    memcache_peers = sub_ctx->memcache_peers;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc; 
    }

    ngx_str_set(&r->headers_out.content_type, "text/plain");
    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    b = ngx_create_temp_buf(r->pool, ngx_pagesize);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    out.buf = b;
    out.next = NULL;

    b->last = ngx_snprintf(b->last,b->end - b->last, "Work process: %P ", ngx_pid);
    b->last = ngx_snprintf(b->last,b->end - b->last, "Config pull times: %d ", 
                                                   ngx_http_oauth_check_shm_generation);
    b->last = ngx_snprintf(b->last,b->end - b->last, "Config update times: %d \n\n", 
                                                        memcache_peers->updating_times);

    if (ngx_http_oauth_check_shm_generation !=0 ) {
        b->last = ngx_snprintf(b->last,b->end - b->last, "\nSub configurations: \n");
        b->last = ngx_snprintf(b->last,b->end - b->last, "\trsa_key_V1: \"%*s\"\n", 
                                            ngx_strlen(sub[0].pub_key), sub[0].pub_key);
        b->last = ngx_snprintf(b->last,b->end - b->last, "\trc4_data_V1: %*s\n\n", 
                                            ngx_strlen(sub[0].key), sub[0].key);
        b->last = ngx_snprintf(b->last,b->end - b->last, "\trsa_key_V2: \"%*s\"\n", 
                                            ngx_strlen(sub[1].pub_key), sub[1].pub_key);
        b->last = ngx_snprintf(b->last,b->end - b->last, "\trc4_data_V2: %*s\n\n", 
                                            ngx_strlen(sub[1].key), sub[1].key);
        b->last = ngx_snprintf(b->last,b->end - b->last, "\trsa_key_V3: \"%*s\"\n", 
                                            ngx_strlen(sub[2].pub_key), sub[2].pub_key);
        b->last = ngx_snprintf(b->last,b->end - b->last, "\trc4_data_V3: %*s\n\n", 
                                            ngx_strlen(sub[2].key), sub[2].key);
    }

    b->last = ngx_snprintf(b->last,b->end - b->last, "\nMemcache status: \n");
    b->last = ngx_snprintf(b->last,b->end - b->last, "\tLive memcache: \n");
    for (i = 0; i < memcache_peers->count; i++) {
        memcache_peer = memcache_peers->peers[i];
        if (memcache_peer.down == 1) {
            continue;
        }
        b->last = ngx_snprintf(b->last,b->end - b->last, "\t\tip: %s free connections: %d\n", 
                                                memcache_peer.name, memcache_peer.free_connection);
        b->last = ngx_snprintf(b->last,b->end - b->last, "\t\tip: %s using connections: %d\n",
                                                memcache_peer.name, memcache_peer.using_connection);
    }

    b->last = ngx_snprintf(b->last,b->end - b->last, "\tDead memcache: \n");
    for (i = 0; i < memcache_peers->count; i++) {
        memcache_peer = memcache_peers->peers[i];
        if (memcache_peer.down == 1) {
            b->last = ngx_snprintf(b->last,b->end - b->last, "\t\tip: %s ", memcache_peer.name);
        }
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;

    r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
    ret = ngx_http_send_header(r);
    ret = ngx_http_output_filter(r, &out);
 
    return ret;
}

