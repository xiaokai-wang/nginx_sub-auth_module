
/*
 * Copyright (C) Weibo/xiaokai
 * Copyright (C) Nginx, Inc.
 */

#include "ngx_http_oauth_service_module.h"

#include "ngx_http_sub.h"
#include "ngx_sub_config.h"
#include "ngx_sub_cache.h"
#include "ngx_sub_db.h"
#include "ngx_http_json.h"

ngx_int_t oauth_index;
ngx_http_oauth_service_main_conf_t   *sub_ctx = NULL;

static char *oauth_server = "{\"error\":\"oauth server network is in trouble\"}";
static char *oauth_parse = "{\"error\":\"oauth parse faild\"}";


static ngx_int_t ngx_http_oauth_service_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_oauth_service_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc);

static void ngx_http_oauth_service_emit(ngx_http_request_t *r);

static ngx_int_t ngx_http_oauth_json_parse(ngx_http_request_t *r, void *data);
static ngx_int_t ngx_http_oauth_service_set_variables(ngx_http_request_t *r,
       ngx_http_oauth_service_loc_conf_t *orcf, ngx_http_oauth_service_ctx_t *ctx);
static ngx_int_t ngx_http_oauth_service_variable(ngx_http_request_t *r,
       ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_oauth_service_init(ngx_conf_t *cf);

static void *ngx_http_oauth_service_create_conf(ngx_conf_t *cf);
static void *ngx_http_oauth_service_create_main_conf(ngx_conf_t *cf);

static void ngx_http_oauth_service_status(ngx_http_request_t *r, void *data);

static char *ngx_http_oauth_service_init_main_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_oauth_service_merge_conf(ngx_conf_t *cf,
       void *parent, void *child);
static char *ngx_http_oauth_service(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);

static char *ngx_http_oauth_service_set(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);

static ngx_int_t ngx_http_oauth_service_init_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_add_header(ngx_http_request_t *r, ngx_str_t *key, 
       ngx_str_t *value);
static ngx_table_elt_t *ngx_http_find_header(ngx_http_request_t *r, 
       ngx_str_t *key);


static ngx_command_t ngx_http_oauth_service_commands[] = {
    { ngx_string("oauth_service"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_oauth_service,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("oauth_service_set"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_oauth_service_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    {  ngx_string("sub_show"),
       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
       ngx_http_oauth_service_set_sub_show,
       0,
       0,
       NULL },
 
    {  ngx_string("oauth_body"),
       NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_str_slot,
       NGX_HTTP_LOC_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_loc_conf_t, oauth_body),
       NULL },

    {  ngx_string("oauth_type"),
       NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_str_slot,
       NGX_HTTP_LOC_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_loc_conf_t, oauth_type),
       NULL },

    {  ngx_string("oauth_switch"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_str_slot,
       NGX_HTTP_LOC_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_loc_conf_t, oauth_switch),
       NULL },

    {  ngx_string("shm_size"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_size_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, shm_size),
       NULL },

    {  ngx_string("idc"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_str_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, idc),
       NULL },

    {  ngx_string("memcache_host"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_str_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, memcache_host),
       NULL },

    {  ngx_string("memcache_port"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_num_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, memcache_port),
       NULL },

    {  ngx_string("memcache_keepalive"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_num_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, memcache_keepalive),
       NULL },

    {  ngx_string("memcache_timeout"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_msec_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, memcache_timeout),
       NULL },

    {  ngx_string("http_host"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_str_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, http_host),
       NULL },

    {  ngx_string("http_port"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_num_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, http_port),
       NULL },

    {  ngx_string("http_timeout"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_msec_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, http_timeout),
       NULL },

    {  ngx_string("http_keepalive"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_num_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, http_keepalive),
       NULL },

    {  ngx_string("rsa_key_v1"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_str_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, sub_key.rsa_key_v1),
       NULL },

    {  ngx_string("rc4_data_v1"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_str_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, sub_key.rc4_data_v1),
       NULL },

    {  ngx_string("rsa_key_v2"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_str_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, sub_key.rsa_key_v2),
       NULL },

    {  ngx_string("rc4_data_v2"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_str_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, sub_key.rc4_data_v2),
       NULL },

    {  ngx_string("rsa_key_v3"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_str_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, sub_key.rsa_key_v3),
       NULL },

    {  ngx_string("rc4_data_v3"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_str_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, sub_key.rc4_data_v3),
       NULL },

    {  ngx_string("config_host"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_str_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, config_host),
       NULL },

    {  ngx_string("config_port"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_num_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, config_port),
       NULL },

    {  ngx_string("config_interval"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_msec_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, config_interval),
       NULL },

    {  ngx_string("config_timeout"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_msec_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, config_timeout),
       NULL },

    {  ngx_string("check_interval"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_msec_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, check_interval),
       NULL },

    {  ngx_string("check_times"),
       NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_num_slot,
       NGX_HTTP_MAIN_CONF_OFFSET,
       offsetof(ngx_http_oauth_service_main_conf_t, check_times),
       NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_oauth_service_module_ctx = {
    NULL,                                       /* preconfiguration */
    ngx_http_oauth_service_init,                /* postconfiguration */

    ngx_http_oauth_service_create_main_conf,    /* create main configuration */
    ngx_http_oauth_service_init_main_conf,      /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    ngx_http_oauth_service_create_conf,         /* create location configuration */
    ngx_http_oauth_service_merge_conf           /* merge location configuration */
};


ngx_module_t  ngx_http_oauth_service_module = {
    NGX_MODULE_V1,
    &ngx_http_oauth_service_module_ctx,    /* module context */
    ngx_http_oauth_service_commands,       /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_oauth_service_init_process,   /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_oauth_service_handler(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_str_t                       args, sub;
    ngx_table_elt_t                *sub_header;
    ngx_http_request_t             *sr;
    ngx_http_variable_value_t      *oauth;
    ngx_http_post_subrequest_t     *ps;
    ngx_http_oauth_service_ctx_t   *ctx;
    ngx_http_oauth_service_loc_conf_t  *orcf;

    orcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_service_module);

    if (orcf->uri.len == 0) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oauth request handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_service_module);

    if (ctx != NULL) {
        if (!ctx->done) {
            return NGX_AGAIN;
        }

        /*
         * as soon as we are done - explicitly set variables to make
         * sure they will be available after internal redirects
         */

        if (ngx_http_oauth_service_set_variables(r, orcf, ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ctx->oauth_flag == 1) {

            oauth = ngx_http_get_indexed_variable(r, oauth_index);
            oauth->data = ngx_palloc(r->pool, ngx_strlen("oauth_succeed"));
            ngx_sprintf(oauth->data, "oauth_succeed");
        }

        if (ngx_strcmp(orcf->oauth_switch.data, "on") == 0 && 
                                      ctx->status < NGX_HTTP_CLIENT_CLOSED_REQUEST) {
            return NGX_OK;
        }

        /* return appropriate status */

        if (ctx->oauth_flag == 0 || ctx->parse_flag == 0) {
            ngx_http_oauth_request_status(r, ctx);

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ctx->status >= NGX_HTTP_OK
            && ctx->status < NGX_HTTP_SPECIAL_RESPONSE)
        {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oauth request unexpected status: %d", ctx->status);

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_oauth_service_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ctx->parse_flag = 1;
    ctx->oauth_flag = 0;

    ngx_http_set_ctx(r, ctx, ngx_http_oauth_service_module);

    ngx_str_set(&sub, SUB);

    if ((sub_header = ngx_http_find_header(r, &sub)) != NULL) {
        ctx->sub.data = sub_header->value.data;
        ctx->sub.len = sub_header->value.len;

        ngx_http_sub_auth(r);
        return NGX_DONE;
    }

    if (ngx_strcmp(orcf->oauth_body.data, "on") == 0) {
        rc = ngx_http_read_client_request_body(r, ngx_http_oauth_service_emit);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return NGX_ERROR;
        }

    } else {

        ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
        if (ps == NULL) {
            return NGX_ERROR;
        }

        ps->handler = ngx_http_oauth_service_done;
        ps->data = ctx;

        ngx_str_t sub_option = ngx_string(OPTION_OAUTH_ARGS);

        /* check the auth type and make the first subrequest to authentication */
        if (ngx_strcmp(orcf->oauth_type.data, "default") == 0) {
            if (ngx_http_subrequest(r, &orcf->uri, &r->args, &sr, ps,
                                    NGX_HTTP_SUBREQUEST_WAITED)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

        } else {
            /* length of arguments that needed by option_type of oauth */
            args.len = r->args.len + sub_option.len;
            args.data = ngx_palloc(r->pool, args.len);

            ngx_snprintf(args.data, args.len, "%V%V", &r->args, &sub_option);

            rc = ngx_http_subrequest(r, &orcf->uri, &args, &sr, ps, 
                                                 NGX_HTTP_SUBREQUEST_WAITED);
        }

        /*
        * allocate fake request body to avoid attempts to read it and to make
        * sure real body file (if already read) won't be closed by upstream
        */

        sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
        if (sr->request_body == NULL) {
            return NGX_ERROR;
        }

        sr->header_only = 1;

        ctx->subrequest = sr;

    }

    return NGX_AGAIN;
}


static void
ngx_http_oauth_service_emit(ngx_http_request_t *r)
{
    ngx_int_t                              rc;
    ngx_str_t                              args;
    ngx_http_request_t                    *sr;
    ngx_http_post_subrequest_t            *ps;
    ngx_http_oauth_service_ctx_t          *ctx;
    ngx_http_oauth_service_loc_conf_t         *orcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oauth_service_module);
    orcf = ngx_http_get_module_loc_conf(r, ngx_http_oauth_service_module);

    ctx->oauth_flag = 0;
    ctx->subrequest = sr;

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ps->handler = ngx_http_oauth_service_done;
    ps->data = ctx;

    ngx_str_t sub_option = ngx_string(OPTION_OAUTH_ARGS);

    /* check the auth type and make the first subrequest to authentication */
    if (ngx_strcmp(orcf->oauth_type.data, "default") == 0) {
        rc = ngx_http_subrequest(r, &orcf->uri, &r->args, &sr, ps, 
                  NGX_HTTP_SUBREQUEST_IN_MEMORY | NGX_HTTP_SUBREQUEST_WAITED);

    } else {
        /* length of arguments that needed by option_type of oauth */
        args.len = r->args.len + sub_option.len;
        args.data = ngx_palloc(r->pool, args.len);

        ngx_snprintf(args.data, args.len, "%V%V", &r->args, &sub_option);

        rc = ngx_http_subrequest(r, &orcf->uri, &args, &sr, ps, 
                   NGX_HTTP_SUBREQUEST_IN_MEMORY | NGX_HTTP_SUBREQUEST_WAITED);
    }

    if (rc != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    sr->method = r->method;
    sr->method_name = r->method_name;
    sr->request_body = r->request_body;

    return;
}


static ngx_int_t
ngx_http_oauth_service_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_int_t                              kv_num = 0, i = 0;
    ngx_http_request_t                    *pr = r->parent;
    ngx_http_oauth_service_ctx_t          *ctx = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oauth request done s:%d", r->headers_out.status);

    ctx->done = 1;
    ctx->status = r->headers_out.status;

    pr->upstream_states = r->upstream_states;
    pr->headers_out.status = r->headers_out.status;

    if ((kv_num = ngx_http_oauth_json_parse(r, data)) == NGX_ERROR) {
        return rc;
    }

    if (kv_num != 0) {

        for (i = 0; i < kv_num; i++) {
            if (ngx_http_add_header(pr, &ctx->oauth_header[i].key, 
                                    &ctx->oauth_header[i].value) != NGX_OK) {
                return NGX_ERROR;
            }
        }

    }

    return rc;
}


static void
ngx_http_oauth_service_status(ngx_http_request_t *r, void *data)
{
    ngx_int_t                              flag = 0;
    ngx_buf_t                             *b = NULL;
    ngx_http_oauth_service_ctx_t          *ctx = data;

    if (ctx->status == NGX_HTTP_BAD_REQUEST || 
        ctx->status == NGX_HTTP_FORBIDDEN || ctx->status == NGX_HTTP_UNAUTHORIZED) {

        flag = 1;
        r->headers_out.content_length_n = ctx->error_code.len;
 
        b = ngx_create_temp_buf(r->pool, ctx->error_code.len);
        b->pos = ctx->error_code.data;
        b->last = b->pos + ctx->error_code.len;

    } else if (ctx->parse_flag == 0) {

        flag = 1;
        r->headers_out.content_length_n = ngx_strlen(oauth_parse);
 
        b = ngx_create_temp_buf(r->pool, ngx_strlen(oauth_parse));
        b->pos = (u_char *)oauth_parse;
        b->last = b->pos + ngx_strlen(oauth_parse);

    } else if (ctx->status >= NGX_HTTP_BAD_GATEWAY 
                          && ctx->status <= NGX_HTTP_GATEWAY_TIME_OUT) {

        flag = 1;
        r->headers_out.content_length_n = ngx_strlen(oauth_server);
 
        b = ngx_create_temp_buf(r->pool, ngx_strlen(oauth_server));
        b->pos = (u_char *)oauth_server;
        b->last = b->pos + ngx_strlen(oauth_server);
    }

    if (flag) {
        b->last_buf = 1;
        ngx_chain_t out;
        out.buf = b;
        out.next = NULL;
 
        r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
        ngx_int_t ret = ngx_http_send_header(r);
        ret = ngx_http_output_filter(r, &out);
 
        ngx_http_finalize_request(r, ret);
        return;
    }

    ngx_http_finalize_request(r, NGX_OK);
    return;
}


static ngx_int_t
ngx_http_oauth_json_parse(ngx_http_request_t *r, void *data)
{
    json_t                                *root = NULL, *temp = NULL;
    u_char                                *oauth_json;
    ngx_int_t                              string_len;
    ngx_int_t                              kv_num = 0, i = 0, len = 0;
    ngx_buf_t                             *recv_buf = &r->upstream->buffer;
    ngx_http_oauth_service_ctx_t          *ctx = data;
    ngx_http_oauth_service_loc_conf_t         *orcf;

    orcf = ngx_http_get_module_loc_conf(r->parent, ngx_http_oauth_service_module);

    if (r->headers_out.status >= NGX_HTTP_CLIENT_CLOSED_REQUEST || 
                  r->upstream->state->status >= NGX_HTTP_CLIENT_CLOSED_REQUEST) {
        return NGX_ERROR;
    }

    if (r->upstream->length <= 0 && recv_buf->pos == recv_buf->last) {

        if (recv_buf->pos != NULL && *(recv_buf->pos) == '{') {
            len = json_extract_text(recv_buf->pos, ngx_strlen(recv_buf->pos));
        }

        if (len > 1) {
            r->upstream->length = len + 1;
            recv_buf->last = recv_buf->pos + len + 1;

        } else {
            return NGX_ERROR;
        }
    }

    if (r->upstream->length > 0) {
        string_len = r->upstream->length;
    } else {
        string_len = recv_buf->last - recv_buf->pos;
    }

    oauth_json = ngx_palloc(r->pool, string_len + 1);
    ngx_sprintf(oauth_json, "%*s", string_len, recv_buf->pos);
    oauth_json[string_len] = '\0';

    if (json_parse_document(&root, (char *)oauth_json) != JSON_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "request oauth parse failed: \"%*s\"", string_len, recv_buf->pos);

        ctx->parse_flag = 0;
        return NGX_ERROR;
    }

    temp = json_find_first_label(root, "error");
    if (temp != NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "request auth failed: \"%*s\"", string_len, recv_buf->pos);

        if (ngx_strcmp(orcf->oauth_switch.data, "off") == 0) {
            ctx->error_code.len = string_len;
            ctx->error_code.data = ngx_palloc(r->pool, ctx->error_code.len);

            ngx_snprintf(ctx->error_code.data, ctx->error_code.len, "%*s", 
                                            ctx->error_code.len, recv_buf->pos);

            return NGX_ERROR;

        } else if (ngx_strcmp(orcf->oauth_switch.data, "on") == 0) {
            return NGX_OK;
        }
    }

    ctx->oauth_flag = 1;

    for (i = 0; i < OAUTH_REQ_HEADER_SIZE; i++) {
        temp = json_find_first_label(root, oauth_key[i]);

        if (temp != NULL && temp->child != NULL) {
            ctx->oauth_header[kv_num].key.len = ngx_strlen(temp->text);
            ctx->oauth_header[kv_num].key.data = ngx_palloc(r->pool, 
                                                            ctx->oauth_header[i].key.len);
            ngx_sprintf(ctx->oauth_header[i].key.data, "%*s", 
                                                      ngx_strlen(temp->text), temp->text);

            ctx->oauth_header[kv_num].value.len = ngx_strlen(temp->child->text);
            ctx->oauth_header[kv_num].value.data = ngx_palloc(r->pool, 
                                                          ctx->oauth_header[i].value.len);
            ngx_sprintf(ctx->oauth_header[i].value.data, "%*s", 
                                        ngx_strlen(temp->child->text), temp->child->text);
            kv_num++;
        }
        temp = NULL;
    }
    json_free_value(&root);

    return kv_num;
}


static ngx_table_elt_t *
ngx_http_find_header(ngx_http_request_t *r, ngx_str_t *key)
{
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;

    if (key != NULL) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        ngx_uint_t  i;
        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (header[i].key.len == key->len) {

                if (ngx_strncmp(header[i].key.data, key->data, key->len) == 0)
                {
                    return &header[i];
                }
            }
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_add_header(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *value)
{
    ngx_table_elt_t            *h;
    ngx_http_header_t          *hh;
    ngx_table_elt_t            *header;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    if (key == NULL || value == NULL) {
        return NGX_ERROR;
    }

    if ((header = ngx_http_find_header(r, key)) != NULL) {

        header->value.len = value->len;
        header->value.data = ngx_palloc(r->pool, value->len);
        ngx_snprintf(header->value.data, header->value.len, "%V", value);

        return NGX_OK;
    }

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    h->hash = r->header_hash;

    h->key.len = key->len;
    h->key.data = ngx_palloc(r->pool, key->len);
    ngx_snprintf(h->key.data, h->key.len, "%V", key);

    h->value.len = value->len;
    h->value.data = ngx_palloc(r->pool, value->len);
    ngx_snprintf(h->value.data, h->value.len, "%V", value);

    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    if (h->key.len == r->lowcase_index) {
        ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

    } else {
        ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
    }

    hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

    if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
        return NGX_ERROR;
    }

    r->headers_in.headers.part.nelts = r->headers_in.headers.last->nelts;

    return NGX_OK;
}


static ngx_int_t
ngx_http_oauth_service_set_variables(ngx_http_request_t *r,
    ngx_http_oauth_service_loc_conf_t *orcf, ngx_http_oauth_service_ctx_t *ctx)
{
    ngx_str_t                           val;
    ngx_http_variable_t                *v;
    ngx_http_variable_value_t          *vv;
    ngx_http_oauth_service_variable_t  *av, *last;
    ngx_http_core_main_conf_t          *cmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oauth request set variables");

    if (orcf->vars == NULL) {
        return NGX_OK;
    }

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    v = cmcf->variables.elts;

    av = orcf->vars->elts;
    last = av + orcf->vars->nelts;

    while (av < last) {
        /*
         * explicitly set new value to make sure it will be available after
         * internal redirects
         */

        vv = &r->variables[av->index];

        if (ngx_http_complex_value(ctx->subrequest, &av->value, &val)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        vv->valid = 1;
        vv->not_found = 0;
        vv->data = val.data;
        vv->len = val.len;

        if (av->set_handler) {
            /*
             * set_handler only available in cmcf->variables_keys, so we store
             * it explicitly
             */

            av->set_handler(r, vv, v[av->index].data);
        }

        av++;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_oauth_service_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oauth request variable");

    v->not_found = 1;

    return NGX_OK;
}


static void *
ngx_http_oauth_service_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_oauth_service_main_conf_t  *osmcf;

    osmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_oauth_service_main_conf_t));
    if (osmcf == NULL) {
        return NULL;
    }
    osmcf->shm_size            = NGX_CONF_UNSET_UINT;
    osmcf->http_port           = NGX_CONF_UNSET_UINT;
    osmcf->config_port         = NGX_CONF_UNSET_UINT;
    osmcf->check_times         = NGX_CONF_UNSET_UINT;
    osmcf->http_timeout        = NGX_CONF_UNSET_MSEC;
    osmcf->memcache_port       = NGX_CONF_UNSET_UINT;
    osmcf->check_interval      = NGX_CONF_UNSET_MSEC;
    osmcf->config_timeout      = NGX_CONF_UNSET_MSEC;
    osmcf->http_keepalive      = NGX_CONF_UNSET_UINT;
    osmcf->config_interval     = NGX_CONF_UNSET_MSEC;
    osmcf->memcache_timeout    = NGX_CONF_UNSET_MSEC;
    osmcf->memcache_keepalive  = NGX_CONF_UNSET_UINT;

    osmcf->config_peer = ngx_pcalloc(cf->pool, sizeof(ngx_http_config_peer_t));
    if (osmcf->config_peer == NULL) {
        return NULL;
    }
    osmcf->config_peer->owner              = NGX_INVALID_PID;
    osmcf->config_peer->config_host        = NGX_CONF_UNSET_PTR;
    osmcf->config_peer->config_url         = NGX_CONF_UNSET_PTR;
    osmcf->config_peer->config_arg         = NGX_CONF_UNSET_PTR;
    osmcf->config_peer->config_idc         = NGX_CONF_UNSET_PTR;
    osmcf->config_peer->config_port        = NGX_CONF_UNSET_UINT;
    osmcf->config_peer->config_interval    = NGX_CONF_UNSET_MSEC;
    osmcf->config_peer->config_timeout     = NGX_CONF_UNSET_MSEC;
    osmcf->config_peer->access_time        = NGX_CONF_UNSET_MSEC;

    osmcf->config_peer->m.len  = CONFIG_M_LEN;
    osmcf->config_peer->m.data = ngx_pcalloc(cf->pool, CONFIG_M_LEN);

    osmcf->memcache_peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_memcache_peers_t));
    if (osmcf->memcache_peers == NULL) {
        return NULL;
    }
    osmcf->memcache_peers->count           = NGX_CONF_UNSET_UINT;
    osmcf->memcache_peers->updating_times  = NGX_CONF_UNSET_UINT;
    osmcf->memcache_peers->peers           = NGX_CONF_UNSET_PTR;

    osmcf->http_peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_http_peers_t));
    if (osmcf->http_peers == NULL) {
        return NULL;
    }
    osmcf->http_peers->count    = NGX_CONF_UNSET_UINT;
    osmcf->http_peers->peers    = NGX_CONF_UNSET_PTR;

    osmcf->sub_shm = ngx_pcalloc(cf->pool, sizeof(ngx_http_oauth_sub_shm_t));
    if (osmcf->sub_shm == NULL) {
        return NULL;
    }
    osmcf->sub_shm->owner     = NGX_INVALID_PID;
    osmcf->sub_shm->flag      = 0;
    osmcf->sub_shm->main      = NGX_CONF_UNSET_PTR;
    osmcf->sub_shm->counter   = NGX_CONF_UNSET_PTR;
    osmcf->sub_shm->log       = NGX_CONF_UNSET_PTR;
    osmcf->sub_shm->domain    = NGX_CONF_UNSET_PTR;
    osmcf->sub_shm->timeout   = NGX_CONF_UNSET_MSEC;
    osmcf->sub_shm->sid       = NGX_CONF_UNSET_PTR;
    osmcf->sub_shm->idc       = NGX_CONF_UNSET_PTR;
    osmcf->sub_shm->session   = NGX_CONF_UNSET_PTR;

    osmcf->config_peer->sub_shm     = osmcf->sub_shm;
    osmcf->memcache_peers->sub_shm  = osmcf->sub_shm;
    osmcf->http_peers->sub_shm      = osmcf->sub_shm;

    return osmcf;
}


static char *
ngx_http_oauth_service_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_oauth_service_main_conf_t  *osmcf = conf;

    if (osmcf->shm_size == NGX_CONF_UNSET_UINT) {
        osmcf->shm_size = 1 * 1024 * 1024;
    }
    if (osmcf->config_interval == NGX_CONF_UNSET_MSEC) {
        osmcf->config_interval = 5 * 60 * 1000;
    }
    if (osmcf->config_timeout == NGX_CONF_UNSET_MSEC) {
        osmcf->config_timeout = 3 * 1000;
    }
    if (osmcf->http_timeout == NGX_CONF_UNSET_MSEC) {
        osmcf->http_timeout = 3 * 1000;
    }
    if (osmcf->http_port == NGX_CONF_UNSET_UINT) {
        osmcf->http_port = 80;
    }
    if (osmcf->http_keepalive == NGX_CONF_UNSET_UINT) {
        osmcf->http_keepalive = 5;
    }
    if (osmcf->memcache_timeout == NGX_CONF_UNSET_MSEC) {
        osmcf->memcache_timeout = 3 * 1000;
    }
    if (osmcf->memcache_keepalive == NGX_CONF_UNSET_UINT) {
        osmcf->memcache_keepalive = 50;
    }
    if (osmcf->memcache_port == NGX_CONF_UNSET_UINT) {
        return NGX_CONF_ERROR;
    }
    if (osmcf->check_interval == NGX_CONF_UNSET_MSEC) {
        osmcf->check_interval = 10 * 60 * 1000;
    }
    if (osmcf->check_times == NGX_CONF_UNSET_UINT) {
        osmcf->check_times = 10;
    }

    if (osmcf->config_port == NGX_CONF_UNSET_UINT) {
        osmcf->config_peer->config_port = 80;
    } else {
        osmcf->config_peer->config_port = osmcf->config_port;
    }
    if (osmcf->config_peer->config_interval == NGX_CONF_UNSET_MSEC) {
        osmcf->config_peer->config_interval = osmcf->config_interval;
    }
    if (osmcf->config_peer->config_timeout == NGX_CONF_UNSET_MSEC) {
        osmcf->config_peer->config_timeout = osmcf->config_timeout;
    }
    if (osmcf->config_peer->access_time == NGX_CONF_UNSET_MSEC) {
        osmcf->config_peer->access_time = 0;
    }
    if (osmcf->config_peer->config_idc == NGX_CONF_UNSET_PTR) {
        osmcf->config_peer->config_idc = &osmcf->idc;
    }

    osmcf->config_peer->pool = ngx_create_pool(osmcf->shm_size, ngx_cycle->log);
    if (osmcf->config_peer->pool == NULL) {
        return NGX_CONF_ERROR;
    }

    osmcf->sub_shm->pool = ngx_create_pool(osmcf->shm_size, ngx_cycle->log);
    if (osmcf->sub_shm->pool == NULL) {
        return NGX_CONF_ERROR;
    }

    sub_ctx = osmcf;

    if (ngx_http_config_peer_init(cf, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_memcache_peers_init(cf, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_http_peers_init(cf, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_sub_shm_init(cf, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_http_oauth_check_shm_generation = 0;

    return NGX_CONF_OK;
}


static void *
ngx_http_oauth_service_create_conf(ngx_conf_t *cf)
{
    ngx_http_oauth_service_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_oauth_service_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->uri = { 0, NULL };
     */

    conf->vars = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_oauth_service_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_oauth_service_loc_conf_t *prev = parent;
    ngx_http_oauth_service_loc_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->uri, prev->uri, "");
    ngx_conf_merge_str_value(conf->oauth_type, prev->oauth_type, "default");
    ngx_conf_merge_str_value(conf->oauth_body, prev->oauth_body, "off");
    ngx_conf_merge_str_value(conf->oauth_switch, prev->oauth_switch, "off");

    ngx_conf_merge_ptr_value(conf->vars, prev->vars, NULL);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_oauth_service_init(ngx_conf_t *cf)
{
    ngx_str_t                   oauth_arg;

    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    ngx_str_set(&oauth_arg, "oauth");

    oauth_index = ngx_http_get_variable_index(cf, &oauth_arg);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_oauth_service_handler;

    return NGX_OK;
}


static ngx_int_t
ngx_http_oauth_service_init_process(ngx_cycle_t *cycle)
{
    ngx_http_config_peer_t        *config_peer;
    ngx_http_oauth_sub_shm_t      *sub_shm;

    sub_shm = sub_ctx->sub_shm;
    config_peer = sub_ctx->config_peer;

    ngx_http_config_add_timers(cycle);

    if (ngx_http_memcache_peers_init_process(cycle) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "oauth_memcache_peers_init_pro failed");
        return NGX_ERROR;
    }

    ngx_http_http_peers_init_process(cycle);

    sub_shm->pool->log = cycle->log;
    config_peer->pool->log = cycle->log;

    return NGX_OK;
}


static char *
ngx_http_oauth_service(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oauth_service_loc_conf_t *orcf = conf;

    ngx_str_t        *value;

    if (orcf->uri.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        orcf->uri.len = 0;
        orcf->uri.data = (u_char *) "";

        return NGX_CONF_OK;
    }

    orcf->uri = value[1];

    return NGX_CONF_OK;
}


static char *
ngx_http_oauth_service_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oauth_service_loc_conf_t *orcf = conf;

    ngx_str_t                          *value;
    ngx_http_variable_t                *v;
    ngx_http_oauth_service_variable_t  *av;
    ngx_http_compile_complex_value_t    ccv;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    if (orcf->vars == NGX_CONF_UNSET_PTR) {
        orcf->vars = ngx_array_create(cf->pool, 1,
                                      sizeof(ngx_http_oauth_service_variable_t));
        if (orcf->vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    av = ngx_array_push(orcf->vars);
    if (av == NULL) {
        return NGX_CONF_ERROR;
    }

    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    av->index = ngx_http_get_variable_index(cf, &value[1]);
    if (av->index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (v->get_handler == NULL) {
        v->get_handler = ngx_http_oauth_service_variable;
        v->data = (uintptr_t) av;
    }

    av->set_handler = v->set_handler;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &av->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
