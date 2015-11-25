#ifndef _NGX_HTTP_OAUTH_SERVICE_MODULE_H_
#define _NGX_HTTP_OAUTH_SERVICE_MODULE_H_


void ngx_http_sub_auth(ngx_http_request_t *r);

void *ngx_http_sub_shm_init(ngx_conf_t *cf, void *conf);

void ngx_http_finalize_request_success(ngx_http_oauth_keepalive_peer_data_t *mkp);
void ngx_http_finalize_request_failed(ngx_http_oauth_keepalive_peer_data_t *mkp);

void ngx_http_oauth_service_keepalive_close(ngx_connection_t *c);
void ngx_http_oauth_service_keepalive_dummy_handler(ngx_event_t *ev);

ngx_int_t ngx_http_oauth_service_test_connect(ngx_connection_t *c);
ngx_int_t ngx_http_oauth_service_parse_status_line(ngx_buf_t *b, ngx_http_status_t *status);
ngx_int_t ngx_http_oauth_service_parse_header(ngx_buf_t *b, ngx_uint_t allow_underscores);

ngx_int_t ngx_http_oauth_service_need_exit();
void ngx_http_oauth_service_clear_all_events();

char *ngx_http_oauth_service_set_sub_show(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_int_t ngx_http_oauth_service_sub_show(ngx_http_request_t *r);


#endif
