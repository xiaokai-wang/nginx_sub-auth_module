#ifndef _NGX_SUB_CACHE_H_
#define _NGX_SUB_CACHE_H_


void *ngx_http_memcache_peers_init(ngx_conf_t *cf, void *conf);

ngx_int_t ngx_http_memcache_peers_init_process(ngx_cycle_t *cycle);
ngx_int_t ngx_http_memcache_connect_handler(ngx_http_oauth_keepalive_peer_data_t *mkp);
ngx_int_t ngx_http_memcache_make_key(ngx_http_request_t *r, u_char *data);

void ngx_http_memcache_check_handler(ngx_event_t *event);
void ngx_http_check_memcache_timeout(ngx_event_t *event);


#endif
