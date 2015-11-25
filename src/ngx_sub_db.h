#ifndef _NGX_SUB_DB_H_
#define _NGX_SUB_DB_H_


void *ngx_http_http_peers_init(ngx_conf_t *cf, void *conf);

void ngx_http_http_peers_init_process(ngx_cycle_t *cycle);
void ngx_http_http_check_handler(ngx_event_t *event);

ngx_int_t ngx_http_http_connect_handler(ngx_http_oauth_keepalive_peer_data_t *mkp);


#endif
