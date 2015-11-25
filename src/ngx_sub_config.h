#ifndef _NGX_SUB_CONFIG_H_
#define _NGX_SUB_CONFIG_H_


void ngx_http_config_add_timers(ngx_cycle_t *cycle);

void *ngx_http_config_peer_init(ngx_conf_t *cf, void *conf);

void ngx_http_config_begin_handler(ngx_event_t *event);
void ngx_http_config_connect_handler(ngx_event_t *event);


#endif
