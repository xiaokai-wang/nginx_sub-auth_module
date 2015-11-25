#ifndef _NGX_HTTP_OAUTH_SERVICE_MODULE_H_
#define _NGX_HTTP_OAUTH_SERVICE_MODULE_H_

#include <ngx_config.h>
#include <ngx_http.h>
#include <ngx_core.h>

#include "ngx_sub_ssl.h"


#define OAUTH_REQ_HEADER_SIZE  8
#define OPTION_OAUTH_ARGS  "&auth_type=option"


///////////////////////////////sub struct///////////////////////////////

#define FIXED_TIME  1400083200
#define ETAG_LEN  32
#define INDEX_NUM  20
#define NAME_LEN  32

#define SUB  "SUB"
#define PIN  "6f127d3a037b126bb8bab48198d53ee2"

#define NGX_TCP_CONNECT_DONE          0x0001
#define NGX_TCP_SEND_DONE             0x0002

#define NGX_OAUTH_PARSE_LINE_DONE      0x0004
#define NGX_OAUTH_PARSE_HEADER_DONE    0x0008

#define NGX_TCP_RECV_DONE             0x0010
#define NGX_TCP_ALL_DONE              0x0020


typedef struct {
    u_char                           host[NAME_LEN];
    ngx_uint_t                       port;
    u_char                           status[8];
} ngx_http_memcache_server_t;


typedef struct {
    u_char                           host[NAME_LEN];
    u_char                           url[32];
    ngx_uint_t                       port;
    u_char                           status[8];
} ngx_http_http_server_t;


typedef struct {
    ngx_http_memcache_server_t      *cache;
    ngx_http_http_server_t          *http;
    u_char                          *udp;
} ngx_http_resource_t;

/*
typedef struct {
    u_char                           key[40];
    u_char                           pub_key[240];
} ngx_http_sub_t;
*/

typedef struct {
    ngx_http_sub_t                  *sub;
    u_char                          *subp;
    u_char                          *checkgsid;
    u_char                          *suesup;
} ngx_http_key_t;


typedef struct {
    ngx_str_t                        etag;
    ngx_msec_t                       expire;
    ngx_msec_t                       ctime;
} ngx_http_meta_t;


typedef struct {
    ngx_pid_t                        owner;

    ngx_flag_t                       flag;

    ngx_pool_t                      *pool;

    u_char                          *main;
    u_char                          *counter;

    ngx_http_resource_t             *res;

    ngx_http_key_t                  *key;

    u_char                          *log;
    u_char                          *domain;
    u_char                          *idc;
    u_char                          *sid;
    u_char                          *session;

    ngx_msec_t                       timeout;

    ngx_http_meta_t                 *meta;
} ngx_http_oauth_sub_shm_t;


typedef struct {
    void                            *data;

    ngx_queue_t                      queue;
    ngx_connection_t                *connection;

    socklen_t                        socklen;
    u_char                           sockaddr[NGX_SOCKADDRLEN];
} ngx_http_oauth_service_keepalive_cache_t;


typedef struct {
    ngx_flag_t                      state;

    ngx_http_request_t             *request;

    void                           *conf;

    ngx_peer_connection_t           pc;

    ngx_event_t                     check_timeout_ev;
    ngx_msec_t                      memcache_interval;
} ngx_http_oauth_keepalive_peer_data_t;


typedef struct {
    ngx_str_t                       rsa_key_v1;
    ngx_str_t                       rc4_data_v1;

    ngx_str_t                       rsa_key_v2;
    ngx_str_t                       rc4_data_v2;

    ngx_str_t                       rsa_key_v3;
    ngx_str_t                       rc4_data_v3;
} ngx_sub_t;


//////////////////////////////////cache struct////////////////////////////////////////////

#define MEMCACHE_NOT_FOUND  -7 


typedef struct {
    u_char                           sockaddr[NGX_SOCKADDRLEN];
    socklen_t                        socklen;
    u_char                           name[NAME_LEN];

    ngx_int_t                        current_weight;
    ngx_int_t                        effective_weight;
    ngx_int_t                        weight;

    ngx_uint_t                       down;          /* unsigned  down:1; */

    ngx_msec_t                       check_interval;
    ngx_uint_t                       check_up_times;
    ngx_uint_t                       check_times;

    ngx_queue_t                      free;
    ngx_queue_t                      cache;

    ngx_int_t                        free_connection;
    ngx_int_t                        using_connection;

    ngx_event_t                      check_ev;
    ngx_event_t                      check_timeout_ev;

    ngx_msec_t                       memcache_interval;

    ngx_peer_connection_t            pc;

    ngx_event_handler_pt             send_handler;
    ngx_event_handler_pt             recv_handler;
} ngx_http_memcache_peer_t;


typedef struct {
    ngx_uint_t                       count;

    ngx_uint_t                       updating_times;

    ngx_http_memcache_peer_t        *peers;

    ngx_http_oauth_sub_shm_t        *sub_shm;
} ngx_http_memcache_peers_t;


/////////////////////////////////////////config struct//////////////////////////////////////

#define CONFIG_SERVER_URL  "/api/session/config"
#define CONFIG_DOMAIN  "domain=.weibo.com"
#define CONFIG_ENTRY  "entry=openapi"
#define CONFIG_M_LEN  32

#define C_DOMAIN  ".weibo.com"


typedef struct {
    ngx_flag_t                       state;

    ngx_pid_t                        owner;

    ngx_buf_t                        buf;

    u_char                          *config_host;
    u_char                          *config_url;
    u_char                          *config_arg;

    ngx_pool_t                      *pool;

    ngx_str_t                       *config_idc;

    ngx_str_t                        m;

    ngx_uint_t                       config_port;

    u_char                           sockaddr[NGX_SOCKADDRLEN];
    socklen_t                        socklen;
    u_char                           name[NAME_LEN];

    ngx_event_t                      check_timer_ev;
    ngx_event_t                      check_timeout_ev;

    ngx_msec_t                       config_interval;
    ngx_msec_t                       config_timeout;
    ngx_msec_t                       access_time;

    ngx_peer_connection_t            pc;

    ngx_event_handler_pt             send_handler;
    ngx_event_handler_pt             recv_handler;

    ngx_http_oauth_sub_shm_t        *sub_shm;
} ngx_http_config_peer_t;


///////////////////////////////////////////db struct////////////////////////////////////////

#define HTTP_SERVER_URL  "/api/session/validate"
#define HTTP_DOMAIN  "domain=.weibo.com"
#define HTTP_ENTRY  "entry=openapi"
#define HTTP_M_LEN  32

#define H_DOMAIN  ".weibo.com"


typedef struct {
    void                            *data;

    ngx_buf_t                        buf;

    u_char                           sockaddr[NGX_SOCKADDRLEN];
    socklen_t                        socklen;
    u_char                           name[NAME_LEN];

    ngx_int_t                        current_weight;
    ngx_int_t                        effective_weight;
    ngx_int_t                        weight;

    ngx_str_t                       *http_idc;

    ngx_uint_t                       down;          /* unsigned  down:1; */

    ngx_queue_t                      free;
    ngx_queue_t                      cache;

    ngx_event_t                      check_timeout_ev;
    ngx_msec_t                       config_interval;

    ngx_peer_connection_t            pc;

    ngx_event_handler_pt             send_handler;
    ngx_event_handler_pt             recv_handler;
} ngx_http_http_peer_t;


typedef struct {
    ngx_uint_t                       count;

    ngx_http_http_peer_t            *peers;

    ngx_http_oauth_sub_shm_t        *sub_shm;
} ngx_http_http_peers_t;


/////////////////////////////////////////////end/////////////////////////////////////////////////


extern ngx_module_t ngx_http_oauth_service_module;


typedef struct {
    ngx_str_t           key;
    ngx_str_t           value;
} ngx_oauth_header_t;


typedef struct {
    ngx_str_t                 uri;
    ngx_str_t                 oauth_type;
    ngx_str_t                 oauth_body;
    ngx_str_t                 oauth_switch;
    ngx_array_t              *vars;
} ngx_http_oauth_service_loc_conf_t;


typedef struct {
    ngx_oauth_header_t           oauth_header[OAUTH_REQ_HEADER_SIZE];

    ngx_http_request_t          *subrequest;

    ngx_str_t                    error_code;

    ngx_uint_t                   done;
    ngx_uint_t                   status;

    ngx_flag_t                   parse_flag;
    ngx_flag_t                   oauth_flag;
    ngx_flag_t                   sub_signed_flag;

    ngx_str_t                    type;

    ngx_str_t                    sub;
    ngx_str_t                    data;

    ngx_str_t                    uid;
    ngx_str_t                    rand;
    ngx_str_t                    domain;
    ngx_str_t                    ctime;

    ngx_uint_t                   etime;

    ngx_str_t                    memcache_key;
    ngx_str_t                    memcache_content;
    ngx_int_t                    memcache_flag;
} ngx_http_oauth_service_ctx_t;


typedef struct {
    ngx_uint_t                      shm_size;

    ngx_str_t                       memcache_host;
    ngx_uint_t                      memcache_port;
    ngx_msec_t                      memcache_timeout;
    ngx_uint_t                      memcache_keepalive;

    ngx_msec_t                      check_interval;
    ngx_uint_t                      check_times;

    ngx_str_t                       http_host;
    ngx_uint_t                      http_port;
    ngx_msec_t                      http_timeout;
    ngx_uint_t                      http_keepalive;

    ngx_str_t                       idc;

    ngx_sub_t                       sub_key;

    ngx_str_t                       config_host;
    ngx_uint_t                      config_port;
    ngx_msec_t                      config_interval;
    ngx_msec_t                      config_timeout;

    ngx_http_config_peer_t         *config_peer;

    ngx_http_memcache_peers_t      *memcache_peers;

    ngx_http_http_peers_t          *http_peers;

    ngx_http_oauth_sub_shm_t       *sub_shm;
} ngx_http_oauth_service_main_conf_t;


typedef struct {
    ngx_int_t                 index;
    ngx_http_complex_value_t  value;
    ngx_http_set_variable_pt  set_handler;
} ngx_http_oauth_service_variable_t;


extern ngx_uint_t ngx_http_oauth_check_shm_generation;
extern ngx_http_oauth_service_main_conf_t   *sub_ctx;
extern ngx_int_t oauth_index;


extern void ngx_http_sub_auth(ngx_http_request_t *r);
extern void *ngx_http_sub_shm_init(ngx_conf_t *cf, void *conf);

extern void ngx_http_memcache_check_handler(ngx_event_t *event);
extern void ngx_http_check_memcache_timeout(ngx_event_t *event);

extern ngx_int_t ngx_http_memcache_connect_handler(ngx_http_oauth_keepalive_peer_data_t *mkp);
extern ngx_int_t ngx_http_memcache_make_key(ngx_http_request_t *r, u_char *data);

extern void ngx_http_http_check_handler(ngx_event_t *event);
extern ngx_int_t ngx_http_http_connect_handler(ngx_http_oauth_keepalive_peer_data_t *mkp);

extern void ngx_http_finalize_request_success(ngx_http_oauth_keepalive_peer_data_t *mkp);
extern void ngx_http_finalize_request_failed(ngx_http_oauth_keepalive_peer_data_t *mkp);

extern char *ngx_http_oauth_service_set_sub_show(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
extern ngx_int_t ngx_http_oauth_service_sub_show(ngx_http_request_t *r);

extern ngx_int_t ngx_http_oauth_service_need_exit();
extern void ngx_http_oauth_service_clear_all_events();

extern ngx_int_t ngx_http_oauth_service_test_connect(ngx_connection_t *c);
extern ngx_int_t ngx_http_oauth_service_parse_status_line(ngx_buf_t *b, ngx_http_status_t *status);
extern ngx_int_t ngx_http_oauth_service_parse_header(ngx_buf_t *b, ngx_uint_t allow_underscores);

extern void ngx_http_oauth_service_keepalive_close(ngx_connection_t *c);
extern void ngx_http_oauth_service_keepalive_dummy_handler(ngx_event_t *ev);


#endif
