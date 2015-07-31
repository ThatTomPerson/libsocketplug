#include <yajl/yajl_tree.h>
#include "socketplug.h"

#define SOCKET_URL "wss//godj.plug.dj/socket"
#define MAX_MESSAGE_SIZE 4096


bstring parse_csrf_token(bstring *page);

bstring get_login_post(bstring *token, bstring email, bstring pass);

int is_chat(bstring *message);

int status_ok(yajl_val *node);


bstring get_websocket_payload(bstring *token);

void join_room();

void send_chat(bstring *message);

bstring get_websocket_token();


bstring timestamp() {
    time_t t = time(NULL);
    bstring time = bformat("%d", (unsigned) t);
    return time;
}

static char *room;

/*
 * libwebsockets-test-client - libwebsockets test implementation
 *
 * Copyright (C) 2011 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

static int was_closed;
static volatile int force_exit = 0;

/*
 * This demo shows how to connect multiple websockets simultaneously to a
 * websocket server (there is no restriction on their having to be the same
 * server just it simplifies the demo).
 *
 *  dumb-increment-protocol:  we connect to the server and print the number
 *				we are given
 *
 *  lws-mirror-protocol: draws random circles, which are mirrored on to every
 *				client (see them being drawn in every browser
 *				session also using the test server)
 */

enum protocol_list {
    PROTOCOL_PLUG_SOCKET
};

/* lws-mirror_protocol */


static int
callback_plug_socket(struct libwebsocket_context *context,
                     struct libwebsocket *wsi,
                     enum libwebsocket_callback_reasons reason,
                     void *user, void *in, size_t len)
{
    struct per_session_data__fraggle *psf = user;
    switch (reason) {

        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            fprintf(
                    stderr,
                    "callback_dumb_increment: LWS_CALLBACK_CLIENT_ESTABLISHED\n"
            );
            libwebsocket_callback_on_writable(context, wsi);
            break;

        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            fprintf(stderr, "LWS_CALLBACK_CLIENT_CONNECTION_ERROR\n");
            was_closed = 1;
            break;

        case LWS_CALLBACK_CLOSED:
            fprintf(stderr, "LWS_CALLBACK_CLOSED\n");
            was_closed = 1;
            break;

        case LWS_CALLBACK_CLIENT_RECEIVE:
            ((char *) in)[len] = '\0';
            bstring r = bfromcstr(in);
            fprintf(stderr, "rx %d '%s'\n", (int) len, (char *) in);
            if (strcmp((char *) in, "[{\"a\":\"ack\","
                    "\"p\":\"1\","
                    "\"s\":\"dashboard\"}]"
            ) == 0) {
                fprintf(stderr, "logged into plug");
                join_room();
            } else if (is_chat(&r)) {
                send_chat(&r);
            }
            libwebsocket_callback_on_writable(context, wsi);
            break;

        case LWS_CALLBACK_CLIENT_WRITEABLE:
            if (messages_empty()) { break; }

            unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + MAX_MESSAGE_SIZE +
                              LWS_SEND_BUFFER_POST_PADDING];
            unsigned char *msg = &buf[LWS_SEND_BUFFER_PRE_PADDING];

            bstring *message = pop_message();
            check(blength(*message) < MAX_MESSAGE_SIZE,
                  "Message length longer than maximum length")

            strncpy((char *) msg, bdata(*message), (size_t) blength(*message));
            //msg = (unsigned char *) bdata(bstrcpy(*message));

            libwebsocket_write(
                    wsi, msg, (size_t) blength(*message), LWS_WRITE_TEXT
            );
            debug("sent to websocket: %s\n", bdata(*message));
        error:
            bdestroy(*message);


            break;
        default:
            break;
    }

    return 0;
}


/* list of supported protocols and callbacks */

static struct libwebsocket_protocols protocols[] = {
        {
                "plug-socket-protocol",
                callback_plug_socket,
                     0,
                        4096,
        },
        {NULL, NULL, 0, 0} /* end */
};

void sighandler(int sig)
{
    force_exit = 1;
}

int is_chat(bstring *message)
{
    yajl_val node;
    char errbuf[1024];
    node = yajl_tree_parse(bdata(*message), errbuf, sizeof(errbuf));

    check(!status_ok(&node), "status not 'ok'");
    check(node != NULL, "not a valid node");
    fprintf(stderr, "%s", errbuf);

    const char *path[] = {"a", (const char *) 0};
    const char *un[] = {"p", "uid", 0};
    yajl_val str = yajl_tree_get(node->u.array.values[0], path, yajl_t_string);
    yajl_val sender = yajl_tree_get(
            node->u.array.values[0], un,
            yajl_t_number
    );
    if (str && YAJL_IS_STRING(str) && strcmp(YAJL_GET_STRING(str), "chat") == 0
        && YAJL_IS_NUMBER(sender) &&
        strcmp(YAJL_GET_NUMBER(sender), "3539555") ==
        0) {
        return 1;
    }

    error:
    return 0;
}


void send_chat(bstring *message)
{
    bstring msg = NULL;
    yajl_val node;
    char errbuf[1024];
    node = yajl_tree_parse(bdata(*message), errbuf, sizeof(errbuf));

    check(!status_ok(&node), "status not 'ok'");
    check(node != NULL, "not a valid node");
    fprintf(stderr, "%s", errbuf);

    const char *path[] = {"a", (const char *) 0};
    const char *un[] = {"p", "uid", 0};
    const char *messageurl[] = {"p", "message", 0};
    yajl_val str = yajl_tree_get(node->u.array.values[0], path, yajl_t_string);
    yajl_val sender = yajl_tree_get(
            node->u.array.values[0], un,
            yajl_t_number
    );
    yajl_val mesg = yajl_tree_get(
            node->u.array.values[0], messageurl,
            yajl_t_string
    );
    if (str && YAJL_IS_STRING(str) && strcmp(YAJL_GET_STRING(str), "chat") == 0
        && YAJL_IS_NUMBER(sender) &&
        strcmp(YAJL_GET_NUMBER(sender), "3539555") == 0) {
        msg = cstr2bstr(YAJL_GET_STRING(mesg));
    }


    bstring t = timestamp();
    typedef const unsigned char *json_str;
    yajl_gen g = yajl_gen_alloc(NULL);
    yajl_gen_config(g, yajl_gen_beautify, 0);
    yajl_gen_map_open(g);
    yajl_gen_string(g, (json_str) "a", 1);
    yajl_gen_string(g, (json_str) "chat", 4);
    yajl_gen_string(g, (json_str) "p", 1);
    yajl_gen_string(g, (json_str) bdata(msg), (size_t) blength(msg));
    yajl_gen_string(g, (json_str) "t", 1);
    yajl_gen_number(g, bdata(t), (size_t) blength(t));

    yajl_gen_map_close(g);
    const unsigned char *buf;
    size_t len;
    yajl_gen_get_buf(g, &buf, &len);
    bstring json = blk2bstr(buf, (int) len);
    yajl_gen_free(g);

    debug("sending chat : %s", bdata(json));

    if (msg != NULL) {
        add_message(&json);
    }
    error:
    return;
}

void join_room()
{
    typedef const unsigned char *json_str;
    yajl_gen g = yajl_gen_alloc(NULL);
    yajl_gen_config(g, yajl_gen_beautify, 0);
    yajl_gen_map_open(g);
    yajl_gen_string(g, (json_str) "slug", 4);
    yajl_gen_string(g, (json_str) room, strlen(room));
    yajl_gen_map_close(g);
    const unsigned char *buf;
    size_t len;
    yajl_gen_get_buf(g, &buf, &len);
    bstring json = blk2bstr(buf, (int) len);
    yajl_gen_free(g);

    http_post("https://plug.dj/_/rooms/join", &json);

    debug("room payload: %s", bdata(json));

    bstring state = http_get("https://plug.dj/_/rooms/state");

    debug("room state: %s", bdata(state));

    bdestroy(json);
}


void socketplug_stop()
{
    http_destroy();
}

bstring get_login_post(bstring *token, bstring email, bstring pass)
{
    typedef const unsigned char *json_str;
    yajl_gen g = yajl_gen_alloc(NULL);
    yajl_gen_config(g, yajl_gen_beautify, 0);
    yajl_gen_map_open(g);
    yajl_gen_string(g, (json_str) "csrf", 4);
    yajl_gen_string(g, (json_str) bdata(*token), (size_t) blength(*token));
    yajl_gen_string(g, (json_str) "email", 5);
    yajl_gen_string(g, (json_str) bdata(email), (size_t) blength(email));
    yajl_gen_string(g, (json_str) "password", 8);
    yajl_gen_string(g, (json_str) bdata(pass), (size_t) blength(pass));
    yajl_gen_map_close(g);
    const unsigned char *buf;
    size_t len;
    yajl_gen_get_buf(g, &buf, &len);
    bstring json = blk2bstr(buf, (int) len);
    yajl_gen_free(g);

    debug("login payload: %s", bdata(json));

    bdestroy(email);
    bdestroy(pass);

    return json;
}


int status_ok(yajl_val *node)
{
    const char *path[] = {"status", (const char *) 0};
    yajl_val str = yajl_tree_get(*node, path, yajl_t_string);
    if (str && YAJL_IS_STRING(str) && strcmp(YAJL_GET_STRING(str), "ok")) {
        return 1;
    }
    return 0;
}

bstring get_websocket_payload(bstring *token)
{
    //bstring t = timestamp();
    typedef const unsigned char *json_str;
    yajl_gen g = yajl_gen_alloc(NULL);
    yajl_gen_config(g, yajl_gen_beautify, 0);
    yajl_gen_map_open(g);
    yajl_gen_string(g, (json_str) "a", 1);
    yajl_gen_string(g, (json_str) "auth", 4);
    yajl_gen_string(g, (json_str) "t", 1);
    yajl_gen_number(g, "1406505600", 10);
    //yajl_gen_number(g, bdata(t), (size_t) blength(t));
    yajl_gen_string(g, (json_str) "p", 1);
    yajl_gen_string(g, (json_str) bdata(*token), (size_t) blength(*token));
    yajl_gen_map_close(g);
    const unsigned char *buf;
    size_t len;
    yajl_gen_get_buf(g, &buf, &len);
    bstring json = blk2bstr(buf, (int) len);
    yajl_gen_free(g);

    debug("websocket payload: %s", bdata(json));

    bdestroy(*token);

    return json;
}

bstring get_websocket_token()
{
    bstring data = http_get("https://plug.dj/_/auth/token");
    bstring token = NULL;

    yajl_val node;
    char errbuf[1024];
    node = yajl_tree_parse(bdata(data), errbuf, sizeof(errbuf));

    check(!status_ok(&node), "status not 'ok'");
    check(node != NULL, "some shit");

    const char *path[] = {"data", (const char *) 0};
    yajl_val v = yajl_tree_get(node, path, yajl_t_array);
    if (v && YAJL_IS_ARRAY(v)) {
        yajl_val auth = v->u.array.values[0];
        if (auth && YAJL_IS_STRING(auth)) {
            token = bfromcstr(YAJL_GET_STRING(auth));
        }
    }

    error:
    bdestroy(data);
    yajl_tree_free(node);
    return token;
}

bstring parse_csrf_token(bstring *page)
{
    const int MAX_MATCHES = 12;
    bstring token = NULL;
    const char *error;
    int erroffset;
    int match_info[MAX_MATCHES];
    int matches;

    char *pattern = "var _csrf=\"(.*?)\"";
    int subgroup = 1; // We want whats inside the first group
    int regex_options = 0; // default options
    pcre_extra *extra = NULL; // no pattern study
    int offset = 0; // no reason to have an offset for the regex search

    pcre *regex = pcre_compile(
            pattern,
            regex_options,
            &error,
            &erroffset,
            NULL
    );

    check(regex != NULL, "Regex engine compilation failed at offset %d: %s\n",
          erroffset, error);

    matches = pcre_exec(
            regex, extra, (const char *) bdata(*page), blength(*page), offset,
            regex_options, match_info, MAX_MATCHES
    );

    check(matches >= 2, "Matching error, # of matches found for csrf token: %d",
          matches);

    debug("Match succeeded at offset %d\n", match_info[0]);
    token = bmidstr(
            *page, match_info[2 * subgroup],
            match_info[2 * subgroup + 1] - match_info[2 * subgroup]
    );
    log_info("csrf token: %s\n", bdata(token));

    error:

    pcre_free(regex);
    return token;
}

int socketplug_init(char *login, char *pass, char *roomm)
{
    room = roomm;
    init_messages();
    http_init();
    CURLcode res;
    bstring data = NULL;
    int success = 0;

    data = http_get("https://plug.dj");

    bstring token = parse_csrf_token(&data);
    check(token != NULL, "Could not parse csrf token!");

    success = 1;
    bstring payload = get_login_post(&token, bfromcstr(login), bfromcstr(pass));


    bdestroy(data);
    data = http_post("https://plug.dj/_/auth/login", &payload);

    bstring ws_token = get_websocket_token();


    //printf("%s", bdata(get("https://plug.dj/dashboard/")));

    bstring ws_payload = get_websocket_payload(&ws_token);
    add_message(&ws_payload);


    int ret = 0;
    int port = 443;
    int use_ssl = 1;
    struct libwebsocket_context *context;
    struct libwebsocket *wsi_dumb;
    int ietf_version = -1; /* latest */
    struct lws_context_creation_info info;

    memset(&info, 0, sizeof info);

    //lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO | LLL_DEBUG
    //                  | LLL_HEADER | LLL_CLIENT
    //        , NULL);


    signal(SIGINT, sighandler);

    //address = SOCKET_URL;

    /*
     * create the websockets context.  This tracks open connections and
     * knows how to route any traffic and which protocol version to use,
     * and if each connection is client or server side.
     *
     * For this client-only demo, we tell it to not listen on any port.
     */

    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
#ifndef LWS_NO_EXTENSIONS
    info.extensions = libwebsocket_get_internal_extensions();
#endif
    info.gid = -1;
    info.uid = -1;

    context = libwebsocket_create_context(&info);
    if (context == NULL) {
        fprintf(stderr, "Creating libwebsocket context failed\n");
        return 1;
    }


    /* create a client websocket using dumb increment protocol */

    wsi_dumb = libwebsocket_client_connect(
            context, "godj.plug.dj",
            port,
            use_ssl,
            "/socket", "godj.plug.dj",
            "https://plug.dj",
            protocols[PROTOCOL_PLUG_SOCKET].name, ietf_version
    );


    if (wsi_dumb == NULL) {
        fprintf(stderr, "libwebsocket connect failed\n");
    }

    fprintf(stderr, "Waiting for connect...\n");

    /*
     * sit there servicing the websocket context to handle incoming
     * packets, and drawing random circles on the mirror protocol websocket
     * nothing happens until the client websocket connection is
     * asynchronously established
     */

    while (!was_closed && !force_exit) {
        libwebsocket_service(context, 10);
    }

    bail:
    fprintf(stderr, "Exiting\n");

    libwebsocket_context_destroy(context);


    error:

    bdestroy(payload);
    bdestroy(token);
    bdestroy(data);
    return success;
}