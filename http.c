#include "http.h"
#include "config.h"
#include "db.h"
#include <microhttpd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define POSTBUFFERSIZE  512

// 간단한 세션 관리 구조체
typedef struct Session {
    char token[33]; // 32자 랜덤 토큰 + NULL
    time_t last_active;
    int user_id;    // 로그인한 사용자 id
    struct Session *next;
} Session;

static Session *session_list = NULL;

// 보안 개선: /dev/urandom을 이용한 토큰 생성
static void generate_token(char *buf, size_t len) {
    FILE *urandom = fopen("/dev/urandom", "r");
    if (urandom) {
        for (size_t i = 0; i < len - 1; i++) {
            int r = fgetc(urandom);
            buf[i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[r % 62];
        }
        fclose(urandom);
    } else {
        for (size_t i = 0; i < len - 1; i++) {
            buf[i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[rand() % 62];
        }
    }
    buf[len-1] = '\0';
}

// 세션 생성 및 리스트에 추가
static Session* session_create(int user_id) {
    Session *sess = malloc(sizeof(Session));
    generate_token(sess->token, sizeof(sess->token));
    sess->last_active = time(NULL);
    sess->user_id = user_id;
    sess->next = session_list;
    session_list = sess;
    return sess;
}

// 세션 검증 (쿠키의 token 비교)
static Session* session_validate(const char *token) {
    Session *sess = session_list;
    time_t now = time(NULL);
    while(sess) {
        if(strcmp(sess->token, token) == 0) {
            if(now - sess->last_active > SESSION_TIMEOUT)
                return NULL;
            sess->last_active = now;
            return sess;
        }
        sess = sess->next;
    }
    return NULL;
}

// 만료된 세션 삭제
static void session_cleanup() {
    Session **ptr = &session_list;
    time_t now = time(NULL);
    while(*ptr) {
        if(now - (*ptr)->last_active > SESSION_TIMEOUT) {
            Session *tmp = *ptr;
            *ptr = (*ptr)->next;
            free(tmp);
        } else {
            ptr = &((*ptr)->next);
        }
    }
}

// 보안 헤더 추가 함수
static void add_security_headers(struct MHD_Response *response) {
    MHD_add_response_header(response, "X-Content-Type-Options", "nosniff");
    MHD_add_response_header(response, "X-Frame-Options", "DENY");
    MHD_add_response_header(response, "Content-Security-Policy", "default-src 'self'");
}

// 공통 응답 전송 함수
static int send_response(struct MHD_Connection *connection, const char *response_str, int status_code) {
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(response_str), (void*)response_str, MHD_RESPMEM_MUST_COPY);
    if (!response)
        return MHD_NO;
    MHD_add_response_header(response, "Content-Type", "text/html");
    add_security_headers(response);
    int ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    return ret;
}

// 업로드된 파일 저장 (원자적 파일 쓰기)
static int save_uploaded_file(const char *filename, const char *data, size_t size, char *saved_path, size_t path_len) {
    mkdir(UPLOAD_DIR, 0755);
    snprintf(saved_path, path_len, "%s/%s", UPLOAD_DIR, filename);
    int fd = open(saved_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if(fd < 0)
        return -1;
    if(write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return -1;
    }
    fsync(fd);
    close(fd);
    return 0;
}

// URL별 처리 함수 선언
static int handle_root(struct MHD_Connection *connection, const char *method,
                         const char *upload_data, size_t *upload_data_size, void **con_cls);
static int handle_login(struct MHD_Connection *connection, const char *method,
                          const char *upload_data, size_t *upload_data_size, void **con_cls);
static int handle_upload(struct MHD_Connection *connection, const char *method,
                           const char *upload_data, size_t *upload_data_size, void **con_cls);

// HTTP 요청 처리 콜백 (멀티스레드 모드)
static int request_handler(void *cls, struct MHD_Connection *connection,
                           const char *url, const char *method,
                           const char *version, const char *upload_data,
                           size_t *upload_data_size, void **con_cls)
{
    session_cleanup();
    if(strcmp(url, "/") == 0)
        return handle_root(connection, method, upload_data, upload_data_size, con_cls);
    else if(strcmp(url, "/login") == 0)
        return handle_login(connection, method, upload_data, upload_data_size, con_cls);
    else if(strcmp(url, "/upload") == 0)
        return handle_upload(connection, method, upload_data, upload_data_size, con_cls);
    else {
        return send_response(connection, "<html><body><h1>404 Not Found</h1></body></html>", MHD_HTTP_NOT_FOUND);
    }
}

// --- 루트 (블로그 목록, 글 등록) 처리 ---
static int handle_root(struct MHD_Connection *connection, const char *method,
                         const char *upload_data, size_t *upload_data_size, void **con_cls)
{
    static int dummy;
    if (*con_cls == NULL) {
        *con_cls = &dummy;
        return MHD_YES;
    }
    if (strcmp(method, "GET") == 0) {
        Post *posts = NULL;
        int count = 0;
        db_get_posts(&posts, &count);
        char html[16384] = "<html><body><h1>My Blog</h1>";
        for (int i = 0; i < count; i++) {
            char buf[2048];
            snprintf(buf, sizeof(buf),
                     "<h2>%s</h2><p>%s</p><small>%s</small><hr>",
                     posts[i].title, posts[i].content, posts[i].date);
            strncat(html, buf, sizeof(html) - strlen(html) - 1);
        }
        strncat(html,
                "<h2>New Post</h2>"
                "<form method='POST' action='/'>"
                "Title: <input type='text' name='title'><br>"
                "Content: <textarea name='content'></textarea><br>"
                "<input type='submit' value='Submit'>"
                "</form>"
                "<p><a href='/login'>Login</a> | <a href='/upload'>Upload Image</a></p>"
                "</body></html>",
                sizeof(html) - strlen(html) - 1);
        free(posts);
        return send_response(connection, html, MHD_HTTP_OK);
    } else if (strcmp(method, "POST") == 0) {
        const char *title = MHD_lookup_connection_value(connection, MHD_POSTDATA_KIND, "title");
        const char *content = MHD_lookup_connection_value(connection, MHD_POSTDATA_KIND, "content");
        if (title && content) {
            char date_str[64];
            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M:%S", tm_info);
            if (db_add_post(title, content, date_str) != 0) {
                return send_response(connection, "<html><body><h1>DB Error</h1></body></html>", MHD_HTTP_INTERNAL_SERVER_ERROR);
            }
            return send_response(connection, "<html><body><h1>Post added!</h1><p><a href='/'>Go back</a></p></body></html>", MHD_HTTP_OK);
        }
    }
    return MHD_YES;
}

// --- 로그인 처리 ---
static int handle_login(struct MHD_Connection *connection, const char *method,
                          const char *upload_data, size_t *upload_data_size, void **con_cls)
{
    static int dummy;
    if (*con_cls == NULL) {
        *con_cls = &dummy;
        return MHD_YES;
    }
    if (strcmp(method, "GET") == 0) {
        const char *html =
            "<html><body><h1>Login</h1>"
            "<form method='POST' action='/login'>"
            "Username: <input type='text' name='username'><br>"
            "Password: <input type='password' name='password'><br>"
            "<input type='submit' value='Login'>"
            "</form></body></html>";
        return send_response(connection, html, MHD_HTTP_OK);
    } else if (strcmp(method, "POST") == 0) {
        const char *username = MHD_lookup_connection_value(connection, MHD_POSTDATA_KIND, "username");
        const char *password = MHD_lookup_connection_value(connection, MHD_POSTDATA_KIND, "password");
        if (username && password) {
            int user_id = db_validate_user(username, password);
            if (user_id > 0) {
                Session *sess = session_create(user_id);
                char cookie_hdr[128];
                snprintf(cookie_hdr, sizeof(cookie_hdr), "SESSION=%s; Path=/; HttpOnly; Secure", sess->token);
                struct MHD_Response *response = MHD_create_response_from_buffer(strlen("<html><body><h1>Login successful!</h1><a href='/'>Go to Blog</a></body></html>"),
                                                                                 (void*)"<html><body><h1>Login successful!</h1><a href='/'>Go to Blog</a></body></html>",
                                                                                 MHD_RESPMEM_MUST_COPY);
                MHD_add_response_header(response, "Set-Cookie", cookie_hdr);
                add_security_headers(response);
                int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
                MHD_destroy_response(response);
                return ret;
            }
        }
        return send_response(connection, "<html><body><h1>Login failed!</h1><a href='/login'>Try again</a></body></html>", MHD_HTTP_UNAUTHORIZED);
    }
    return MHD_YES;
}

// --- 파일 업로드 처리 ---
static int handle_upload(struct MHD_Connection *connection, const char *method,
                           const char *upload_data, size_t *upload_data_size, void **con_cls)
{
    static int dummy;
    if (*con_cls == NULL) {
        *con_cls = &dummy;
        return MHD_YES;
    }
    const char *cookie = MHD_lookup_connection_value(connection, MHD_COOKIE_KIND, "SESSION");
    if(!cookie || !session_validate(cookie)) {
        return send_response(connection, "<html><body><h1>Unauthorized. Please login.</h1></body></html>", MHD_HTTP_FORBIDDEN);
    }
    if (strcmp(method, "GET") == 0) {
        const char *html =
            "<html><body><h1>Upload Image</h1>"
            "<form method='POST' action='/upload' enctype='multipart/form-data'>"
            "Select image: <input type='file' name='image'><br>"
            "<input type='submit' value='Upload'>"
            "</form>"
            "<p><a href='/'>Back to Blog</a></p>"
            "</body></html>";
        return send_response(connection, html, MHD_HTTP_OK);
    } else if (strcmp(method, "POST") == 0) {
        const char *data = MHD_lookup_connection_value(connection, MHD_POSTDATA_KIND, "image");
        if(data) {
            char filename[256] = "uploaded_image.jpg"; // 실제 운영 시 파일명 추출 로직 필요
            char saved_path[512];
            if (save_uploaded_file(filename, data, strlen(data), saved_path, sizeof(saved_path)) == 0) {
                char resp[1024];
                snprintf(resp, sizeof(resp),
                         "<html><body><h1>File uploaded!</h1><p>Saved at %s</p><a href='/'>Back</a></body></html>",
                         saved_path);
                return send_response(connection, resp, MHD_HTTP_OK);
            }
        }
        return send_response(connection, "<html><body><h1>Upload failed</h1></body></html>", MHD_HTTP_BAD_REQUEST);
    }
    return MHD_YES;
}

int start_http_server() {
    struct MHD_Daemon *daemon;
    srand(time(NULL));
    daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION,
                              SERVER_PORT,
                              NULL, NULL,
                              &request_handler, NULL,
                              MHD_OPTION_END);
    if (NULL == daemon) {
        fprintf(stderr, "Failed to start HTTP daemon\n");
        return -1;
    }
    printf("HTTP server started on port %d\n", SERVER_PORT);
    // 실제 운영에서는 signal handling 및 graceful shutdown 구현 필요
    getchar();
    MHD_stop_daemon(daemon);
    return 0;
}
