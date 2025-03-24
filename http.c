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

#define POSTBUFFERSIZE 512

// 간단한 세션 관리 구조체
typedef struct Session {
    char token[33]; // 32자 랜덤 토큰 + NULL
    time_t last_active;
    int user_id;    // 로그인한 사용자 id
    struct Session *next;
} Session;

static Session *session_list = NULL;

// POST 데이터 처리를 위한 연결 정보 구조체
typedef struct ConnectionInfo {
    char *post_data;         // 누적 POST 데이터 (JSON 형식)
    size_t post_data_size;   // 누적된 데이터 크기
    struct MHD_PostProcessor *post_processor; // Post Processor (로그인 등에서 사용)
} ConnectionInfo;

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
    buf[len - 1] = '\0';
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
    while (sess) {
        if (strcmp(sess->token, token) == 0) {
            if (now - sess->last_active > SESSION_TIMEOUT)
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
    while (*ptr) {
        if (now - (*ptr)->last_active > SESSION_TIMEOUT) {
            Session *tmp = *ptr;
            *ptr = (*ptr)->next;
            free(tmp);
        } else {
            ptr = &((*ptr)->next);
        }
    }
}

// JSON 응답 전송 함수 (Content-Type: application/json + CORS)
static int send_json_response(struct MHD_Connection *connection, const char *json_str, int status_code) {
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_str), (void*)json_str, MHD_RESPMEM_MUST_COPY);
    if (!response)
        return MHD_NO;
    MHD_add_response_header(response, "Content-Type", "application/json");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "X-Content-Type-Options", "nosniff");
    MHD_add_response_header(response, "X-Frame-Options", "DENY");
    int ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    return ret;
}

// 업로드된 파일 저장 (원자적 파일 쓰기)
static int save_uploaded_file(const char *filename, const char *data, size_t size, char *saved_path, size_t path_len) {
    mkdir(UPLOAD_DIR, 0755);
    snprintf(saved_path, path_len, "%s/%s", UPLOAD_DIR, filename);
    int fd = open(saved_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return -1;
    }
    fsync(fd);
    close(fd);
    return 0;
}

// POST 데이터 누적을 위한 iterate_post 콜백 (로그인 등에서 사용)
static MHD_Result iterate_post(void *coninfo_cls, enum MHD_ValueKind kind,
                               const char *key, const char *filename,
                               const char *content_type, const char *transfer_encoding,
                               const char *data, uint64_t off, size_t size)
{
    ConnectionInfo *con_info = (ConnectionInfo *)coninfo_cls;
    if (size > 0) {
        char *new_ptr = realloc(con_info->post_data, con_info->post_data_size + size + 1);
        if (!new_ptr)
            return MHD_NO;
        con_info->post_data = new_ptr;
        memcpy(con_info->post_data + con_info->post_data_size, data, size);
        con_info->post_data_size += size;
        con_info->post_data[con_info->post_data_size] = '\0';
    }
    return MHD_YES;
}

// URL별 처리 함수 선언 (upload_data_size 타입: unsigned long*)
static int handle_posts(struct MHD_Connection *connection, const char *method,
                         const char *upload_data, unsigned long *upload_data_size, void **con_cls);
static int handle_login(struct MHD_Connection *connection, const char *method,
                         const char *upload_data, unsigned long *upload_data_size, void **con_cls);
static int handle_upload(struct MHD_Connection *connection, const char *method,
                          const char *upload_data, unsigned long *upload_data_size, void **con_cls);

// HTTP 요청 처리 콜백 (멀티스레드 모드)
// OPTIONS 요청에 대해 CORS Preflight 응답을 추가합니다.
static int request_handler(void *cls, struct MHD_Connection *connection,
                           const char *url, const char *method,
                           const char *version, const char *upload_data,
                           unsigned long *upload_data_size, void **con_cls)
{
    // OPTIONS 요청 처리 (CORS Preflight)
    if (strcmp(method, "OPTIONS") == 0) {
        struct MHD_Response *response = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
        if (!response)
            return MHD_NO;
        MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(response, "Access-Control-Allow-Methods", "POST, GET, OPTIONS");
        MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    }
    
    session_cleanup();
    if (NULL == *con_cls) {
        // POST 요청이면 ConnectionInfo 할당 및 post processor 생성
        if (strcmp(method, "POST") == 0) {
            ConnectionInfo *con_info = malloc(sizeof(ConnectionInfo));
            if (!con_info)
                return MHD_NO;
            con_info->post_data = NULL;
            con_info->post_data_size = 0;
            *con_cls = con_info;
            // 로그인나 파일 업로드 등의 POST 데이터 처리를 위해 post processor 생성
            struct MHD_PostProcessor *pp = MHD_create_post_processor(connection, POSTBUFFERSIZE, iterate_post, (void *)con_info);
            if (pp == NULL) {
                free(con_info);
                return MHD_NO;
            }
            // 저장: con_cls will hold ConnectionInfo; post processor pointer can be stored if needed
            con_info->post_processor = pp;
        } else {
            *con_cls = NULL;
        }
    }
    
    if (strcmp(url, "/posts") == 0)
        return handle_posts(connection, method, upload_data, upload_data_size, con_cls);
    else if (strcmp(url, "/login") == 0)
        return handle_login(connection, method, upload_data, upload_data_size, con_cls);
    else if (strcmp(url, "/upload") == 0)
        return handle_upload(connection, method, upload_data, upload_data_size, con_cls);
    else {
        const char *json_err = "{\"error\":\"Not Found\"}";
        return send_json_response(connection, json_err, MHD_HTTP_NOT_FOUND);
    }
}

// --- 게시글 처리 ---
// GET: 데이터베이스에서 게시글 목록을 JSON 배열로 반환
// POST: JSON 요청으로 전달된 title과 content를 새 게시글로 추가 (수동 누적 방식)
static int handle_posts(struct MHD_Connection *connection, const char *method,
                         const char *upload_data, unsigned long *upload_data_size, void **con_cls)
{
    if (strcmp(method, "GET") == 0) {
        Post *posts = NULL;
        int count = 0;
        db_get_posts(&posts, &count);
        char json[16384];
        strcpy(json, "{\"posts\":[");
        for (int i = 0; i < count; i++) {
            char post_json[1024];
            snprintf(post_json, sizeof(post_json),
                     "{\"id\":%d,\"title\":\"%s\",\"content\":\"%s\",\"date\":\"%s\"}%s",
                     posts[i].id, posts[i].title, posts[i].content, posts[i].date,
                     (i < count - 1) ? "," : "");
            strncat(json, post_json, sizeof(json) - strlen(json) - 1);
        }
        strcat(json, "]}");
        free(posts);
        return send_json_response(connection, json, MHD_HTTP_OK);
    } else if (strcmp(method, "POST") == 0) {
        // 여기서는 manual accumulation 대신 post processor를 사용하지 않고,
        // 단순하게 ConnectionInfo에 누적된 데이터를 처리합니다.
        ConnectionInfo *con_info = *con_cls;
        if (con_info->post_data == NULL || con_info->post_data_size == 0) {
            return send_json_response(connection, "{\"error\":\"No data provided\"}", MHD_HTTP_BAD_REQUEST);
        }
        char title[256] = {0}, content[1024] = {0};
        sscanf(con_info->post_data, "{\"title\":\"%255[^\"]\",\"content\":\"%1023[^\"]\"}", title, content);
        free(con_info->post_data);
        con_info->post_data = NULL;
        con_info->post_data_size = 0;
        char date_str[64];
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M:%S", tm_info);
        if (db_add_post(title, content, date_str) != 0) {
            return send_json_response(connection, "{\"error\":\"DB Error\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
        }
        return send_json_response(connection, "{\"result\":\"Post added\"}", MHD_HTTP_OK);
    }
    return MHD_YES;
}

// --- 로그인 처리 ---
// GET: JSON 메시지 안내
// POST: post processor를 통해 누적된 JSON 데이터를 파싱하여 로그인 처리 후 세션 토큰 반환
static int handle_login(struct MHD_Connection *connection, const char *method,
                         const char *upload_data, unsigned long *upload_data_size, void **con_cls)
{
    if (strcmp(method, "GET") == 0) {
        return send_json_response(connection, "{\"message\":\"Please use POST to login\"}", MHD_HTTP_OK);
    } else if (strcmp(method, "POST") == 0) {
        ConnectionInfo *con_info = *con_cls;
        // post processor will call iterate_post to accumulate data.
        // When *upload_data_size becomes 0, it means all data has been processed.
        if (*upload_data_size != 0) {
            MHD_post_process(con_info->post_processor, upload_data, *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        } else {
            if (con_info->post_data == NULL || con_info->post_data_size == 0) {
                return send_json_response(connection, "{\"error\":\"No data provided\"}", MHD_HTTP_BAD_REQUEST);
            }
            fprintf(stderr, "Login post data: %s\n", con_info->post_data);
            char username[128] = {0}, password[128] = {0};
            int parsed = sscanf(con_info->post_data, "{\"username\":\"%127[^\"]\",\"password\":\"%127[^\"]\"}", username, password);
            free(con_info->post_data);
            con_info->post_data = NULL;
            con_info->post_data_size = 0;
            if (parsed != 2) {
                fprintf(stderr, "Failed to parse login JSON\n");
                return send_json_response(connection, "{\"error\":\"Invalid login format\"}", MHD_HTTP_BAD_REQUEST);
            }
            int user_id = db_validate_user(username, password);
            if (user_id > 0) {
                Session *sess = session_create(user_id);
                char json_resp[256];
                snprintf(json_resp, sizeof(json_resp),
                         "{\"result\":\"Login successful\",\"session\":\"%s\"}", sess->token);
                return send_json_response(connection, json_resp, MHD_HTTP_OK);
            } else {
                return send_json_response(connection, "{\"error\":\"Login failed\"}", MHD_HTTP_UNAUTHORIZED);
            }
        }
    }
    return MHD_YES;
}

// --- 파일 업로드 처리 ---
// GET: JSON 메시지 안내
// POST: 단순하게 POST 데이터 전체를 파일 내용으로 저장하고, JSON 결과 반환
static int handle_upload(struct MHD_Connection *connection, const char *method,
                          const char *upload_data, unsigned long *upload_data_size, void **con_cls)
{
    const char *cookie = MHD_lookup_connection_value(connection, MHD_COOKIE_KIND, "SESSION");
    if (!cookie || !session_validate(cookie)) {
        return send_json_response(connection, "{\"error\":\"Unauthorized. Please login.\"}", MHD_HTTP_FORBIDDEN);
    }
    if (strcmp(method, "GET") == 0) {
        return send_json_response(connection, "{\"message\":\"Use POST to upload file\"}", MHD_HTTP_OK);
    } else if (strcmp(method, "POST") == 0) {
        if (*upload_data_size != 0) {
            char filename[256] = "uploaded_image.jpg"; // 파일명 추출 로직 필요
            char saved_path[512];
            if (save_uploaded_file(filename, upload_data, *upload_data_size, saved_path, sizeof(saved_path)) == 0) {
                char json_resp[256];
                snprintf(json_resp, sizeof(json_resp),
                         "{\"result\":\"File uploaded\",\"path\":\"%s\"}", saved_path);
                *upload_data_size = 0;
                return send_json_response(connection, json_resp, MHD_HTTP_OK);
            } else {
                *upload_data_size = 0;
                return send_json_response(connection, "{\"error\":\"File upload failed\"}", MHD_HTTP_BAD_REQUEST);
            }
        }
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
    getchar();  // 서버 종료 전까지 대기
    MHD_stop_daemon(daemon);
    return 0;
}
