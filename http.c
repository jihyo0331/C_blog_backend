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

// JSON 응답 전송 함수 (Content-Type: application/json)
static int send_json_response(struct MHD_Connection *connection, const char *json_str, int status_code) {
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_str), (void*)json_str, MHD_RESPMEM_MUST_COPY);
    if (!response)
        return MHD_NO;
    MHD_add_response_header(response, "Content-Type", "application/json");
    // 보안 헤더 추가 (원하는 경우)
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

// URL별 처리 함수 선언 (upload_data_size의 타입은 unsigned long*)
static int handle_posts(struct MHD_Connection *connection, const char *method,
                         const char *upload_data, unsigned long *upload_data_size, void **con_cls);
static int handle_login(struct MHD_Connection *connection, const char *method,
                          const char *upload_data, unsigned long *upload_data_size, void **con_cls);
static int handle_upload(struct MHD_Connection *connection, const char *method,
                           const char *upload_data, unsigned long *upload_data_size, void **con_cls);

// HTTP 요청 처리 콜백 (멀티스레드 모드)
static int request_handler(void *cls, struct MHD_Connection *connection,
                           const char *url, const char *method,
                           const char *version, const char *upload_data,
                           unsigned long *upload_data_size, void **con_cls)
{
    session_cleanup();
    if (NULL == *con_cls) {
        if (strcmp(method, "POST") == 0) {
            ConnectionInfo *con_info = malloc(sizeof(ConnectionInfo));
            con_info->post_data = NULL;
            con_info->post_data_size = 0;
            *con_cls = con_info;
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
// POST: JSON 요청으로 전달된 title과 content를 새 게시글로 추가
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
        ConnectionInfo *con_info = *con_cls;
        if (*upload_data_size != 0) {
            // 누적 POST 데이터를 저장
            con_info->post_data = realloc(con_info->post_data, con_info->post_data_size + *upload_data_size + 1);
            memcpy(con_info->post_data + con_info->post_data_size, upload_data, *upload_data_size);
            con_info->post_data_size += *upload_data_size;
            con_info->post_data[con_info->post_data_size] = '\0';
            *upload_data_size = 0;
            return MHD_YES;
        } else {
            // 간단한 JSON 파싱: {"title":"...","content":"..."}
            char title[256] = {0}, content[1024] = {0};
            // 형식이 고정되어 있다고 가정 (실제 환경에서는 robust JSON 파서를 사용)
            sscanf(con_info->post_data, "{\"title\":\"%255[^\"]\",\"content\":\"%1023[^\"]\"}", title, content);
            free(con_info->post_data);
            con_info->post_data = NULL;
            con_info->post_data_size = 0;
            char date_str[64];
            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M:%S", tm_info);
            if (db_add_post(title, content, date_str) != 0) {
                const char *json_err = "{\"error\":\"DB Error\"}";
                return send_json_response(connection, json_err, MHD_HTTP_INTERNAL_SERVER_ERROR);
            }
            const char *json_success = "{\"result\":\"Post added\"}";
            return send_json_response(connection, json_success, MHD_HTTP_OK);
        }
    }
    return MHD_YES;
}

// --- 로그인 처리 ---
// GET: 단순 JSON 메시지 (외부 클라이언트는 POST 방식 사용 권장)
// POST: JSON 요청 {"username":"...", "password":"..."}를 파싱하여 로그인 처리 후 세션 토큰 반환
static int handle_login(struct MHD_Connection *connection, const char *method,
                          const char *upload_data, unsigned long *upload_data_size, void **con_cls)
{
    if (strcmp(method, "GET") == 0) {
        const char *json_msg = "{\"message\":\"Please use POST to login\"}";
        return send_json_response(connection, json_msg, MHD_HTTP_OK);
    } else if (strcmp(method, "POST") == 0) {
        ConnectionInfo *con_info = *con_cls;
        if (*upload_data_size != 0) {
            con_info->post_data = realloc(con_info->post_data, con_info->post_data_size + *upload_data_size + 1);
            memcpy(con_info->post_data + con_info->post_data_size, upload_data, *upload_data_size);
            con_info->post_data_size += *upload_data_size;
            con_info->post_data[con_info->post_data_size] = '\0';
            *upload_data_size = 0;
            return MHD_YES;
        } else {
            char username[128] = {0}, password[128] = {0};
            sscanf(con_info->post_data, "{\"username\":\"%127[^\"]\",\"password\":\"%127[^\"]\"}", username, password);
            free(con_info->post_data);
            con_info->post_data = NULL;
            con_info->post_data_size = 0;
            int user_id = db_validate_user(username, password);
            if (user_id > 0) {
                Session *sess = session_create(user_id);
                char json_resp[256];
                snprintf(json_resp, sizeof(json_resp),
                         "{\"result\":\"Login successful\",\"session\":\"%s\"}", sess->token);
                return send_json_response(connection, json_resp, MHD_HTTP_OK);
            } else {
                const char *json_err = "{\"error\":\"Login failed\"}";
                return send_json_response(connection, json_err, MHD_HTTP_UNAUTHORIZED);
            }
        }
    }
    return MHD_YES;
}

// --- 파일 업로드 처리 ---
// GET: JSON 메시지 안내
// POST: 파일 업로드는 단순화하여, 업로드된 데이터 전체를 파일로 저장 후 JSON 결과 반환
static int handle_upload(struct MHD_Connection *connection, const char *method,
                           const char *upload_data, unsigned long *upload_data_size, void **con_cls)
{
    const char *cookie = MHD_lookup_connection_value(connection, MHD_COOKIE_KIND, "SESSION");
    if (!cookie || !session_validate(cookie)) {
        const char *json_err = "{\"error\":\"Unauthorized. Please login.\"}";
        return send_json_response(connection, json_err, MHD_HTTP_FORBIDDEN);
    }
    if (strcmp(method, "GET") == 0) {
        const char *json_msg = "{\"message\":\"Use POST to upload file\"}";
        return send_json_response(connection, json_msg, MHD_HTTP_OK);
    } else if (strcmp(method, "POST") == 0) {
        // 단순화를 위해 파일 업로드는 POST 데이터 전체를 파일 내용으로 저장
        // 실제 운영에서는 multipart/form-data 처리가 필요합니다.
        if (*upload_data_size != 0) {
            char filename[256] = "uploaded_image.jpg"; // 클라이언트에서 별도 파일명 전달하지 않는 경우
            char saved_path[512];
            if (save_uploaded_file(filename, upload_data, *upload_data_size, saved_path, sizeof(saved_path)) == 0) {
                char json_resp[256];
                snprintf(json_resp, sizeof(json_resp),
                         "{\"result\":\"File uploaded\",\"path\":\"%s\"}", saved_path);
                *upload_data_size = 0;
                return send_json_response(connection, json_resp, MHD_HTTP_OK);
            } else {
                const char *json_err = "{\"error\":\"File upload failed\"}";
                *upload_data_size = 0;
                return send_json_response(connection, json_err, MHD_HTTP_BAD_REQUEST);
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
    getchar();
    MHD_stop_daemon(daemon);
    return 0;
}
