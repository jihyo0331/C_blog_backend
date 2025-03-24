#include <stdio.h>
#include <stdlib.h>
#include "config.h"
#include "db.h"
#include "http.h"

int main(void) {
    if(db_init(POSTS_FILE, USERS_FILE) != 0) {
        fprintf(stderr, "Database initialization failed.\n");
        return EXIT_FAILURE;
    }
    // 최초 실행 시 기본 사용자 생성 (예: admin / password)
    // db_create_user("admin", "password");

    if(start_http_server() != 0) {
        fprintf(stderr, "Failed to start HTTP server.\n");
        db_close();
        return EXIT_FAILURE;
    }
    db_close();
    return EXIT_SUCCESS;
}
