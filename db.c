#define _XOPEN_SOURCE
#include "db.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>
#include <crypt.h>
#include <errno.h>

static char posts_filename[256];
static char users_filename[256];
static int last_post_id = 0;

// posts 파일에서 마지막 post id를 읽어옴
static void load_last_post_id() {
    FILE *fp = fopen(posts_filename, "r");
    if (!fp) return;
    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        int id;
        if (sscanf(line, "%d|", &id) == 1) {
            if (id > last_post_id)
                last_post_id = id;
        }
    }
    fclose(fp);
}

int db_init(const char *posts_file, const char *users_file) {
    strncpy(posts_filename, posts_file, sizeof(posts_filename) - 1);
    strncpy(users_filename, users_file, sizeof(users_filename) - 1);

    // posts 파일 생성 (없으면 새로 만듦)
    FILE *fp = fopen(posts_filename, "a+");
    if (!fp)
        return -1;
    fclose(fp);

    // users 파일 생성 (없으면 새로 만듦)
    fp = fopen(users_filename, "a+");
    if (!fp)
        return -1;
    fclose(fp);

    load_last_post_id();
    return 0;
}

int db_close() {
    return 0;
}

int db_add_post(const char *title, const char *content, const char *date) {
    FILE *fp = fopen(posts_filename, "a");
    if (!fp)
        return -1;
    // 파일 락으로 동시성 제어
    if (flock(fileno(fp), LOCK_EX) != 0) {
        fclose(fp);
        return -1;
    }
    last_post_id++;
    int ret = fprintf(fp, "%d|%s|%s|%s\n", last_post_id, title, content, date);
    fflush(fp);
    fsync(fileno(fp));
    flock(fileno(fp), LOCK_UN);
    fclose(fp);
    return (ret < 0) ? -1 : 0;
}

int db_get_posts(Post **posts, int *count) {
    FILE *fp = fopen(posts_filename, "r");
    if (!fp)
        return -1;
    int capacity = 10;
    int cnt = 0;
    Post *list = malloc(sizeof(Post) * capacity);
    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        if (cnt >= capacity) {
            capacity *= 2;
            list = realloc(list, sizeof(Post) * capacity);
        }
        int id;
        char title[256], content[1024], date[64];
        if (sscanf(line, "%d|%255[^|]|%1023[^|]|%63[^\n]", &id, title, content, date) == 4) {
            list[cnt].id = id;
            strncpy(list[cnt].title, title, sizeof(list[cnt].title)-1);
            strncpy(list[cnt].content, content, sizeof(list[cnt].content)-1);
            strncpy(list[cnt].date, date, sizeof(list[cnt].date)-1);
            cnt++;
        }
    }
    fclose(fp);
    *posts = list;
    *count = cnt;
    return 0;
}

// 암호 해시 생성 (crypt 사용, SHA-512)
static char *hash_password(const char *password) {
    // 실제 운영에서는 매번 랜덤 salt를 생성하여 저장해야 함. (여기서는 고정 salt 예시)
    const char *salt = "$6$randomsalt$";
    return crypt(password, salt);
}

int db_validate_user(const char *username, const char *password) {
    FILE *fp = fopen(users_filename, "r");
    if (!fp)
        return 0;
    char line[512];
    int valid = 0;
    char *hashed_input = hash_password(password);
    while (fgets(line, sizeof(line), fp)) {
        char file_username[128], file_password[128];
        int id;
        // 형식: id|username|password_hash\n
        if (sscanf(line, "%d|%127[^|]|%127[^\n]", &id, file_username, file_password) == 3) {
            if (strcmp(username, file_username) == 0 &&
                strcmp(hashed_input, file_password) == 0) {
                valid = id;
                break;
            }
        }
    }
    fclose(fp);
    return valid;
}

int db_create_user(const char *username, const char *password) {
    FILE *fp = fopen(users_filename, "a");
    if (!fp)
        return -1;
    if (flock(fileno(fp), LOCK_EX) != 0) {
        fclose(fp);
        return -1;
    }
    int last_user_id = 0;
    char line[512];
    FILE *rf = fopen(users_filename, "r");
    if (rf) {
        while (fgets(line, sizeof(line), rf)) {
            int id;
            if (sscanf(line, "%d|", &id) == 1) {
                if (id > last_user_id)
                    last_user_id = id;
            }
        }
        fclose(rf);
    }
    int new_id = last_user_id + 1;
    char *hashed = hash_password(password);
    int ret = fprintf(fp, "%d|%s|%s\n", new_id, username, hashed);
    fflush(fp);
    fsync(fileno(fp));
    flock(fileno(fp), LOCK_UN);
    fclose(fp);
    return (ret < 0) ? -1 : 0;
}
