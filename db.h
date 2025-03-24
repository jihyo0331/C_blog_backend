#ifndef DB_H
#define DB_H

typedef struct {
    int id;
    char title[256];
    char content[1024];
    char date[64];
} Post;

// 파일 기반 DB 초기화 (posts, users 파일 지정)
int db_init(const char *posts_file, const char *users_file);
// 종료 (별도 리소스 해제 없음)
int db_close();

// 게시글 관련 함수
int db_add_post(const char *title, const char *content, const char *date);
int db_get_posts(Post **posts, int *count);

// 사용자 관련 함수 (암호는 해시 저장 – crypt() 사용)
int db_validate_user(const char *username, const char *password);
int db_create_user(const char *username, const char *password);

#endif // DB_H
