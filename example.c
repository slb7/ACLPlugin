#include <stdio.h>   /* gets */
#include <stdlib.h>  /* atoi, malloc */
#include <string.h>  /* strcpy */
#include "uthash.h"

struct my_struct {
    int id;
    char *u;
    char name[10];
    UT_hash_handle hh;         /* makes this structure hashable */
};

struct my_struct *users = NULL;
void add_u(char *u, char *name) {
    struct my_struct *s;
    s = (struct my_struct*)malloc(sizeof(struct my_struct));
    s->u = strdup(u);
    strcpy(s->name, name);
    HASH_ADD_STR(users,u,s);
}

void add_user(int user_id, char *name) {
    struct my_struct *s;

    HASH_FIND_INT(users, &user_id, s);  /* id already in the hash? */
    if (s==NULL) {
      s = (struct my_struct*)malloc(sizeof(struct my_struct));
      s->id = user_id;
      HASH_ADD_INT( users, id, s );  /* id: name of key field */
    }
    strcpy(s->name, name);
}

struct my_struct *find_user(int user_id) {
    struct my_struct *s;

    HASH_FIND_INT( users, &user_id, s );  /* s: output pointer */
    return s;
}

void delete_user(struct my_struct *user) {
    HASH_DEL(users, user);  /* user: pointer to deletee */
    free(user);
}

void delete_all() {
  struct my_struct *current_user, *tmp;

  HASH_ITER(hh, users, current_user, tmp) {
    HASH_DEL(users, current_user);  /* delete it (users advances to next) */
    free(current_user);             /* free it */
  }
}
void print_u() {
    struct my_struct *s;

    for(s=users; s != NULL; s=(struct my_struct*)(s->hh.next)) {
        printf("user id %s: name %s\n", s->u, s->name);
    }
}

void print_users() {
    struct my_struct *s;

    for(s=users; s != NULL; s=(struct my_struct*)(s->hh.next)) {
        printf("user id %d: name %s\n", s->id, s->name);
    }
}

int name_sort(struct my_struct *a, struct my_struct *b) {
    return strcmp(a->name,b->name);
}

int id_sort(struct my_struct *a, struct my_struct *b) {
    return (a->id - b->id);
}

void sort_by_name() {
    HASH_SORT(users, name_sort);
}

void sort_by_id() {
    HASH_SORT(users, id_sort);
}

int main(int argc, char *argv[]) {
    char in[10];
    int id=1, running=1;
    struct my_struct *s;
    unsigned num_users;
    add_u("s","scott");
    add_u("j","joe");
    print_u();


    delete_all();  /* free any structures */
    return 0;
}
