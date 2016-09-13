#include <stdio.h>
#include <uthash.h>
struct my_struct {
//    char *username;         /* alternative key */
    UT_hash_handle hh2;        /* handle for second hash table */
};
int main(int argc, char **argv) {
    struct my_struct *users_by_id = NULL, *users_by_name = NULL, *s;
    char *name;
    char *name1;
    s = malloc(sizeof(struct my_struct));
 //   s->username = strdup("thanson");
    name1 = strdup("thanson");
    //HASH_ADD_KEYPTR(hh2, users_by_name, s->username, strlen(s->username), s);
    HASH_ADD_KEYPTR(hh2, users_by_name, name1, strlen(name1), s);
    name = "thanson";
    HASH_FIND(hh2, users_by_name, name, strlen(name), s);
    if (s) printf("found user %s: \n", name);
}
