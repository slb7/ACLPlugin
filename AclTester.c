#include <stdio.h>
#include <config.h>
#include <uthash.h>
#include <mosquitto_broker.h>
struct my_struct {
    char *user;
    struct _mosquitto_acl *acl_list;
    UT_hash_handle hh;         /* makes this structure hashable */
};
struct my_struct *users = NULL;
void add_u(char *u, struct _mosquitto_acl_user *item) {
    struct my_struct *s;
    HASH_FIND_STR(users,u,s);
    if(s == NULL) {
      s = (struct my_struct*)malloc(sizeof(struct my_struct));
      s->user = strdup(u);
      s->acl_list = NULL;
      HASH_ADD_KEYPTR(hh,users,s->user,strlen(s->user),s);
      printf("stored  %s\n",s->user);
      HASH_FIND_STR(users,"roger",s);
      printf("find returned %p\n",s);
    }
    struct _mosquitto_acl *l = s->acl_list;
    if(l) {
      while(l->next) l = l->next;
      l->next = item->acl;
    }
    else l = item->acl;
    s->acl_list = l;
}
void testit(char *user,char *topic, struct mosquitto_db *db, int access,
  char *connid)
{
  struct mosquitto context;
  struct _mosquitto_acl_user acl_list;
  context.username = user;
  context.id = connid;
  context.bridge = 0;
  struct my_struct *s;
  HASH_FIND_STR(users,user,s);
  context.acl_list = NULL;
  if(s) {
    context.acl_list = &acl_list;
    context.acl_list->username = user;
    context.acl_list->acl = s->acl_list;
  }
  int rc = mosquitto_acl_check_default(db, &context, topic, access);
  printf("check %s %s %d rc=%d\n",user,topic,access,rc);
}
int init(struct mosquitto_db *db) {
  
  struct my_struct *s;
  s = (struct my_struct*)malloc(sizeof(struct my_struct));
  struct mqtt3_config config;
  db->config = &config;
  db->acl_patterns = NULL;
  db->acl_list = NULL;
  config.acl_file = "aclfile.example"; 
  int rc = mosquitto_security_init_default(db,false);
  printf("rc = %d\n",rc);
  struct _mosquitto_acl_user *al = db->acl_list;
  while(al) {
    if(al->username != NULL) add_u(al->username,al);
     printf("au = %s topic=%s access = %d\n",al->username,al->acl->topic,al->acl->access);
    al = al->next;
  }
}
int main(int argc, char **argv) {
  struct my_struct *s;
  s = (struct my_struct*)malloc(sizeof(struct my_struct));
  s->user = strdup("roger");
//  HASH_ADD_KEYPTR(hh,users,s->user,strlen(s->user),s);
  HASH_FIND_STR(users,"roger",s);
  printf("find returned %p\n",s);
 // return 1;
  struct mosquitto_db db;
  init(&db);
  testit("val","/quote/val/baseline",&db, MOSQ_ACL_READ,"AAA");
  testit("val","/quote/roger/baseline",&db, MOSQ_ACL_READ,"AAA");
  testit("roger","foo/bar",&db, MOSQ_ACL_READ,"AAA");
  testit("val","foo/bar",&db, MOSQ_ACL_READ,"connid");
  testit("roger","foo/bar",&db, MOSQ_ACL_READ,"connid");
}
