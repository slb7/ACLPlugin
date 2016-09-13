#include <stdio.h>
#include <config.h>
#include <uthash.h>
#include <mosquitto_broker.h>
struct plugin_user_data {
  struct mosquitto_db *db;
};
struct my_struct {
    char *user;
    struct _mosquitto_acl *acl_list;
    UT_hash_handle hh;         /* makes this structure hashable */
};
struct my_struct *users = NULL;
static void _free_acl(struct _mosquitto_acl *acl)
{
        if(!acl) return;

        if(acl->next){
                _free_acl(acl->next);
        }
        if(acl->topic){
                _mosquitto_free(acl->topic);
        }
        _mosquitto_free(acl);
}
static int _acl_cleanup(struct mosquitto_db *db, bool reload) {
        struct mosquitto *context, *ctxt_tmp;
        struct _mosquitto_acl_user *user_tail;

        if(!db) return MOSQ_ERR_INVAL;
        if(!db->acl_list) return MOSQ_ERR_SUCCESS;

        /* As we're freeing ACLs, we must clear context->acl_list to ensure no
         * invalid memory accesses take place later.
         * This *requires* the ACLs to be reapplied after _acl_cleanup()
         * is called if we are reloading the config. If this is not done, all 
         * access will be denied to currently connected clients.
         */
        //HASH_ITER(hh_id, db->contexts_by_id, context, ctxt_tmp){
        //        context->acl_list = NULL;
        //}

        while(db->acl_list){
                user_tail = db->acl_list->next;

                _free_acl(db->acl_list->acl);
                if(db->acl_list->username){
                        _mosquitto_free(db->acl_list->username);
                }
                _mosquitto_free(db->acl_list);

                db->acl_list = user_tail;
        }

        if(db->acl_patterns){
                _free_acl(db->acl_patterns);
                db->acl_patterns = NULL;
        }
        return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
  struct plugin_user_data * pd = (struct plugin_user_data *)user_data;
  _acl_cleanup((struct mosquitto_db *)pd->db,true);
  struct my_struct *current_user, *tmp;
  HASH_ITER(hh, users, current_user, tmp) {
    free(current_user->user);
    HASH_DEL(users, current_user);  /* delete it (users advances to next) */
    free(current_user);             /* free it */
  }
  return 0;
}
void add_u(char *u, struct _mosquitto_acl_user *item) {
    struct my_struct *s;
    //HASH_FIND_STR(users,u,s);
    HASH_FIND(hh,users,u,strlen(u),s);
    if(s == NULL) {
      s = (struct my_struct*)malloc(sizeof(struct my_struct));
      s->user = strdup(u);
      s->acl_list = NULL;
      HASH_ADD_KEYPTR(hh,users,s->user,strlen(s->user),s);
      HASH_FIND(hh,users,u,strlen(u),s);
    
      printf("find ster eturned!! %p\n",s);
      if(!s) {
        printf("find returned %p\n",s);
        return;
      }
      printf("find returned!! %p\n",s);
    }
    struct _mosquitto_acl *l = s->acl_list;
    if(l) {
      while(l->next) l = l->next;
      l->next = item->acl;
    }
    else l = item->acl;
    s->acl_list = l;
}
int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload) {
  struct plugin_user_data *pud = (struct plugin_user_data *)user_data;
  struct mqtt3_config config;
  struct mosquitto_db *db = (struct mosquitto_db *)malloc(sizeof(struct mosquitto_db));
  pud->db = db;
  db->config = &config;
  db->acl_patterns = NULL;
  db->acl_list = NULL;
  int i;
  char *fn = NULL;
  struct mosquitto_auth_opt *p = auth_opts;
  for(i=0;i<auth_opt_count;i++) {
    if(!strcmp(p->key,"aclFileName")) fn = p->value;
  }
  if(!fn) {
    printf("no aclFileName in auth plugin config\n");
    return 0;
  } else {
    printf("loading acl file %s\n",fn);
  }
  config.acl_file = fn;
  int rc = mosquitto_security_init_default(db,false);
  printf("rc = %d\n",rc);
  if(rc) return rc;
  struct _mosquitto_acl_user *al = db->acl_list;
  while(al) {
    if(al->username != NULL) add_u(al->username,al);
    printf("au = %s topic=%s access = %d\n",al->username,al->acl->topic,al->acl->access);
    al = al->next;
  }
}
int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
  struct plugin_user_data *pud = (struct plugin_user_data *)malloc(sizeof(struct plugin_user_data));
  *user_data = pud;
  /*struct mqtt3_config config;
  struct mosquitto_db *db = (struct mosquitto_db *)malloc(sizeof(struct mosquitto_db));
  pud->db = db;
  db->config = &config;
  db->acl_patterns = NULL;
  db->acl_list = NULL;
  int i;
  char *fn = NULL;
  struct mosquitto_auth_opt *p = auth_opts;
  for(i=0;i<auth_opt_count;i++) {
    if(!strcmp(p->key,"aclFileName")) fn = p->value;
  }
  if(!fn) {
    printf("no aclFileName in auth plugin config\n");
    return 0;
  } else {
    printf("loading acl file %s\n",fn);
  }
  config.acl_file = fn;
  int rc = mosquitto_security_init_default(db,false);
  printf("rc = %d\n",rc);
  if(rc) return rc;
  struct _mosquitto_acl_user *al = db->acl_list;
  while(al) {
    if(al->username != NULL) add_u(al->username,al);
    printf("au = %s topic=%s access = %d\n",al->username,al->acl->topic,al->acl->access);
    al = al->next;
  }*/
}
int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
  free(user_data);
  return 0;
}
int mosquitto_auth_acl_check(void *user_data, const char *clientid, const char *username, const char *topic, int access) {

  struct mosquitto context;
  struct _mosquitto_acl_user acl_list;
  struct plugin_user_data *pud = (struct plugin_user_data *)user_data;
  struct mosquitto_db *db = pud->db;
  context.username = (char *)username;
  context.id = (char *)clientid;
  context.bridge = 0;
  struct my_struct *s;
  HASH_FIND_STR(users,username,s);
  context.acl_list = NULL;
  if(s) {
    context.acl_list = &acl_list;
    context.acl_list->username = (char *)username;
    context.acl_list->acl = s->acl_list;
  }
  int rc = mosquitto_acl_check_default(db, &context, topic, access);
  //printf("check %s %s %d rc=%d\n",username,topic,access,rc);
  return rc;
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
/*int main(int argc, char **argv) {
  struct plugin_user_data *user_data;
  int rc = mosquitto_auth_plugin_init((void **)&user_data,NULL,0);
  printf("init returned %d\n",rc);
  rc = mosquitto_auth_acl_check((void *)user_data, "AAA", "val",
     "/quote/val/baseline",MOSQ_ACL_READ);
  printf("acl_check returned %d\n",rc);
  rc = mosquitto_auth_plugin_cleanup((void *)user_data,NULL,0);
#*  init(&db);
  testit("val","/quote/val/baseline",&db, MOSQ_ACL_READ,"AAA");
  testit("val","/quote/roger/baseline",&db, MOSQ_ACL_READ,"AAA");
  testit("roger","foo/bar",&db, MOSQ_ACL_READ,"AAA");
  testit("val","foo/bar",&db, MOSQ_ACL_READ,"connid");
  testit("roger","foo/bar",&db, MOSQ_ACL_READ,"connid"); #/
#*/
