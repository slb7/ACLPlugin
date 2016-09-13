#include <stdio.h>
#include <config.h>

#include <mosquitto.h>
#include <mosquitto_plugin.h>
void verify_acl(void *ud, const char *conn, const char *user, const char *topic, int access)
{
  int rc = mosquitto_auth_acl_check(ud, conn, user,
     topic,access);
  char *a = "UNK";
  switch(access) {
  case MOSQ_ACL_READ:
     a = "READ";
     break;
  case MOSQ_ACL_WRITE:
     a = "WRITE";
     break;
  }
  printf("acl_check returned %d t=%s c=%s u=%s %s\n",rc,topic,conn,user,a);
}
int main(int argc, char **argv) {
  struct plugin_user_data *user_data;
  struct mosquitto_auth_opt fn;
  fn.key = "aclFileName";
  fn.value = "aclfile.example";
  int rc = mosquitto_auth_plugin_init((void **)&user_data,&fn,1);
  printf("plugin init returned %d\n",rc);
  rc = mosquitto_auth_security_init((void *)user_data,&fn,1,false);
  printf("init returned %d\n",rc);
  verify_acl((void *)user_data,"AAA","val","/quote/val/baseline",MOSQ_ACL_READ);
  verify_acl((void *)user_data,"AAA","val","/quote/val/baseline",MOSQ_ACL_WRITE);
  verify_acl((void *)user_data,"AAA","QuotePublisher","/quote/val/baseline",MOSQ_ACL_WRITE);
  verify_acl((void *)user_data,"AAA","roger","foo/bar",MOSQ_ACL_WRITE);
  verify_acl((void *)user_data,"AAA","val","foo/bar",MOSQ_ACL_WRITE);
  rc = mosquitto_auth_security_cleanup((void *)user_data,NULL,0,true);
  fn.value = "aclfile.example2";
  rc = mosquitto_auth_security_init((void *)user_data,&fn,1,false);
  verify_acl((void *)user_data,"AAA","val","/quote/val/baseline",MOSQ_ACL_READ);
  verify_acl((void *)user_data,"AAA","val","/quote/val/baseline",MOSQ_ACL_WRITE);
  verify_acl((void *)user_data,"AAA","QuotePublisher","/quote/val/baseline",MOSQ_ACL_WRITE);
  verify_acl((void *)user_data,"AAA","roger","foo/bar",MOSQ_ACL_WRITE);
  verify_acl((void *)user_data,"AAA","val","foo/bar",MOSQ_ACL_WRITE);
  rc = mosquitto_auth_security_cleanup((void *)user_data,NULL,0,true);
  rc = mosquitto_auth_plugin_cleanup((void *)user_data,NULL,0);
}
