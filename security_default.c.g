/*
Copyright (c) 2011-2014 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
*/

#include <config.h>

#include <stdio.h>
#include <string.h>

#include <mosquitto_broker.h>
#include <memory_mosq.h>
#include "util_mosq.h"
void _mosquitto_free(void *ptr)
{
  free(ptr);
}
char *_mosquitto_strdup(const char *in)
{
  return strdup(in);
}
void *_mosquitto_malloc(size_t s)
{
  return malloc(s);
}
static int _aclfile_parse(struct mosquitto_db *db);
static int _acl_cleanup(struct mosquitto_db *db, bool reload);

int mosquitto_security_init_default(struct mosquitto_db *db, bool reload)
{
	int rc;

	/* Load acl data if required. */
	if(db->config->acl_file){
		rc = _aclfile_parse(db);
		if(rc){
			printf("Error opening acl file \"%s\".", db->config->acl_file);
			return rc;
		}
	}
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_security_cleanup_default(struct mosquitto_db *db, bool reload)
{
	return  _acl_cleanup(db, reload);
}


int _add_acl(struct mosquitto_db *db, const char *user, const char *topic, int access)
{
	struct _mosquitto_acl_user *acl_user=NULL, *user_tail;
	struct _mosquitto_acl *acl, *acl_tail;
	char *local_topic;
	bool new_user = false;

	if(!db || !topic) return MOSQ_ERR_INVAL;

	local_topic = _mosquitto_strdup(topic);
	if(!local_topic){
		return MOSQ_ERR_NOMEM;
	}

	if(db->acl_list){
		user_tail = db->acl_list;
		while(user_tail){
			if(user == NULL){
				if(user_tail->username == NULL){
					acl_user = user_tail;
					break;
				}
			}else if(user_tail->username && !strcmp(user_tail->username, user)){
				acl_user = user_tail;
				break;
			}
			user_tail = user_tail->next;
		}
	}
	if(!acl_user){
		acl_user = _mosquitto_malloc(sizeof(struct _mosquitto_acl_user));
		if(!acl_user){
			_mosquitto_free(local_topic);
			return MOSQ_ERR_NOMEM;
		}
		new_user = true;
		if(user){
			acl_user->username = _mosquitto_strdup(user);
			if(!acl_user->username){
				_mosquitto_free(local_topic);
				_mosquitto_free(acl_user);
				return MOSQ_ERR_NOMEM;
			}
		}else{
			acl_user->username = NULL;
		}
		acl_user->next = NULL;
		acl_user->acl = NULL;
	}

	acl = _mosquitto_malloc(sizeof(struct _mosquitto_acl));
	if(!acl){
		_mosquitto_free(local_topic);
		return MOSQ_ERR_NOMEM;
	}
	acl->access = access;
	acl->topic = local_topic;
	acl->next = NULL;
	acl->ccount = 0;
	acl->ucount = 0;

	/* Add acl to user acl list */
	if(acl_user->acl){
		acl_tail = acl_user->acl;
		while(acl_tail->next){
			acl_tail = acl_tail->next;
		}
		acl_tail->next = acl;
	}else{
		acl_user->acl = acl;
	}

	if(new_user){
		/* Add to end of list */
		if(db->acl_list){
			user_tail = db->acl_list;
			while(user_tail->next){
				user_tail = user_tail->next;
			}
			user_tail->next = acl_user;
		}else{
			db->acl_list = acl_user;
		}
	}

	return MOSQ_ERR_SUCCESS;
}

int _add_acl_pattern(struct mosquitto_db *db, const char *topic, int access)
{
	struct _mosquitto_acl *acl, *acl_tail;
	char *local_topic;
	char *s;

	if(!db || !topic) return MOSQ_ERR_INVAL;

	local_topic = _mosquitto_strdup(topic);
	if(!local_topic){
		return MOSQ_ERR_NOMEM;
	}

	acl = _mosquitto_malloc(sizeof(struct _mosquitto_acl));
	if(!acl){
		_mosquitto_free(local_topic);
		return MOSQ_ERR_NOMEM;
	}
	acl->access = access;
	acl->topic = local_topic;
	acl->next = NULL;

	acl->ccount = 0;
	s = local_topic;
	while(s){
		s = strstr(s, "%c");
		if(s){
			acl->ccount++;
			s+=2;
		}
	}

	acl->ucount = 0;
	s = local_topic;
	while(s){
		s = strstr(s, "%u");
		if(s){
			acl->ucount++;
			s+=2;
		}
	}

	if(db->acl_patterns){
		acl_tail = db->acl_patterns;
		while(acl_tail->next){
			acl_tail = acl_tail->next;
		}
		acl_tail->next = acl;
	}else{
		db->acl_patterns = acl;
	}

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_acl_check_default(struct mosquitto_db *db, struct mosquitto *context, const char *topic, int access)
{
	char *local_acl;
	struct _mosquitto_acl *acl_root;
	bool result;
	int i;
	int len, tlen, clen, ulen;
	char *s;

	if(!db || !context || !topic) return MOSQ_ERR_INVAL;
	if(!db->acl_list && !db->acl_patterns) return MOSQ_ERR_SUCCESS;
	if(context->bridge) return MOSQ_ERR_SUCCESS;
	if(!context->acl_list && !db->acl_patterns) return MOSQ_ERR_ACL_DENIED;

	if(context->acl_list){
		acl_root = context->acl_list->acl;
	}else{
		acl_root = NULL;
	}

	/* Loop through all ACLs for this client. */
	while(acl_root){
		/* Loop through the topic looking for matches to this ACL. */

		/* If subscription starts with $, acl_root->topic must also start with $. */
		if(topic[0] == '$' && acl_root->topic[0] != '$'){
			acl_root = acl_root->next;
			continue;
		}
		mosquitto_topic_matches_sub(acl_root->topic, topic, &result);
		if(result){
			if(access & acl_root->access){
				/* And access is allowed. */
				return MOSQ_ERR_SUCCESS;
			}
		}
		acl_root = acl_root->next;
	}

	acl_root = db->acl_patterns;
	/* Loop through all pattern ACLs. */
	clen = strlen(context->id);
	while(acl_root){
		tlen = strlen(acl_root->topic);

		if(acl_root->ucount && !context->username){
			acl_root = acl_root->next;
			continue;
		}

		if(context->username){
			ulen = strlen(context->username);
			len = tlen + acl_root->ccount*(clen-2) + acl_root->ucount*(ulen-2);
		}else{
			ulen = 0;
			len = tlen + acl_root->ccount*(clen-2);
		}
		local_acl = _mosquitto_malloc(len+1);
		if(!local_acl) return 1; // FIXME
		s = local_acl;
		for(i=0; i<tlen; i++){
			if(i<tlen-1 && acl_root->topic[i] == '%'){
				if(acl_root->topic[i+1] == 'c'){
					i++;
					strncpy(s, context->id, clen);
					s+=clen;
					continue;
				}else if(context->username && acl_root->topic[i+1] == 'u'){
					i++;
					strncpy(s, context->username, ulen);
					s+=ulen;
					continue;
				}
			}
			s[0] = acl_root->topic[i];
			s++;
		}
		local_acl[len] = '\0';

		mosquitto_topic_matches_sub(local_acl, topic, &result);
		_mosquitto_free(local_acl);
		if(result){
			if(access & acl_root->access){
				/* And access is allowed. */
				return MOSQ_ERR_SUCCESS;
			}
		}

		acl_root = acl_root->next;
	}

	return MOSQ_ERR_ACL_DENIED;
}

static int _aclfile_parse(struct mosquitto_db *db)
{
	FILE *aclfile;
	char buf[1024];
	char *token;
	char *user = NULL;
	char *topic;
	char *access_s;
	int access;
	int rc;
	int slen;
	int topic_pattern;
	char *saveptr = NULL;

	if(!db || !db->config) return MOSQ_ERR_INVAL;
	if(!db->config->acl_file) return MOSQ_ERR_SUCCESS;

	aclfile = _mosquitto_fopen(db->config->acl_file, "rt");
	if(!aclfile){
		printf("Error: Unable to open acl_file \"%s\".", db->config->acl_file);
		return 1;
	}

	// topic [read|write] <topic> 
	// user <user>

	while(fgets(buf, 1024, aclfile)){
		slen = strlen(buf);
		while(slen > 0 && (buf[slen-1] == 10 || buf[slen-1] == 13)){
			buf[slen-1] = '\0';
			slen = strlen(buf);
		}
		if(buf[0] == '#'){
			continue;
		}
		token = strtok_r(buf, " ", &saveptr);
		if(token){
			if(!strcmp(token, "topic") || !strcmp(token, "pattern")){
				if(!strcmp(token, "topic")){
					topic_pattern = 0;
				}else{
					topic_pattern = 1;
				}

				access_s = strtok_r(NULL, " ", &saveptr);
				if(!access_s){
					printf("Error: Empty topic in acl_file.");
					if(user) _mosquitto_free(user);
					fclose(aclfile);
					return MOSQ_ERR_INVAL;
				}
				token = strtok_r(NULL, "", &saveptr);
				if(token){
					topic = token;
					/* Ignore duplicate spaces */
					while(topic[0] == ' '){
						topic++;
					}
				}else{
					topic = access_s;
					access_s = NULL;
				}
				if(access_s){
					if(!strcmp(access_s, "read")){
						access = MOSQ_ACL_READ;
					}else if(!strcmp(access_s, "write")){
						access = MOSQ_ACL_WRITE;
					}else if(!strcmp(access_s, "readwrite")){
						access = MOSQ_ACL_READ | MOSQ_ACL_WRITE;
					}else{
						printf("Error: Invalid topic access type \"%s\" in acl_file.", access_s);
						if(user) _mosquitto_free(user);
						fclose(aclfile);
						return MOSQ_ERR_INVAL;
					}
				}else{
					access = MOSQ_ACL_READ | MOSQ_ACL_WRITE;
				}
				if(topic_pattern == 0){
					rc = _add_acl(db, user, topic, access);
				}else{
					rc = _add_acl_pattern(db, topic, access);
				}
				if(rc){
					if(user) _mosquitto_free(user);
					fclose(aclfile);
					return rc;
				}
			}else if(!strcmp(token, "user")){
				token = strtok_r(NULL, "", &saveptr);
				if(token){
					/* Ignore duplicate spaces */
					while(token[0] == ' '){
						token++;
					}
					if(user) _mosquitto_free(user);
					user = _mosquitto_strdup(token);
					if(!user){
						fclose(aclfile);
						return MOSQ_ERR_NOMEM;
					}
				}else{
					printf("Error: Missing username in acl_file.");
					if(user) _mosquitto_free(user);
					fclose(aclfile);
					return 1;
				}
			}
		}
	}

	if(user) _mosquitto_free(user);
	fclose(aclfile);

	return MOSQ_ERR_SUCCESS;
}

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

static int _acl_cleanup(struct mosquitto_db *db, bool reload)
{
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
	HASH_ITER(hh_id, db->contexts_by_id, context, ctxt_tmp){
		context->acl_list = NULL;
	}

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
