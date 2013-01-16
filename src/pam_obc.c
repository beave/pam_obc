/*
 *	Copyright(c) 2008 by Paul Sery (pgsery@swcp.com) 
 *
 * 	Champ Clark (cclark@quadrantsec.com)
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as 
 *	published by the Free Software Foundation.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <signal.h>
#include <security/pam_modules.h>

#include "pam_obc.h"

void sigtrap(int sig)
{
        switch(sig) {
        default:
        printf("Abort.\n");
        exit(1);
        }
}

struct actions {
	char *action;
	struct list  *next;
};

static char *
obc_action(const char *pam_uname)
{
	FILE *fp;
	int user_exists=0;
        char line[OBC_ACTION_SIZE];
        char *action=NULL;
        char *uname=NULL;

	fp = fopen("/etc/pam_obc.conf", "r");
	if (fp == NULL) {
		fp = fopen("/usr/local/etc/pam_obc.conf", "r");
		if (fp == NULL) {
			syslog(LOG_ALERT,"pam_obc: Error, can't open pam_obc.conf");
			return (NULL);
		}
	}

	/* parse the user configuration file - specifies obc for each user */ 
        while (fgets(line, sizeof(line), fp) != NULL)
        {
		/* skip comments (currently, # can be anywhere in the line) */
		if ( strstr(line,"#") != NULL) 
			continue;

		/* strip trailing chars */
		if ( (action=strstr(line,"\r")) != NULL)
        	        *action = '\0';
		if ( (action=strstr(line,"\t")) != NULL)
        	        *action = '\0';

		/* extract user name */
		uname=line;
		action=strstr(line,":");
		*action='\0';

		action++;

		if ( strstr(uname,pam_uname) != NULL) {
			user_exists++;
			break;
		} 
	}
	fclose(fp);

	if (!user_exists) {
		syslog(LOG_ALERT,"pam_obc: User %s was not found in pam_obc.conf!", pam_uname);
		action=NULL;
	}

	return(action);
}

char *
obc_gen(void)
{
	int i,ran,obc_size=OBC_MSG_SIZE;
	unsigned int seed;
	char *obc;
	size_t nchars = sizeof(CPOOL) - 1;
	FILE *fp;

	fp = fopen("/dev/random","r");
	if (fp == NULL) {
		syslog(LOG_ALERT,"pam_obc: Error: can't open /dev/random");
		return (NULL);
	}
	if ( fread(&seed,sizeof(seed),1,fp) == 0) {
		return (NULL);
		syslog(LOG_ALERT,"pam_obc: Error: can't read /dev/random");
	}
	fclose(fp);

	/* generate out-of-band challenge (obc) */
	obc = (char *) malloc(obc_size+1);
	if (obc == NULL)
		return obc;

	srandom(seed);

	for (i=0;i < obc_size; i++) {
		ran = random();
		obc[i] = CPOOL[ran%nchars];
	}
	obc[obc_size] = '\0';

	return obc;
}


PAM_EXTERN int pam_sm_setcred (pam_handle_t *pamh,
			       int flags,
			       int argc,
			       const char **argv)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int 
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval;
	char *msg = NULL;
	char *obc = NULL;
	char *pam_uname = NULL;
	char *action = NULL;
	char act_str[OBC_ACTION_SIZE];
	struct passwd *pw;
	struct pam_conv *conversation = NULL;
	struct pam_message message;
	struct pam_message *pmessage = &message;
	struct pam_response *response = NULL;

        signal (SIGHUP,  &sigtrap );
        signal (SIGINT,  &sigtrap );
        signal (SIGQUIT, &sigtrap );
        signal (SIGTERM, &sigtrap );
        signal (SIGABRT, &sigtrap );
	signal (SIGKILL, &sigtrap ); 		/* Not gonna happen */
	signal (SIGFPE,  &sigtrap );
	signal (SIGSEGV, &sigtrap );

        msg = (char *) malloc(PAM_MAX_MSG_SIZE);
        if (msg == NULL) {
                syslog(LOG_ALERT, "pam_obc: Error: Unable to malloc");
                return(PAM_SERVICE_ERR);
        }

        snprintf(msg, PAM_MAX_MSG_SIZE, OBC_PROMPT);
        message.msg_style = PAM_PROMPT_ECHO_OFF;
        message.msg = msg;

	retval = pam_get_item (pamh, PAM_USER, (const void **)&pam_uname);

	if ( retval != PAM_SUCCESS) {
                syslog(LOG_ALERT,"pam_obc: Error: PAM user name error: %d",retval);
		return (PAM_SERVICE_ERR);
	}

	if ((pw = getpwnam(pam_uname)) == NULL) {
	    syslog(LOG_ALERT,"pam_obc: User %s does not exist", pam_uname);	

#ifdef WITH_FAKE_CHALLENGE

	    syslog(LOG_ALERT,"pam_obc: User %s does not exist [sending fake OBC]", pam_uname);
   	    sleep(2);		/* Give the illusion we're doing something */
            retval = pam_get_item(pamh, PAM_CONV, (const void **)&conversation);	/* Fake,  we don't care about return() */
            conversation -> conv(1, (const struct pam_message **)&pmessage, &response, conversation ->appdata_ptr);
#endif

	return(PAM_SERVICE_ERR);
	}

	/* get user's out-of-band action from pam_obc.conf */
	if ( (action = obc_action(pam_uname)) == NULL) {
	        
		syslog(LOG_ALERT,"pam_obc: User %s unknown - continuing",pam_uname);
#ifndef WITH_FAKE_CHALLENGE
		return(PAM_SUCCESS);
#endif

#ifdef WITH_FAKE_CHALLENGE

		syslog(LOG_ALERT,"pam_obc: User %s unknown [sending fake OBC] ",pam_uname);
		sleep(2);               /* Give the illusion we're doing something */
		retval = pam_get_item(pamh, PAM_CONV, (const void **)&conversation);
		conversation -> conv(1, (const struct pam_message **)&pmessage, &response, conversation ->appdata_ptr);
		return(PAM_SERVICE_ERR);
#endif
	} 

	/* generate random out-of-band challenge */
	obc = obc_gen();
	if (obc == NULL) {
		syslog(LOG_ALERT,"pam_obc: ERROR: obc_gen() failed");
		return(PAM_SERVICE_ERR);
	} 

	/* deliver out-of-band challenge */
	snprintf(act_str, sizeof(act_str), "echo %s | %s",obc,action);

	if ( system(act_str) == -1) 
		syslog(LOG_ALERT,"pam_obc: Error sending out-of-band challenge");

	/* borrowed pam_get_item logic from pam_skey */
	retval = pam_get_item(pamh, PAM_CONV, (const void **)&conversation);
	if (retval != PAM_SUCCESS) {
                syslog(LOG_ALERT,"pam_obc: PAM get item error: %d",retval);
		return(PAM_SERVICE_ERR);
	}

	conversation -> conv(1, (const struct pam_message **)&pmessage,
		&response, conversation ->appdata_ptr);

	/* borrowed pam_set_item logic from pam_skey */
	retval = pam_set_item(pamh, PAM_AUTHTOK, response->resp);
	if (retval != PAM_SUCCESS) {
                syslog(LOG_ALERT,"pam_obc: PAM set item error: %d", retval);
		return(PAM_SERVICE_ERR);
	}
	
	if ((strcmp(obc,response->resp)) == 0) {
		syslog(LOG_ALERT,"pam_obc: Authenticated user %s using out-of-band challenge",pam_uname);
		retval=PAM_SUCCESS;
	} else {
		syslog(LOG_ALERT,"pam_obc: Failed auth for user %s using out-of-band challenge",pam_uname);
		retval=PAM_AUTH_ERR;
	}

return(retval);
}
