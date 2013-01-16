/*
 *      Copyright(c) 2008 by Paul Sery (pgsery@swcp.com) 
 *
 *      Champ Clark (cclark@quadrantsec.com)
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License version 2 as 
 *      published by the Free Software Foundation.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 */

/* These are the characters we're allowed to use in a challenge */

#define CPOOL	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ2346789"

/* Challenge message size */

#define OBC_MSG_SIZE    16

/* Max size of the command to be executed */

#define OBC_ACTION_SIZE 255

/* Challenge Prompt */

#define OBC_PROMPT	"Challenge: "

/* If set,  we send a fake "challenge" prompt.  This is to help preent user 
 * enumeration */

#define  OBC_FAKE 	1

