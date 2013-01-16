Orignally By : Paul Sery | <pgsery@swcp.com>

Modified by  : Champ Clark | <cclark@quadrantsec.com>

DESCRIPTION:
------------

Provides an out-of-band challenge-response authentication mechanism.
When a user tries to authenticate, pam_obc looks for the user name
in pam_obc.conf. If the user name exists, pam_obc executes the
associated action to deliver a challenge (a random string) to the user.
The user is authenticated if able to answer the challenge.

The out-of-band challenge provides a useful mechanism for authenticating
temporary or transient users. It could also provide an inexpensive "true"
two-factor authentication if coupled with, for instance, a static password
or public-key. 

OBC could also be used to improve web-based authentication.

It should be noted that pam_obc does not control "how" the challenge
is sent to the user.  It only generates and verifies that the challenge
and response are the same.  It is up to you to come up a means of secure
transport of the challenge strings.  Examples are below.

A short video showing pam_obc in action can be seen at http://www.youtube.com/watch?v=3-vrP2tU6c8
(The video show pam_obc sending challenges via Jabber/XMPP over SSL).


COMPILING:
----------

Compiling is pretty straight forward.  The typical:

	./configure && make && make install

Should work.  The only compile time flag you may wish to alter is the 
"--disable-fake-challenge".  By default,  reguardless of if the user exists
and/or is in the pam_obc.conf a "Challenge:" prompt is sent.  If this
option is disabled,  then "Challenge" prompts will _only_ be sent to
people in the /etc/pam_obc.conf.  If this option is disabled,  it'll make
it easier for an attacker to enumerate users.

To alter the behavior of pam_obc further,  see the pam_obc.h file 
(see https://github.com/beave/pam_obc/blob/master/src/pam_obc.h).

CONFIGURATION FILE:
-------------------

Default location: /etc/pam_obc.conf.  The format is:

	username:action

where action is a command or script. For instance,

	pablo:/bin/mail -s 'Out-of-band challenge' pablo@myisp.com

PAM CONFIGURATION FORMAT:
-------------------------

For example,  append the following to the end of the /etc/pam.d/sshd:

	auth       required    pam_obc.so

This can also be done with other tools requiring authentications, such
as su and sudo.  When testing make _sure_ you have a "root" session open and
_verify_ pam_obc is working properly.  In the past,  I've had to play
with /etc/pam.d/{filename} to get pam_obc to function properly.

EXAMPLE 1:  Challenge at the console.
-------------------------------------

On machine xyz, sshd_config contains the "UsePAM yes" directive and
/etc/pam_obc.conf has the line,

        pablo:cat > /dev/console

When you SSH to machine xyz, sshd calls the pam infrastructure, which 
consults pam_obc. If finds you in pam_obc.conf, it runs the corresponding 
action and, in this case it pipes the challenge to your console.

EXAMPLE 2: Challenge via SMTP
-----------------------------

On machine xyz, sshd_config contains the "UsePAM yes" directive and
/etc/pam_obc.conf contains the line,

        pablo:/bin/mail -s 'Out-of-band challenge' pablo@myisp.com

When you SSH to machine xyz, sshd calls the pam infrastructure, which 
consults pam_obc. If finds you in pam_obc.conf, it runs the corresponding 
action and, in this case, emails a challenge to you. 

Note: This is likely a insecure method of sending a challenge!

EXAMPLE 3: Challenge via Jabber/XMPP
------------------------------------

In the pam_obc "extra" directory is a perl routine called "send-challenge".
(See https://github.com/beave/pam_obc/blob/master/extra/send-challenge).
The allows for communications with a Jabber server (for example, Google
Talk).  I've used this routine with Jabber over SSL to send challenges in a
more secure method.  The /etc/pam_obc.conf would look like this:

	champ:/usr/local/bin/send-challenge dabeave production.example.com

"dabeave" would be the Jabber username to send and "production.example.com"
is what machine the challenge is for.

EXAMPLE 4: Challenges via SSH
-----------------------------

On machine xyz, sshd_config contains the "UsePAM yes" directive and
/etc/pam_obc.conf contains the line,

	pablo:/usr/bin/ssh -t -i /home/pablo/.ssh/your-key pablo@localhost

When you SSH to machine xyz, sshd calls the pam infrastructure, which 
consults pam_obc. If finds you in pam_obc.conf, it runs the corresponding 
action and, in this case, uses SSH to send the challenge to you via 
/dev/console. 

For example,  your .ssh/authorized_keys file contains:
command="cat > /dev/console" ssh-rsa AAAAB...


