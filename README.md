*This file needs updating*

Orignally By : Paul Sery <pgsery@swcp.com>
Modified by  : Champ Clark <champ@quadrantsec.com>


DESCRIPTION:

Provides an out-of-band challenge-response authentication mechanism. 
When a user tries to authenticate, pam_obc looks for the user name 
in pam_obc.conf. If the user name exists, pam_obc executes the 
associated action to deliver a challenge (a random string) to the user. 
The user is authenticated if able to answer the challenge.

The out-of-band challenge provides a useful mechanism for authenticating
temporary or transient users. It could also provide an inexpensive "true"
two-factor authentication if coupled with, for instance, a static password
or public-key. For instance, OpenSSH has a patch that allows multiple 
authentication methods (see https://bugzilla.mindrot.org/show_bug.cgi?id=983)

OBC could also be used to improve web-based authentication.


CONFIGURATION FILE:

Default location: /etc/pam_obc.conf or /usr/local/etc/pam_obc.conf. The format is,

	username:action

where action is a command or script. For instance,

	pablo:/bin/mail -s 'Out-of-band challenge' pablo@myisp.com

PAM CONFIGURATION FORMAT:

	auth	sufficient    pam_obc.so


For example, /etc/pam.d/sshd:

	auth	sufficient    pam_obc.so

And SSH (/etc/ssh/sshd_config) has challenge-response option set.

EXAMPLE 1:

On machine xyz, sshd_config contains the "UsePAM yes" directive and
/etc/pam_obc.conf has the line,

        pablo:cat > /dev/console

When you SSH to machine xyz, sshd calls the pam infrastructure, which 
consults pam_obc. If finds you in pam_obc.conf, it runs the corresponding 
action and, in this case it pipes the challenge to your console.

EXAMPLE 2:

On machine xyz, sshd_config contains the "UsePAM yes" directive and
/etc/pam_obc.conf contains the line,

        pablo:/bin/mail -s 'Out-of-band challenge' pablo@myisp.com

When you SSH to machine xyz, sshd calls the pam infrastructure, which 
consults pam_obc. If finds you in pam_obc.conf, it runs the corresponding 
action and, in this case, emails a challenge to you. 

EXAMPLE 3:

On machine xyz, sshd_config contains the "UsePAM yes" directive and
/etc/pam_obc.conf contains the line,

	pablo:/usr/bin/ssh -t -i /home/pablo/.ssh/your-key pablo@localhost

When you SSH to machine xyz, sshd calls the pam infrastructure, which 
consults pam_obc. If finds you in pam_obc.conf, it runs the corresponding 
action and, in this case, uses SSH to send the challenge to you via 
/dev/console. 

For example,  your .ssh/authorized_keys file contains:
command="cat > /dev/console" ssh-rsa AAAAB...

BUGS:

Doesn't work with SELinux < 3.3.1-87 (or thereabouts).

TODO:

*modify appropriate SELinux context for older machines
*add logic to allow multiple actions per user
 (multiple user:action lines in pam_obc.conf)
*add logic to allow the user to cache 

