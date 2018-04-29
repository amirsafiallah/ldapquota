LDAP Quota
==========
This source code written in C reads quota attirbute from ldap.

How to Use
----------
Change the following parameter, compile then run:

        const char *url = "ldap://192.168.189.156:389";
        const char *dn = "ou=people,dc=iasbs,dc=ac,dc=ir";
        const char *filter = "uidNumber=110";

Useful Resources
----------------
an example of an LDAP synchronous search using an LDAP API
https://gist.github.com/syzdek/1459007

OpenLDAP Manual Pages
http://www.openldap.org/software/man.cgi?manpath=OpenLDAP+2.4-Release