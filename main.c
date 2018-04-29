#include <stdio.h>
#include <stdlib.h>
#include <ldap.h>
#include <err.h>
#include <ctype.h>

struct ldap_quota {
    char fs[BUFSIZ]; //File System
    u_int64_t quotaBhardlimit; //Blocks Hard Limit
    u_int64_t quotaBsoftlimit; //Blocks Soft Limit
    u_int64_t quotaIhardlimit; //INodes Hard Limit
    u_int64_t quotaIsoftlimit; //INodes Soft Limit
};

char *trim(char *str) {
    char *end;

    // Trim leading space
    while (isspace((unsigned char) *str)) str++;

    if (*str == 0)  // All spaces?
        return str;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char) *end)) end--;

    // Write new null terminator
    *(end + 1) = 0;

    return str;
}

//return 1 if success
int read_ldap_quota(char *str, struct ldap_quota *a) {
    //read (FileSystem:BlocksSoft,BlocksHard,InodesSoft,InodesHard) from quota attribute
    //this format is used on quota.schema

    a->fs[0] = '\0';
    char *p = strchr(str, ':'); //find `:` character
    if (p == NULL) return 0;
    *(p) = '\0';
    strcpy(a->fs, trim(str)); //trim any whitespace before and after FS path

    int r = sscanf(p + 1,
                   " %lu , %lu , %lu , %lu ",
                   &a->quotaBsoftlimit,
                   &a->quotaBhardlimit,
                   &a->quotaIsoftlimit,
                   &a->quotaIhardlimit);
    return (r > 0);
}

int main() {
    struct ldap_quota ldapquota; //Quota information from ldap
    int read = 0; //becomes 1 after read
    const char *url = "ldap://192.168.189.156:389";
    const char *dn = "ou=people,dc=iasbs,dc=ac,dc=ir"; //dn
    const char *filter = "uidNumber=110"; //person uid number
    char *attr[] = {"quota", NULL}; //attribute `quota` according to schema.
    LDAP *LDAP;
    int version = LDAP_VERSION3; //version of ldap
    struct timeval search_timeout;
    search_timeout.tv_sec = 1000; //search timeout (seconds)
    search_timeout.tv_usec = 0;//and search timeout (microseconds)
    int err;
    LDAPMessage *res;

    err = ldap_initialize(&LDAP, url);
    if (err != LDAP_SUCCESS) {
        fprintf(stderr, "ldap_initialize(): %s\n", ldap_err2string(err));
        return err;
    }

    err = ldap_set_option(LDAP, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (err != LDAP_SUCCESS) {
        fprintf(stderr, "ldap_set_option(PROTOCOL_VERSION): %s\n", ldap_err2string(err));
        ldap_unbind_ext_s(LDAP, NULL, NULL);
        return err;
    };


    err = ldap_search_ext_s(
            LDAP,                         // LDAP            * ld
            dn,        // char            * base
            LDAP_SCOPE_ONELEVEL,     // int               scope
            filter,    // char            * filter
            attr,     // char            * attrs[]
            0,                          // int               attrsonly
            NULL,                       // LDAPControl    ** serverctrls
            NULL,                       // LDAPControl    ** clientctrls
            &search_timeout,                        // struct timeval  * timeout
            1,        // int               sizelimit
            &res                        // LDAPMessage    ** res
    );

    if (err != LDAP_SUCCESS) {
        fprintf(stderr, "ldap_search_ext_s(): %s\n", ldap_err2string(err));
        ldap_msgfree(res);
        ldap_unbind_ext_s(LDAP, NULL, NULL);
        return err;
    };

    // verify an entry was found
    if (!(ldap_count_entries(LDAP, res))) {
        printf("0 entries found.\n");
        ldap_msgfree(res);
        ldap_unbind_ext_s(LDAP, NULL, NULL);
        return (0);
    };
    printf("# %i entries found.\n", ldap_count_entries(LDAP, res));

    // loops through entries, attributes, and values
    LDAPMessage *entry = ldap_first_entry(LDAP, res);

    BerElement *ber;
    char *attribute = ldap_first_attribute(LDAP, entry, &ber);
    while ((attribute)) {
        struct berval **vals = ldap_get_values_len(LDAP, entry, attribute);
        for (int pos = 0; pos < ldap_count_values_len(vals); pos++)
            if (strcmp(attribute, "quota") == 0) {
                if (read_ldap_quota(vals[pos]->bv_val, &ldapquota))
                    read = 1;
            }
        ldap_value_free_len(vals);
        ldap_memfree(attribute);
        attribute = ldap_next_attribute(LDAP, entry, ber);
    };
    ber_free(ber, 0);

    ldap_msgfree(res);
    ldap_unbind_ext_s(LDAP, NULL, NULL);

    if (read) {
        printf("Quotas (FileSystem:BlocksSoft,BlocksHard,InodesSoft,InodesHard)\n"
               "(%s,%lu,%lu,%lu,%lu)",
               ldapquota.fs, ldapquota.quotaBsoftlimit, ldapquota.quotaBhardlimit, ldapquota.quotaIsoftlimit,
               ldapquota.quotaIhardlimit);
    } else {
        printf("Quotas Not Found!");
    }
    return EXIT_SUCCESS;
}