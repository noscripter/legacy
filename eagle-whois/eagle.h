/******************************************************/
/*              eagle.h -   eagle stuff                */
/*       Part of eagle-whois project                   */
/*  Copyright (c) 2015 by Hypsurus <hypsurus@mail.ru>  */
/******************************************************/ 

#ifndef EAGLE_H
#define EAGLE_H

#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#ifdef GEOIP
        #include <GeoIP.h>
#endif
#define RELEASE "ProRobot"
#define PACKAGE_VERSION "1.0"
#define MAXSTR  256
#define MAXDATA 1024
#define CONF_FILE       "/etc/eagle-whois.conf"
#define GEOIP_DB        "gi/GeoIPCountryWhois.csv"
#define PR_RW   "r+"

typedef char Char[MAXSTR];

/* The eagle ascii logo*/
static char eagle_ascii_art[] =
"\n███████╗ █████╗  ██████╗ ██╗     ███████╗\n"
"██╔════╝██╔══██╗██╔════╝ ██║     ██╔════╝\n"
"█████╗  ███████║██║  ███╗██║     █████╗  \n"
"██╔══╝  ██╔══██║██║   ██║██║     ██╔══╝  \n"
"███████╗██║  ██║╚██████╔╝███████╗███████╗\n"
"╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝\n";


#ifdef GEOIP
/* GeoIP Handler*/
typedef struct {
        const char *country;
        const char *country_code;
} geoip_t;
#endif

typedef struct {
        char *host;
        char *whois_server;
        char *whois_ip_server;
        Char line;
        Char query;
        char *flags;
        int open;
        int flags_only;
        int flags_with;
        int no_comment;
        int geoip;
        int whois_server_passed;
        int lip;
        int ipv4;
        int ipv6;
        int colored_output;
        FILE *fid;
} eagle_t;

typedef struct {
        Char ip;
        int fd;
} tcp_t;

typedef struct {
        Char value;
        Char key;
        int colors;
        FILE *file;
        int open;
} conf_t;

/* Importent Words in the Ouptut*/
static const char * import_words[] = {"e-mail:", "email:", "Email:",
                         "Owner:", "owner:", "OWNER:",
                         "person:", "PERSON:", "Person:"};

/* Prototypes*/
#endif /* EAGLE_H */
