/********************************************************************/
/*    eagle.c -   A modern whois client.                            */
/*        Copyright (c) 2015 by Hypsurus <hypsurus@mail.ru>         */
/********************************************************************/ 
/*
  eagle-whois is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 3 of the License, or
  (at your option) any later version.

  eagle-whois is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "eagle.h"

void die(char *format, ...) {
        va_list li;
        Char msg;
        
        va_start(li, format);
        vsprintf(msg, format, li);
        va_end(li);

        fprintf(stderr, "[eagle] %s\n", msg);
        exit(1);
}

void debug(char *format, ...) {
        va_list li;
        Char msg;
        
        va_start(li, format);
        vsprintf(msg, format, li);
        va_end(li);

        fprintf(stdout, "[Debug] %s\n", msg);
}

void eagle_free(tcp_t *tcp, conf_t *conf, eagle_t *eagle) {
        free(tcp);
        free(conf);
        free(eagle);
}

void eagle_draw_char(int n, int ch) {
        int index = 0;

        putchar(0x09);
        for ( index = 0; index <= n; index++ ) {
                putchar(ch);
        }
        putchar(0x0a);
}

char * eagle_read_conf(conf_t *conf, char *key) {
        int i = 0;
        conf->open = 1;
        char line[MAXSTR];

        memset(conf->value, 0, sizeof conf->value);

        if ((conf->file = fopen(CONF_FILE, "r")) == NULL ) {
                die("Failed to open: %s", CONF_FILE);
        }

        while ( conf->open ) {
                if ( fgets(line, MAXSTR, conf->file) == NULL ) {
                        conf->open = 0;
                }
        
                for ( i = 0; line[i] != 0; i++ ) {
                        if ( i >= MAXSTR-6 )
                                die("String too long!");
                }

                /* avoid white-spaces and comments*/
                if ( line[0] == 0x3b || line[0] == 0x0d )
                        ; /* do nothing */

                else {
                        sscanf(line, "%s = %s", conf->key, conf->value);
                        if (!strcmp(key, conf->key))
                                conf->open = 0;
                }

        }

        fclose(conf->file);
        
        return conf->value;
}

void eagle_version(int c) {
        printf("Copyright eagle-whois %s (%s) (c) 2015 by Hypsurus <hypsurus@mail.ru> \n"
                "\n-=[ Compiled in: %s %s\n"
                "\n-=[ Bugs report to: hypsurus@mail.ru\n"
                #ifdef DEBUG
                "-=[ Compiled with DEBUG flag\n"
                #endif
                #ifdef GEOIP
                "-=[ Compiled with GeoIP support\n"
                #endif
                "%s"
                "\n\"let the eagle fly.\"\n",
                PACKAGE_VERSION, RELEASE, 
                __DATE__, __TIME__, 
                eagle_ascii_art);

        exit(c);
}

void eagle_usage(void) {
        printf("Usage: eagle [host] [OPTIONS]..\n"
                "\t\nOPTIONS:\n"
                "\t-i :       Get host IP address(s)\n"
                "\t-f :       Send whois flag request.\n"
                "\t-F :       Send only whois flag request.\n"
                "\t-n :       Hide whois comments.\n"
                "\t-g :       Search the host in the geoip Database.\n"
                "\t-h :       Display help and quit.\n"
                "\t-s :       Connect to a server.\n"
                "\t-c :       Highlight Email, Person.\n"
                "\t-v :       Print version, build number.\n"
                "\nCopyright (c) 2015 Hypsurus. <hypsurus@mail.ru>\n"
                "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n\n");
        exit(EXIT_SUCCESS);
}

/* Check string length*/
void eagle_strsec(char *buffer) {
        int i = 0;

        for( i = 0; buffer[i] != 0; i++ ) {
                if ( i > MAXSTR-6 )
                        die("Error: Input too long.");
        }
}

/* Find char and replace it*/
void eagle_find_replace(char *target, int find, int replace) {
        int index = 0;

        for ( index = 0; target[index] != 0; index++ ) {
                if ( target[index] == find )
                        target[index] = replace;
        }
}

#ifdef GEOIP
/* eagle_geoip2 Function replace the old eagle_geoip function.
 * eagle_geoip2 Uses maxmind geoip API*/
void eagle_geoip2(geoip_t *geoip, eagle_t *eagle) {
        GeoIP *gi;

        if (( gi  = GeoIP_open("/usr/share/GeoIP/GeoIP.dat", GEOIP_STANDARD)) == NULL ) 
                die("Failed to open the GeoIP.dat file\n");

        if ( eagle->ipv4 ) {
                geoip->country = GeoIP_country_name_by_addr(gi, eagle->host);
                geoip->country_code = GeoIP_country_code_by_addr(gi, eagle->host);

        }       
        
        if ( eagle->ipv6 ) {
                geoip->country = GeoIP_country_name_by_addr_v6(gi, eagle->host);
                geoip->country_code = GeoIP_country_code_by_addr_v6(gi, eagle->host);
        }
        else {

                geoip->country = GeoIP_country_name_by_name(gi, eagle->host);
                geoip->country_code = GeoIP_country_code_by_name(gi, eagle->host);
        }

        printf(" (%s) GeoIP: %s, %s.\n", eagle->host, geoip->country_code, geoip->country);
}
#endif

/* Will add color to output */
void eagle_colored_output(char *output) {
        const char **ptr = NULL;

        for ( ptr = import_words; *ptr; ptr++) { 
                if ( strstr(output, *ptr))
                        printf("\t- \033[01;31m%s\033[00m", output);
        }
}


/* Handle the TCP Connection and return IP address from host */
void eagle_tcp(tcp_t *tcp, char *host) { 
        struct sockaddr_in *s = NULL;
        struct addrinfo h, *srv = NULL, *p = NULL;

        memset(&h, 0, sizeof(h));

        h.ai_family = AF_INET;
        h.ai_protocol = IPPROTO_TCP;
        h.ai_socktype= SOCK_STREAM;

        if (( getaddrinfo(host, "43",  &h, &srv)) != 0 )
                die("Connection failed.");

        for ( p = srv; p != NULL; p = p->ai_next ) {
                s = (struct sockaddr_in *)p->ai_addr;

                sprintf(tcp->ip, "%s", inet_ntoa( s->sin_addr) );
                break; /* get the first entry*/
        }

        if (( tcp->fd = socket(h.ai_family, h.ai_socktype, h.ai_protocol)) < 0 ) {
                die("Failed to create socket.");
        }

        if (( connect(tcp->fd, p->ai_addr, p->ai_addrlen)) <  0 ) {
                die("Failed to connect: %s (Maybe the host shotdown? )", host);
        }

}

/* Get the host ip(s) using addrinfo */
void eagle_get_lip(tcp_t *tcp, char *host) {
        struct sockaddr_in *s = NULL;
        struct addrinfo h, *srv = NULL, *p = NULL;   

        memset(&h,0, sizeof(h));
        h.ai_family = AF_INET;
        h.ai_socktype = SOCK_STREAM;

        eagle_strsec(host);

        /* the Must common Protocol*/
        if (( getaddrinfo(host, "http", &h, &srv)) != 0 ) {
                die("Connection Failed.");
        }
 
        #ifdef DEBUG
                printf("[*] %s: \n", host);
        #endif

        for ( p = srv; p != NULL; p = p->ai_next ) {
                s = (struct sockaddr_in * )p->ai_addr;
                printf("%s\n", inet_ntoa( s->sin_addr ));
        }

        freeaddrinfo(srv);
        
        exit(0);
}

/* Whois Host? */
void eagle_whois_host(tcp_t *tcp, conf_t *conf, eagle_t *eagle) {
        int iana_get_server = 0, redirect_server = 0;
        int index = 0;
        
        /* Check if the  host contain www., if contain remove WWW. */
        if ( strcasestr(eagle->host, "WWW.")) {
                for ( index = 0; eagle->host[index] != 0; index++) {
                        if ( eagle->host[index] == 0x77 || eagle->host[index] == 0x57 || eagle->host[index] == 0x2e )
                                eagle->host++;
                }
                eagle->host++;
        }

        if ( eagle->whois_server_passed ) {
                iana_get_server = 2;
                redirect_server = 1;
        }

         /* Step 1: get the whois server from IANA*/
        if ( !iana_get_server ) {
                eagle->whois_server = eagle_read_conf(conf, "whois_server");
                eagle_tcp(tcp, eagle->whois_server);

                if (( eagle->fid = fdopen(tcp->fd, PR_RW)) == NULL )
                        die("Error: Failed to create FD");
                else
                        eagle->open = 1;

                /* Send a request*/
                fprintf(eagle->fid, "%s\r\n", eagle->host);

                while ( eagle->open ) {
                        if ( fgets(eagle->line, sizeof(eagle->line), eagle->fid) == NULL )
                                 break;
                        
                        /* Get the whois server from the Output*/
                        if ( eagle->line[0] == 'r' && eagle->line[1] == 'e' ) {
                                sscanf(eagle->line, "refer:   %s", eagle->whois_server);
                                #ifdef DEBUG
                                        debug("(Step 1) WHOIS Server: %s", eagle->whois_server);
                                #endif
                                iana_get_server++;
                                fclose(eagle->fid);
                                close(tcp->fd);
                                break;
                        }
                }
        }

       /* Step 2: get data */
        if ( iana_get_server == 1 ) {
                /* we got the whois server from IANA,
                 * now let's connect and send request.*/

                eagle_tcp(tcp, eagle->whois_server);

                 if (( eagle->fid = fdopen(tcp->fd, PR_RW)) == NULL )
                         die("Error: Failed to create FD");
                 else
                         eagle->open = 1;

                 /* Handle the flags passed by the user 
                  * -f - eagle->flags_with.
                  * -F - eagle->flags_only.*/
                 if ( eagle->flags_with )
                        fprintf(eagle->fid, "%s %s\r\n", eagle->flags, eagle->host);
                 else if ( eagle->flags_only )
                         fprintf(eagle->fid, "%s\r\n", eagle->flags);
                 /* Handle .COM,.NET,.EDU domains*/
                 else if ( strstr(eagle->whois_server, "whois.verisign-grs.com"))
                        fprintf(eagle->fid, "domain =%s\r\n", eagle->host);
                 /* Handle .DE domains*/
                 else if ( strstr(eagle->whois_server, "whois.denic.de"))
                        fprintf(eagle->fid, "%s -T domain\r\n", eagle->host);
                 else
                         fprintf(eagle->fid, "%s\r\n", eagle->host);


                 /* draw header*/
                 eagle_draw_char(strlen(eagle->host), '.');
                 printf("\t%s\n", eagle->host);
                 eagle_draw_char(strlen(eagle->host), '.');

                 while ( eagle->open ) {
                         if ( fgets(eagle->line, sizeof(eagle->line), eagle->fid) == NULL )
                                 break;

                         /* check for Redirected servers */
                         if ( strstr(eagle->line, "Whois Server:")) {
                                 sscanf(eagle->line, "   Whois Server: %s", eagle->whois_server);
                                 #ifdef DEBUG
                                        debug("(Step 2) 2nd WHOIS Server: %s", eagle->whois_server);
                                #endif
                                 redirect_server = 1;
                                 break;
                         }
                          /* Handle no_comment */
                        if ( eagle->no_comment ) {
                                if ( eagle->line[0] == 0x25 )
                                        ;
                        }
                        else
                                /* Handle colored output */
                                if ( eagle->colored_output )
                                        eagle_colored_output(eagle->line);
                                printf("\t- %s", eagle->line);
                 }       

                fclose(eagle->fid);
                close(tcp->fd);
        }

         /* Step 3: in case the server will redirect to another server */
        if ( redirect_server ) {
                eagle_tcp(tcp, eagle->whois_server);

                if (( eagle->fid = fdopen(tcp->fd, PR_RW)) == NULL )
                        die("Error: Failed to create FD");
                else
                        eagle->open = 1;

                /* Send a request*/
                fprintf(eagle->fid, "%s\r\n", eagle->host);

                while ( eagle->open ) {
                        if ( fgets(eagle->line, sizeof(eagle->line), eagle->fid) == NULL )
                                 break;  
                        
                        if ( eagle->colored_output)
                                eagle_colored_output(eagle->line);
                        printf("\t- %s", eagle->line);
                }
                fclose(eagle->fid);
                close(tcp->fd);
        }

        /* put a new line*/
        putchar(0x0a);
        
}

/* Whois ip? */
void eagle_whois_ip(tcp_t *tcp, conf_t *conf, eagle_t *eagle) {
        eagle->whois_ip_server = eagle_read_conf(conf, "whois_ip_server");
        
        eagle_tcp(tcp, eagle->whois_ip_server); 
        if (( eagle->fid = fdopen(tcp->fd, PR_RW)) == NULL )
                die("Error: Failed to create FD\n");

        eagle->open = 1;
        /* Sending -B flag to IANA for Non filtered output */
        fprintf(eagle->fid, "%s -B\r\n", eagle->host);

        while ( eagle->open ) {
                if ( fgets(eagle->line, sizeof eagle->line, eagle->fid) == NULL )
                        eagle->open = 0;
                else
                        printf("\t- %s", eagle->line);
        }

        fclose(eagle->fid);
}

/* detect ip version*/
void eagle_detect_ip(eagle_t *eagle) {
        struct in_addr addr;
        struct in6_addr addr6;

        if ( inet_pton(AF_INET, eagle->host, &addr))
                eagle->ipv4 = 1;
        if ( inet_pton(AF_INET6, eagle->host, &addr6.s6_addr))
                eagle->ipv6 = 1;
}

int main(int argc, char **argv)  {
        int opt = 0;
        tcp_t *tcp = malloc(sizeof *tcp);
        eagle_t *eagle = malloc(sizeof *eagle);
        conf_t *conf = malloc(sizeof *conf);
        #ifdef GEOIP
                geoip_t *geoip = malloc(sizeof(*geoip));
        #endif

        /* shift optarg */
        if ( argc < 2 )
                eagle_usage();
        else if( argv[1][0] != 0x2d ) {
                eagle->host = argv[1];
                eagle_strsec(eagle->host);
                argv[1] = argv[0];
                argv++;
                argc--;
        }

        while (( opt = getopt(argc, argv, "vHif:F:ngs:c")) != -1 ) {
                switch(opt) {
                        case 'v':
                                eagle_version(0);
                                break;
                        case 'h':
                                eagle_usage();
                                break;
                        case 'i':
                                eagle->lip = 1;
                                break;
                        case 'F':
                                eagle->flags = optarg;
                                eagle->flags_only = 1;
                                break;
                        case 'f':
                                eagle->flags = optarg;
                                eagle->flags_with = 1;
                                break;
                        case 'n':
                                eagle->no_comment = 1;
                                break;
                        case 'g':
                                eagle->geoip = 1;
                                break;
                        case 's':
                                eagle->whois_server = optarg;
                                eagle->whois_server_passed = 1;
                                break;
                        case 'c':
                                eagle->colored_output = 1;
                                break;
                        default:
                                eagle_usage();
                                break;
                }
        }


        if ( !eagle->host )
                die("Error: plase provide hostname.");
        else
                eagle_detect_ip(eagle);
        
        /* start eagle*/
        if ( eagle->geoip )
                #ifdef GEOIP
                        eagle_geoip2(geoip,eagle);
                #else
                        die("Error: GeoIP not compiled with eagle.\n\t-=[ to Use GeoIP run: \"make geoip\"");
                #endif
        else if ( eagle->lip )
                eagle_get_lip(tcp, eagle->host);
        else if ( eagle->ipv4 || eagle->ipv6 )
                eagle_whois_ip(tcp, conf, eagle);
        else
                eagle_whois_host(tcp, conf, eagle);
        
        /* End eagle*/
        eagle_free(tcp, conf, eagle);
        
        return 0;

}
