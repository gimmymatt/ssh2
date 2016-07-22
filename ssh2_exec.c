#include "libssh2_config.h"

#include <libssh2.h>

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/types.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>

static int waitsocket(int socket_fd, LIBSSH2_SESSION *session)
{
    struct timeval timeout;
    int rc;
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd = NULL;
    int dir;

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    FD_ZERO(&fd);
    FD_SET(socket_fd, &fd);
    /* now make sure we wait in the correct direction */
    dir = libssh2_session_block_directions(session);
    if(dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;
    if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;
    rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);

    return rc;
}


int main(int argc , char **argv)
{
	int ret = 0;
	int sock;
	const char *hostname = "192.168.88.11";
	const char *username    = "root";
	const char *password    = "root";
	const char *commandline = "uptime";
	LIBSSH2_SESSION *session;
	LIBSSH2_CHANNEL *channel;
	struct sockaddr_in sin;
	LIBSSH2_KNOWNHOSTS *nh;

	// 初始化libssh2
	ret = libssh2_init(0);
	if (ret != 0) {
	    fprintf (stderr, "libssh2 initialization failed (%d)\n", ret);
	    return ret;
	}
	// 创建socket
	sock = socket(AF_INET, SOCK_STREAM, 0);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(hostname);
	sin.sin_port = htons(22);
	if (connect(sock, (struct sockaddr*)(&sin),sizeof(struct sockaddr_in)) != 0) {
		fprintf(stderr, "failed to connect!\n");
		ret = sock;
		goto free_ssh2;
	}
	//初始化session
	session = libssh2_session_init();
	if (!session) {
		fprintf (stderr, "libssh2 session initialization failed (%d)\n", ret);
	    ret= -1;
	    goto free_sock;
	}

	libssh2_session_set_blocking(session, 0);
	while ((ret = libssh2_session_handshake(session, sock)) == LIBSSH2_ERROR_EAGAIN);

#if 0
	nh = libssh2_knownhost_init(session);
	if(!nh) {
	        /* eeek, do cleanup here */
		fprintf (stderr, "libssh2 knownhost initialization failed (%d)\n", ret);
	    ret = -1;
	    goto free_session;
	 }

	 libssh2_knownhost_readfile(nh, "known_hosts",  LIBSSH2_KNOWNHOST_FILE_OPENSSH);
	 libssh2_knownhost_writefile(nh, "dumpfile",  LIBSSH2_KNOWNHOST_FILE_OPENSSH);
	 libssh2_knownhost_free(nh);
#endif
     // 密码认证
	 if ( strlen(password) != 0 ) {
	     while ((ret = libssh2_userauth_password(session, username, password)) == LIBSSH2_ERROR_EAGAIN);
	     if (ret) {
	           fprintf(stderr, "Authentication by password failed.\n");
	           goto shutdown;
	      }
	 }
    // 打开一个channel
	 while( (channel = libssh2_channel_open_session(session)) == NULL &&  \
	       libssh2_session_last_error(session,NULL,NULL,0) ==  LIBSSH2_ERROR_EAGAIN )
	 {
	     waitsocket(sock, session);
	 }
	 if( channel == NULL )
	 {
	         fprintf(stderr,"Error\n");
	         ret = -1;
	         goto shutdown;
	 }
	 // 执行命令
	 while( (ret = libssh2_channel_exec(channel, commandline)) == LIBSSH2_ERROR_EAGAIN )
	 {
	     waitsocket(sock, session);
	 }
	 if( !ret ) // 读取返回内容
	 {
		 for(;;)
		 {
			 int rc;
			 do
			 {
			     char buffer[0x4000];
			     rc = libssh2_channel_read( channel, buffer, sizeof(buffer) );
			     if( rc > 0 )
			     {
			         int i;
			         //bytecount += rc;
			         fprintf(stderr, "We read:%d\n",rc);
			         for( i=0; i < rc; ++i )
			            fputc( buffer[i], stderr);
			          //  fprintf(stderr, "\n");
			         }
			     else {
			         if( rc != LIBSSH2_ERROR_EAGAIN )
			            /* no need to output this for the EAGAIN case */
			             fprintf(stderr, "libssh2_channel_read returned %d\n", rc);
			         }
			 }while( rc > 0 );
			 if( rc == LIBSSH2_ERROR_EAGAIN )
			 {
			    waitsocket(sock, session);
			 }
			 else
			    break;
		 }
	 }

	 // 关闭channel
	 while( (ret = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN )
	        waitsocket(sock, session);

	 libssh2_channel_free(channel);
	 channel = NULL;

shutdown:
	libssh2_session_disconnect(session, "Normal Shutdown, Thank you for playing");
free_session:
	libssh2_session_free(session);
free_sock:
		close(sock);
free_ssh2:
	libssh2_exit();

	return ret;
}
