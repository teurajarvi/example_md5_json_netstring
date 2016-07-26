/*  ANSI-C Example:

    Authenticate to a server using your personal username and password. 
    The authentication protocol that is used is CRAM-MD5 over JSON-RPC 2.0 
    over Netstrings transport over a plain TCP socket.

    To get Open SSL:
    sudo apt-get install libssl-dev - /usr/include/openssl

    To link openssl library use -lcrypto:
    f.e.> gcc auth_example.c -o auth_example -lcrypto
*/

/*
References:
- CRAM-MD5 https://tools.ietf.org/html/rfc2195
- JSON-RPC 2.0 http://www.jsonrpc.org/specification
- JSON-RPC 2.0 http://www.jsonrpc.org/
- Netstrings transport http://cr.yp.to/proto/netstrings.txt
- TCP Socket http://www.linuxhowtos.org/C_C++/socket.htm
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <openssl/md5.h> 
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/bio.h> /* decode base64 */
#include <openssl/evp.h>
#include <stdint.h> /* decode base64 */
#include <assert.h> /* decode base64 */

#define BUFSIZE 1024

/* error - wrapper for perror */
void error( char *msg ) 
    {
    perror( msg );
    exit( 0 );
    }

size_t calcDecodeLength( const char* b64input ) 
    { 
    size_t len = strlen( b64input ), padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=')
        { //last two chars are =
		padding = 2;
        }
    else if (b64input[len-1] == '=')
        { //last char is =
        padding = 1;
        }

    return ( len*3 )/4 - padding;
}

int Base64Decode( char* b64message, unsigned char** buffer, size_t* length ) 
    { 
	BIO *bio, *b64;

	int decodeLen = calcDecodeLength( b64message );
	*buffer = ( unsigned char* ) malloc( decodeLen + 1 );
	(*buffer)[decodeLen] = '\0';

	bio = BIO_new_mem_buf( b64message, -1 );
	b64 = BIO_new( BIO_f_base64( ) );
	bio = BIO_push( b64, bio );

	BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL );
	*length = BIO_read( bio, *buffer, strlen( b64message ) );
	assert( *length == decodeLen );
	BIO_free_all( bio );

	return ( 0 );
}

int Base64Encode( const unsigned char* buffer, size_t length, char** b64text) { 
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new( BIO_f_base64( ) );
	bio = BIO_new( BIO_s_mem( ) );
	bio = BIO_push( b64, bio );

	BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL ); 
	BIO_write( bio, buffer, length );
	BIO_flush( bio );
	BIO_get_mem_ptr( bio, &bufferPtr );
	BIO_set_close( bio, BIO_NOCLOSE );
	BIO_free_all( bio );

	*b64text=(*bufferPtr).data;

	return (0);
}

int main( int argc, char **argv ) 
    {
    int sockfd, portno, n, i;
    unsigned int size;
    size_t length;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname = NULL;
    char buf[BUFSIZE];
    char base64_message[BUFSIZE];
    int len = 0;
    int len_head = 0;
    int len_tail = 0;
    char *message = NULL;
    char *message_head = NULL;
    char next[1];
    unsigned char *base64_decoded = NULL;
    unsigned char *final_data = NULL;
    char *base64_encoded = NULL;
    char *secret = NULL;
    char *user_name = NULL;
    char *hash = NULL;
    static char res_hexstring[32];

    hostname = "www.--------.com";  /* re- define this! */
    portno = 666;                   /* re-define this! */
    secret = "Secret";              /* re-define this! */
    user_name = "User_name ";       /* user name + space, re-define this! */

    /* socket: create the socket */
    sockfd = socket( AF_INET, SOCK_STREAM, 0 );

    if ( sockfd < 0 )
        {
        error( "ERROR opening socket\n" );
        }

    /* gethostbyname: get the server's DNS entry */
    server = gethostbyname( hostname );

    if ( server == NULL ) 
        {
        fprintf( stderr, "ERROR, no such host as %s\n", hostname );
        exit( 0 );
        }

    /* build the server's Internet address */
    bzero( ( char * ) &serveraddr, sizeof( serveraddr ) );
    serveraddr.sin_family = AF_INET;
    bcopy( ( char * ) server->h_addr, 
	    ( char * ) &serveraddr.sin_addr.s_addr, server->h_length );
    serveraddr.sin_port = htons( portno );

    /* connect: create a connection with the server */
    if ( connect( sockfd, ( struct sockaddr * ) &serveraddr, sizeof( serveraddr ) ) < 0 ) 
        {
        error( "\nERROR connecting\n" );
        }
    else
        {
        printf( "\nConnect ok to %s\n", hostname );
        }

    /* Client auth request message to the server www.---.com, port == 0x29A
     *
     * message CRAM-MD5 / JSON / Netstring to www.---.com port 666:
     * "msg: 53:{"jsonrpc": "2.0", "method": "auth_request", "id": 1}," where
     *  
     * "auth_request" == AUTH CRAM-MD5 
     * (Challenge-Response Authentication Mechanism (CRAM)) and where
     *  
     * {"[string]"}," is called JSON where
     * {"jsonrpc": "2.0", "method": "auth_request", "id": 1} and where
     *
     * [len]":"[string]"," is called a Netstring where
     * 53:{"jsonrpc": "2.0", "method": "auth_request", "id": 1}, and where
     *
     * server response: 105:{"jsonrpc": "2.0", "result":
     * "PDE0NjgyNDkzOTA3MjUuRlZCSkNXUUYzVVhDMVNMRkB3d3cudG9zaWJveC5jb20+", "id": 1},
     *
     * result after base64 decoding something like that:
     * <1468249390725.FVBJCWQF3UXC1SLF@www.-----.com>
     */

    /* construct the auth_request message */
    bzero( buf, BUFSIZE );
    len = strlen( "{\"jsonrpc\": \"2.0\", \"method\": \"auth_request\", \"id\": 1}" );
    sprintf( buf, "%d", len );
    strcat( buf, ":" );
    strcat( buf, "{\"jsonrpc\": \"2.0\", \"method\": \"auth_request\", \"id\": 1}," );

    /* send the message line to the server */
    n = write( sockfd, buf, strlen( buf ) );

    if ( n < 0 )
        { 
        error( "\nERROR writing to socket\n" );
        }
    else
        {
        printf( "\nWriting to socket ok:\n %s\n", buf );
        }

    /* print the server's reply */
    bzero( buf, BUFSIZE );
    n = read( sockfd, buf, BUFSIZE );

    if ( n < 0 )
        {
        error( "\nERROR reading from socket\n" );
        }
    else
        {
        printf( "\nChallenge from server:\n %s\n", buf );

        /* Parse Server Challenge data */
        message = strstr( buf, "result" );

        if ( NULL != message )
            {
            /* move to the head of the data */
            message = strchr( message, ':' );
            message = strchr( message, '\"' );
            if (message[0] == '\"')
                { 
                memmove( message, message+1, strlen( message ) );
                }
            
            /* store the head of the data */
            message_head = message;
            len_head = strlen( message_head );

            /* find the end of the data */
            message = strchr( message, ',' );
            len_tail = strlen( message );

            /* strip the tailing '"' */
            strncpy( base64_message, message_head, ( len_head - len_tail ) );
            len = strlen( base64_message );
            printf( "\nChallenge data length: %d\nChallenge data:\n %s\n", len, base64_message );
            }       
        else
            {
            error( "\nERROR invalid request\n" );
            return 0;
            }
        }
    
    /* Do base64 decoding for reply data to the Challenge.
     * result after base64 decoding is something like this:  
     * <1468355028278.SKSIB5QJX32CEAZF@www.------.com> -> 50f140bd152ab8a0a13eb7692fba4e25
     */

    Base64Decode( base64_message, &base64_decoded, &length );
    printf( "\nChallenge data decoded length: %d\nChallenge data decoded: \n %s \n", (int)length,
        base64_decoded );

    /* Do SRAM-MD5 decoding */
 
    /* hash the Challenge (<1468396945867.K2O2J12A7HQE6KMW@www.-----.com>) 
     * + secret (Secret)
     */
    len = strlen( secret );    
    hash = HMAC( EVP_md5( ), secret, len, base64_decoded, length, NULL, &size );

    if ( NULL != hash )
        {
        /* convert hashed data to lowercase hex digits */
        bzero( res_hexstring, sizeof( res_hexstring ) );

        for ( i = 0; i < size; i++ )
            {
            sprintf( &( res_hexstring[i * 2]), "%02x", (unsigned char)hash[i] );
            }

        /* result after hash-MD5 + lowercase hex is something like
         * this 0823d39459ba2536aead1906e185c0ef
         */
        printf( "\nHash as lowercase hex digits:\n %s\n", res_hexstring );
        }
    else
        {
        error( "\nHash failed!\n" );
        return 0;
        }

    /* concatenate username + space with hex strings 
     * "User_name 0823d39459ba2536aead1906e185c0ef"
     */
    bzero( buf, BUFSIZE );
    strcat( buf, user_name );
    strcat( buf, res_hexstring );
    printf( "\nConcatenated hex string:\n %s\n", buf );

    /* endcode the whole response data to base64
     * result after encoding is something like this 
     * if hash-MD5 alcorithm used:
     * - dca9LmTIvydDRflUOVICCQ==
     * if non-cryptocraphic function is used:
     * - extra-base64-encode: dXNlcjE1IDExNTk4ZTFlNDMwYzdmN2QzZTI2MzY1ZmViNWRlMDJl
     */
    len = strlen( buf );
    final_data = malloc( len + 1 );   
    strcpy( final_data, buf );

    Base64Encode( final_data, len, &base64_encoded );
    printf( "\nBase64 encoded data: \n %s\n", base64_encoded );

    free( final_data );
    
    /* Auth response message to the server challenge. 
     * tunnus: User_name
     * salasana: Secret
     *
     * test data for CRAM-MD5 / JSON / Netstring : www.------.com 666
     * msg: 92:{"jsonrpc": "2.0", "method": "auth_response", "params":
     * "dca9LmTIvydDRflUOVICCQ==",
     * "id": 2}, where
     *
     * "auth_response" == AUTH CRAM-MD5 where params:
     *  "dca9LmTIvydDRflUOVICCQ=="
     *
     */

    /* construct the auth_response message */
    bzero( base64_message, BUFSIZE );
    bzero( buf, BUFSIZE );
    strcat( buf, "{\"jsonrpc\": \"2.0\", \"method\": \"auth_response\", \"params\": \"");
    strcat( buf, base64_encoded );
    strcat( buf, "\", \"id\": 2}," );
    len = strlen( buf );
    sprintf( base64_message, "%d", len - 1 );
    strcat( base64_message, ":" );
    strcat( base64_message, buf );
    
    /* send the message line to the server */
    n = write( sockfd, base64_message, strlen( base64_message ) );

    if ( n < 0 )
        { 
        error( "\nERROR writing to socket\n" );
        }
    else
        {
        printf( "\nWriting to socket ok:\n %s\n", base64_message );
        }

    /* print the server's reply */
    bzero( buf, BUFSIZE );
    bzero( base64_message, BUFSIZE );
    n = read( sockfd, buf, BUFSIZE );

    if ( n < 0 )
        {
        error( "\nERROR reading from socket\n" );
        }
    else
        {
        printf( "\nReply from server: %s\n", buf );
        }

    close( sockfd );

    return 0;
    }
