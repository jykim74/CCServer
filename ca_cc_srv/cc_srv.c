#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "js_pki.h"
#include "js_http.h"
#include "js_process.h"
#include "js_db.h"
#include "js_ssl.h"
#include "js_log.h"
#include "js_cc.h"
#include "js_cfg.h"

#include "cc_proc.h"
#include "cc_tools.h"
#include "js_ldap.h"


SSL_CTX     *g_pSSLCTX = NULL;
BIN         g_binPri = {0,0};
BIN         g_binCert = {0,0};
int         g_nKeyType = JS_PKI_KEY_TYPE_RSA;


JEnvList        *g_pEnvList = NULL;
char            *g_pDBPath = NULL;
static char     g_sConfPath[1024];
int             g_bVerbose = 0;

LDAP            *g_pLDAP = NULL;

int isLogin( sqlite3* db, JNameValList *pHeaderList )
{
    JDB_Auth sAuth;
    const char *pToken = NULL;
    if( pHeaderList == NULL ) return 0;

    memset( &sAuth, 0x00, sizeof(sAuth));

    pToken = JS_UTIL_valueFromNameValList( pHeaderList, "Token" );
    if( pToken == NULL ) return 0;

    JS_DB_getAuth( db, pToken, &sAuth );

    if( sAuth.pToken && strcasecmp( pToken, sAuth.pToken ) == 0 )
    {
        JS_DB_resetAuth( &sAuth );
        return 1;
    }

    JS_DB_resetAuth( &sAuth );
    return 0;
}

int CC_Service( JThreadInfo *pThInfo )
{
    int ret = 0;
    int status = 0;
    int nType = -1;
    char *pPath = NULL;

    char    *pReq = NULL;
    char    *pRsp = NULL;

    char    *pMethInfo = NULL;
    JNameValList    *pHeaderList = NULL;
    JNameValList    *pRspHeaderList = NULL;
    JNameValList    *pParamList = NULL;

    sqlite3* db = JS_DB_open( g_pDBPath );
    if( db == NULL )
    {
        fprintf( stderr, "fail to open db file(%s)\n", g_pDBPath );
        ret = -1;
        goto end;
    }

    ret = JS_HTTP_recv( pThInfo->nSockFd, &pMethInfo, &pHeaderList, &pReq );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to receive message(%d)\n", ret );
        goto end;
    }

    JS_LOG_write( JS_LOG_LEVEL_VERBOSE, "Req: %s", pReq );

    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath, &pParamList );

    if( strcasecmp( pPath, "PING" ) == 0 )
    {

    }
    else
    {
        if( strcasecmp( pPath, JS_CC_PATH_AUTH ) != 0 )
        {
            if( isLogin( db, pHeaderList ) == 0 )
            {
                fprintf( stderr, "not logined\n" );
                JS_LOG_write( JS_LOG_LEVEL_ERROR, "not logined" );
                goto end;
            }
        }

        status = procCC( db, pReq, nType, pPath, pParamList, &pRsp );
    }

    JS_UTIL_createNameValList2("accept", "application/json", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/json");
    const char *pRspMethod = JS_HTTP_getStatusMsg( status );

    ret = JS_HTTP_send( pThInfo->nSockFd, pRspMethod, pRspHeaderList, pRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to send message(%d)\n", ret );
        goto end;
    }

    if( pRsp ) fprintf( stdout, "Rsp: %s\n", pRsp );
    /* send response body */
end:
    if( pReq ) JS_free( pReq );
    if( pRsp ) JS_free( pRsp );

    if( pPath ) JS_free( pPath );

    if( pHeaderList ) JS_UTIL_resetNameValList( &pHeaderList );
    if( pRspHeaderList ) JS_UTIL_resetNameValList( &pRspHeaderList );
    if( pParamList ) JS_UTIL_resetNameValList( &pParamList );

    JS_DB_close( db );

    return 0;
}

int CC_SSL_Service( JThreadInfo *pThInfo )
{
    int ret = 0;
    int status = 0;
    int nType = -1;
    char *pPath = NULL;

    SSL     *pSSL = NULL;

    char    *pReq = NULL;
    char    *pRsp = NULL;

    char    *pMethInfo = NULL;
    JNameValList    *pHeaderList = NULL;
    JNameValList    *pRspHeaderList = NULL;
    JNameValList    *pParamList = NULL;

    sqlite3* db = JS_DB_open( g_pDBPath );
    if( db == NULL )
    {
        fprintf( stderr, "fail to open db file(%s)\n", g_pDBPath );
        ret = -1;
        goto end;
    }

    ret = JS_SSL_accept( g_pSSLCTX, pThInfo->nSockFd, &pSSL );

    ret = JS_HTTPS_recv( pSSL, &pMethInfo, &pHeaderList, &pReq );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to receive message(%d)\n", ret );
        goto end;
    }


    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath, &pParamList );

    if( strcasecmp( pPath, "PING" ) == 0 )
    {

    }
    else
    {
        if( strcasecmp( pPath, JS_CC_PATH_AUTH ) != 0 )
        {
            if( isLogin( db, pHeaderList ) == 0 )
            {
                fprintf( stderr, "not logined\n" );
                JS_LOG_write( JS_LOG_LEVEL_ERROR, "not logined" );
                goto end;
            }
        }

        status = procCC( db, pReq, nType, pPath, pParamList, &pRsp );
    }

    JS_UTIL_createNameValList2("accept", "application/json", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/json");
    const char *pRspMethod = JS_HTTP_getStatusMsg( status );

    ret = JS_HTTPS_send( pSSL, pRspMethod, pRspHeaderList, pRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to send message(%d)\n", ret );
        goto end;
    }

    if( pRsp ) fprintf( stdout, "Rsp: %s\n", pRsp );
    /* send response body */
end:
    if( pReq ) JS_free( pReq );
    if( pRsp ) JS_free( pRsp );

    if( pPath ) JS_free( pPath );

    if( pHeaderList ) JS_UTIL_resetNameValList( &pHeaderList );
    if( pRspHeaderList ) JS_UTIL_resetNameValList( &pRspHeaderList );
    if( pParamList ) JS_UTIL_resetNameValList( &pParamList );

    if( pSSL ) JS_SSL_clear( pSSL );
    JS_DB_close(db);

    return 0;
}

int serverInit()
{
    int     ret = 0;
    const char  *value = NULL;

    ret = JS_CFG_readConfig( g_sConfPath, &g_pEnvList );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to read config file(%s:%d)\n", g_sConfPath, ret );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "CA_KEY_TYPE" );
    if( value )
    {
        if( strcasecmp( value, "ECC") == 0 )
            g_nKeyType = JS_PKI_KEY_TYPE_ECC;
        else
            g_nKeyType = JS_PKI_KEY_TYPE_RSA;
    }

    value = JS_CFG_getValue( g_pEnvList, "CA_CERT_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'CA_CERT_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileRead( value, &g_binCert );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to read certificate file(%s:%d)\n", value, ret );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "CA_PRIVATE_KEY_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'CA_PRIVATE_KEY_PATH'" );
        exit(0);
    }

    ret = JS_BIN_fileRead( value, &g_binPri );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to read private key file(%s:%d)\n", value, ret );
        exit( 0 );
    }

    value = JS_CFG_getValue( g_pEnvList, "CC_DB_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'CC_DB_PATH'" );
        exit(0);
    }

    g_pDBPath = value;

    value = JS_CFG_getValue( g_pEnvList, "LDAP_USE" );
    if( value && strcasecmp( value, "YES" ) == 0 )
    {
        int nLdapPort = -1;
        const char *pLdapHost = NULL;
        const char *pBindDN = NULL;
        const char *pSecert = NULL;

        value = JS_CFG_getValue( g_pEnvList, "LDAP_HOST" );

        if( value == NULL )
        {
            fprintf( stderr, "You have to set 'LDAP_HOST'\n" );
            exit(0);
        }

        pLdapHost = value;

        value = JS_CFG_getValue( g_pEnvList, "LDAP_PORT");
        if( value == NULL )
        {
            fprintf( stderr, "You have to set 'LDAP_PORT'\n" );
            exit(0);
        }

        nLdapPort = atoi( value );

        value = JS_CFG_getValue( g_pEnvList, "LDAP_BINDDN" );
        if( value == NULL )
        {
            fprintf( stderr, "You have to set 'LDAP_BINDDN'\n" );
            exit(0);
        }

        pBindDN = value;

        value = JS_CFG_getValue( g_pEnvList, "LDAP_SECRET" );
        if( value == NULL )
        {
            fprintf( stderr, "You have to set 'LDAP_SECRET'\n" );
            exit(0);
        }

        pSecert = value;

        g_pLDAP = JS_LDAP_init( pLdapHost, nLdapPort );
        if( g_pLDAP == NULL )
        {
            fprintf( stderr, "fail to initialize ldap(%s:%d)\n", pLdapHost, nLdapPort );
            exit(0);
        }

        ret = JS_LDAP_bind( g_pLDAP, pBindDN, pSecert );
        if( ret != LDAP_SUCCESS )
        {
            fprintf( stderr, "fail to bind ldap(%s:%d)\n", pBindDN, ret );
            exit(0);
        }

        printf( "success to connect to ldap server\n" );
    }

    JS_SSL_initServer( &g_pSSLCTX );
    JS_SSL_setCertAndPriKey( g_pSSLCTX, &g_binPri, &g_binCert );

    printf( "CC_Server Init OK\n" );

    return 0;
}

int quitDaemon( const char *pCmd )
{
    return 0;
}

void printUsage()
{

}


int main( int argc, char *argv[] )
{
    int     nRet = 0;
    int     nStatus = 0;
    int     nOpt = 0;

    sprintf( g_sConfPath, "%s", "../ca_cc_srv.cfg" );

    while(( nOpt = getopt( argc, argv, "c:qth")) != -1 )
    {
        switch( nOpt )
        {
            case 'q':
                return quitDaemon(argv[0]);
                break;

            case 'h':
                printUsage();
                return 0;

            case 't':
                g_bVerbose = 1;
                break;

            case 'c':
                sprintf( g_sConfPath, "%s", optarg );
                break;
        }
    }

    serverInit();

    JS_THD_logInit( "./log", "cc", 2 );
    JS_THD_registerService( "JS_CC", NULL, 9050, 4, NULL, CC_Service );
    JS_THD_registerService( "JS_CC_SSL", NULL, 9150, 4, NULL, CC_SSL_Service );
    JS_THD_serviceStartAll();

    return 0;
}

