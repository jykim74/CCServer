#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "js_pki.h"
#include "js_http.h"
#include "js_process.h"
#include "js_db.h"
#include "js_ssl.h"
#include "js_log.h"
#include "js_cc.h"

#include "cc_srv.h"


SSL_CTX     *g_pSSLCTX = NULL;
BIN         g_binPri = {0,0};
BIN         g_binCert = {0,0};

const char* g_dbPath = "/Users/jykim/work/CAMan/ca.db";

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
    int nType = -1;
    char *pPath = NULL;

    char    *pReq = NULL;
    char    *pRsp = NULL;

    char    *pMethInfo = NULL;
    JNameValList    *pHeaderList = NULL;
    JNameValList    *pRspHeaderList = NULL;
    JNameValList    *pParamList = NULL;

    sqlite3* db = JS_DB_open( g_dbPath );
    if( db == NULL )
    {
        fprintf( stderr, "fail to open db file(%s)\n", g_dbPath );
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

        ret = procCC( db, pReq, nType, pPath, &pRsp );
        if( ret != 0 )
        {
            goto end;
        }
    }

    JS_UTIL_createNameValList2("accept", "application/json", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/json");

    JS_LOG_write( JS_LOG_LEVEL_VERBOSE, "Rsp: %s", pRsp );
    ret = JS_HTTP_send( pThInfo->nSockFd, JS_HTTP_OK, pRspHeaderList, pRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to send message(%d)\n", ret );
        goto end;
    }
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
    int nType = -1;
    char *pPath = NULL;

    SSL     *pSSL = NULL;

    char    *pReq = NULL;
    char    *pRsp = NULL;

    char    *pMethInfo = NULL;
    JNameValList    *pHeaderList = NULL;
    JNameValList    *pRspHeaderList = NULL;
    JNameValList    *pParamList = NULL;

    sqlite3* db = JS_DB_open( g_dbPath );
    if( db == NULL )
    {
        fprintf( stderr, "fail to open db file(%s)\n", g_dbPath );
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

        ret = procCC( db, pReq, nType, pPath, &pRsp );
        if( ret != 0 )
        {
            goto end;
        }
    }

    JS_UTIL_createNameValList2("accept", "application/json", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/json");

    ret = JS_HTTPS_send( pSSL, JS_HTTP_OK, pRspHeaderList, pRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to send message(%d)\n", ret );
        goto end;
    }
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

int Init()
{
//    const char *pCACertPath = "/Users/jykim/work/certs/root_cert.der";
    const char *pCertPath = "/Users/jykim/work/certs/server_cert.der";
    const char *pPriPath = "/Users/jykim/work/certs/server_prikey.der";

//    JS_BIN_fileRead( pCACertPath, &g_binCACert );
    JS_BIN_fileRead( pCertPath, &g_binCert );
    JS_BIN_fileRead( pPriPath, &g_binPri );

    JS_SSL_initServer( &g_pSSLCTX );
    JS_SSL_setCertAndPriKey( g_pSSLCTX, &g_binPri, &g_binCert );

    return 0;
}

int main( int argc, char *argv[] )
{
    Init();

    JS_THD_logInit( "./log", "cc", 2 );
    JS_THD_registerService( "JS_CC", NULL, 9050, 4, NULL, CC_Service );
    JS_THD_registerService( "JS_CC_SSL", NULL, 9150, 4, NULL, CC_SSL_Service );
    JS_THD_serviceStartAll();

    return 0;
}
