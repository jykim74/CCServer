#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "js_pki.h"
#include "js_http.h"
#include "js_process.h"
#include "js_db.h"
#include "js_ssl.h"

#include "cc_srv.h"


SSL_CTX     *g_pSSLCTX = NULL;
BIN         g_binPri = {0,0};
BIN         g_binCert = {0,0};

int CC_Service( JThreadInfo *pThInfo )
{
    int ret = 0;
    int nType = -1;
    char *pPath = NULL;

    char    *pReq = NULL;
    char    *pRsp = NULL;

    char    *pMethInfo = NULL;
    JNameValList   *pHeaderList = NULL;
    JNameValList   *pRspHeaderList = NULL;

    ret = JS_HTTP_recv( pThInfo->nSockFd, &pMethInfo, &pHeaderList, &pReq );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to receive message(%d)\n", ret );
        goto end;
    }

    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath );

    if( strcasecmp( pPath, "PING" ) == 0 )
    {

    }
    else
    {
        ret = procCC( pReq, nType, pPath, &pRsp );
        if( ret != 0 )
        {
            goto end;
        }
    }

    JS_UTIL_createNameValList2("accept", "application/json", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/json");

    ret = JS_HTTPS_send( pThInfo->nSockFd, JS_HTTP_OK, pRspHeaderList, pRsp );
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
    JNameValList   *pHeaderList = NULL;
    JNameValList   *pRspHeaderList = NULL;

    ret = JS_SSL_accept( g_pSSLCTX, pThInfo->nSockFd, &pSSL );

    ret = JS_HTTPS_recv( pSSL, &pMethInfo, &pHeaderList, &pReq );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to receive message(%d)\n", ret );
        goto end;
    }

    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath );

    if( strcasecmp( pPath, "PING" ) == 0 )
    {

    }
    else
    {
        ret = procCC( pReq, nType, pPath, &pRsp );
        if( ret != 0 )
        {
            goto end;
        }
    }

    JS_UTIL_createNameValList2("accept", "application/json", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/json");

    ret = JS_HTTPS_sendBin( pSSL, JS_HTTP_OK, pRspHeaderList, pRsp );
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
    if( pSSL ) JS_SSL_clear( pSSL );


    return 0;
}

int Init()
{
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
