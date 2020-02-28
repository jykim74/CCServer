#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "js_bin.h"
#include "js_http.h"
#include "js_cc.h"
#include "js_cc_data.h"

#include "cc_srv.h"

int runGet( sqlite3 *db, const char *pPath, const char **ppRsp )
{
    return 0;
}

int runPost( sqlite3 *db, const char *pPath, const char *pReq, const char **ppRsp )
{
    int ret = 0;
    if( strcasecmp( pPath, JS_CC_PATH_AUTH ) == 0)
    {
        JCC_AuthReq sAuthReq;
        JCC_AuthRsp sAuthRsp;

        memset( &sAuthReq, 0x00, sizeof(sAuthReq));
        memset( &sAuthRsp, 0x00, sizeof(sAuthRsp));

        JS_CC_decodeAuthReq( pReq, &sAuthReq );

        ret = authWork( db, &sAuthReq, &sAuthRsp );

        JS_CC_encodeAuthRsp( &sAuthRsp, ppRsp );
    }

    return 0;
}

int runPut( sqlite3 *db, const char *pPath, const char *pReq, const char **ppRsp )
{
    return 0;
}

int runDelete( sqlite3 *db, const char *pPath, const char *pReq, const char **ppRsp )
{
    return 0;
}

int procCC( sqlite3 *db, const char *pReq, int nType, const char *pPath, char **ppRsp )
{
    int ret = 0;

    if( nType == JS_HTTP_METHOD_GET )
    {
        ret = runGet( db, pPath, ppRsp );
    }
    else if( nType == JS_HTTP_METHOD_POST )
    {
        ret = runPost( db, pPath, pReq, ppRsp );
    }
    else if( nType == JS_HTTP_METHOD_PUT )
    {
        ret = runPut( db, pPath, pReq, ppRsp );
    }
    else if( nType == JS_HTTP_METHOD_DELETE )
    {
        ret = runDelete( db, pPath, pReq, ppRsp );
    }

    return 0;
}
