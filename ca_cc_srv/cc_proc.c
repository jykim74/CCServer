#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "js_bin.h"
#include "js_http.h"

int runGet( const char *pPath, const char **ppRsp )
{
    return 0;
}

int runPost( const char *pPath, const char *pReq, const char **ppRsp )
{
    return 0;
}

int runPut( const char *pPath, const char *pReq, const char **ppRsp )
{
    return 0;
}

int runDelete( const char *pPath, const char *pReq, const char **ppRsp )
{
    return 0;
}

int procCC( const char *pReq, int nType, const char *pPath, char **ppRsp )
{
    int ret = 0;

    if( nType == JS_HTTP_METHOD_GET )
    {
        ret = runGet( pPath, ppRsp );
    }
    else if( nType == JS_HTTP_METHOD_POST )
    {
        ret = runPost( pPath, pReq, ppRsp );
    }
    else if( nType == JS_HTTP_METHOD_PUT )
    {
        ret = runPut( pPath, pReq, ppRsp );
    }
    else if( nType == JS_HTTP_METHOD_DELETE )
    {
        ret = runDelete( pPath, pReq, ppRsp );
    }

    return 0;
}
