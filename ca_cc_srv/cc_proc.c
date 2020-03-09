#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "js_bin.h"
#include "js_http.h"
#include "js_cc.h"
#include "js_cc_data.h"

#include "cc_srv.h"

int runGet( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    if( strncasecmp( pPath, JS_CC_PATH_USER, strlen(JS_CC_PATH_USER)) == 0 )
    {
        getUsers( db, pPath, pParamList, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_COUNT, strlen(JS_CC_PATH_COUNT)) == 0 )
    {
        getCount( db, pPath, pParamList, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_CERT_POLICY, strlen(JS_CC_PATH_CERT_POLICY)) == 0 )
    {
        getCertPolicies( db, pPath, pParamList, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_CRL_POLICY, strlen(JS_CC_PATH_CRL_POLICY)) == 0 )
    {
        getCRLPolicies( db, pPath, pParamList, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_SIGNER, strlen(JS_CC_PATH_SIGNER)) == 0 )
    {
        getSigners( db, pPath, pParamList, ppRsp );
    }

    return 0;
}

int runPost( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp )
{
    int ret = 0;
    if( strncasecmp( pPath, JS_CC_PATH_AUTH, strlen( JS_CC_PATH_AUTH) ) == 0)
    {
        ret = authWork( db, pReq, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_USER, strlen(JS_CC_PATH_USER) ) == 0 )
    {
        ret = regUser( db, pReq, ppRsp );
    }

    return 0;
}

int runPut( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp )
{
    return 0;
}

int runDelete( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp )
{
    int ret = 0;
    if( strncasecmp( pPath, JS_CC_PATH_USER, strlen(JS_CC_PATH_USER)) == 0 )
    {
        ret = delUser( db, pPath, ppRsp );
    }

    return 0;
}

int procCC( sqlite3 *db, const char *pReq, int nType, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;

    JS_UTIL_printNameValList( stdout, "ParamList", pParamList );
    fprintf( stdout, "Path: %s\n", pPath );

    if( nType == JS_HTTP_METHOD_GET )
    {
        ret = runGet( db, pPath, pParamList, ppRsp );
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
