#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "js_bin.h"
#include "js_http.h"
#include "js_cc.h"
#include "js_cc_data.h"

#include "cc_srv.h"

int runGet( sqlite3 *db, const char *pPath, const JNameValList *pParamList, const char **ppRsp )
{
    JStrList    *pInfoList = NULL;

    if( strncasecmp( pPath, JS_CC_PATH_USER, strlen(JS_CC_PATH_USER)) == 0 )
    {
        JDB_UserList    *pDBUserList = NULL;

        JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_USER, &pInfoList );
        getUser( db, pInfoList, &pDBUserList );

        JS_CC_encodeUserList( pDBUserList, ppRsp );
        if( pDBUserList ) JS_DB_resetUserList( &pDBUserList );
    }

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );
    return 0;
}

int runPost( sqlite3 *db, const char *pPath, const char *pReq, const char **ppRsp )
{
    int ret = 0;
    if( strncasecmp( pPath, JS_CC_PATH_AUTH, strlen( JS_CC_PATH_AUTH) ) == 0)
    {
        JCC_AuthReq sAuthReq;
        JCC_AuthRsp sAuthRsp;

        memset( &sAuthReq, 0x00, sizeof(sAuthReq));
        memset( &sAuthRsp, 0x00, sizeof(sAuthRsp));

        JS_CC_decodeAuthReq( pReq, &sAuthReq );

        ret = authWork( db, &sAuthReq, &sAuthRsp );

        JS_CC_encodeAuthRsp( &sAuthRsp, ppRsp );

        JS_CC_resetAuthReq( &sAuthReq );
        JS_CC_resetAuthRsp( &sAuthRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_USER, strlen(JS_CC_PATH_USER) ) == 0 )
    {
        JCC_RegUserReq sRegUserReq;
        JCC_RegUserRsp sRegUserRsp;

        memset( &sRegUserReq, 0x00, sizeof(sRegUserReq));
        memset( &sRegUserRsp, 0x00, sizeof(sRegUserRsp));

        JS_CC_decodeRegUserReq( pReq, &sRegUserReq );
        ret = regUser( db, &sRegUserReq, &sRegUserRsp );

        JS_CC_encodeRegUserRsp( &sRegUserRsp, ppRsp );

        JS_CC_resetRegUserReq( &sRegUserReq );
        JS_CC_resetRegUserRsp( &sRegUserRsp );
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

int procCC( sqlite3 *db, const char *pReq, int nType, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;

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
