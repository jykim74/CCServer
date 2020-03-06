#include "js_bin.h"
#include "js_cc.h"
#include "js_cc_data.h"
#include "js_bin.h"
#include "js_db.h"
#include "js_pki.h"
#include "js_util.h"
#include "js_http.h"

int genToken( const char *pPassword, time_t tTime, char *pToken )
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binKey = {0,0};
    BIN binHMAC = {0,0};
    char    *pHex = NULL;

    JS_BIN_set( &binSrc, pPassword, strlen( pPassword));
    JS_BIN_append( &binSrc, &tTime, sizeof(tTime));
    JS_BIN_set( &binKey, "1234567890123456", 16 );

    ret = JS_PKI_genHMAC( "SHA1", &binSrc, &binKey, &binHMAC );
    if( ret != 0 )
    {
        goto end;
    }

    JS_BIN_encodeHex( &binHMAC, &pHex );

end :
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binHMAC );

    if( pHex )
    {
        sprintf( pToken, pHex );
        JS_free( pHex );
    }

    return ret;
}

int authWork( sqlite3 *db, const char *pReq, char **ppRsp )
{
    int ret = 0;
    JDB_Admin   sAdmin;
    JDB_Auth    sAuth;
    time_t      tNow = 0;

    JCC_AuthReq sAuthReq;
    JCC_AuthRsp sAuthRsp;

    char        sResCode[5];
    char        sResMsg[256];
    char        sToken[128];

    memset( &sAdmin, 0x00, sizeof(sAdmin));
    memset( &sAuth, 0x00, sizeof(sAuth));
    memset( &sAuthReq, 0x00, sizeof(sAuthReq));
    memset( &sAuthRsp, 0x00, sizeof(sAuthRsp));

    JS_CC_decodeAuthReq( pReq, &sAuthReq );

    ret = JS_DB_getAdmin( db, sAuthReq.pUserName, &sAdmin );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_INVALID_USER;
        goto end;
    }

    if( strcasecmp( sAuthReq.pPasswd, sAdmin.pPassword ) != 0 )
    {
        ret = JS_CC_ERROR_INVALID_PASSWD;
        goto end;
    }

    tNow = time(NULL);
    ret = genToken( sAuthReq.pPasswd, tNow, sToken );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_BASE;
        goto end;
    }

    JS_DB_setAuth( &sAuth, sToken, sAuthReq.pUserName, tNow, 18400 );
    JS_DB_delAuthByName( db, sAuthReq.pUserName );
    JS_DB_addAuth( db, &sAuth );

    if( ret == JS_CC_OK )
    {
        sprintf( sResCode, "0000" );
        sprintf( sResMsg, "OK" );
        JS_CC_setAuthRsp( &sAuthRsp, sResCode, sResMsg, sToken, NULL );
        JS_CC_encodeAuthRsp( &sAuthRsp, ppRsp );
    }

end :
    JS_DB_resetAdmin( &sAdmin );
    JS_DB_resetAuth( &sAuth );
    JS_CC_resetAuthReq( &sAuthReq );
    JS_CC_resetAuthRsp( &sAuthRsp );

    return ret;
}

int regUser( sqlite3 *db, const char *pReq, char **ppRsp )
{
    int ret = 0;
    BIN binRand = {0,0};
    int nRefNum = 0;
    char sRefNum[64];
    char *pRand = NULL;

    JDB_User    sDBUser;
    JCC_RegUserReq  sRegUserReq;
    JCC_RegUserRsp  sRegUserRsp;

    memset( &sDBUser, 0x00, sizeof(sDBUser ));
    memset( &sRegUserReq, 0x00, sizeof(sRegUserReq));
    memset( &sRegUserRsp, 0x00, sizeof(sRegUserRsp));

    JS_CC_decodeRegUserReq( pReq, &sRegUserReq );

    nRefNum = JS_DB_getSeq( db, "TB_USER" );
    if( nRefNum < 0 )
    {
        ret = JS_CC_ERROR_BASE;
        goto end;
    }

    sprintf( sRefNum, "%d", nRefNum );
    ret = JS_PKI_genRandom( 4, &binRand );
    ret = JS_BIN_encodeHex( &binRand, &pRand );

    ret = JS_DB_setUser( &sDBUser,
                         -1,
                         sRegUserReq.pName,
                         sRegUserReq.pSSN,
                         sRegUserReq.pEmail,
                         0,
                         sRefNum,
                         pRand );

    ret = JS_DB_addUser( db, &sDBUser );

    if( ret == JS_CC_OK )
    {
        JS_CC_setRegUserRsp( &sRegUserRsp, "0000", "OK", sRefNum, pRand );
        JS_CC_encodeRegUserRsp( &sRegUserRsp, ppRsp );
    }

end :
    JS_DB_resetUser( &sDBUser );
    if( pRand ) JS_free( pRand );
    JS_BIN_reset( &binRand );
    JS_CC_resetRegUserReq( &sRegUserReq );
    JS_CC_resetRegUserRsp( &sRegUserRsp );

    return ret;
}

int getUsers( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_USER, &pInfoList );

    if( pInfoList == NULL )
    {
        JDB_UserList *pUserList = NULL;
        ret = JS_DB_getUserList( db, &pUserList );
        JS_CC_encodeUserList( pUserList, ppRsp );
        if( pUserList ) JS_DB_resetUserList( &pUserList );
    }
    else
    {
        JDB_User sUser;
        memset( &sUser, 0x00, sizeof(sUser));
        int nSeq = atoi( pInfoList->pStr );

        ret = JS_DB_getUser( db, nSeq, &sUser );
        JS_CC_encodeUser( &sUser, ppRsp );
        JS_DB_resetUser( &sUser );
    }

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );

    return ret;
}

int delUser( sqlite3 *db, const char *pPath, char **ppRsp )
{
    int ret = 0;
    JStrList    *pInfoList = NULL;
    JCC_CodeMsg sCodeMsg;

    memset( &sCodeMsg, 0x00, sizeof(sCodeMsg));

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_USER, &pInfoList );

    if( pInfoList == NULL ) return -1;

    int nNum = atoi( pInfoList->pStr );

    ret = JS_DB_delUser( db, nNum );

    JS_CC_setCodeMsg( &sCodeMsg, 0, "ok" );

    JS_CC_encodeCodeMsg( &sCodeMsg, ppRsp );
    JS_CC_resetCodeMsg( &sCodeMsg );

    return ret;
}
