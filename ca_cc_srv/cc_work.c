#include "js_bin.h"
#include "js_cc.h"
#include "js_cc_data.h"
#include "js_bin.h"
#include "js_db.h"
#include "js_pki.h"

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

int authWork( sqlite3 *db, const JCC_AuthReq *pReq, JCC_AuthRsp *pRsp )
{
    int ret = 0;
    JDB_Admin   sAdmin;
    JDB_Auth    sAuth;
    time_t      tNow = 0;

    char        sResCode[5];
    char        sResMsg[256];
    char        sToken[128];

    memset( &sAdmin, 0x00, sizeof(sAdmin));
    memset( &sAuth, 0x00, sizeof(sAuth));

    ret = JS_DB_getAdmin( db, pReq->pUserName, &sAdmin );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_INVALID_USER;
        goto end;
    }

    if( strcasecmp( pReq->pPasswd, sAdmin.pPassword ) != 0 )
    {
        ret = JS_CC_ERROR_INVALID_PASSWD;
        goto end;
    }

    tNow = time(NULL);
    ret = genToken( pReq->pPasswd, tNow, sToken );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_BASE;
        goto end;
    }

    JS_DB_setAuth( &sAuth, sToken, pReq->pUserName, tNow, 18400 );

end :
    JS_DB_resetAdmin( &sAdmin );
    JS_DB_resetAuth( &sAuth );

    if( ret == JS_CC_OK )
    {
        sprintf( sResCode, "0000" );
        sprintf( sResMsg, "OK" );
        JS_CC_setAuthRsp( pRsp, sResCode, sResMsg, sToken, NULL );
    }
    else
    {
        sprintf( sResMsg, "%d", ret );
        sprintf( sResMsg, "Error" );
        JS_CC_setAuthRsp( pRsp, sResCode, sResMsg, NULL, NULL );
    }

    return ret;
}
