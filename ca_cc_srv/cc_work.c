#include "js_bin.h"
#include "js_cc.h"
#include "js_bin.h"
#include "js_db.h"
#include "js_pki.h"
#include "js_util.h"
#include "js_http.h"

void _setCodeMsg( int nCode, const char *pMsg, char **ppJson )
{
    JCC_CodeMsg sCodeMsg;

    memset( &sCodeMsg, 0x00, sizeof(sCodeMsg));
    JS_CC_setCodeMsg( nCode, pMsg, &sCodeMsg );
    JS_CC_encodeCodeMsg( &sCodeMsg, ppJson );
    JS_CC_resetCodeMsg( &sCodeMsg );
}

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
    int status = JS_HTTP_STATUS_OK;

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

    ret = JS_CC_decodeAuthReq( pReq, &sAuthReq );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_WRONG_MSG;
        goto end;
    }

    ret = JS_DB_getAdmin( db, sAuthReq.pUserName, &sAdmin );
    if( ret < 1 )
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
    ret = JS_DB_addAuth( db, &sAuth );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }


end :
    if( ret == JS_CC_OK )
    {
        JS_CC_setAuthRsp( &sAuthRsp, sToken, "" );
        JS_CC_encodeAuthRsp( &sAuthRsp, ppRsp );
    }
    else
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    JS_DB_resetAdmin( &sAdmin );
    JS_DB_resetAuth( &sAuth );
    JS_CC_resetAuthReq( &sAuthReq );
    JS_CC_resetAuthRsp( &sAuthRsp );

    return status;
}

int regUser( sqlite3 *db, const char *pReq, char **ppRsp )
{
    int ret = 0;
    int status = JS_HTTP_STATUS_OK;
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

    ret = JS_CC_decodeRegUserReq( pReq, &sRegUserReq );
    if( ret != 0 ) return JS_CC_ERROR_WRONG_MSG;

    nRefNum = JS_DB_getSeq( db, "TB_USER" );
    if( nRefNum < 0 )
    {
        ret = JS_CC_ERROR_BASE;
        goto end;
    }

    sprintf( sRefNum, "%d", nRefNum );
    ret = JS_PKI_genRandom( 4, &binRand );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

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
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

end :
    if( ret == JS_CC_OK )
    {
        JS_CC_setRegUserRsp( &sRegUserRsp, sRefNum, pRand );
        JS_CC_encodeRegUserRsp( &sRegUserRsp, ppRsp );
    }
    else
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    JS_DB_resetUser( &sDBUser );
    if( pRand ) JS_free( pRand );
    JS_BIN_reset( &binRand );
    JS_CC_resetRegUserReq( &sRegUserReq );
    JS_CC_resetRegUserRsp( &sRegUserRsp );

    return status;
}

int addSigner( sqlite3 *db, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    int     status = JS_HTTP_STATUS_OK;

    JCC_Signer  sSigner;
    memset( &sSigner, 0x00, sizeof(sSigner));

    JS_CC_decodeSigner( pReq, &sSigner );
    if( ret != 0 ) return JS_CC_ERROR_WRONG_MSG;

    ret = JS_DB_addSigner( db, &sSigner );
    JS_DB_resetSigner( &sSigner );

    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    return status;
}

int delSigner( sqlite3 *db, const char *pPath, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_SIGNER, &pInfoList );

    if( pInfoList == NULL ) return JS_CC_ERROR_WRONG_LINK;

    int nNum = atoi( pInfoList->pStr );

    ret = JS_DB_delSigner( db, nNum );

    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );

    return status;
}

int delRevoked( sqlite3 *db, const char *pPath, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_REVOKED, &pInfoList );

    if( pInfoList == NULL ) return JS_CC_ERROR_WRONG_LINK;

    int nNum = atoi( pInfoList->pStr );

    ret = JS_DB_delRevoked( db, nNum );

    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );

    return status;
}

int addRevoked( sqlite3 *db, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JCC_Revoked sRevoked;

    memset( &sRevoked, 0x00, sizeof(sRevoked));

    ret = JS_CC_decodeRevoked( pReq, &sRevoked );
    if( ret != 0 ) return JS_CC_ERROR_WRONG_MSG;

    ret = JS_DB_addRevoked( db, &sRevoked );
    if( ret != 0 ) goto end;

    ret = JS_DB_changeCertStatus( db, sRevoked.nCertNum, 1 );

 end :
    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    JS_DB_resetRevoked( &sRevoked );

    return status;
}

int addCertPolicy( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    int     nPolicyNum = -1;
    JStrList    *pLinkList = NULL;


    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CERT_POLICY, &pLinkList );

    if( pLinkList ) nPolicyNum = atoi( pLinkList->pStr );

    if( nPolicyNum >= 0 )
    {
        JCC_PolicyExt   sPolicyExt;
        memset( &sPolicyExt, 0x00, sizeof(sPolicyExt));

        ret = JS_CC_decodePolicyExt( pReq, &sPolicyExt );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_WRONG_MSG;
            goto end;
        }

        ret = JS_DB_addCertPolicyExt( db, &sPolicyExt );
        JS_DB_resetPolicyExt( &sPolicyExt );
    }
    else
    {
        JCC_CertPolicy sCertPolicy;
        memset( &sCertPolicy, 0x00, sizeof(sCertPolicy));

        ret = JS_CC_decodeCertPolicy( pReq, &sCertPolicy );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_WRONG_MSG;
            goto end;
        }

        JS_DB_addCertPolicy( db, &sCertPolicy );
        JS_DB_resetCertPolicy( &sCertPolicy );
    }

end :
    if( pLinkList ) JS_UTIL_resetStrList( &pLinkList );

    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    return status;
}

int addCRLPolicy( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    int     nPolicyNum = -1;
    JStrList    *pLinkList = NULL;


    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CRL_POLICY, &pLinkList );

    if( pLinkList ) nPolicyNum = atoi( pLinkList->pStr );

    if( nPolicyNum >= 0 )
    {
        JCC_PolicyExt   sPolicyExt;
        memset( &sPolicyExt, 0x00, sizeof(sPolicyExt));

        ret = JS_CC_decodePolicyExt( pReq, &sPolicyExt );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_WRONG_MSG;
            goto end;
        }

        ret = JS_DB_addCRLPolicyExt( db, &sPolicyExt );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_SYSTEM;
            goto end;
        }

        JS_DB_resetPolicyExt( &sPolicyExt );
    }
    else
    {
        JCC_CRLPolicy sCRLPolicy;
        memset( &sCRLPolicy, 0x00, sizeof(sCRLPolicy));

        ret = JS_CC_decodeCRLPolicy( pReq, &sCRLPolicy );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_WRONG_MSG;
            goto end;
        }

        ret = JS_DB_addCRLPolicy( db, &sCRLPolicy );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_SYSTEM;
            goto end;
        }

        JS_DB_resetCRLPolicy( &sCRLPolicy );
    }

    if( pLinkList ) JS_UTIL_resetStrList( &pLinkList );

end :
    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    return status;
}

int modCertPolicy( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    int     nPolicyNum = -1;
    JStrList    *pLinkList = NULL;
    JCC_CertPolicy  sCertPolicy;

    memset( &sCertPolicy, 0x00, sizeof(sCertPolicy));

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CERT_POLICY, &pLinkList );

    if( pLinkList == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    nPolicyNum = atoi( pLinkList->pStr );

    ret = JS_CC_decodeCertPolicy( pReq, &sCertPolicy );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_WRONG_MSG;
        goto end;
    }

    ret = JS_DB_modCertPolcy( db, nPolicyNum, &sCertPolicy );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

    JS_DB_resetCertPolicy( &sCertPolicy );

    if( pLinkList ) JS_UTIL_resetStrList( &pLinkList );

 end:
    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );


    return status;
}

int modCRLPolicy( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    int     nPolicyNum = -1;
    JStrList    *pLinkList = NULL;

    JCC_CRLPolicy   sCRLPolicy;

    memset( &sCRLPolicy, 0x00, sizeof(sCRLPolicy));

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CRL_POLICY, &pLinkList );

    if( pLinkList == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    nPolicyNum = atoi( pLinkList->pStr );

    ret = JS_CC_decodeCRLPolicy( pReq, &sCRLPolicy );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_WRONG_MSG;
        goto end;
    }

    ret = JS_DB_modCRLPolcy( db, nPolicyNum, &sCRLPolicy );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_BASE;
        goto end;
    }

    JS_DB_resetCRLPolicy( &sCRLPolicy );

end :
    if( pLinkList ) JS_UTIL_resetStrList( &pLinkList );
    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    return status;
}


int getUsers( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_USER, &pInfoList );

    if( pInfoList == NULL )
    {
        JDB_UserList *pUserList = NULL;
        if( pParamList )
        {
            const char *pValue = NULL;
            int nOffset = 0;
            int nLimit = 0;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "offset" );
            if( pValue ) nOffset = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "limit" );
            if( pValue ) nLimit = atoi( pValue );

            ret = JS_DB_getUserPageList( db, nOffset, nLimit, &pUserList );
            if( ret < 1 )
            {
                ret = JS_CC_ERROR_NO_DATA;
                goto end;
            }
        }
        else
        {
            ret = JS_DB_getUserList( db, &pUserList );
            if( ret < 1 )
            {
                ret = JS_CC_ERROR_NO_DATA;
                goto end;
            }
        }

        JS_CC_encodeUserList( pUserList, ppRsp );
        if( pUserList ) JS_DB_resetUserList( &pUserList );
    }
    else
    {
        JDB_User sUser;
        memset( &sUser, 0x00, sizeof(sUser));
        int nSeq = atoi( pInfoList->pStr );

        ret = JS_DB_getUser( db, nSeq, &sUser );
        if( ret < 1 )
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }

        JS_CC_encodeUser( &sUser, ppRsp );
        JS_DB_resetUser( &sUser );
    }

    ret = 0;

end :
    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );

    return status;
}

int delUser( sqlite3 *db, const char *pPath, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_USER, &pInfoList );

    if( pInfoList == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    int nNum = atoi( pInfoList->pStr );
    if( nNum < 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

    ret = JS_DB_delUser( db, nNum );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

end :
    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    return status;
}

int delCertPolicy( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pLinkList = NULL;
    int nPolicyNum = -1;
    int bExtOnly = 0;


    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CERT_POLICY, &pLinkList );

    if( pLinkList == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    nPolicyNum = atoi( pLinkList->pStr );

    if( pParamList )
    {
        const char *pValue = JS_UTIL_valueFromNameValList( pParamList, "mode" );
        if( pValue )
        {
            if( strcasecmp( pValue, "extonly") == 0 )
                bExtOnly = 1;
        }
    }

    if( bExtOnly )
    {
        ret = JS_DB_delCertPolicyExtsByPolicyNum( db, nPolicyNum );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_SYSTEM;
            goto end;
        }
    }
    else
    {
        ret = JS_DB_delCertPolicy( db, nPolicyNum );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_SYSTEM;
            goto end;
        }

        ret = JS_DB_delCertPolicyExtsByPolicyNum( db, nPolicyNum );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_SYSTEM;
            goto end;
        }
    }

end :
    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    return status;
}

int delCRLPolicy( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pLinkList = NULL;
    int nPolicyNum = -1;
    int bExtOnly = 0;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CRL_POLICY, &pLinkList );

    if( pLinkList == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    nPolicyNum = atoi( pLinkList->pStr );

    if( pParamList )
    {
        const char *pValue = JS_UTIL_valueFromNameValList( pParamList, "mode" );
        if( pValue )
        {
            if( strcasecmp( pValue, "extonly") == 0 )
                bExtOnly = 1;
        }
    }

    if( bExtOnly )
    {
        ret = JS_DB_delCRLPolicyExtsByPolicyNum( db, nPolicyNum );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_SYSTEM;
            goto end;
        }
    }
    else
    {
        ret = JS_DB_delCRLPolicy( db, nPolicyNum );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_SYSTEM;
            goto end;
        }

        ret = JS_DB_delCRLPolicyExtsByPolicyNum( db, nPolicyNum );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_SYSTEM;
            goto end;
        }
    }

end :
    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    return status;
}

int getCount( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;
    JCC_NameVal sNameVal;
    int count = 0;
    char sValue[32];

    memset( &sNameVal, 0x00, sizeof(sNameVal));

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_COUNT, &pInfoList );
    if( pInfoList == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    if( strcasecmp( pInfoList->pStr, "users" ) == 0 )
        count = JS_DB_getCount( db, "TB_USER" );
    else if( strcasecmp( pInfoList->pStr, "certs" ) == 0 )
        count = JS_DB_getCount( db, "TB_CERT" );
    else if( strcasecmp( pInfoList->pStr, "crls" ) == 0 )
        count = JS_DB_getCount( db, "TB_CRL" );
    else if( strcasecmp( pInfoList->pStr, "revokeds" ) == 0 )
        count = JS_DB_getCount( db, "TB_REVOKED" );

    if( count < 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

    sprintf( sValue, "%d", count );

    JS_CC_setNameVal( &sNameVal, "count", sValue );
    JS_CC_encodeNameVal( &sNameVal, ppRsp );
    JS_CC_resetNameVal( &sNameVal );

end :
    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    return status;
}

int getNum( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;
    JCC_NameVal sNameVal;
    int num = 0;
    char sValue[32];

    memset( &sNameVal, 0x00, sizeof(sNameVal));

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_NUM, &pInfoList );
    if( pInfoList == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    if( strcasecmp( pInfoList->pStr, "users" ) == 0 )
        num = JS_DB_getNum( db, "TB_USER" );
    else if( strcasecmp( pInfoList->pStr, "certs" ) == 0 )
        num = JS_DB_getNum( db, "TB_CERT" );
    else if( strcasecmp( pInfoList->pStr, "crls" ) == 0 )
        num = JS_DB_getNum( db, "TB_CRL" );
    else if( strcasecmp( pInfoList->pStr, "revokeds" ) == 0 )
        num = JS_DB_getNum( db, "TB_REVOKED" );
    else if( strcasecmp( pInfoList->pStr, "cert_policies" ) == 0 )
        num = JS_DB_getNum( db, "TB_CERT_POLICY" );
    else if( strcasecmp( pInfoList->pStr, "crl_policies" ) == 0 )
        num = JS_DB_getNum( db, "TB_CRL_POLICY" );
    else
    {
        fprintf( stderr, "invalid link(%s)\n", pInfoList->pStr );
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    if( num < 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

    sprintf( sValue, "%d", num );

    JS_CC_setNameVal( &sNameVal, "num", sValue );
    JS_CC_encodeNameVal( &sNameVal, ppRsp );
    JS_CC_resetNameVal( &sNameVal );

end :
    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    return status;
}

int getCertPolicies( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CERT_POLICY, &pInfoList );

    if( pInfoList == NULL )
    {
        JCC_CertPolicyList *pCertPolicyList = NULL;

        ret = JS_DB_getCertPolicyList( db, &pCertPolicyList );
        if( ret < 1 )
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }

        JS_CC_encodeCertPolicyList( pCertPolicyList, ppRsp );
        if( pCertPolicyList ) JS_DB_resetCertPolicyList( &pCertPolicyList );
    }
    else
    {
        int nInfoCnt = JS_UTIL_countStrList( pInfoList );

        if( nInfoCnt == 1 )
        {
            JCC_CertPolicy sCertPolicy;
            memset( &sCertPolicy, 0x00, sizeof(sCertPolicy));

            int nNum = atoi( pInfoList->pStr );
            if( nNum < 0 )
            {
                ret = JS_CC_ERROR_SYSTEM;
                goto end;
            }

            ret = JS_DB_getCertPolicy( db, nNum, &sCertPolicy );
            if( ret < 1 )
            {
                ret = JS_CC_ERROR_NO_DATA;
                goto end;
            }

            JS_CC_encodeCertPolicy( &sCertPolicy, ppRsp );
            JS_DB_resetCertPolicy( &sCertPolicy );
        }
        else if( nInfoCnt == 2 )
        {
            int nPolicyNum = atoi( pInfoList->pStr );

            if( strcasecmp( pInfoList->pNext->pStr, "extensions" ) == 0 )
            {
               JCC_PolicyExtList *pPolicyExtList = NULL;

               ret = JS_DB_getCertPolicyExtList( db, nPolicyNum, &pPolicyExtList );
               if( ret < 1 )
               {
                   ret = JS_CC_ERROR_NO_DATA;
                   goto end;
               }

               JS_CC_encodePolicyExtList( pPolicyExtList, ppRsp );
               if( pPolicyExtList ) JS_DB_resetPolicyExtList( &pPolicyExtList );
            }
        }
    }

    ret = 0;

end :
    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );

    return status;
}

int getCRLPolicies( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CRL_POLICY, &pInfoList );

    if( pInfoList == NULL )
    {
        JCC_CRLPolicyList *pCRLPolicyList = NULL;

        ret = JS_DB_getCRLPolicyList( db, &pCRLPolicyList );
        if( ret < 1 )
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }

        JS_CC_encodeCRLPolicyList( pCRLPolicyList, ppRsp );
        if( pCRLPolicyList ) JS_DB_resetCRLPolicyList( &pCRLPolicyList );
    }
    else
    {
        int nInfoCnt = JS_UTIL_countStrList( pInfoList );

        if( nInfoCnt == 1 )
        {
            JCC_CRLPolicy sCRLPolicy;
            memset( &sCRLPolicy, 0x00, sizeof(sCRLPolicy));

            int nNum = atoi( pInfoList->pStr );
            if( nNum < 0 )
            {
                ret = JS_CC_ERROR_WRONG_LINK;
                goto end;
            }

            ret = JS_DB_getCRLPolicy( db, nNum, &sCRLPolicy );
            if( ret < 1 )
            {
                ret = JS_CC_ERROR_NO_DATA;
                goto end;
            }

            JS_CC_encodeCRLPolicy( &sCRLPolicy, ppRsp );
            JS_DB_resetCRLPolicy( &sCRLPolicy );
        }
        else if( nInfoCnt == 2 )
        {
            int nPolicyNum = atoi( pInfoList->pStr );

            if( strcasecmp( pInfoList->pNext->pStr, "extensions" ) == 0 )
            {
               JCC_PolicyExtList *pPolicyExtList = NULL;

               ret = JS_DB_getCRLPolicyExtList( db, nPolicyNum, &pPolicyExtList );
               if( ret < 1 )
               {
                   ret = JS_CC_ERROR_NO_DATA;
                   goto end;
               }

               JS_CC_encodePolicyExtList( pPolicyExtList, ppRsp );
               if( pPolicyExtList ) JS_DB_resetPolicyExtList( &pPolicyExtList );
            }
        }
    }

    ret = 0;

end :
    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );

    return status;
}

int getSigners( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_SIGNER, &pInfoList );

    if( pInfoList == NULL )
    {
        int nType = -1;
        const char *pValue = NULL;
        JDB_SignerList  *pSignerList = NULL;

        if( pParamList )
        {
            pValue = JS_UTIL_valueFromNameValList( pParamList, "type" );
            if( pValue ) nType = atoi( pValue );
            ret = JS_DB_getSignerListByType( db, nType, &pSignerList );
            if( ret < 1 )
            {
                ret = JS_CC_ERROR_NO_DATA;
                goto end;
            }
        }

        JS_CC_encodeSignerList( pSignerList, ppRsp );
        if( pSignerList ) JS_DB_resetSignerList( &pSignerList );
    }
    else
    {
        int nNum = atoi( pInfoList->pStr );
        JDB_Signer  sSigner;

        memset( &sSigner, 0x00, sizeof(sSigner));

        ret = JS_DB_getSigner( db, nNum, &sSigner );
        if( ret < 1 )
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }

        JS_CC_encodeSigner( &sSigner, ppRsp );

        JS_DB_resetSigner( &sSigner );
    }

    ret = 0;

end :
    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );
    return status;
}

int getCerts( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CERT, &pInfoList );

    if( pInfoList == NULL )
    {
        JDB_CertList *pCertList = NULL;
        if( pParamList )
        {
            const char *pValue = NULL;
            int nOffset = 0;
            int nLimit = 0;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "offset" );
            if( pValue ) nOffset = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "limit" );
            if( pValue ) nLimit = atoi( pValue );

            ret = JS_DB_getCertPageList( db, nOffset, nLimit, &pCertList );
            if( ret < 1 )
            {
                ret = JS_CC_ERROR_NO_DATA;
                goto end;
            }
        }

        JS_CC_encodeCertList( pCertList, ppRsp );
        if( pCertList ) JS_DB_resetCertList( &pCertList );
    }
    else
    {
        JDB_Cert sCert;
        memset( &sCert, 0x00, sizeof(sCert));
        int nSeq = atoi( pInfoList->pStr );

        ret = JS_DB_getCert( db, nSeq, &sCert );
        if( ret < 1 )
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }

        JS_CC_encodeCert( &sCert, ppRsp );
        JS_DB_resetCert( &sCert );
    }

    ret = 0;

end :
    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );
    return status;
}

int getCRLs( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CRL, &pInfoList );

    if( pInfoList == NULL )
    {
        JDB_CRLList *pCRLList = NULL;
        if( pParamList )
        {
            const char *pValue = NULL;
            int nOffset = 0;
            int nLimit = 0;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "offset" );
            if( pValue ) nOffset = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "limit" );
            if( pValue ) nLimit = atoi( pValue );

            ret = JS_DB_getCRLPageList( db, nOffset, nLimit, &pCRLList );
            if( ret < 1 )
            {
                ret = JS_CC_ERROR_NO_DATA;
                goto end;
            }
        }

        JS_CC_encodeCRLList( pCRLList, ppRsp );
        if( pCRLList ) JS_DB_resetCRLList( &pCRLList );
    }
    else
    {
        JDB_CRL sCRL;
        memset( &sCRL, 0x00, sizeof(sCRL));
        int nSeq = atoi( pInfoList->pStr );

        ret = JS_DB_getCRL( db, nSeq, &sCRL );
        if( ret < 1 )
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }

        JS_CC_encodeCRL( &sCRL, ppRsp );
        JS_DB_resetCRL( &sCRL );
    }

    ret = 0;

end :
    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );
    return status;
}

int getRevokeds( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_REVOKED, &pInfoList );

    if( pInfoList == NULL )
    {
        JDB_RevokedList *pRevokedList = NULL;
        if( pParamList )
        {
            const char *pValue = NULL;
            int nOffset = 0;
            int nLimit = 0;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "offset" );
            if( pValue ) nOffset = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "limit" );
            if( pValue ) nLimit = atoi( pValue );

            ret = JS_DB_getRevokedPageList( db, nOffset, nLimit, &pRevokedList );
            if( ret < 1 )
            {
                ret = JS_CC_ERROR_NO_DATA;
                goto end;
            }
        }

        JS_CC_encodeRevokedList( pRevokedList, ppRsp );
        if( pRevokedList ) JS_DB_resetRevokedList( &pRevokedList );
    }
    else
    {
        JDB_Revoked sRevoked;
        memset( &sRevoked, 0x00, sizeof(sRevoked));
        int nSeq = atoi( pInfoList->pStr );

        ret = JS_DB_getRevoked( db, nSeq, &sRevoked );
        if( ret < 1 )
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }

        JS_CC_encodeRevoked( &sRevoked, ppRsp );
        JS_DB_resetRevoked( &sRevoked );
    }

    ret = 0;

end :
    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );
    return status;
}
