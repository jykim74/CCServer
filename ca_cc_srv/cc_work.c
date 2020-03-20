#include "js_bin.h"
#include "js_cc.h"
#include "js_bin.h"
#include "js_db.h"
#include "js_pki.h"
#include "js_pki_ext.h"
#include "js_util.h"
#include "js_http.h"
#include "js_cfg.h"

#include "cc_tools.h"
#include "js_ldap.h"

extern  JEnvList    *g_pEnvList;
extern  BIN         g_binCert;
extern  BIN         g_binPri;
extern  int         g_nKeyType;
extern  LDAP        *g_pLDAP;

void _setCodeMsg( int nCode, const char *pMsg, char **ppJson )
{
    JCC_CodeMsg sCodeMsg;

    memset( &sCodeMsg, 0x00, sizeof(sCodeMsg));
    JS_CC_setCodeMsg( &sCodeMsg, nCode, pMsg );
    JS_CC_encodeCodeMsg( &sCodeMsg, ppJson );
    JS_CC_resetCodeMsg( &sCodeMsg );
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

    time_t now_t = time(NULL);

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
                         now_t,
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

int issueCert( sqlite3 *db, const char *pReq, char **ppRsp )
{
    int ret = 0;
    int status = JS_HTTP_STATUS_OK;
    int nPolicyNum = -1;
    int nUserNum = -1;

    JCC_IssueCertReq    sIssueCertReq;
    JCC_IssueCertRsp    sIssueCertRsp;
    JDB_CertPolicy      sCertPolicy;
    JDB_PolicyExtList   *pPolicyExtList = NULL;
    JDB_User            sUser;
    JIssueCertInfo      sIssueCertInfo;
    JCertInfo           sCertInfo;
    JReqInfo            sReqInfo;
    JDB_Cert            sCert;
    JExtensionInfoList  *pExtInfoList = NULL;
    char                *pHexCRLDP = NULL;
    char                *pCRLDP = NULL;

    BIN                 binCert = {0,0};
    BIN                 binCSR = {0,0};
    BIN                 binPub = {0,0};

    char                sSerial[32];
    long                uNotBefore = 0;
    long                uNotAfter = 0;
    char                *pHexCert = NULL;
    char                *pHexCACert = NULL;
    char                sKeyID[128];

    time_t now_t = time(NULL);

    memset( &sIssueCertReq, 0x00, sizeof(sIssueCertReq));
    memset( &sIssueCertRsp, 0x00, sizeof(sIssueCertRsp));
    memset( &sCertPolicy, 0x00, sizeof(sCertPolicy));
    memset( &sUser, 0x00, sizeof(sUser));
    memset( &sIssueCertInfo, 0x00, sizeof(sIssueCertInfo));
    memset( &sReqInfo, 0x00, sizeof(sReqInfo));
    memset( sSerial, 0x00, sizeof(sSerial));
    memset( &sCert, 0x00, sizeof(sCert));
    memset( &sCertInfo, 0x00, sizeof(sCertInfo));
    memset( &sKeyID, 0x00, sizeof(sKeyID));

    ret = JS_CC_decodeIssueCertReq( pReq, &sIssueCertReq );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_WRONG_MSG;
        goto end;
    }

    nUserNum = sIssueCertReq.nUserNum;

    if( nUserNum > 0 )
    {
        ret = JS_DB_getUser( db, nUserNum, &sUser );
        if( ret != 1 )
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }
    }
    else
    {
        JS_DB_setUser( &sUser, -1, now_t, sIssueCertReq.pName, sIssueCertReq.pSSN, sIssueCertReq.pEmail, 0, NULL, NULL );
    }

    nPolicyNum = sIssueCertReq.nCertPolicyNum;

    ret = JS_DB_getCertPolicy( db, nPolicyNum, &sCertPolicy );
    if( ret != 1 )
    {
        ret = JS_CC_ERROR_NO_DATA;
        goto end;
    }

    JS_DB_getCertPolicyExtList( db, nPolicyNum, &pPolicyExtList );

    JS_BIN_decodeHex( sIssueCertReq.pCSR, &binCSR );
    ret = JS_PKI_getReqInfo( &binCSR, &sReqInfo, NULL );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }


    JS_BIN_decodeHex( sReqInfo.pPublicKey, &binPub );
    JS_PKI_getKeyIdentifier( &binPub, sKeyID );

    if( sCertPolicy.nNotBefore <= 0 )
    {
        uNotBefore = 0;
        uNotAfter = sCertPolicy.nNotAfter * 60 * 60 * 24;
    }
    else
    {
        uNotBefore = sCertPolicy.nNotBefore - now_t;
        uNotAfter = sCertPolicy.nNotAfter - now_t;
    }

    int nSeq = JS_DB_getSeq( db, "TB_CERT" );
    sprintf( sSerial, "%d", nSeq );

    JS_PKI_setIssueCertInfo( &sIssueCertInfo,
                             sCertPolicy.nVersion,
                             sSerial,
                             sCertPolicy.pHash,
                             sReqInfo.pSubjectDN,
                             uNotBefore,
                             uNotAfter,
                             sReqInfo.nKeyAlg,
                             sReqInfo.pPublicKey );

    ret = makeCert( &sCertPolicy, pPolicyExtList, &sIssueCertInfo, &binCert );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

    JS_BIN_encodeHex( &binCert, &pHexCert );
    JS_BIN_encodeHex( &g_binCert, &pHexCACert );

    if( nUserNum < 0 )
    {
        nUserNum = JS_DB_getSeq( db, "TB_USER" );
        sUser.nNum = nUserNum;

        ret = JS_DB_addUser( db, &sUser );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_SYSTEM;
            goto end;
        }
    }

    JS_PKI_getCertInfo( &binCert, &sCertInfo, &pExtInfoList );
    JS_PKI_getExtensionValue( pExtInfoList, JS_PKI_ExtNameCRLDP, &pHexCRLDP );
    if( pHexCRLDP ) JS_PKI_getExtensionStringValue( pHexCRLDP, JS_PKI_ExtNameCRLDP, &pCRLDP );

    JS_DB_setCert( &sCert,
                   -1,
                   now_t,
                   -1,
                   sUser.nNum,
                   sCertInfo.pSignAlgorithm,
                   pHexCert,
                   0,
                   0,
                   0,
                   sCertInfo.pSubjectName,
                   0,
                   sCertInfo.pSerial,
                   sCertInfo.pDNHash,
                   sKeyID,
                   pCRLDP ? pCRLDP : "" );

    ret = JS_DB_addCert( db, &sCert );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

    JS_CC_setIssueCertRsp( &sIssueCertRsp, nUserNum, sReqInfo.pSubjectDN, pHexCert, pHexCACert );
    JS_CC_encodeIssueCertRsp( &sIssueCertRsp, ppRsp );

    if( g_pLDAP )
    {
        JS_LDAP_publishData( g_pLDAP, sCertInfo.pSubjectName, JS_LDAP_TYPE_USER_CERTIFICATE, &binCert );
    }

    ret = 0;

end:
    JS_CC_resetIssueCertReq( &sIssueCertReq );
    JS_CC_resetIssueCertRsp( &sIssueCertRsp );
    JS_DB_resetCertPolicy( &sCertPolicy );
    if( pPolicyExtList ) JS_DB_resetPolicyExtList( &pPolicyExtList );
    JS_DB_resetUser( &sUser );
    JS_PKI_resetReqInfo( &sReqInfo );
    JS_PKI_resetIssueCertInfo( &sIssueCertInfo );
    JS_BIN_reset( &binCert );
    if( pHexCert ) JS_free( pHexCert );
    if( pHexCACert ) JS_free( pHexCACert );
    JS_DB_resetCert( &sCert );
    JS_BIN_reset( &binPub );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );
    if( pCRLDP ) JS_free( pCRLDP );
    if( pHexCRLDP ) JS_free( pHexCRLDP );

    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    return status;
}

int issueCRL( sqlite3 *db, const char *pReq, char **ppRsp )
{
    int         ret = 0;
    int         status = JS_HTTP_STATUS_OK;


    JCC_IssueCRLReq     sCRLReq;
    JCC_IssueCRLRsp     sCRLRsp;

    JDB_CRLPolicy       sDBPolicy;
    JDB_PolicyExtList   *pDBPolicyExtList = NULL;
    JDB_PolicyExtList   *pDBCurExtList = NULL;
    JDB_RevokedList     *pDBRevokedList = NULL;
    JDB_CRL             sDBCRL;

    BIN     binCRL = {0,0};
    char    *pHexCRL = NULL;
    JCRLInfo            sCRLInfo;
    time_t now_t = time(NULL);

    memset( &sCRLReq, 0x00, sizeof(sCRLReq));
    memset( &sCRLRsp, 0x00, sizeof(sCRLRsp));
    memset( &sDBPolicy, 0x00, sizeof(sDBPolicy));
    memset( &sCRLInfo, 0x00, sizeof(sCRLInfo));
    memset( &sDBCRL, 0x00, sizeof(sDBCRL));

    ret = JS_CC_decodeIssueCRLReq( pReq, &sCRLReq );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_WRONG_MSG;
        goto end;
    }

    ret = JS_DB_getCRLPolicy( db, sCRLReq.nCRLPolicyNum, &sDBPolicy );
    if( ret != 1 )
    {
        ret = JS_CC_ERROR_NO_DATA;
        goto end;
    }

    ret = JS_DB_getCRLPolicyExtList( db, sCRLReq.nCRLPolicyNum, &pDBPolicyExtList );
    if( ret < 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

    pDBCurExtList = pDBPolicyExtList;
    int nSeq = JS_DB_getSeq( db, "TB_CRL" );
    nSeq++;

    while( pDBCurExtList )
    {
        if( strcasecmp( pDBCurExtList->sPolicyExt.pSN, JS_PKI_ExtNameAKI ) == 0 )
        {
            BIN binCert = {0,0};
            char        sHexID[256];
            char        sHexSerial[256];
            char        sHexIssuer[1024];
            char        *pValue = NULL;
            int         len = 0;

            memset( sHexID, 0x00, sizeof(sHexID));
            memset( sHexSerial, 0x00, sizeof(sHexSerial));
            memset( sHexIssuer, 0x00, sizeof(sHexIssuer));

            JS_PKI_getAuthorityKeyIdentifier(  &g_binCert, sHexID, sHexSerial, sHexIssuer );

            len = strlen( sHexID );
            len += strlen( sHexSerial );
            len += strlen( sHexIssuer );

            pValue = (char *)JS_malloc( len + 128 );
            sprintf( pValue, "KEYID$%s#ISSUER$%s#SERIAL$%s", sHexID, sHexIssuer, sHexSerial );
            if( pDBCurExtList->sPolicyExt.pValue )
            {
                JS_free( pDBCurExtList->sPolicyExt.pValue );
            }

            pDBCurExtList->sPolicyExt.pValue = pValue;
        }
        else if( strcasecmp( pDBCurExtList->sPolicyExt.pSN, JS_PKI_ExtNameCRLNum ) == 0 )
        {
            if( strcasecmp( pDBCurExtList->sPolicyExt.pValue, "auto") == 0 )
            {
                char *pValue = NULL;
                pValue = (char *)JS_malloc( 32 );
                sprintf( pValue, "%04x", nSeq );
                JS_free( pDBCurExtList->sPolicyExt.pValue );
                pDBCurExtList->sPolicyExt.pValue = pValue;
            }
        }

        pDBCurExtList = pDBCurExtList->pNext;
    }

    ret = JS_DB_getRevokedList( db, &pDBRevokedList );
    if( ret < 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

    ret = makeCRL( &sDBPolicy, pDBPolicyExtList, pDBRevokedList, &binCRL );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

    JS_BIN_encodeHex( &binCRL, &pHexCRL );

    ret = JS_PKI_getCRLInfo( &binCRL, &sCRLInfo, NULL, NULL );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

    JS_DB_setCRL( &sDBCRL, nSeq, now_t, -1, sCRLInfo.pSignAlgorithm, pHexCRL );

    ret = JS_DB_addCRL( db, &sDBCRL );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

    JS_CC_setIssueCRLRsp( &sCRLRsp,
                          nSeq,
                          sCRLInfo.pIssuerName,
                          sCRLReq.bDownload ? pHexCRL : "" );

    JS_CC_encodeIssueCRLRsp( &sCRLRsp, ppRsp );

    if( g_pLDAP ) JS_LDAP_publishData( g_pLDAP, sCRLInfo.pIssuerName, JS_LDAP_TYPE_CERTIFICATE_REVOCATION_LIST, &binCRL );

    ret = 0;

end :
    JS_CC_resetIssueCRLReq( &sCRLReq );
    JS_CC_resetIssueCRLRsp( &sCRLRsp );
    JS_DB_resetCRLPolicy( &sDBPolicy );
    JS_PKI_resetCRLInfo( &sCRLInfo );
    if( pHexCRL ) JS_free( pHexCRL );
    JS_DB_resetCRL( &sDBCRL );

    JS_BIN_reset( &binCRL );

    if( pDBPolicyExtList ) JS_DB_resetPolicyExtList( &pDBPolicyExtList );
    if( pDBRevokedList ) JS_DB_resetRevokedList( &pDBRevokedList );

    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    return status;
}

int getCA( char **ppRsp )
{
    int ret = 0;
    int status = JS_HTTP_STATUS_OK;
    char    *pHex = NULL;
    JCC_NameVal sNameVal;

    memset( &sNameVal, 0x00, sizeof(sNameVal));

    JS_BIN_encodeHex( &g_binCert, &pHex );

    JS_CC_setNameVal( &sNameVal, "CACERT", pHex );
    JS_CC_encodeNameVal( &sNameVal, ppRsp );

    JS_CC_resetNameVal( &sNameVal );

    return status;
}

int publishLDAP( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int     ret = 0;
    int     status = JS_HTTP_STATUS_OK;

    JStrList    *pInfoList = NULL;
    const char  *pCmd = NULL;
    const char  *pType = NULL;
    const char  *pNum = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_REVOKED, &pInfoList );

    pCmd = JS_UTIL_valueFromNameValList( pParamList, "cmd" );
    pType = JS_UTIL_valueFromNameValList( pParamList, "type" );
    pNum = JS_UTIL_valueFromNameValList( pParamList, "num" );

    if( pCmd == NULL || pType == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    if( strcasecmp( pCmd, "publish" ) == 0 )
    {
        int nNum = -1;
        int nType = -1;
        const char *pDN = NULL;
        BIN binData = {0,0};
        JCertInfo   sCertInfo;
        JCRLInfo    sCRLInfo;

        if( pNum ) nNum = atoi( pNum );

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));
        memset( &sCRLInfo, 0x00, sizeof(sCRLInfo));

        if( strcasecmp( pType, "cacert" ) == 0 )
        {
            nType = JS_LDAP_TYPE_CA_CERTIFICATE;

            JS_BIN_copy( &binData, &g_binCert );
            JS_PKI_getCertInfo( &g_binCert, &sCertInfo, NULL );
            pDN = sCertInfo.pSubjectName;
        }
        else if( strcasecmp( pType, "crl" ) == 0 )
        {
            nType = JS_LDAP_TYPE_CERTIFICATE_REVOCATION_LIST;
            JDB_CRL sCRL;

            memset( &sCRL, 0x00, sizeof(sCRL));
            JS_DB_getCRL( db, nNum, &sCRL );

            JS_BIN_decodeHex( sCRL.pCRL, &binData );
            JS_PKI_getCRLInfo( &binData, &sCRLInfo, NULL, NULL );
            JS_DB_resetCRL( &sCRL );

            pDN = sCRLInfo.pIssuerName;
        }
        else if( strcasecmp( pType, "cert" ) == 0 )
        {
            nType = JS_LDAP_TYPE_USER_CERTIFICATE;
            JDB_Cert sCert;

            memset( &sCert, 0x00, sizeof(sCert));
            JS_DB_getCert( db, nNum, &sCert );

            JS_BIN_decodeHex( sCert.pCert, &binData );
            JS_PKI_getCertInfo( &binData, &sCertInfo, NULL );
            JS_DB_resetCert( &sCert );

            pDN = sCertInfo.pSubjectName;
        }

        if( binData.nLen > 0 )
        {
            ret = JS_LDAP_publishData( g_pLDAP, pDN, nType, &binData );
            if( ret != 0 )
            {
                ret = JS_CC_ERROR_SYSTEM;
                goto end;
            }
        }
        else
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }

        JS_PKI_resetCertInfo( &sCertInfo );
        JS_PKI_resetCRLInfo( &sCRLInfo );

        JS_BIN_reset( &binData );
    }

    ret = 0;

end :
    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );
    return status;
}
