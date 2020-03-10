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
        }
        else
        {
            ret = JS_DB_getUserList( db, &pUserList );
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

int getCount( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    JStrList    *pInfoList = NULL;
    JCC_NameVal sNameVal;
    int count = 0;
    char sValue[32];

    memset( &sNameVal, 0x00, sizeof(sNameVal));

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_COUNT, &pInfoList );
    if( pInfoList == NULL ) return -1;

    if( strcasecmp( pInfoList->pStr, "users" ) == 0 )
        count = JS_DB_getCount( db, "TB_USER" );
    else if( strcasecmp( pInfoList->pStr, "certs" ) == 0 )
        count = JS_DB_getCount( db, "TB_CERT" );
    else if( strcasecmp( pInfoList->pStr, "crls" ) == 0 )
        count = JS_DB_getCount( db, "TB_CRL" );
    else if( strcasecmp( pInfoList->pStr, "revokeds" ) == 0 )
        count = JS_DB_getCount( db, "TB_REVOKED" );

    sprintf( sValue, "%d", count );

    JS_CC_setNameVal( &sNameVal, "count", sValue );
    JS_CC_encodeNameVal( &sNameVal, ppRsp );
    JS_CC_resetNameVal( &sNameVal );

    return 0;
}

int getNum( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    JStrList    *pInfoList = NULL;
    JCC_NameVal sNameVal;
    int count = 0;
    char sValue[32];

    memset( &sNameVal, 0x00, sizeof(sNameVal));

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_COUNT, &pInfoList );
    if( pInfoList == NULL ) return -1;

    if( strcasecmp( pInfoList->pStr, "users" ) == 0 )
        count = JS_DB_getNum( db, "TB_USER" );
    else if( strcasecmp( pInfoList->pStr, "certs" ) == 0 )
        count = JS_DB_getNum( db, "TB_CERT" );
    else if( strcasecmp( pInfoList->pStr, "crls" ) == 0 )
        count = JS_DB_getNum( db, "TB_CRL" );
    else if( strcasecmp( pInfoList->pStr, "revokeds" ) == 0 )
        count = JS_DB_getNum( db, "TB_REVOKED" );

    sprintf( sValue, "%d", count );

    JS_CC_setNameVal( &sNameVal, "num", sValue );
    JS_CC_encodeNameVal( &sNameVal, ppRsp );
    JS_CC_resetNameVal( &sNameVal );

    return 0;
}

int getCertPolicies( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CERT_POLICY, &pInfoList );

    if( pInfoList == NULL )
    {
        JCC_CertPolicyList *pCertPolicyList = NULL;

        ret = JS_DB_getCertPolicyList( db, &pCertPolicyList );

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

            ret = JS_DB_getCertPolicy( db, nNum, &sCertPolicy );

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

               JS_CC_encodePolicyExtList( pPolicyExtList, ppRsp );
               if( pPolicyExtList ) JS_DB_resetPolicyExtList( &pPolicyExtList );
            }
        }
    }

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );

    return ret;
}

int getCRLPolicies( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CRL_POLICY, &pInfoList );

    if( pInfoList == NULL )
    {
        JCC_CRLPolicyList *pCRLPolicyList = NULL;

        ret = JS_DB_getCRLPolicyList( db, &pCRLPolicyList );

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

            ret = JS_DB_getCRLPolicy( db, nNum, &sCRLPolicy );

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

               JS_CC_encodePolicyExtList( pPolicyExtList, ppRsp );
               if( pPolicyExtList ) JS_DB_resetPolicyExtList( &pPolicyExtList );
            }
        }
    }

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );

    return ret;
}

int getSigners( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
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

        JS_CC_encodeSigner( &sSigner, ppRsp );

        JS_DB_resetSigner( &sSigner );
    }

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );
    return 0;
}

int getCerts( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
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
        JS_CC_encodeCert( &sCert, ppRsp );
        JS_DB_resetCert( &sCert );
    }

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );

    return ret;
}

int getCRLs( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
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
        JS_CC_encodeCRL( &sCRL, ppRsp );
        JS_DB_resetCRL( &sCRL );
    }

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );

    return ret;
}

int getRevokeds( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
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
        JS_CC_encodeRevoked( &sRevoked, ppRsp );
        JS_DB_resetRevoked( &sRevoked );
    }

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );

    return ret;
}
