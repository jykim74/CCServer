#include "js_bin.h"
#include "js_cc.h"
#include "js_bin.h"
#include "js_db.h"
#include "js_pki.h"
#include "js_pki_ext.h"
#include "js_util.h"
#include "js_http.h"
#include "js_cfg.h"
#include "js_gen.h"

#include "cc_tools.h"
#include "js_ldap.h"
#include "js_pki_tools.h"
#include "js_license.h"


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

    ret = JS_DB_getAdminByName( db, sAuthReq.pUserName, &sAdmin );
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
        JS_addAudit( db, JS_GEN_KIND_CC_SRV, JS_GEN_OP_LOGIN, NULL );
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

//    nRefNum = JS_DB_getSeq( db, "TB_USER" );
    nRefNum = JS_DB_getLastVal( db, "TB_USER" );
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
        JS_addAudit( db, JS_GEN_KIND_CC_SRV, JS_GEN_OP_REG_USER, NULL );
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

int addAdmin( sqlite3 *db, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    int     status = JS_HTTP_STATUS_OK;

    JCC_Admin  sAdmin;
    memset( &sAdmin, 0x00, sizeof(sAdmin));

    JS_CC_decodeAdmin( pReq, &sAdmin );
    if( ret != 0 ) return JS_CC_ERROR_WRONG_MSG;

    ret = JS_DB_addAdmin( db, &sAdmin );
    JS_DB_resetAdmin( &sAdmin );

    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    return status;
}

int modAdmin( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    int     nSeq = -1;
    JStrList    *pLinkList = NULL;
    JCC_Admin  sAdmin;

    memset( &sAdmin, 0x00, sizeof(sAdmin));

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_ADMIN, &pLinkList );

    if( pLinkList == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    nSeq = atoi( pLinkList->pStr );

    ret = JS_CC_decodeAdmin( pReq, &sAdmin );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_WRONG_MSG;
        goto end;
    }

    ret = JS_DB_modAdmin( db, nSeq, &sAdmin );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

end :
    JS_DB_resetAdmin( &sAdmin );
    if( pLinkList ) JS_UTIL_resetStrList( &pLinkList );

    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );


    return status;
}

int delAdmin( sqlite3 *db, const char *pPath, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_ADMIN, &pInfoList );

    if( pInfoList == NULL ) return JS_CC_ERROR_WRONG_LINK;

    int nNum = atoi( pInfoList->pStr );

    ret = JS_DB_delAdmin( db, nNum );

    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );

    return status;
}

int addLCN( sqlite3 *db, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    BIN     binLCN = {0,0};
    char    *pHexLCN = NULL;

    JCC_LCN  sLCN;
    memset( &sLCN, 0x00, sizeof(sLCN));

    JS_CC_decodeLCN( pReq, &sLCN );
    if( ret != 0 ) return JS_CC_ERROR_WRONG_MSG;

    if( sLCN.nStatus == 1 )
    {
        char sKey[128];
        JS_LICENSE_INFO sLCNInfo;

        memset( &sLCNInfo, 0x00, sizeof(sLCNInfo));
        memset( sKey, 0x00, sizeof(sKey));

        if( sLCN.pSID )
            strcpy( sLCNInfo.sSID, sLCN.pSID );
        if( sLCN.pUser )
            strcpy( sLCNInfo.sUser, sLCN.pUser );
        if( sLCN.pProductName )
            strcpy( sLCNInfo.sProduct, sLCN.pProductName );

        if( sLCN.pExtension )
            strcpy( sLCNInfo.sExt, sLCN.pExtension );

        sLCNInfo.nQTY = sLCN.nQuantity;
        strcpy( sLCNInfo.sIssued, sLCN.pIssueDate );
        strcpy( sLCNInfo.sExpire, sLCN.pExpireDate );

        JS_License_DeriveKey( sKey, &sLCNInfo );

        strcpy( sLCNInfo.sKey, sKey );

        if( sLCN.pKey )
        {
            JS_free( sLCN.pKey );
            sLCN.pKey = NULL;
        }

        sLCN.pKey = JS_strdup( sKey );

        JS_BIN_set( &binLCN, (unsigned char *)&sLCNInfo, sizeof(sLCNInfo));
        JS_BIN_encodeHex( &binLCN, &pHexLCN );

        if( sLCN.pLicense )
        {
            JS_free( sLCN.pLicense );
            sLCN.pLicense = NULL;
        }

        sLCN.pLicense = pHexLCN;
    }

    ret = JS_DB_addLCN( db, &sLCN );
end :
    JS_DB_resetLCN( &sLCN );

    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    JS_BIN_reset( &binLCN );

    return status;
}

int delLCN( sqlite3 *db, const char *pPath, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_LICENSE, &pInfoList );

    if( pInfoList == NULL ) return JS_CC_ERROR_WRONG_LINK;

    int nNum = atoi( pInfoList->pStr );

    ret = JS_DB_delLCN( db, nNum );

    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );

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

int addCertProfile( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    int     nProfileNum = -1;
    JStrList    *pLinkList = NULL;


    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CERT_PROFILE, &pLinkList );

    if( pLinkList ) nProfileNum = atoi( pLinkList->pStr );

    if( nProfileNum >= 0 )
    {
        JCC_ProfileExt   sProfileExt;
        memset( &sProfileExt, 0x00, sizeof(sProfileExt));

        ret = JS_CC_decodeProfileExt( pReq, &sProfileExt );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_WRONG_MSG;
            goto end;
        }

        ret = JS_DB_addCertProfileExt( db, &sProfileExt );
        JS_DB_resetProfileExt( &sProfileExt );
    }
    else
    {
        JCC_CertProfile sCertProfile;
        memset( &sCertProfile, 0x00, sizeof(sCertProfile));

        ret = JS_CC_decodeCertProfile( pReq, &sCertProfile );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_WRONG_MSG;
            goto end;
        }

        JS_DB_addCertProfile( db, &sCertProfile );
        JS_DB_resetCertProfile( &sCertProfile );
    }

end :
    if( pLinkList ) JS_UTIL_resetStrList( &pLinkList );

    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    return status;
}

int addCRLProfile( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    int     nProfileNum = -1;
    JStrList    *pLinkList = NULL;


    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CRL_PROFILE, &pLinkList );

    if( pLinkList ) nProfileNum = atoi( pLinkList->pStr );

    if( nProfileNum >= 0 )
    {
        JCC_ProfileExt   sProfileExt;
        memset( &sProfileExt, 0x00, sizeof(sProfileExt));

        ret = JS_CC_decodeProfileExt( pReq, &sProfileExt );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_WRONG_MSG;
            goto end;
        }

        ret = JS_DB_addCRLProfileExt( db, &sProfileExt );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_SYSTEM;
            goto end;
        }

        JS_DB_resetProfileExt( &sProfileExt );
    }
    else
    {
        JCC_CRLProfile sCRLProfile;
        memset( &sCRLProfile, 0x00, sizeof(sCRLProfile));

        ret = JS_CC_decodeCRLProfile( pReq, &sCRLProfile );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_WRONG_MSG;
            goto end;
        }

        ret = JS_DB_addCRLProfile( db, &sCRLProfile );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_SYSTEM;
            goto end;
        }

        JS_DB_resetCRLProfile( &sCRLProfile );
    }

    if( pLinkList ) JS_UTIL_resetStrList( &pLinkList );

end :
    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    return status;
}

int modCertProfile( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    int     nProfileNum = -1;
    JStrList    *pLinkList = NULL;
    JCC_CertProfile  sCertProfile;

    memset( &sCertProfile, 0x00, sizeof(sCertProfile));

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CERT_PROFILE, &pLinkList );

    if( pLinkList == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    nProfileNum = atoi( pLinkList->pStr );

    ret = JS_CC_decodeCertProfile( pReq, &sCertProfile );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_WRONG_MSG;
        goto end;
    }

    ret = JS_DB_modCertPolcy( db, nProfileNum, &sCertProfile );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

end :
    JS_DB_resetCertProfile( &sCertProfile );
    if( pLinkList ) JS_UTIL_resetStrList( &pLinkList );

    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );


    return status;
}

int modCRLProfile( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    int     nProfileNum = -1;
    JStrList    *pLinkList = NULL;

    JCC_CRLProfile   sCRLProfile;

    memset( &sCRLProfile, 0x00, sizeof(sCRLProfile));

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CRL_PROFILE, &pLinkList );

    if( pLinkList == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    nProfileNum = atoi( pLinkList->pStr );

    ret = JS_CC_decodeCRLProfile( pReq, &sCRLProfile );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_WRONG_MSG;
        goto end;
    }

    ret = JS_DB_modCRLProfile( db, nProfileNum, &sCRLProfile );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_BASE;
        goto end;
    }

end :
    JS_DB_resetCRLProfile( &sCRLProfile );

    if( pLinkList ) JS_UTIL_resetStrList( &pLinkList );
    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    return status;
}

int getAdmins( sqlite3 *db, const char *pPath, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_ADMIN, &pInfoList );

    if( pInfoList == NULL )
    {
        JDB_AdminList *pAdminList = NULL;

        ret = JS_DB_getAdminList( db, &pAdminList );
        if( ret < 1 )
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }

        JS_CC_encodeAdminList( pAdminList, ppRsp );
        if( pAdminList ) JS_DB_resetAdminList( &pAdminList );
    }
    else
    {
        JDB_Admin sAdmin;
        memset( &sAdmin, 0x00, sizeof(sAdmin));
        int nSeq = atoi( pInfoList->pStr );

        ret = JS_DB_getAdmin( db, nSeq, &sAdmin );
        if( ret < 1 )
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }

        JS_CC_encodeAdmin( &sAdmin, ppRsp );
        JS_DB_resetAdmin( &sAdmin );
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

int getUser( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
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
            const char *pTarget = NULL;
            const char *pWord = NULL;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "offset" );
            if( pValue ) nOffset = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "limit" );
            if( pValue ) nLimit = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "target" );
            if( pValue ) pTarget = pValue;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "word" );
            if( pValue ) pWord = pValue;

            if( pTarget == NULL || pWord == NULL )
                ret = JS_DB_getUserPageList( db, nOffset, nLimit, &pUserList );
            else
                ret = JS_DB_searchUserPageList( db, pTarget, pWord, nOffset, nLimit, &pUserList );

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

int modUser( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    int     nSeq = -1;
    JStrList    *pLinkList = NULL;
    JCC_User  sUser;

    memset( &sUser, 0x00, sizeof(sUser));

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_USER, &pLinkList );

    if( pLinkList == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    nSeq = atoi( pLinkList->pStr );

    ret = JS_CC_decodeUser( pReq, &sUser );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_WRONG_MSG;
        goto end;
    }

    ret = JS_DB_modUser( db, nSeq, &sUser );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

end :
    JS_DB_resetUser( &sUser );
    if( pLinkList ) JS_UTIL_resetStrList( &pLinkList );

    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );


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
    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );

    return status;
}

int delCertProfile( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pLinkList = NULL;
    int nProfileNum = -1;
    int bExtOnly = 0;


    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CERT_PROFILE, &pLinkList );

    if( pLinkList == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    nProfileNum = atoi( pLinkList->pStr );

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
        ret = JS_DB_delCertProfileExtsByProfileNum( db, nProfileNum );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_SYSTEM;
            goto end;
        }
    }
    else
    {
        ret = JS_DB_delCertProfile( db, nProfileNum );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_SYSTEM;
            goto end;
        }

        ret = JS_DB_delCertProfileExtsByProfileNum( db, nProfileNum );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_SYSTEM;
            goto end;
        }
    }

end :
    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    if( pLinkList ) JS_UTIL_resetStrList( &pLinkList );

    return status;
}

int delCRLProfile( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pLinkList = NULL;
    int nProfileNum = -1;
    int bExtOnly = 0;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CRL_PROFILE, &pLinkList );

    if( pLinkList == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    nProfileNum = atoi( pLinkList->pStr );

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
        ret = JS_DB_delCRLProfileExtsByProfileNum( db, nProfileNum );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_SYSTEM;
            goto end;
        }
    }
    else
    {
        ret = JS_DB_delCRLProfile( db, nProfileNum );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_SYSTEM;
            goto end;
        }

        ret = JS_DB_delCRLProfileExtsByProfileNum( db, nProfileNum );
        if( ret != 0 )
        {
            ret = JS_CC_ERROR_SYSTEM;
            goto end;
        }
    }

end :
    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    if( pLinkList ) JS_UTIL_resetStrList( &pLinkList );

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

    if( pParamList )
    {
        const char *pValue = NULL;
        const char *pTarget = NULL;
        const char *pWord = NULL;

        pValue = JS_UTIL_valueFromNameValList( pParamList, "target" );
        if( pValue ) pTarget = pValue;

        pValue = JS_UTIL_valueFromNameValList( pParamList, "word" );
        if( pValue ) pWord = pValue;

        count = JS_DB_searchCount( db, pTarget, pWord, JS_DB_getTableName( pInfoList->pStr ) );
    }
    else
    {
        count = JS_DB_getCount( db, JS_DB_getTableName( pInfoList->pStr ));
    }

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
    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );

    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    return status;
}

int getNum( sqlite3 *db, const char *pPath, char **ppRsp )
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

    num = JS_DB_getNum( db, JS_DB_getTableName( pInfoList->pStr ));

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
    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );

    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    return status;
}

int getName( sqlite3 *db, const char *pPath, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;
    JCC_NameVal sNameVal;
    char *pName = NULL;
    char sColName[128];
    char sTableName[128];
    int nNum = 0;

    memset( &sNameVal, 0x00, sizeof(sNameVal));

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_NAME, &pInfoList );
    if( pInfoList == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    if( JS_UTIL_countStrList( pInfoList ) < 2 )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    sprintf( sTableName, "%s", JS_DB_getTableName( pInfoList->pStr ) );
    sprintf( sColName, "%s", JS_DB_getIndexColumn( sTableName ) );
    nNum = atoi( pInfoList->pNext->pStr );

    ret = JS_DB_getName( db, sColName, nNum, sTableName, &pName );
    if( ret < 1 )
    {
        ret = JS_CC_ERROR_NO_DATA;
        goto end;
    }

    JS_CC_setNameVal( &sNameVal, "name", pName );
    JS_CC_encodeNameVal( &sNameVal, ppRsp );
    JS_CC_resetNameVal( &sNameVal );

    ret = 0;

end :
    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );
    if( pName ) JS_free( pName );
    return status;
}

int getDN( sqlite3 *db, const char *pPath, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;
    JCC_NameVal sNameVal;
    char *pDN = NULL;
    int nCertNum = 0;

    memset( &sNameVal, 0x00, sizeof(sNameVal));

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_DN, &pInfoList );
    if( pInfoList == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    if( JS_UTIL_countStrList( pInfoList ) < 1 )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    nCertNum = atoi( pInfoList->pStr );

    ret = JS_DB_getCertDN( db, nCertNum, &pDN );
    if( ret < 1 )
    {
        ret = JS_CC_ERROR_NO_DATA;
        goto end;
    }

    JS_CC_setNameVal( &sNameVal, "dn", pDN );
    JS_CC_encodeNameVal( &sNameVal, ppRsp );
    JS_CC_resetNameVal( &sNameVal );
    ret = 0;

end :
    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );
    if( pDN ) JS_free( pDN );
    return status;
}

int getCertPolicies( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CERT_PROFILE, &pInfoList );

    if( pInfoList == NULL )
    {
        JCC_CertProfileList *pCertProfileList = NULL;

        ret = JS_DB_getCertProfileList( db, &pCertProfileList );
        if( ret < 1 )
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }

        JS_CC_encodeCertProfileList( pCertProfileList, ppRsp );
        if( pCertProfileList ) JS_DB_resetCertProfileList( &pCertProfileList );
    }
    else
    {
        int nInfoCnt = JS_UTIL_countStrList( pInfoList );

        if( nInfoCnt == 1 )
        {
            JCC_CertProfile sCertProfile;
            memset( &sCertProfile, 0x00, sizeof(sCertProfile));

            int nNum = atoi( pInfoList->pStr );
            if( nNum < 0 )
            {
                ret = JS_CC_ERROR_SYSTEM;
                goto end;
            }

            ret = JS_DB_getCertProfile( db, nNum, &sCertProfile );
            if( ret < 1 )
            {
                ret = JS_CC_ERROR_NO_DATA;
                goto end;
            }

            JS_CC_encodeCertProfile( &sCertProfile, ppRsp );
            JS_DB_resetCertProfile( &sCertProfile );
        }
        else if( nInfoCnt == 2 )
        {
            int nProfileNum = atoi( pInfoList->pStr );

            if( strcasecmp( pInfoList->pNext->pStr, "extensions" ) == 0 )
            {
               JCC_ProfileExtList *pProfileExtList = NULL;

               ret = JS_DB_getCertProfileExtList( db, nProfileNum, &pProfileExtList );
               if( ret < 1 )
               {
                   ret = JS_CC_ERROR_NO_DATA;
                   goto end;
               }

               JS_CC_encodeProfileExtList( pProfileExtList, ppRsp );
               if( pProfileExtList ) JS_DB_resetProfileExtList( &pProfileExtList );
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

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CRL_PROFILE, &pInfoList );

    if( pInfoList == NULL )
    {
        JCC_CRLProfileList *pCRLProfileList = NULL;

        ret = JS_DB_getCRLProfileList( db, &pCRLProfileList );
        if( ret < 1 )
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }

        JS_CC_encodeCRLProfileList( pCRLProfileList, ppRsp );
        if( pCRLProfileList ) JS_DB_resetCRLProfileList( &pCRLProfileList );
    }
    else
    {
        int nInfoCnt = JS_UTIL_countStrList( pInfoList );

        if( nInfoCnt == 1 )
        {
            JCC_CRLProfile sCRLProfile;
            memset( &sCRLProfile, 0x00, sizeof(sCRLProfile));

            int nNum = atoi( pInfoList->pStr );
            if( nNum < 0 )
            {
                ret = JS_CC_ERROR_WRONG_LINK;
                goto end;
            }

            ret = JS_DB_getCRLProfile( db, nNum, &sCRLProfile );
            if( ret < 1 )
            {
                ret = JS_CC_ERROR_NO_DATA;
                goto end;
            }

            JS_CC_encodeCRLProfile( &sCRLProfile, ppRsp );
            JS_DB_resetCRLProfile( &sCRLProfile );
        }
        else if( nInfoCnt == 2 )
        {
            int nProfileNum = atoi( pInfoList->pStr );

            if( strcasecmp( pInfoList->pNext->pStr, "extensions" ) == 0 )
            {
               JCC_ProfileExtList *pProfileExtList = NULL;

               ret = JS_DB_getCRLProfileExtList( db, nProfileNum, &pProfileExtList );
               if( ret < 1 )
               {
                   ret = JS_CC_ERROR_NO_DATA;
                   goto end;
               }

               JS_CC_encodeProfileExtList( pProfileExtList, ppRsp );
               if( pProfileExtList ) JS_DB_resetProfileExtList( &pProfileExtList );
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
            const char *pTarget = NULL;
            const char *pWord = NULL;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "offset" );
            if( pValue ) nOffset = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "limit" );
            if( pValue ) nLimit = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "target" );
            if( pValue ) pTarget = pValue;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "word" );
            if( pValue ) pWord = pValue;

            if( pWord == NULL || pTarget == NULL )
                ret = JS_DB_getCertPageList( db, nOffset, nLimit, &pCertList );
            else
                ret = JS_DB_searchCertPageList( db, pTarget, pWord, nOffset, nLimit, &pCertList );

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
            const char *pTarget = NULL;
            const char *pWord = NULL;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "offset" );
            if( pValue ) nOffset = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "limit" );
            if( pValue ) nLimit = atoi( pValue );


            pValue = JS_UTIL_valueFromNameValList( pParamList, "target" );
            if( pValue ) pTarget = pValue;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "word" );
            if( pValue ) pWord = pValue;

            if( pTarget == NULL || pWord == NULL )
                ret = JS_DB_getCRLPageList( db, nOffset, nLimit, &pCRLList );
            else
                ret = JS_DB_searchCRLPageList( db, pTarget, pWord, nOffset, nLimit, &pCRLList );

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
            const char *pTarget = NULL;
            const char *pWord = NULL;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "offset" );
            if( pValue ) nOffset = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "limit" );
            if( pValue ) nLimit = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "target" );
            if( pValue ) pTarget = pValue;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "word" );
            if( pValue ) pWord = pValue;

            if( pTarget == NULL || pWord == NULL )
                ret = JS_DB_getRevokedPageList( db, nOffset, nLimit, &pRevokedList );
            else
                ret = JS_DB_searchRevokedPageList( db, pTarget, pWord, nOffset, nLimit, &pRevokedList );

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

int _getReplaceValue( const char *pDNTemplate, JDB_User *pDBUser, char **ppRealDN )
{
    int ret = 0;
    JNameValList    *pNameValList = NULL;

    if( pDBUser == NULL || pDNTemplate == NULL ) return -1;

    JS_UTIL_createNameValList2( JS_PKI_TEMPLATE_NAME, pDBUser->pName, &pNameValList );
    JS_UTIL_appendNameValList2( pNameValList, JS_PKI_TEMPLATE_EMAIL, pDBUser->pEmail );
    JS_UTIL_appendNameValList2( pNameValList, JS_PKI_TEMPLATE_SSN, pDBUser->pSSN );

    ret = JS_PKI_getReplacedDN( pDNTemplate, pNameValList, ppRealDN );

    if( pNameValList ) JS_UTIL_resetNameValList( &pNameValList );

    return ret;
}

int issueCert( sqlite3 *db, const char *pReq, char **ppRsp )
{
    int ret = 0;
    int status = JS_HTTP_STATUS_OK;
    int nProfileNum = -1;
    int nUserNum = -1;

    JCC_IssueCertReq    sIssueCertReq;
    JCC_IssueCertRsp    sIssueCertRsp;
    JDB_CertProfile      sCertProfile;
    JDB_ProfileExtList   *pProfileExtList = NULL;
    JDB_ProfileExtList   *pCurProfileExtList = NULL;
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
	BIN					binPubVal = {0,0};

    char                sSerial[32];
    long                uNotBefore = 0;
    long                uNotAfter = 0;
    char                *pHexCert = NULL;
    char                *pHexCACert = NULL;
    char                sKeyID[128];
    char                *pRealDN = NULL;

    time_t now_t = time(NULL);

    memset( &sIssueCertReq, 0x00, sizeof(sIssueCertReq));
    memset( &sIssueCertRsp, 0x00, sizeof(sIssueCertRsp));
    memset( &sCertProfile, 0x00, sizeof(sCertProfile));
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

    nProfileNum = sIssueCertReq.nCertProfileNum;

    ret = JS_DB_getCertProfile( db, nProfileNum, &sCertProfile );
    if( ret != 1 )
    {
        ret = JS_CC_ERROR_NO_DATA;
        goto end;
    }

    JS_DB_getCertProfileExtList( db, nProfileNum, &pProfileExtList );

    JS_BIN_decodeHex( sIssueCertReq.pCSR, &binCSR );
    ret = JS_PKI_getReqInfo( &binCSR, &sReqInfo, NULL );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }


    JS_BIN_decodeHex( sReqInfo.pPublicKey, &binPub );
	JS_PKI_getPublicKeyValue( &binPub, &binPubVal );
    JS_PKI_getKeyIdentifier( &binPubVal, sKeyID );

    if( sCertProfile.nNotBefore <= 0 )
    {
        uNotBefore = 0;
        uNotAfter = sCertProfile.nNotAfter * 60 * 60 * 24;
    }
    else
    {
        uNotBefore = sCertProfile.nNotBefore - now_t;
        uNotAfter = sCertProfile.nNotAfter - now_t;
    }

//    int nSeq = JS_DB_getSeq( db, "TB_CERT" );
    int nSeq = JS_DB_getNextVal( db, "TB_CERT" );
    sprintf( sSerial, "%d", nSeq );

    if( strcasecmp( sCertProfile.pDNTemplate, "#CSR") == 0 )
    {
        pRealDN = JS_strdup( sReqInfo.pSubjectDN );
    }
    else
    {
        _getReplaceValue( sCertProfile.pDNTemplate, &sUser, &pRealDN );
    }

    pCurProfileExtList = pProfileExtList;

    while( pCurProfileExtList )
    {
        JExtensionInfo sExtInfo;

        memset( &sExtInfo,0x00, sizeof(sExtInfo));


        if( strcasecmp( pCurProfileExtList->sProfileExt.pSN, JS_PKI_ExtNameSKI ) == 0 )
        {
            BIN binPub = {0,0};
            char    sHexID[128];

            memset( sHexID, 0x00, sizeof(sHexID));
            JS_BIN_decodeHex(sReqInfo.pPublicKey, &binPub);
            JS_PKI_getKeyIdentifier( &binPub, sHexID );

            if( pCurProfileExtList->sProfileExt.pValue )
            {
                JS_free( pCurProfileExtList->sProfileExt.pValue );
                pCurProfileExtList->sProfileExt.pValue = NULL;
            }

            pCurProfileExtList->sProfileExt.pValue = JS_strdup( sHexID );
            JS_BIN_reset( &binPub );
        }
        else if( strcasecmp( pCurProfileExtList->sProfileExt.pSN, JS_PKI_ExtNameAKI ) == 0 )
        {
            char    sHexID[128];
            char    sHexSerial[128];
            char    sHexIssuer[1024];

            char    sBuf[2048];

            memset( sHexID, 0x00, sizeof(sHexID));
            memset( sHexSerial, 0x00, sizeof(sHexSerial));
            memset( sHexIssuer, 0x00, sizeof(sHexIssuer));
            memset( sBuf, 0x00, sizeof(sBuf));

            JS_PKI_getAuthorityKeyIdentifier( &g_binCert, sHexID, sHexSerial, sHexIssuer );
            sprintf( sBuf, "KEYID$%s#ISSUER$%s#SERIAL$%s", sHexID, sHexIssuer, sHexSerial );
            if( pCurProfileExtList->sProfileExt.pValue )
            {
                JS_free( pCurProfileExtList->sProfileExt.pValue );
                pCurProfileExtList->sProfileExt.pValue = NULL;
            }

            pCurProfileExtList->sProfileExt.pValue = JS_strdup( sBuf );
        }
        else if( strcasecmp( pCurProfileExtList->sProfileExt.pSN, JS_PKI_ExtNameCRLDP) == 0 )
        {
            char *pDP = NULL;
            JS_PKI_getDP( pCurProfileExtList->sProfileExt.pValue, nSeq, &pDP );
            if( pDP )
            {
                if( pCurProfileExtList->sProfileExt.pValue ) JS_free( pCurProfileExtList->sProfileExt.pValue );
                pCurProfileExtList->sProfileExt.pValue = pDP;
            }
        }
        else if( strcasecmp( pCurProfileExtList->sProfileExt.pSN, JS_PKI_ExtNameSAN ) == 0 )
        {
            char *pReplaced = NULL;
            _getReplaceValue( pCurProfileExtList->sProfileExt.pValue, &sUser, &pReplaced );

            if( pReplaced )
            {
                if( pCurProfileExtList->sProfileExt.pValue )
                    JS_free( pCurProfileExtList->sProfileExt.pValue );

                pCurProfileExtList->sProfileExt.pValue = pReplaced;
            }
        }

        pCurProfileExtList = pCurProfileExtList->pNext;
    }

    JS_PKI_setIssueCertInfo( &sIssueCertInfo,
                             sCertProfile.nVersion,
                             sSerial,
                             sCertProfile.pHash,
                             pRealDN,
                             uNotBefore,
                             uNotAfter,
                             sReqInfo.nKeyAlg,
                             sReqInfo.pPublicKey );

    ret = makeCert( &sCertProfile, pProfileExtList, &sIssueCertInfo, &binCert );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

    JS_BIN_encodeHex( &binCert, &pHexCert );
    JS_BIN_encodeHex( &g_binCert, &pHexCACert );

    if( nUserNum < 0 )
    {
//        nUserNum = JS_DB_getSeq( db, "TB_USER" );
        nUserNum = JS_DB_getLastVal( db, "TB_USER" );
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
                   nSeq,
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
    JS_addAudit( db, JS_GEN_KIND_CC_SRV, JS_GEN_OP_GEN_CERT, NULL );

end:
    JS_CC_resetIssueCertReq( &sIssueCertReq );
    JS_CC_resetIssueCertRsp( &sIssueCertRsp );
    JS_DB_resetCertProfile( &sCertProfile );
    if( pProfileExtList ) JS_DB_resetProfileExtList( &pProfileExtList );
    JS_DB_resetUser( &sUser );
    JS_PKI_resetReqInfo( &sReqInfo );
    JS_PKI_resetIssueCertInfo( &sIssueCertInfo );
    JS_BIN_reset( &binCert );
    if( pHexCert ) JS_free( pHexCert );
    if( pHexCACert ) JS_free( pHexCACert );
    JS_DB_resetCert( &sCert );
    JS_BIN_reset( &binPub );
	JS_BIN_reset( &binPubVal );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );
    if( pCRLDP ) JS_free( pCRLDP );
    if( pHexCRLDP ) JS_free( pHexCRLDP );
    if( pRealDN ) JS_free( pRealDN );

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

    JDB_CRLProfile       sDBProfile;
    JDB_ProfileExtList   *pDBProfileExtList = NULL;
    JDB_ProfileExtList   *pDBCurExtList = NULL;
    JDB_RevokedList     *pDBRevokedList = NULL;
    JDB_CRL             sDBCRL;

    BIN     binCRL = {0,0};
    char    *pHexCRL = NULL;
    JCRLInfo            sCRLInfo;
    time_t now_t = time(NULL);

    memset( &sCRLReq, 0x00, sizeof(sCRLReq));
    memset( &sCRLRsp, 0x00, sizeof(sCRLRsp));
    memset( &sDBProfile, 0x00, sizeof(sDBProfile));
    memset( &sCRLInfo, 0x00, sizeof(sCRLInfo));
    memset( &sDBCRL, 0x00, sizeof(sDBCRL));

    ret = JS_CC_decodeIssueCRLReq( pReq, &sCRLReq );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_WRONG_MSG;
        goto end;
    }

    ret = JS_DB_getCRLProfile( db, sCRLReq.nCRLProfileNum, &sDBProfile );
    if( ret != 1 )
    {
        ret = JS_CC_ERROR_NO_DATA;
        goto end;
    }

    ret = JS_DB_getCRLProfileExtList( db, sCRLReq.nCRLProfileNum, &pDBProfileExtList );
    if( ret < 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

    pDBCurExtList = pDBProfileExtList;
//    int nSeq = JS_DB_getSeq( db, "TB_CRL" );
//    nSeq++;

    int nSeq = JS_DB_getLastVal( db, "TB_CRL" );

    while( pDBCurExtList )
    {
        if( strcasecmp( pDBCurExtList->sProfileExt.pSN, JS_PKI_ExtNameAKI ) == 0 )
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
            if( pDBCurExtList->sProfileExt.pValue )
            {
                JS_free( pDBCurExtList->sProfileExt.pValue );
            }

            pDBCurExtList->sProfileExt.pValue = pValue;
        }
        else if( strcasecmp( pDBCurExtList->sProfileExt.pSN, JS_PKI_ExtNameCRLNum ) == 0 )
        {
            if( strcasecmp( pDBCurExtList->sProfileExt.pValue, "auto") == 0 )
            {
                char *pValue = NULL;
                pValue = (char *)JS_malloc( 32 );
                sprintf( pValue, "%04x", nSeq );
                JS_free( pDBCurExtList->sProfileExt.pValue );
                pDBCurExtList->sProfileExt.pValue = pValue;
            }
        }

        pDBCurExtList = pDBCurExtList->pNext;
    }

//    ret = JS_DB_getRevokedList( db, &pDBRevokedList );
    ret = JS_DB_getRevokedListByCRLDP( db, sCRLReq.pCRLDP, &pDBRevokedList );
    if( ret < 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

    ret = makeCRL( &sDBProfile, pDBProfileExtList, pDBRevokedList, &binCRL );
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

    JS_DB_setCRL( &sDBCRL, nSeq, now_t, -1, sCRLInfo.pSignAlgorithm, sCRLReq.pCRLDP, pHexCRL );

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
    JS_addAudit( db, JS_GEN_KIND_CC_SRV, JS_GEN_OP_GEN_CRL, NULL );

end :
    JS_CC_resetIssueCRLReq( &sCRLReq );
    JS_CC_resetIssueCRLRsp( &sCRLRsp );
    JS_DB_resetCRLProfile( &sDBProfile );
    JS_PKI_resetCRLInfo( &sCRLInfo );
    if( pHexCRL ) JS_free( pHexCRL );
    JS_DB_resetCRL( &sDBCRL );

    JS_BIN_reset( &binCRL );

    if( pDBProfileExtList ) JS_DB_resetProfileExtList( &pDBProfileExtList );
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

    if( g_pLDAP == NULL )
    {
        return JS_HTTP_STATUS_METHOD_NOT_ALLOWED;
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

int getCRDPs( sqlite3 *db, char **ppRsp )
{
    int ret = 0;
    int status = JS_HTTP_STATUS_OK;
    JStrList    *pCRLDPList = NULL;
    JStrList    *pCurList = NULL;
    JNameValList    *pNameValList = NULL;

    ret = JS_DB_getCRLDPListFromCert( db, &pCRLDPList );
    if( ret < 1 )
    {
        ret = JS_CC_ERROR_NO_DATA;
        goto end;
    }

    pCurList = pCRLDPList;
    while( pCurList )
    {
        JNameVal    sNameVal;

        if( pNameValList == NULL )
            JS_UTIL_createNameValList2( "CRLDP", pCurList->pStr, &pNameValList );
        else
            JS_UTIL_appendNameValList2( pNameValList, "CRLDP", pCurList->pStr );

        pCurList = pCurList->pNext;
    }

    JS_CC_encodeNameValList( pNameValList, ppRsp );
    ret = 0;

end :
    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    if( pCRLDPList ) JS_UTIL_resetStrList( &pCRLDPList );

    return status;
}

int getCertStatus( sqlite3 *db, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int status = JS_HTTP_STATUS_OK;
    JDB_Cert    sDBCert;
    JCC_CertStatus  sCertStatus;

    memset( &sDBCert, 0x00, sizeof(sDBCert));
    memset( &sCertStatus, 0x00, sizeof(sCertStatus));

    if( pParamList == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    const char *pSerial = JS_UTIL_valueFromNameValList( pParamList, "serial" );
    if( pSerial == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    ret = JS_DB_getCertBySerial( db, pSerial, &sDBCert );
    if( ret != 1 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

    if( sDBCert.nStatus > 0 )
    {
        JDB_Revoked sDBRevoked;
        memset( &sDBRevoked, 0x00, sizeof(sDBRevoked));

        ret = JS_DB_getRevokedByCertNum( db, sDBCert.nNum, &sDBRevoked );
        if( ret != 1 )
        {
            ret = JS_CC_ERROR_SYSTEM;
            goto end;
        }

        JS_CC_setCertStatus( &sCertStatus,
                             sDBCert.nStatus,
                             sDBRevoked.nReason,
                             sDBRevoked.nRevokedDate );
    }
    else
    {
        JS_CC_setCertStatus( &sCertStatus, 0, -1, -1 );
    }

    JS_CC_encodeCertStatus( &sCertStatus, ppRsp );
    ret = 0;

end :
    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }


    return status;
}

int getKMS( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int status = JS_HTTP_STATUS_OK;
    JStrList *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_KMS, &pInfoList );

    if( pInfoList == NULL )
    {
        JDB_KMSList *pKMSList = NULL;

        if( pParamList )
        {
            const char *pValue = NULL;
            int nOffset = 0;
            int nLimit = 0;
            const char *pTarget = NULL;
            const char *pWord = NULL;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "offset" );
            if( pValue ) nOffset = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "limit" );
            if( pValue ) nLimit = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "target" );
            if( pValue ) pTarget = pValue;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "word" );
            if( pValue ) pWord = pValue;

            if( pTarget == NULL || pWord == NULL )
                ret = JS_DB_getKMSPageList( db, nOffset, nLimit, &pKMSList );
            else
                ret = JS_DB_searchKMSPageList( db, pTarget, pWord, nOffset, nLimit, &pKMSList );

            if( ret < 1 )
            {
                ret = JS_CC_ERROR_NO_DATA;
                goto end;
            }
        }

        JS_CC_encodeKMSList( pKMSList, ppRsp );
        if( pKMSList ) JS_DB_resetKMSList( &pKMSList );
    }
    else
    {
        JDB_KMS sKMS;
        memset( &sKMS, 0x00, sizeof(sKMS));
        int nSeq = atoi( pInfoList->pStr );

        ret = JS_DB_getKMS( db, nSeq, &sKMS );
        if( ret < 1 )
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }

        JS_CC_encodeKMS( &sKMS, ppRsp );
        JS_DB_resetKMS( &sKMS );
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

int getTSP( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int status = JS_HTTP_STATUS_OK;
    JStrList *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_TSP, &pInfoList );

    if( pInfoList == NULL )
    {
        JDB_TSPList *pTSPList = NULL;

        if( pParamList )
        {
            const char *pValue = NULL;
            int nOffset = 0;
            int nLimit = 0;
            const char *pTarget = NULL;
            const char *pWord = NULL;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "offset" );
            if( pValue ) nOffset = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "limit" );
            if( pValue ) nLimit = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "target" );
            if( pValue ) pTarget = pValue;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "word" );
            if( pValue ) pWord = pValue;

            if( pTarget == NULL || pWord == NULL )
                ret = JS_DB_getTSPPageList( db, nOffset, nLimit, &pTSPList );
            else
                ret = JS_DB_searchTSPPageList( db, pTarget, pWord, nOffset, nLimit, &pTSPList );

            if( ret < 1 )
            {
                ret = JS_CC_ERROR_NO_DATA;
                goto end;
            }
        }

        JS_CC_encodeTSPList( pTSPList, ppRsp );
        if( pTSPList ) JS_DB_resetTSPList( &pTSPList );
    }
    else
    {
        JDB_TSP sTSP;
        memset( &sTSP, 0x00, sizeof(sTSP));
        int nSeq = atoi( pInfoList->pStr );

        ret = JS_DB_getTSP( db, nSeq, &sTSP );
        if( ret < 1 )
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }

        JS_CC_encodeTSP( &sTSP, ppRsp );
        JS_DB_resetTSP( &sTSP );
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

int getLCN( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int status = JS_HTTP_STATUS_OK;
    JStrList *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_LICENSE, &pInfoList );

    if( pInfoList == NULL )
    {
        JDB_LCNList *pLCNList = NULL;

        if( pParamList )
        {
            const char *pValue = NULL;
            int nOffset = 0;
            int nLimit = 0;
            const char *pTarget = NULL;
            const char *pWord = NULL;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "offset" );
            if( pValue ) nOffset = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "limit" );
            if( pValue ) nLimit = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "target" );
            if( pValue ) pTarget = pValue;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "word" );
            if( pValue ) pWord = pValue;

            if( pTarget == NULL || pWord == NULL )
                ret = JS_DB_getLCNPageList( db, nOffset, nLimit, &pLCNList );
            else
                ret = JS_DB_searchLCNPageList( db, pTarget, pWord, nOffset, nLimit, &pLCNList );

            if( ret < 1 )
            {
                ret = JS_CC_ERROR_NO_DATA;
                goto end;
            }
        }

        JS_CC_encodeLCNList( pLCNList, ppRsp );
        if( pLCNList ) JS_DB_resetLCNList( &pLCNList );
    }
    else
    {
        JDB_LCN sLCN;
        memset( &sLCN, 0x00, sizeof(sLCN));
        int nSeq = atoi( pInfoList->pStr );

        ret = JS_DB_getLCN( db, nSeq, &sLCN );
        if( ret < 1 )
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }

        JS_CC_encodeLCN( &sLCN, ppRsp );
        JS_DB_resetLCN( &sLCN );
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

int getStatistics( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;
    JCC_NameVal sNameVal;
    int count = 0;
    int start = -1;
    int end = -1;
    char* pTable = NULL;
    char sValue[32];

    memset( &sNameVal, 0x00, sizeof(sNameVal));
    memset( sValue, 0x00, sizeof(sValue));

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_STATISTICS, &pInfoList );
    if( pInfoList == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    int len = strlen( pInfoList->pStr );
    pTable = (char *)JS_calloc( len + 1, 1);
    sprintf( pTable, "%s", pInfoList->pStr );

    if( pParamList )
    {
        const char *pValue = NULL;

        pValue = JS_UTIL_valueFromNameValList( pParamList, "start" );
        if( pValue ) start = atoi( pValue );

        pValue = JS_UTIL_valueFromNameValList( pParamList, "end" );
        if( pValue ) end = atoi( pValue );
    }

    count = JS_DB_getStatisticsCount( db, start, end, pTable );

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
    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );

    if( ret != 0 )
    {
        status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
        _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );
    }

    if( pTable ) JS_free( pTable );

    return status;
}

int getAudit( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    int status = JS_HTTP_STATUS_OK;
    JStrList *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_AUDIT, &pInfoList );

    if( pInfoList == NULL )
    {
        JDB_AuditList *pAuditList = NULL;

        if( pParamList )
        {
            const char *pValue = NULL;
            int nOffset = 0;
            int nLimit = 0;
            const char *pTarget = NULL;
            const char *pWord = NULL;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "offset" );
            if( pValue ) nOffset = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "limit" );
            if( pValue ) nLimit = atoi( pValue );

            pValue = JS_UTIL_valueFromNameValList( pParamList, "target" );
            if( pValue ) pTarget = pValue;

            pValue = JS_UTIL_valueFromNameValList( pParamList, "word" );
            if( pValue ) pWord = pValue;

            if( pTarget == NULL || pWord == NULL )
                ret = JS_DB_getAuditPageList( db, nOffset, nLimit, &pAuditList );
            else
                ret = JS_DB_searchAuditPageList( db, pTarget, pWord, nOffset, nLimit, &pAuditList );

            if( ret < 1 )
            {
                ret = JS_CC_ERROR_NO_DATA;
                goto end;
            }
        }

        JS_CC_encodeAuditList( pAuditList, ppRsp );
        if( pAuditList ) JS_DB_resetAuditList( &pAuditList );
    }
    else
    {
        JDB_Audit sAudit;
        memset( &sAudit, 0x00, sizeof(sAudit));
        int nSeq = atoi( pInfoList->pStr );

        ret = JS_DB_getAudit( db, nSeq, &sAudit );
        if( ret < 1 )
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }

        JS_CC_encodeAudit( &sAudit, ppRsp );
        JS_DB_resetAudit( &sAudit );
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

int addConfig( sqlite3 *db, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    int     status = JS_HTTP_STATUS_OK;

    JCC_Config  sConfig;
    memset( &sConfig, 0x00, sizeof(sConfig));

    JS_CC_decodeConfig( pReq, &sConfig );
    if( ret != 0 ) return JS_CC_ERROR_WRONG_MSG;

    ret = JS_DB_addConfig( db, &sConfig );
    JS_DB_resetConfig( &sConfig );

    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    return status;
}

int getConfigs( sqlite3 *db, const char *pPath, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CONFIG, &pInfoList );

    if( pInfoList == NULL )
    {
        JDB_ConfigList *pConfigList = NULL;

        ret = JS_DB_getConfigList( db, &pConfigList );
        if( ret < 1 )
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }

        JS_CC_encodeConfigList( pConfigList, ppRsp );
        if( pConfigList ) JS_DB_resetConfigList( &pConfigList );
    }
    else
    {
        JDB_Config sConfig;
        memset( &sConfig, 0x00, sizeof(sConfig));
        int nSeq = atoi( pInfoList->pStr );

        ret = JS_DB_getConfig( db, nSeq, &sConfig );
        if( ret < 1 )
        {
            ret = JS_CC_ERROR_NO_DATA;
            goto end;
        }

        JS_CC_encodeConfig( &sConfig, ppRsp );
        JS_DB_resetConfig( &sConfig );
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

int modConfig( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp )
{
    int     ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    int     nSeq = -1;
    JStrList    *pLinkList = NULL;
    JCC_Config  sConfig;

    memset( &sConfig, 0x00, sizeof(sConfig));

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CONFIG, &pLinkList );

    if( pLinkList == NULL )
    {
        ret = JS_CC_ERROR_WRONG_LINK;
        goto end;
    }

    nSeq = atoi( pLinkList->pStr );

    ret = JS_CC_decodeConfig( pReq, &sConfig );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_WRONG_MSG;
        goto end;
    }

    ret = JS_DB_modConfig( db, nSeq, &sConfig );
    if( ret != 0 )
    {
        ret = JS_CC_ERROR_SYSTEM;
        goto end;
    }

end :
    JS_DB_resetConfig( &sConfig );
    if( pLinkList ) JS_UTIL_resetStrList( &pLinkList );

    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );


    return status;
}

int delConfig( sqlite3 *db, const char *pPath, char **ppRsp )
{
    int ret = 0;
    int     status = JS_HTTP_STATUS_OK;
    JStrList    *pInfoList = NULL;

    JS_HTTP_getPathRestInfo( pPath, JS_CC_PATH_CONFIG, &pInfoList );

    if( pInfoList == NULL ) return JS_CC_ERROR_WRONG_LINK;

    int nNum = atoi( pInfoList->pStr );

    ret = JS_DB_delConfig( db, nNum );

    if( ret != 0 ) status = JS_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    _setCodeMsg( ret, JS_CC_getCodeMsg(ret), ppRsp );

    if( pInfoList ) JS_UTIL_resetStrList( &pInfoList );

    return status;
}
