#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cc_tools.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"
#include "js_pki_ext.h"

extern BIN g_binCert;
extern BIN g_binPri;
extern int g_nKeyType;

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

int makeCert( JDB_CertPolicy *pDBCertPolicy,
              JDB_PolicyExtList *pDBPolicyExtList,
              JIssueCertInfo *pIssueCertInfo,
              BIN *pCert )
{
    int ret = 0;

    JExtensionInfoList  *pExtInfoList = NULL;
    JDB_PolicyExtList   *pDBCurList = NULL;
    int nExtCnt = JS_DB_countPolicyExtList( pDBPolicyExtList );

    pDBCurList = pDBPolicyExtList;

    while( pDBCurList )
    {
        JExtensionInfo sExtInfo;

        memset( &sExtInfo,0x00, sizeof(sExtInfo));


        if( strcasecmp( pDBCurList->sPolicyExt.pSN, JS_PKI_ExtNameSKI ) == 0 )
        {
            BIN binPub = {0,0};
            char    sHexID[128];

            memset( sHexID, 0x00, sizeof(sHexID));
            JS_BIN_decodeHex(pIssueCertInfo->pPublicKey, &binPub);
            JS_PKI_getKeyIdentifier( &binPub, sHexID );

            if( pDBCurList->sPolicyExt.pValue )
            {
                JS_free( pDBCurList->sPolicyExt.pValue );
                pDBCurList->sPolicyExt.pValue = NULL;
            }

            pDBCurList->sPolicyExt.pValue = JS_strdup( sHexID );
            JS_BIN_reset( &binPub );
        }
        else if( strcasecmp( pDBCurList->sPolicyExt.pSN, JS_PKI_ExtNameAKI ) == 0 )
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
            if( pDBCurList->sPolicyExt.pValue )
            {
                JS_free( pDBCurList->sPolicyExt.pValue );
                pDBCurList->sPolicyExt.pValue = NULL;
            }

            pDBCurList->sPolicyExt.pValue = JS_strdup( sBuf );
        }

        JS_PKI_setExtensionFromDB( &sExtInfo, &pDBCurList->sPolicyExt );

        if( pExtInfoList == NULL )
            JS_PKI_createExtensionInfoList( &sExtInfo, &pExtInfoList );
        else
            JS_PKI_appendExtensionInfoList( pExtInfoList, &sExtInfo );

        pDBCurList = pDBCurList->pNext;
    }

    ret = JS_PKI_makeCertificate( 0, pIssueCertInfo, pExtInfoList, g_nKeyType, &g_binPri, &g_binCert, pCert );


    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );

    return ret;
}

int makeCRL( JDB_CRLPolicy  *pDBCRLPolicy,
             JDB_PolicyExtList  *pDBPolicyExtList,
             JDB_RevokedList    *pDBRevokedList,
             BIN *pCRL )
{
    int     ret = 0;
    int     nVersion = 1;
    long    uLastUpdate = 0;
    long    uNextUpdate = 0;
    JIssueCRLInfo       sIssueCRLInfo;

    JExtensionInfoList  *pExtInfoList = NULL;
    JRevokeInfoList     *pRevokedList = NULL;

    memset( &sIssueCRLInfo, 0x00, sizeof(sIssueCRLInfo));

    if( pDBCRLPolicy->nLastUpdate <= 0 )
    {
        uLastUpdate = 0;
        uNextUpdate = pDBCRLPolicy->nNextUpdate * 60 * 60 * 24;
    }
    else
    {
        time_t now_t = time(NULL);
        uLastUpdate = pDBCRLPolicy->nLastUpdate - now_t;
        uNextUpdate = pDBCRLPolicy->nNextUpdate - now_t;
    }

    while( pDBPolicyExtList )
    {
        JExtensionInfo  sExtInfo;

        memset( &sExtInfo, 0x00, sizeof(sExtInfo));

        JS_PKI_setExtensionFromDB( &sExtInfo, &pDBPolicyExtList->sPolicyExt );

        if( pExtInfoList == NULL )
            JS_PKI_createExtensionInfoList( &sExtInfo, &pExtInfoList );
        else
            JS_PKI_appendExtensionInfoList( pExtInfoList, &sExtInfo );

        pDBPolicyExtList = pDBPolicyExtList->pNext;
        JS_PKI_resetExtensionInfo( &sExtInfo );
    }

    while( pDBRevokedList )
    {
        JRevokeInfo     sRevokeInfo;
        JExtensionInfo  sExtReason;
        JDB_PolicyExt   sDBPolicyExt;

        char        sReason[64];

        memset( &sRevokeInfo, 0x00, sizeof(sRevokeInfo));
        memset( &sExtReason, 0x00, sizeof(sExtReason));
        memset( &sDBPolicyExt, 0x00, sizeof(sDBPolicyExt));

        sprintf( sReason, "%d", pDBRevokedList->sRevoked.nReason );
        JS_DB_setPolicyExt( &sDBPolicyExt,
                            -1,
                            pDBCRLPolicy->nNum,
                            1,
                            JS_PKI_ExtNameCRLReason,
                            sReason );

        JS_PKI_setExtensionFromDB( &sExtReason, &sDBPolicyExt );

        JS_PKI_setRevokeInfo( &sRevokeInfo,
                              pDBRevokedList->sRevoked.pSerial,
                              pDBRevokedList->sRevoked.nRevokedDate,
                              &sExtReason );

        if( pRevokedList == NULL )
            JS_PKI_createRevokeInfoList( &sRevokeInfo, &pRevokedList );
        else
            JS_PKI_appendRevokeInfoList( pRevokedList, &sRevokeInfo );

        JS_PKI_resetRevokeInfo( &sRevokeInfo );
        JS_PKI_resetExtensionInfo( &sExtReason );
        JS_DB_resetPolicyExt( &sDBPolicyExt );

        pDBRevokedList = pDBRevokedList->pNext;
    }

    JS_PKI_setIssueCRLInfo( &sIssueCRLInfo,
                            nVersion,
                            pDBCRLPolicy->pHash,
                            uLastUpdate,
                            uNextUpdate );

    ret = JS_PKI_makeCRL( &sIssueCRLInfo,
                          pExtInfoList,
                          pRevokedList,
                          g_nKeyType,
                          &g_binPri,
                          &g_binCert,
                          pCRL );

end :
    JS_PKI_resetIssueCRLInfo( &sIssueCRLInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );
    if( pRevokedList ) JS_PKI_resetRevokeInfoList( &pRevokedList );

    return ret;
}