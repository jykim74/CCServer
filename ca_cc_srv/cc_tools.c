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
extern  JP11_CTX        *g_pP11CTX;

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

int makeCert( JDB_CertProfile *pDBCertProfile,
              JDB_ProfileExtList *pDBProfileExtList,
              JExtensionInfoList *pCSRExtInfoList,
              JIssueCertInfo *pIssueCertInfo,
              BIN *pCert )
{
    int ret = 0;

    JExtensionInfoList  *pExtInfoList = NULL;
    JExtensionInfoList  *pCertExtInfoList = NULL;
    JDB_ProfileExtList   *pDBCurList = NULL;
    int nExtCnt = JS_DB_countProfileExtList( pDBProfileExtList );

    pDBCurList = pDBProfileExtList;

    while( pDBCurList )
    {
        JExtensionInfo sExtInfo;

        memset( &sExtInfo,0x00, sizeof(sExtInfo));

        JS_PKI_transExtensionFromDBRec( &sExtInfo, &pDBCurList->sProfileExt );

        if( pExtInfoList == NULL )
            JS_PKI_createExtensionInfoList( &sExtInfo, &pExtInfoList );
        else
            JS_PKI_appendExtensionInfoList( pExtInfoList, &sExtInfo );

        pDBCurList = pDBCurList->pNext;
    }

    JS_PKI_getExtensionUsageList( pDBCertProfile->nExtUsage, pCertExtInfoList, pCSRExtInfoList, &pExtInfoList );

    if( g_pP11CTX )
    {
        ret = JS_PKI_makeCertificateByP11( 0, pIssueCertInfo, pExtInfoList, &g_binPri, &g_binCert, g_pP11CTX, pCert );
    }
    else
    {
        ret = JS_PKI_makeCertificate( 0, pIssueCertInfo, pExtInfoList, &g_binPri, &g_binCert, pCert );
    }


    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );
    if( pCertExtInfoList ) JS_PKI_resetExtensionInfoList( &pCertExtInfoList );

    return ret;
}

int makeCRL( JDB_CRLProfile  *pDBCRLProfile,
             JDB_ProfileExtList  *pDBProfileExtList,
             JDB_RevokedList    *pDBRevokedList,
             BIN *pCRL )
{
    int     ret = 0;
    int     nVersion = 1;
    time_t  tLastUpdate = 0;
    time_t  tNextUpdate = 0;
    JIssueCRLInfo       sIssueCRLInfo;

    JExtensionInfoList  *pExtInfoList = NULL;
    JRevokeInfoList     *pRevokedList = NULL;

    memset( &sIssueCRLInfo, 0x00, sizeof(sIssueCRLInfo));

    if( pDBCRLProfile->tThisUpdate <= 0 )
    {
        tLastUpdate = 0;
        tNextUpdate = pDBCRLProfile->tNextUpdate * 60 * 60 * 24;
    }
    else
    {
        time_t now_t = time(NULL);
        tLastUpdate = pDBCRLProfile->tThisUpdate - now_t;
        tNextUpdate = pDBCRLProfile->tNextUpdate - now_t;
    }

    while( pDBProfileExtList )
    {
        JExtensionInfo  sExtInfo;

        memset( &sExtInfo, 0x00, sizeof(sExtInfo));

        JS_PKI_transExtensionFromDBRec( &sExtInfo, &pDBProfileExtList->sProfileExt );

        if( pExtInfoList == NULL )
            JS_PKI_createExtensionInfoList( &sExtInfo, &pExtInfoList );
        else
            JS_PKI_appendExtensionInfoList( pExtInfoList, &sExtInfo );

        pDBProfileExtList = pDBProfileExtList->pNext;
        JS_PKI_resetExtensionInfo( &sExtInfo );
    }

    while( pDBRevokedList )
    {
        JRevokeInfo     sRevokeInfo;
        JExtensionInfo  sExtReason;
        JDB_ProfileExt   sDBProfileExt;

        char        sReason[64];

        memset( &sRevokeInfo, 0x00, sizeof(sRevokeInfo));
        memset( &sExtReason, 0x00, sizeof(sExtReason));
        memset( &sDBProfileExt, 0x00, sizeof(sDBProfileExt));

        sprintf( sReason, "%d", pDBRevokedList->sRevoked.nReason );
        JS_DB_setProfileExt( &sDBProfileExt,
                            -1,
                            pDBCRLProfile->nNum,
                            1,
                            JS_PKI_ExtNameCRLReason,
                            sReason );

        JS_PKI_transExtensionFromDBRec( &sExtReason, &sDBProfileExt );

        JS_PKI_setRevokeInfo( &sRevokeInfo,
                              pDBRevokedList->sRevoked.pSerial,
                              pDBRevokedList->sRevoked.tRevokedDate,
                              &sExtReason );

        if( pRevokedList == NULL )
            JS_PKI_createRevokeInfoList( &sRevokeInfo, &pRevokedList );
        else
            JS_PKI_appendRevokeInfoList( pRevokedList, &sRevokeInfo );

        JS_PKI_resetRevokeInfo( &sRevokeInfo );
        JS_PKI_resetExtensionInfo( &sExtReason );
        JS_DB_resetProfileExt( &sDBProfileExt );

        pDBRevokedList = pDBRevokedList->pNext;
    }

    JS_PKI_setIssueCRLInfo( &sIssueCRLInfo,
                            nVersion,
                            pDBCRLProfile->pHash,
                            tLastUpdate,
                            tNextUpdate );

    if( g_pP11CTX )
        ret = JS_PKI_makeCRLByP11( &sIssueCRLInfo,
                                  pExtInfoList,
                                  pRevokedList,
                                  &g_binPri,
                                  &g_binCert,
                                  g_pP11CTX,
                                  pCRL );
    else
        ret = JS_PKI_makeCRL( &sIssueCRLInfo,
                          pExtInfoList,
                          pRevokedList,
                          &g_binPri,
                          &g_binCert,
                          pCRL );

end :
    JS_PKI_resetIssueCRLInfo( &sIssueCRLInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );
    if( pRevokedList ) JS_PKI_resetRevokeInfoList( &pRevokedList );

    return ret;
}
