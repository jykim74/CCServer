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
              int nKeyType,
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

    ret = JS_PKI_makeCertificate( 0, pIssueCertInfo, pExtInfoList, nKeyType, &g_binPri, &g_binCert, pCert );


    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );

    return ret;
}

