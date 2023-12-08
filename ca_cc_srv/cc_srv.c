#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "js_gen.h"
#include "js_log.h"
#include "js_pki.h"
#include "js_http.h"
#include "js_process.h"
#include "js_db.h"
#include "js_ssl.h"
#include "js_log.h"
#include "js_cc.h"
#include "js_cfg.h"

#include "cc_proc.h"
#include "cc_tools.h"
#include "js_ldap.h"
#include "js_pkcs11.h"


SSL_CTX     *g_pSSLCTX = NULL;
BIN         g_binPri = {0,0};
BIN         g_binCert = {0,0};
int         g_nKeyType = JS_PKI_KEY_TYPE_RSA;
int         g_nLogLevel = JS_LOG_LEVEL_INFO;


JEnvList        *g_pEnvList = NULL;
char            *g_pDBPath = NULL;
static char     g_sConfPath[1024];
int             g_bVerbose = 0;
int             g_nPort = JS_CC_PORT;
int             g_nSSLPort = JS_CC_SSL_PORT;

LDAP            *g_pLDAP = NULL;
JP11_CTX        *g_pP11CTX = NULL;

int isLogin( sqlite3* db, JNameValList *pHeaderList )
{
    JDB_Auth sAuth;
    const char *pToken = NULL;
    if( pHeaderList == NULL ) return 0;

    memset( &sAuth, 0x00, sizeof(sAuth));

    pToken = JS_UTIL_valueFromNameValList( pHeaderList, "Token" );
    if( pToken == NULL ) return 0;

    JS_DB_getAuth( db, pToken, &sAuth );

    if( sAuth.pToken && strcasecmp( pToken, sAuth.pToken ) == 0 )
    {
        JS_DB_resetAuth( &sAuth );
        return 1;
    }

    JS_DB_resetAuth( &sAuth );
    return 0;
}

int CC_Service( JThreadInfo *pThInfo )
{
    int ret = 0;
    int status = 0;
    int nType = -1;
    char *pPath = NULL;

    char    *pReq = NULL;
    char    *pRsp = NULL;

    char    *pMethInfo = NULL;
    JNameValList    *pHeaderList = NULL;
    JNameValList    *pRspHeaderList = NULL;
    JNameValList    *pParamList = NULL;

    sqlite3* db = JS_DB_open( g_pDBPath );
    if( db == NULL )
    {
        fprintf( stderr, "fail to open db file(%s)\n", g_pDBPath );
        ret = -1;
        goto end;
    }

    ret = JS_HTTP_recv( pThInfo->nSockFd, &pMethInfo, &pHeaderList, &pReq );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to receive message(%d)\n", ret );
        goto end;
    }

    JS_LOG_write( JS_LOG_LEVEL_VERBOSE, "Req: %s", pReq );

    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath, &pParamList );

    if( strcasecmp( pPath, "PING" ) == 0 )
    {

    }
    else
    {
        if( strcasecmp( pPath, JS_CC_PATH_AUTH ) != 0 )
        {
            if( isLogin( db, pHeaderList ) == 0 )
            {
                fprintf( stderr, "not logined\n" );
                JS_LOG_write( JS_LOG_LEVEL_ERROR, "not logined" );
                goto end;
            }
        }

        status = procCC( db, pReq, nType, pPath, pParamList, &pRsp );
    }

    JS_UTIL_createNameValList2("accept", "application/json", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/json");
    const char *pRspMethod = JS_HTTP_getStatusMsg( status );

    ret = JS_HTTP_send( pThInfo->nSockFd, pRspMethod, pRspHeaderList, pRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to send message(%d)\n", ret );
        JS_LOG_write( JS_LOG_LEVEL_ERROR, "fail to send message(%d)", ret );
        goto end;
    }

    if( pRsp ) fprintf( stdout, "Rsp: %s\n", pRsp );
    /* send response body */
end:
    if( pReq ) JS_free( pReq );
    if( pRsp ) JS_free( pRsp );

    if( pPath ) JS_free( pPath );

    if( pHeaderList ) JS_UTIL_resetNameValList( &pHeaderList );
    if( pRspHeaderList ) JS_UTIL_resetNameValList( &pRspHeaderList );
    if( pParamList ) JS_UTIL_resetNameValList( &pParamList );

    JS_DB_close( db );

    return 0;
}

int CC_SSL_Service( JThreadInfo *pThInfo )
{
    int ret = 0;
    int status = 0;
    int nType = -1;
    char *pPath = NULL;

    SSL     *pSSL = NULL;

    char    *pReq = NULL;
    char    *pRsp = NULL;

    char    *pMethInfo = NULL;
    JNameValList    *pHeaderList = NULL;
    JNameValList    *pRspHeaderList = NULL;
    JNameValList    *pParamList = NULL;

    sqlite3* db = JS_DB_open( g_pDBPath );
    if( db == NULL )
    {
        fprintf( stderr, "fail to open db file(%s)\n", g_pDBPath );
        ret = -1;
        goto end;
    }

    ret = JS_SSL_accept( g_pSSLCTX, pThInfo->nSockFd, &pSSL );

    ret = JS_HTTPS_recv( pSSL, &pMethInfo, &pHeaderList, &pReq );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to receive message(%d)\n", ret );
        goto end;
    }

    JS_LOG_write( JS_LOG_LEVEL_VERBOSE, "Req: %s", pReq );

    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath, &pParamList );

    if( strcasecmp( pPath, "PING" ) == 0 )
    {

    }
    else
    {
        if( strcasecmp( pPath, JS_CC_PATH_AUTH ) != 0 )
        {
            if( isLogin( db, pHeaderList ) == 0 )
            {
                fprintf( stderr, "not logined\n" );
                JS_LOG_write( JS_LOG_LEVEL_ERROR, "not logined" );
                goto end;
            }
        }

        status = procCC( db, pReq, nType, pPath, pParamList, &pRsp );
    }

    JS_UTIL_createNameValList2("accept", "application/json", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/json");
    const char *pRspMethod = JS_HTTP_getStatusMsg( status );

    ret = JS_HTTPS_send( pSSL, pRspMethod, pRspHeaderList, pRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to send message(%d)\n", ret );
        JS_LOG_write( JS_LOG_LEVEL_ERROR, "fail to send message(%d)", ret );
        goto end;
    }

    if( pRsp ) fprintf( stdout, "Rsp: %s\n", pRsp );
    /* send response body */
end:
    if( pReq ) JS_free( pReq );
    if( pRsp ) JS_free( pRsp );

    if( pPath ) JS_free( pPath );

    if( pHeaderList ) JS_UTIL_resetNameValList( &pHeaderList );
    if( pRspHeaderList ) JS_UTIL_resetNameValList( &pRspHeaderList );
    if( pParamList ) JS_UTIL_resetNameValList( &pParamList );

    if( pSSL ) JS_SSL_clear( pSSL );
    JS_DB_close(db);

    return 0;
}

int loginHSM()
{
    int ret = 0;
    int nFlags = 0;


    CK_ULONG uSlotCnt = 0;
    CK_SLOT_ID  sSlotList[10];

    int nUserType = 0;

    nFlags |= CKF_RW_SESSION;
    nFlags |= CKF_SERIAL_SESSION;
    nUserType = CKU_USER;

    int nSlotID = -1;
    const char *pLibPath = NULL;
    const char *pPIN = NULL;
    int nPINLen = 0;
    const char *value = NULL;

    pLibPath = JS_CFG_getValue( g_pEnvList, "CA_HSM_LIB_PATH" );
    if( pLibPath == NULL )
    {
        fprintf( stderr, "You have to set 'CA_HSM_LIB_PATH'\n" );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "CA_HSM_SLOT_ID" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'CA_HSM_SLOT_ID'\n" );
        exit(0);
    }

    nSlotID = atoi( value );

    pPIN = JS_CFG_getValue( g_pEnvList, "CA_HSM_PIN" );
    if( pPIN == NULL )
    {
        fprintf( stderr, "You have to set 'CA_HSM_PIN'\n" );
        exit(0);
    }

    nPINLen = atoi( pPIN );

    value = JS_CFG_getValue( g_pEnvList, "CA_HSM_KEY_ID" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'CA_HSM_KEY_ID'\n" );
        exit( 0);
    }

    JS_BIN_decodeHex( value, &g_binPri );

    ret = JS_PKCS11_LoadLibrary( &g_pP11CTX, pLibPath );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to load library(%s:%d)\n", value, ret );
        exit(0);
    }

    ret = JS_PKCS11_Initialize( g_pP11CTX, NULL );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run initialize(%d)\n", ret );
        return -1;
    }

    ret = JS_PKCS11_GetSlotList2( g_pP11CTX, CK_TRUE, sSlotList, &uSlotCnt );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run getSlotList fail(%d)\n", ret );
        return -1;
    }

    if( uSlotCnt < 1 )
    {
        fprintf( stderr, "there is no slot(%d)\n", uSlotCnt );
        return -1;
    }

    ret = JS_PKCS11_OpenSession( g_pP11CTX, sSlotList[nSlotID], nFlags );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run opensession(%s:%x)\n", JS_PKCS11_GetErrorMsg(ret), ret );
        return -1;
    }

    ret = JS_PKCS11_Login( g_pP11CTX, nUserType, pPIN, nPINLen );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to run login hsm(%d)\n", ret );
        return -1;
    }

    printf( "HSM login ok\n" );

    return 0;
}

int readPriKey()
{
    int ret = 0;
    const char *value = NULL;

    value = JS_CFG_getValue( g_pEnvList, "CA_PRIVATE_KEY_ENC" );
    if( value && strcasecmp( value, "NO" ) == 0 )
    {
        value = JS_CFG_getValue( g_pEnvList, "CA_PRIVATE_KEY_PATH" );
        if( value == NULL )
        {
            fprintf( stderr, "You have to set 'CA_PRIVATE_KEY_PATH'" );
            exit(0);
        }

        ret = JS_BIN_fileReadBER( value, &g_binPri );
        if( ret <= 0 )
        {
            fprintf( stderr, "fail to read private key file(%s:%d)\n", value, ret );
            exit( 0 );
        }
    }
    else
    {
        BIN binEnc = {0,0};
        const char *pPasswd = NULL;

        pPasswd = JS_CFG_getValue( g_pEnvList, "CA_PRIVATE_KEY_PASSWD" );
        if( pPasswd == NULL )
        {
            fprintf( stderr, "You have to set 'CA_PRIVATE_KEY_PASSWD'\n" );
            exit(0);
        }

        value = JS_CFG_getValue( g_pEnvList, "CA_PRIVATE_KEY_PATH" );
        if( value == NULL )
        {
            fprintf( stderr, "You have to set 'CA_PRIVATE_KEY_PATH'" );
            exit(0);
        }

        ret = JS_BIN_fileReadBER( value, &binEnc );
        if( ret <= 0 )
        {
            fprintf( stderr, "fail to read private key file(%s:%d)\n", value, ret );
            exit( 0 );
        }

        ret = JS_PKI_decryptPrivateKey( pPasswd, &binEnc, NULL, &g_binPri );
        if( ret != 0 )
        {
            fprintf( stderr, "invalid password (%d)\n", ret );
            exit(0);
        }
    }
    return 0;
}


int serverInit()
{
    int     ret = 0;
    const char  *value = NULL;

    ret = JS_CFG_readConfig( g_sConfPath, &g_pEnvList );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to read config file(%s:%d)\n", g_sConfPath, ret );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "LOG_LEVEL" );
    if( value ) g_nLogLevel = atoi( value );

    JS_LOG_setLevel( g_nLogLevel );

    value = JS_CFG_getValue( g_pEnvList, "LOG_PATH" );
    if( value )
        JS_LOG_open( value, "CC", JS_LOG_TYPE_DAILY );
    else
        JS_LOG_open( "log", "CC", JS_LOG_TYPE_DAILY );

    value = JS_CFG_getValue( g_pEnvList, "CA_KEY_TYPE" );
    if( value )
    {
        if( strcasecmp( value, "ECC") == 0 )
            g_nKeyType = JS_PKI_KEY_TYPE_ECC;
        else
            g_nKeyType = JS_PKI_KEY_TYPE_RSA;
    }

    value = JS_CFG_getValue( g_pEnvList, "CA_CERT_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'CA_CERT_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileReadBER( value, &g_binCert );
    if( ret <= 0 )
    {
        fprintf( stderr, "fail to read certificate file(%s:%d)\n", value, ret );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "CA_HSM_USE" );
    if( value && strcasecmp( value, "YES" ) == 0 )
    {
        ret = loginHSM();
        if( ret != 0 )
        {
            fprintf( stderr, "fail to login HSM:%d\n", ret );
            exit(0);
        }
    }
    else
    {
        ret = readPriKey();
        if( ret != 0 )
        {
            fprintf( stderr, "fail to read private key:%d\n", ret );
            exit( 0 );
        }
    }

    value = JS_CFG_getValue( g_pEnvList, "CC_DB_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'CC_DB_PATH'" );
        exit(0);
    }

    g_pDBPath = value;

    value = JS_CFG_getValue( g_pEnvList, "CC_PORT" );
    if( value ) g_nPort = atoi( value );

    value = JS_CFG_getValue( g_pEnvList, "CC_SSL_PORT" );
    if( value ) g_nSSLPort = atoi( value );

    value = JS_CFG_getValue( g_pEnvList, "LDAP_USE" );
    if( value && strcasecmp( value, "YES" ) == 0 )
    {
        int nLdapPort = -1;
        const char *pLdapHost = NULL;
        const char *pBindDN = NULL;
        const char *pSecert = NULL;

        value = JS_CFG_getValue( g_pEnvList, "LDAP_HOST" );

        if( value == NULL )
        {
            fprintf( stderr, "You have to set 'LDAP_HOST'\n" );
            exit(0);
        }

        pLdapHost = value;

        value = JS_CFG_getValue( g_pEnvList, "LDAP_PORT");
        if( value == NULL )
        {
            fprintf( stderr, "You have to set 'LDAP_PORT'\n" );
            exit(0);
        }

        nLdapPort = atoi( value );

        value = JS_CFG_getValue( g_pEnvList, "LDAP_BINDDN" );
        if( value == NULL )
        {
            fprintf( stderr, "You have to set 'LDAP_BINDDN'\n" );
            exit(0);
        }

        pBindDN = value;

        value = JS_CFG_getValue( g_pEnvList, "LDAP_SECRET" );
        if( value == NULL )
        {
            fprintf( stderr, "You have to set 'LDAP_SECRET'\n" );
            exit(0);
        }

        pSecert = value;

        g_pLDAP = JS_LDAP_init( pLdapHost, nLdapPort );
        if( g_pLDAP == NULL )
        {
            fprintf( stderr, "fail to initialize ldap(%s:%d)\n", pLdapHost, nLdapPort );
            exit(0);
        }

        ret = JS_LDAP_bind( g_pLDAP, pBindDN, pSecert );
        if( ret != LDAP_SUCCESS )
        {
            fprintf( stderr, "fail to bind ldap(%s:%d)\n", pBindDN, ret );
            exit(0);
        }

        printf( "success to connect to ldap server\n" );
    }

    JS_SSL_initServer( &g_pSSLCTX );
    JS_SSL_setCertAndPriKey( g_pSSLCTX, &g_binPri, &g_binCert );

    printf( "CC_Server Init OK [Port:%d SSL:%d]\n", g_nPort, g_nSSLPort );

    return 0;
}

int quitDaemon( const char *pCmd )
{
    return 0;
}

void printUsage()
{

}

#if !defined WIN32 && defined USE_PRC
static int MainProcessInit()
{
    return 0;
}

static int MainProcessTerm()
{
    return 0;
}

static int ChildProcessInit()
{
    return 0;
}

static int ChildProcessTerm()
{
    return 0;
}
#endif

int main( int argc, char *argv[] )
{
    int     nOpt = 0;

    sprintf( g_sConfPath, "%s", "../ca_cc_srv.cfg" );

    while(( nOpt = getopt( argc, argv, "c:qth")) != -1 )
    {
        switch( nOpt )
        {
            case 'q':
                return quitDaemon(argv[0]);
                break;

            case 'h':
                printUsage();
                return 0;

            case 't':
                g_bVerbose = 1;
                break;

            case 'c':
                sprintf( g_sConfPath, "%s", optarg );
                break;
        }
    }

    serverInit();

#if !defined WIN32 && defined USE_PRC
    JProcInit sProcInit;

    memset( &sProcInit, 0x00, sizeof(JProcInit));

    sProcInit.nCreateNum = 1;
    sProcInit.ParentInitFunction = MainProcessInit;
    sProcInit.ParemtTermFunction = MainProcessTerm;
    sProcInit.ChidInitFunction = ChildProcessInit;
    sProcInit.ChildTermFunction = ChildProcessTerm;

    JS_PRC_initRegister( &sProcInit );
    JS_PRC_register( "JS_CC", NULL, g_nPort, 4, CC_Service );
    JS_PRC_register( "JS_CC_SSL", NULL, g_nSSLPort, 4, CC_SSL_Service );
    JS_PRC_registerAdmin( NULL, g_nPort + 10 );

    JS_PRC_start();
    JS_PRC_detach();
#else
    JS_THD_registerService( "JS_CC", NULL, g_nPort, 4, CC_Service );
    JS_THD_registerService( "JS_CC_SSL", NULL, g_nSSLPort, 4, CC_SSL_Service );
    JS_THD_registerAdmin( NULL, g_nPort + 10 );
    JS_THD_serviceStartAll();
#endif

    return 0;
}

