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
#include "js_log.h"

#include "cc_proc.h"
#include "cc_tools.h"
#include "js_ldap.h"
#include "js_pkcs11.h"


SSL_CTX     *g_pSSLCTX = NULL;
BIN         g_binPri = {0,0};
BIN         g_binCert = {0,0};
int         g_nConfigDB = 0;


JEnvList        *g_pEnvList = NULL;
char            *g_pDBPath = NULL;
static char     g_sConfPath[1024];
int             g_bVerbose = 0;
int             g_nPort = JS_CC_PORT;
int             g_nSSLPort = JS_CC_SSL_PORT;

LDAP            *g_pLDAP = NULL;
JP11_CTX        *g_pP11CTX = NULL;

static char g_sBuildInfo[1024];

const char *getBuildInfo()
{
    sprintf( g_sBuildInfo, "Version: %s Build Date : %s %s",
            JS_CC_SRV_VERSION, __DATE__, __TIME__ );

    return g_sBuildInfo;
}

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

    const char *pRspMethod = NULL;

    sqlite3* db = JS_DB_open( g_pDBPath );
    if( db == NULL )
    {
        LE( "fail to open db file(%s)", g_pDBPath );
        ret = -1;
        goto end;
    }

    ret = JS_HTTP_recv( pThInfo->nSockFd, &pMethInfo, &pHeaderList, &pReq );
    if( ret != 0 )
    {
        LE( "fail to receive message(%d)", ret );
        goto end;
    }

    if( pMethInfo ) LI("MethInfo : %s", pMethInfo );

    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath, &pParamList );

    if( pPath ) LI( "Path: %s", pPath );

    if( strcasecmp( pPath, "/PING" ) == 0 )
    {
        pRspMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else
    {
        if( strcasecmp( pPath, JS_CC_PATH_AUTH ) != 0 )
        {
            if( isLogin( db, pHeaderList ) == 0 )
            {
                LE( "not logined" );
                goto end;
            }
        }

        status = procCC( db, pReq, nType, pPath, pParamList, &pRsp );
        pRspMethod = JS_HTTP_getStatusMsg( status );
    }

    JS_UTIL_createNameValList2("accept", "application/json", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/json");

    ret = JS_HTTP_send( pThInfo->nSockFd, pRspMethod, pRspHeaderList, pRsp );
    if( ret != 0 )
    {
        LE( "fail to send message(%d)", ret );
        goto end;
    }

    if( pRsp ) LV( "Rsp: %s", pRsp );
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

    const char *pRspMethod = NULL;

    sqlite3* db = JS_DB_open( g_pDBPath );
    if( db == NULL )
    {
        LE( "fail to open db file(%s)", g_pDBPath );
        ret = -1;
        goto end;
    }

    ret = JS_SSL_initAccept( g_pSSLCTX, pThInfo->nSockFd, &pSSL );

    ret = JS_HTTPS_recv( pSSL, &pMethInfo, &pHeaderList, &pReq );
    if( ret != 0 )
    {
        LE( "fail to receive message(%d)", ret );
        goto end;
    }

    if( pMethInfo ) LI("MethInfo : %s", pMethInfo );

    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath, &pParamList );

    if( pPath ) LI( "Path: %s", pPath );

    if( strcasecmp( pPath, "/PING" ) == 0 )
    {
        pRspMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else
    {
        if( strcasecmp( pPath, JS_CC_PATH_AUTH ) != 0 )
        {
            if( isLogin( db, pHeaderList ) == 0 )
            {
                LE( "not logined" );
                goto end;
            }
        }

        status = procCC( db, pReq, nType, pPath, pParamList, &pRsp );
        pRspMethod = JS_HTTP_getStatusMsg( status );
    }

    JS_UTIL_createNameValList2("accept", "application/json", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/json");

    ret = JS_HTTPS_send( pSSL, pRspMethod, pRspHeaderList, pRsp );
    if( ret != 0 )
    {
        LE( "fail to send message(%d)", ret );
        goto end;
    }

    if( pRsp ) LV( "Rsp: %s", pRsp );
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
    char sPIN[1024];
    const char *value = NULL;

    memset( sPIN, 0x00, sizeof(sPIN));

    pLibPath = JS_CFG_getValue( g_pEnvList, "CA_HSM_LIB_PATH" );
    if( pLibPath == NULL )
    {
        LE( "You have to set 'CA_HSM_LIB_PATH'" );
        return -1;
    }

    value = JS_CFG_getValue( g_pEnvList, "CA_HSM_SLOT_ID" );
    if( value == NULL )
    {
        LE( "You have to set 'CA_HSM_SLOT_ID'" );
        return -1;
    }

    nSlotID = atoi( value );

    value = JS_CFG_getValue( g_pEnvList, "CA_HSM_PIN" );
    if( value == NULL )
    {
        ret = JS_GEN_getPassword( sPIN );
        if( ret != 0 )
        {
            LE( "You have to set 'CMP_HSM_PIN'" );
            return -1;
        }
    }
    else
    {
        memcpy( sPIN, value, strlen(value));
    }

    if( strncasecmp( sPIN, "{ENC}", 5 ) == 0 )
    {
        JS_GEN_decPassword( sPIN, sPIN );
    }

    value = JS_CFG_getValue( g_pEnvList, "CA_HSM_KEY_ID" );
    if( value == NULL )
    {
        LE( "You have to set 'CA_HSM_KEY_ID'" );
        return -1;
    }

    JS_BIN_decodeHex( value, &g_binPri );

    ret = JS_PKCS11_LoadLibrary( &g_pP11CTX, pLibPath );
    if( ret != 0 )
    {
        LE( "fail to load library(%s:%d)", value, ret );
        return -1;
    }

    ret = JS_PKCS11_Initialize( g_pP11CTX, NULL );
    if( ret != CKR_OK )
    {
        LE( "fail to run initialize(%d)", ret );
        return -1;
    }

    ret = JS_PKCS11_GetSlotList2( g_pP11CTX, CK_TRUE, sSlotList, &uSlotCnt );
    if( ret != CKR_OK )
    {
        LE( "fail to run getSlotList fail(%d)", ret );
        return -1;
    }

    if( uSlotCnt < 1 )
    {
        LE( "there is no slot(%d)", uSlotCnt );
        return -1;
    }

    ret = JS_PKCS11_OpenSession( g_pP11CTX, sSlotList[nSlotID], nFlags );
    if( ret != CKR_OK )
    {
        LE( "fail to run opensession(%s:%x)", JS_PKCS11_GetErrorMsg(ret), ret );
        return -1;
    }

    ret = JS_PKCS11_Login( g_pP11CTX, nUserType, sPIN, strlen(sPIN) );
    if( ret != 0 )
    {
        LE( "fail to run login hsm(%d)", ret );
        return -1;
    }

    LI( "HSM login ok" );

    return 0;
}

int readPriKeyDB( sqlite3 *db )
{
    int ret = 0;
    const char *value = NULL;
    JDB_KeyPair sKeyPair;

    memset( &sKeyPair, 0x00, sizeof(sKeyPair));

    value = JS_CFG_getValue( g_pEnvList, "CA_PRIVATE_KEY_NUM" );
    if( value == NULL )
    {
        LE( "You have to set 'CA_PRIVATE_KEY_NUM'" );
        return -1;
    }

    ret = JS_DB_getKeyPair(db, atoi(value), &sKeyPair );
    if( ret != 1 )
    {
        LE( "There is no key pair: %d", atoi(value));
        return -1;
    }

    // 암호화 경우 복호화 필요함
    value = JS_CFG_getValue( g_pEnvList, "CA_PRIVATE_KEY_ENC" );

    if( value && strcasecmp( value, "NO" ) == 0 )
    {
        JS_BIN_decodeHex( sKeyPair.pPrivate, &g_binPri );

        if( ret <= 0 )
        {
            LE( "fail to read private key file(%s:%d)", value, ret );
            return -2;
        }
    }
    else
    {
        BIN binEnc = {0,0};
        char sPasswd[1024];

        memset( sPasswd, 0x00, sizeof(sPasswd));

        value = JS_CFG_getValue( g_pEnvList, "CA_PRIVATE_KEY_PASSWD" );
        if( value == NULL )
        {
            LE( "You have to set 'CA_PRIVATE_KEY_PASSWD'" );
            return -3;
        }

        if( strncasecmp( value, "{ENC}", 5 ) == 0 )
        {
            JS_GEN_decPassword( value, sPasswd );
        }
        else
        {
            memcpy( sPasswd, value, strlen(value));
        }

        JS_BIN_decodeHex( sKeyPair.pPrivate, &binEnc );

        ret = JS_PKI_decryptPrivateKey( sPasswd, &binEnc, NULL, &g_binPri );
        if( ret != 0 )
        {
            LE( "invalid password (%d)", ret );
            return -3;
        }

        JS_BIN_reset( &binEnc );
    }

    JS_DB_resetKeyPair( &sKeyPair );

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
            LE( "You have to set 'CA_PRIVATE_KEY_PATH'" );
            return -1;
        }

        ret = JS_BIN_fileReadBER( value, &g_binPri );
        if( ret <= 0 )
        {
            LE( "fail to read private key file(%s:%d)", value, ret );
            return -1;
        }
    }
    else
    {
        BIN binEnc = {0,0};
        char sPasswd[1024];

        memset( sPasswd, 0x00, sizeof(sPasswd));

        value = JS_CFG_getValue( g_pEnvList, "CA_PRIVATE_KEY_PASSWD" );
        if( value == NULL )
        {
            LE( "You have to set 'CA_PRIVATE_KEY_PASSWD'" );
            return -1;
        }

        if( strncasecmp( value, "{ENC}", 5 ) == 0 )
        {
            JS_GEN_decPassword( value, sPasswd );
        }
        else
        {
            memcpy( sPasswd, value, strlen(value));
        }

        value = JS_CFG_getValue( g_pEnvList, "CA_PRIVATE_KEY_PATH" );
        if( value == NULL )
        {
            LE( "You have to set 'CA_PRIVATE_KEY_PATH'" );
            return -1;
        }

        ret = JS_BIN_fileReadBER( value, &binEnc );
        if( ret <= 0 )
        {
            LE( "fail to read private key file(%s:%d)", value, ret );
            return -1;
        }

        ret = JS_PKI_decryptPrivateKey( sPasswd, &binEnc, NULL, &g_binPri );
        if( ret != 0 )
        {
            LE( "invalid password (%d)", ret );
            return -1;
        }
    }

    return 0;
}


int serverInit( sqlite3* db )
{
    int     ret = 0;
    const char  *value = NULL;

    value = JS_CFG_getValue( g_pEnvList, "LOG_LEVEL" );
    if( value ) JS_LOG_setLevel( atoi( value ));

    value = JS_CFG_getValue( g_pEnvList, "LOG_PATH" );
    if( value )
        JS_LOG_open( value, "CC", JS_LOG_TYPE_DAILY );
    else
        JS_LOG_open( "log", "CC", JS_LOG_TYPE_DAILY );

    if( g_nConfigDB == 1 )
    {
        JDB_Cert sCert;
        memset( &sCert, 0x00, sizeof(sCert));

        value = JS_CFG_getValue( g_pEnvList, "CA_CERT_NUM" );
        if( value == NULL )
        {
            LE( "You have to set 'CA_CERT_NUM'" );
            return -1;
        }

        JS_DB_getCert( db, atoi(value), &sCert );
        ret = JS_BIN_decodeHex( sCert.pCert, &g_binCert );

        JS_DB_resetCert( &sCert );
    }
    else
    {
        value = JS_CFG_getValue( g_pEnvList, "CA_CERT_PATH" );
        if( value == NULL )
        {
            LE( "You have to set 'CA_CERT_PATH'" );
            return -1;
        }

        ret = JS_BIN_fileReadBER( value, &g_binCert );
        if( ret <= 0 )
        {
            LE( "fail to read certificate file(%s:%d)", value, ret );
            return -1;
        }
    }

    value = JS_CFG_getValue( g_pEnvList, "CA_HSM_USE" );
    if( value && strcasecmp( value, "YES" ) == 0 )
    {
        ret = loginHSM();
        if( ret != 0 )
        {
            LE( "fail to login HSM:%d", ret );
            return -1;
        }
    }
    else
    {
        if( g_nConfigDB == 1 )
        {
            ret = readPriKeyDB( db );
        }
        else
        {
            ret = readPriKey();
        }

        if( ret != 0 )
        {
            LE( "fail to read private key:%d", ret );
            return -1;
        }
    }

    if( g_pDBPath == NULL && g_nConfigDB == 0 )
    {
        value = JS_CFG_getValue( g_pEnvList, "CC_DB_PATH" );
        if( value == NULL )
        {
            LE( "You have to set 'CC_DB_PATH'" );
            return -1;
        }

        g_pDBPath = JS_strdup( value );
        if( JS_UTIL_isFileExist( g_pDBPath ) == 0 )
        {
            LE( "The data file is no exist[%s]", g_pDBPath );
            return -1;
        }
    }

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
            LE( "You have to set 'LDAP_HOST'" );
            return -1;
        }

        pLdapHost = value;

        value = JS_CFG_getValue( g_pEnvList, "LDAP_PORT");
        if( value == NULL )
        {
            LE( "You have to set 'LDAP_PORT'" );
            return -1;
        }

        nLdapPort = atoi( value );

        value = JS_CFG_getValue( g_pEnvList, "LDAP_BINDDN" );
        if( value == NULL )
        {
            LE( "You have to set 'LDAP_BINDDN'" );
            return -1;
        }

        pBindDN = value;

        value = JS_CFG_getValue( g_pEnvList, "LDAP_SECRET" );
        if( value == NULL )
        {
            LE( "You have to set 'LDAP_SECRET'" );
            return -1;
        }

        pSecert = value;

        g_pLDAP = JS_LDAP_init( pLdapHost, nLdapPort );
        if( g_pLDAP == NULL )
        {
            LE( "fail to initialize ldap(%s:%d)", pLdapHost, nLdapPort );
            return -1;
        }

        ret = JS_LDAP_bind( g_pLDAP, pBindDN, pSecert );
        if( ret != LDAP_SUCCESS )
        {
            LE( "fail to bind ldap(%s:%d)", pBindDN, ret );
            return -1;
        }

        LI( "success to connect to ldap server" );
    }

    JS_SSL_initServer( &g_pSSLCTX );
    JS_SSL_setCertAndPriKey( g_pSSLCTX, &g_binPri, &g_binCert );

    LI( "CC_Server Init OK [Port:%d SSL:%d]", g_nPort, g_nSSLPort );

    return 0;
}

int quitDaemon( const char *pCmd )
{
    return 0;
}

void printUsage()
{
    printf( "JS CC Server ( %s )\n", getBuildInfo() );
    printf( "[Options]\n" );
    printf( "-v         : Verbose on(%d)\n", g_bVerbose );
    printf( "-c config  : Set config file(%s)\n", g_sConfPath );
    printf( "-d dbfile  : Use DB config(%d)\n", g_nConfigDB );
    printf( "-h         : Print this message\n" );
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
    int ret = 0;
    int nOpt = 0;
    sqlite3* db = NULL;

    sprintf( g_sConfPath, "%s", "../ca_cc_srv.cfg" );

    while(( nOpt = getopt( argc, argv, "c:d:qvh")) != -1 )
    {
        switch( nOpt )
        {
            case 'q':
                return quitDaemon(argv[0]);
                break;

            case 'h':
                printUsage();
                return 0;

            case 'v':
                g_bVerbose = 1;
                break;

            case 'c':
                sprintf( g_sConfPath, "%s", optarg );
                break;

            case 'd':
                g_pDBPath = JS_strdup( optarg );
                g_nConfigDB = 1;
                break;
        }
    }

    if( g_nConfigDB == 1 )
    {
        JDB_ConfigList *pConfigList = NULL;

        if( JS_UTIL_isFileExist( g_pDBPath ) == 0 )
        {
            fprintf( stderr, "The data file is no exist[%s]\n", g_pDBPath );
            exit(0);
        }

        db = JS_DB_open( g_pDBPath );
        if( db == NULL )
        {
            fprintf( stderr, "fail to open db file(%s)\n", g_pDBPath );
            exit(0);
        }

        ret = JS_DB_getConfigListByKind( db, JS_GEN_KIND_CC_SRV, &pConfigList );
        if( ret <= 0 )
        {
            fprintf( stderr, "There is no config data in database: %d\n", ret );
            exit(0);
        }

        ret = JS_CFG_readConfigFromDB( pConfigList, &g_pEnvList );
        if( ret != 0 )
        {
            fprintf( stderr, "fail to open config file(%s)\n", g_sConfPath );
            exit(0);
        }


        if( pConfigList ) JS_DB_resetConfigList( &pConfigList );
    }
    else
    {
        ret = JS_CFG_readConfig( g_sConfPath, &g_pEnvList );
        if( ret != 0 )
        {
            fprintf( "fail to open config file(%s)\n", g_sConfPath );
            exit(0);
        }
    }

    ret = serverInit( db );

    if( ret != 0 )
    {
        LE( "fail to initialize server: %d", ret );
        exit( 0 );
    }

    if( g_nConfigDB == 1 )
    {
        if( db ) JS_DB_close( db );
    }

    LI( "CC Server initialized succfully" );

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

