#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "js_bin.h"
#include "js_http.h"
#include "js_cc.h"

#include "cc_proc.h"

int runGet( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    if( strncasecmp( pPath, JS_CC_PATH_USER, strlen(JS_CC_PATH_USER)) == 0 )
    {
        ret = getUsers( db, pPath, pParamList, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_ADMIN, strlen(JS_CC_PATH_ADMIN)) == 0 )
    {
        ret = getAdmins( db, pPath, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_COUNT, strlen(JS_CC_PATH_COUNT)) == 0 )
    {
        ret = getCount( db, pPath, pParamList, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_NUM, strlen(JS_CC_PATH_NUM)) == 0 )
    {
        ret = getNum( db, pPath, pParamList, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_CERT_PROFILE, strlen(JS_CC_PATH_CERT_PROFILE)) == 0 )
    {
        ret = getCertPolicies( db, pPath, pParamList, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_CRL_PROFILE, strlen(JS_CC_PATH_CRL_PROFILE)) == 0 )
    {
        ret = getCRLPolicies( db, pPath, pParamList, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_SIGNER, strlen(JS_CC_PATH_SIGNER)) == 0 )
    {
        ret = getSigners( db, pPath, pParamList, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_CERT, strlen(JS_CC_PATH_CERT)) == 0 )
    {
        ret = getCerts( db, pPath, pParamList, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_CRL, strlen(JS_CC_PATH_CRL)) == 0 )
    {
        ret = getCRLs( db, pPath, pParamList, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_REVOKED, strlen(JS_CC_PATH_REVOKED )) == 0 )
    {
        ret = getRevokeds( db, pPath, pParamList, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_CA, strlen(JS_CC_PATH_CA)) == 0 )
    {
        ret = getCA( ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_CRLDP, strlen(JS_CC_PATH_CRLDP)) == 0 )
    {
        ret = getCRDPs( db, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_CERT_STATUS, strlen(JS_CC_PATH_CERT_STATUS)) == 0 )
    {
        ret = getCertStatus( db, pParamList, ppRsp );
    }
    else
    {
        ret = JS_HTTP_STATUS_NOT_FOUND;
    }

    return ret;
}

int runPost( sqlite3 *db, const char *pPath, const JNameValList *pParamList, const char *pReq, char **ppRsp )
{
    int ret = 0;
    if( strncasecmp( pPath, JS_CC_PATH_AUTH, strlen( JS_CC_PATH_AUTH) ) == 0)
    {
        ret = authWork( db, pReq, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_USER, strlen(JS_CC_PATH_USER) ) == 0 )
    {
        ret = regUser( db, pReq, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_CERT_PROFILE, strlen(JS_CC_PATH_CERT_PROFILE)) == 0 )
    {
        ret = addCertProfile( db, pPath, pReq, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_CRL_PROFILE, strlen(JS_CC_PATH_CRL_PROFILE)) == 0 )
    {
        ret = addCRLProfile( db, pPath, pReq, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_REVOKED, strlen( JS_CC_PATH_REVOKED)) == 0 )
    {
        ret = addRevoked( db, pReq, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_ISSUE_CERT, strlen( JS_CC_PATH_ISSUE_CERT)) == 0 )
    {
        ret = issueCert( db, pReq, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_ISSUE_CRL, strlen( JS_CC_PATH_ISSUE_CRL)) == 0 )
    {
        ret = issueCRL( db, pReq, ppRsp );
    }
    else
    {
        ret = JS_HTTP_STATUS_NOT_FOUND;
    }

    return ret;
}

int runPut( sqlite3 *db, const char *pPath, const JNameValList *pParamList, const char *pReq, char **ppRsp )
{
    int ret = 0;

    if( strncasecmp( pPath, JS_CC_PATH_CERT_PROFILE, strlen(JS_CC_PATH_CERT_PROFILE)) == 0 )
        ret = modCertProfile( db, pPath, pReq, ppRsp );
    else if( strncasecmp( pPath, JS_CC_PATH_CRL_PROFILE, strlen(JS_CC_PATH_CRL_PROFILE)) == 0 )
        ret = modCRLProfile( db, pPath, pReq, ppRsp );
    else if( strncasecmp( pPath, JS_CC_PATH_SIGNER, strlen(JS_CC_PATH_SIGNER)) == 0 )
        ret = addSigner( db, pReq, ppRsp );
    else if( strncasecmp( pPath, JS_CC_PATH_LDAP, strlen(JS_CC_PATH_LDAP)) == 0 )
        ret = publishLDAP( db, pPath, pParamList, ppRsp );
    else
        ret = JS_HTTP_STATUS_NOT_FOUND;

    return ret;
}

int runDelete( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;
    if( strncasecmp( pPath, JS_CC_PATH_USER, strlen(JS_CC_PATH_USER)) == 0 )
    {
        ret = delUser( db, pPath, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_SIGNER, strlen(JS_CC_PATH_SIGNER)) == 0 )
    {
        ret = delSigner( db, pPath, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_CERT_PROFILE, strlen(JS_CC_PATH_CERT_PROFILE)) == 0 )
    {
        ret = delCertProfile( db, pPath, pParamList, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_CRL_PROFILE, strlen(JS_CC_PATH_CRL_PROFILE )) == 0 )
    {
        ret = delCRLProfile( db, pPath, pParamList, ppRsp );
    }
    else if( strncasecmp( pPath, JS_CC_PATH_REVOKED, strlen(JS_CC_PATH_REVOKED)) == 0 )
    {
        ret = delRevoked( db, pPath, ppRsp );
    }
    else
    {
        ret = JS_HTTP_STATUS_NOT_FOUND;
    }

    return ret;
}

int procCC( sqlite3 *db, const char *pReq, int nType, const char *pPath, const JNameValList *pParamList, char **ppRsp )
{
    int ret = 0;

    JS_UTIL_printNameValList( stdout, "ParamList", pParamList );
    fprintf( stdout, "Path: %s\n", pPath );

    if( nType == JS_HTTP_METHOD_GET )
    {
        ret = runGet( db, pPath, pParamList, ppRsp );
    }
    else if( nType == JS_HTTP_METHOD_POST )
    {
        ret = runPost( db, pPath, pParamList, pReq, ppRsp );
    }
    else if( nType == JS_HTTP_METHOD_PUT )
    {
        ret = runPut( db, pPath, pParamList, pReq, ppRsp );
    }
    else if( nType == JS_HTTP_METHOD_DELETE )
    {
        ret = runDelete( db, pPath, pParamList, ppRsp );
    }

    return ret;
}
