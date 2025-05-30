#ifndef __CC_WORK_H__
#define __CC_WORK_H__

#include <time.h>
#include "js_bin.h"
#include "js_util.h"
#include "js_db.h"


int authWork( sqlite3 *db, const char *pReq, char **ppRsp );
int regUser( sqlite3 *db, const char *pReq, char **ppRsp );
int addSigner( sqlite3 *db, const char *pReq, char **ppRsp );
int addAdmin( sqlite3 *db, const char *pReq, char **ppRsp );
int modAdmin( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp );
int delAdmin( sqlite3 *db, const char *pPath, char **ppRsp );
int addLCN( sqlite3 *db, const char *pReq, char **ppRsp );
int delLCN( sqlite3 *db, const char *pPath, char **ppRsp );
int addRevoked( sqlite3 *db, const char *pReq, char **ppRsp );
int delSigner( sqlite3 *db, const char *pPath, char **ppRsp );
int delRevoked( sqlite3 *db, const char *pPath, char **ppRsp );
int addCertProfile( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp );
int addCRLProfile( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp );
int modCertProfile( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp );
int modCRLProfile( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp );
int getAdmins( sqlite3 *db, const char *pPath, char **ppRsp );
int getUser( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp );
int modUser( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp );
int getCount( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp );
int getNum( sqlite3 *db, const char *pPath, char **ppRsp );
int getName( sqlite3 *db, const char *pPath, char **ppRsp );
int getDN( sqlite3 *db, const char *pPath, char **ppRsp );
int delUser( sqlite3 *db, const char *pPath, char **ppRsp );
int delCertProfile( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp );
int delCRLProfile( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp );
int getCertProfiles( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp );
int getCRLProfiles( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp );
int getSigners( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp );
int getCerts( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp );
int getCRLs( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp );
int getRevokeds( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp );
int issueCert( sqlite3 *db, const char *pReq, char **ppRsp );
int issueCRL( sqlite3 *db, const char *pReq, char **ppRsp );
int getCA( char **ppRsp );
int publishLDAP( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp );
int getCRDPs( sqlite3 *db, char **ppRsp );
int getCertStatus( sqlite3 *db, const JNameValList *pParamList, char **ppRsp );
int getKMS( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp );
int getTSP( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp );
int getLCN( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp );
int getStatistics( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp );
int getAudit( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp );
int addConfig( sqlite3 *db, const char *pReq, char **ppRsp );
int getConfigs( sqlite3 *db, const char *pPath, char **ppRsp );
int modConfig( sqlite3 *db, const char *pPath, const char *pReq, char **ppRsp );
int delConfig( sqlite3 *db, const char *pPath, char **ppRsp );


#endif
