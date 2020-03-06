#ifndef CC_SRV_H
#define CC_SRV_H

#include <time.h>
#include "js_bin.h"
#include "js_util.h"
#include "js_db.h"
#include "js_cc_data.h"

int genToken( const char *pPassword, time_t tTime, char *pToken );
int procCC( sqlite3 *db, const char *pReq, int nType, const char *pPath, const JNameValList *pParamList, char **ppRsp );


int authWork( sqlite3 *db, const char *pReq, char **pRsp );
int regUser( sqlite3 *db, const char *pReq, char **pRsp );
int getUsers( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp );
int getCount( sqlite3 *db, const char *pPath, const JNameValList *pParamList, char **ppRsp );
int delUser( sqlite3 *db, const char *pPath, char **ppRsp );

#endif // CC_SRV_H
