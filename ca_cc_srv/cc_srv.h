#ifndef CC_SRV_H
#define CC_SRV_H

#include "js_bin.h"
#include "js_db.h"
#include "js_cc_data.h"

int procCC( sqlite3 *db, const char *pReq, int nType, const char *pPath, char **ppRsp );
int authWork( sqlite3 *db, const JCC_AuthReq *pReq, JCC_AuthRsp *pRsp );

#endif // CC_SRV_H
