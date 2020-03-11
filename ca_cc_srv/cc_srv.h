#ifndef CC_SRV_H
#define CC_SRV_H

#include <time.h>
#include "js_bin.h"
#include "js_util.h"
#include "js_db.h"
#include "js_cc_data.h"
#include "cc_work.h"

int genToken( const char *pPassword, time_t tTime, char *pToken );
int procCC( sqlite3 *db, const char *pReq, int nType, const char *pPath, const JNameValList *pParamList, char **ppRsp );




#endif // CC_SRV_H
