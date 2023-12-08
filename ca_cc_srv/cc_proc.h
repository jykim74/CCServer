#ifndef CC_SRV_H
#define CC_SRV_H

#include <time.h>
#include "js_bin.h"
#include "js_util.h"
#include "js_db.h"
#include "cc_work.h"

// #define CC_DEFAULT_CFG_PATH        "/Users/jykim/work/ca_cc_srv/ca_cc_srv.cfg"
#define     JS_CC_SRV_VERSION          "0.9.2"

int procCC( sqlite3 *db, const char *pReq, int nType, const char *pPath, const JNameValList *pParamList, char **ppRsp );

#endif // CC_SRV_H
