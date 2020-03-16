#ifndef CC_TOOLS_H
#define CC_TOOLS_H

#include <time.h>
#include "js_bin.h"
#include "js_util.h"
#include "js_db.h"
#include "cc_work.h"
#include "js_pki_x509.h"

int genToken( const char *pPassword, time_t tTime, char *pToken );
int makeCert( JDB_CertPolicy *pDBCertPolicy,
              JDB_PolicyExtList *pDBPolicyExtList,
              JIssueCertInfo *pIssueCertInfo,
              BIN *pCert );

int makeCRL( JDB_CRLPolicy  *pDBCRLPolicy,
             JDB_PolicyExtList  *pDBPolicyExtList,
             JDB_RevokedList    *pDBRevokedList,
             BIN *pCRL );

#endif // CC_TOOLS_H
