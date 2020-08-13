#ifndef TSP_SRV_H
#define TSP_SRV_H

#include "js_bin.h"
#include "js_db.h"

#define     JS_TSP_SRV_VERSION          "0.9.1"

int procTSP( sqlite3 *db, const BIN *pReq, BIN *pRsp );

#endif // TSP_SRV_H
