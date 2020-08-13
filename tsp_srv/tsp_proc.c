#include "js_bin.h"
#include "js_tsp.h"
#include "js_db.h"
#include "tsp_srv.h"

extern BIN g_binTspCert;
extern BIN g_binTspPri;

int procTSP( sqlite3 *db, const BIN *pReq, BIN *pRsp )
{
    int     ret = 0;
    BIN     binMsg = {0,0};
    char    sHash[1024];
    char    sPolicy[1024];

    ret = JS_TSP_decodeRequest( pReq, &binMsg, sHash, sPolicy );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to decode tsp request(%d)\n", ret );
        ret = JS_TSP_encodeFailResponse( JS_TS_STATUS_REJECTION, pRsp );
        goto end;
    }

    ret = JS_TSP_encodeResponse( pReq, sHash, sPolicy, &g_binTspCert, &g_binTspPri, pRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to encode tsp response(%d)\n", ret );
        ret = JS_TSP_encodeFailResponse( JS_TS_STATUS_REJECTION, pRsp );
        goto end;
    }

end :
    JS_BIN_reset( &binMsg );
    return ret;
}
