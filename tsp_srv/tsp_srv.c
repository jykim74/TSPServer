#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "js_process.h"
#include "js_http.h"
#include "js_tsp.h"

#include "tsp_srv.h"

BIN     g_binTspCert = {0,0};
BIN     g_binTspPri = {0,0};

int TSP_Service( JThreadInfo *pThInfo )
{
    int ret = 0;
    JSNameValList   *pHeaderList = NULL;
    JSNameValList   *pRspHeaderList = NULL;
    char            *pBody = NULL;
    int             nStatus = -1;
    BIN             binReq = {0,0};
    BIN             binRsp = {0,0};
    const char      *pMethod = "POST";

    printf( "Service start\n" );

    ret = JS_HTTP_recvBin( pThInfo->nSockFd, &nStatus, &pHeaderList, &binReq );
    if( ret != 0 )
    {
        goto end;
    }

    if( nStatus == 200 )
    {
        ret = procTSP( &binReq, &binRsp );
    }

    ret = JS_HTTP_sendBin( pThInfo->nSockFd, pMethod, pRspHeaderList, &binRsp );

end :
    if( pBody ) JS_free( pBody );
    if( pHeaderList ) JS_UTIL_resetNameValList( &pHeaderList );
    if( pRspHeaderList ) JS_UTIL_resetNameValList( &pRspHeaderList );

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    return ret;
}

int TSP_SSL_Service( JThreadInfo *pThInfo )
{
    printf( "Service SSL start\n" );

    return 0;
}

int initServer()
{
    const char *pTSPCertPath = "/Users/jykim/work/PKITester/data/user_cert.der";
    const char *pTSPPriPath = "/Users/jykim/work/PKITester/data/user_prikey.der";

    JS_BIN_fileRead( pTSPCertPath, &g_binTspCert );
    JS_BIN_fileRead( pTSPPriPath, &g_binTspPri );

    return 0;
}

int main( int argc, char *argv[] )
{
    initServer();

    JS_THD_logInit( "./log", "tsp", 2 );
    JS_THD_registerService( "JS_TSP", NULL, 9020, 4, NULL, TSP_Service );
    JS_THD_registerService( "JS_TSP_SSL", NULL, 9120, 4, NULL, TSP_SSL_Service );
    JS_THD_serviceStartAll();

    return 0;
}
