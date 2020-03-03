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
    JNameValList   *pHeaderList = NULL;
    JNameValList   *pRspHeaderList = NULL;
    JNameValList    *pParamList = NULL;

    char            *pBody = NULL;

    BIN             binReq = {0,0};
    BIN             binRsp = {0,0};
    const char      *pMethod = "POST /TSP HTTP/1.1";
    char            *pMethInfo = NULL;

    char            *pPath = NULL;
    int             nType = -1;

    printf( "Service start\n" );

    ret = JS_HTTP_recvBin( pThInfo->nSockFd, &pMethInfo, &pHeaderList, &binReq );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to receive message(%d)\n", ret );
        goto end;
    }

    if( pMethInfo ) printf( "MethInfo : %s\n", pMethInfo );
    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath, &pParamList );

    if( strcasecmp( pPath, "/PING" ) == 0 )
    {

    }
    else if( strcasecmp( pPath, "/TSP" ) == 0 )
    {
        ret = procTSP( &binReq, &binRsp );
        if( ret != 0 )
        {
            fprintf( stderr, "fail procTCP(%d)\n", ret );
           goto end;
       }
    }

    JS_UTIL_createNameValList2("accept", "application/tsp-response", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/tps-response");

    ret = JS_HTTP_sendBin( pThInfo->nSockFd, JS_HTTP_OK, pRspHeaderList, &binRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to send message(%d)\n", ret );
        goto end;
    }

end :
    if( pBody ) JS_free( pBody );
    if( pHeaderList ) JS_UTIL_resetNameValList( &pHeaderList );
    if( pRspHeaderList ) JS_UTIL_resetNameValList( &pRspHeaderList );
    if( pParamList ) JS_UTIL_resetNameValList( &pParamList );

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    if( pMethInfo ) JS_free( pMethInfo );
    if( pPath ) JS_free( pPath );

    return ret;
}

int TSP_SSL_Service( JThreadInfo *pThInfo )
{
    printf( "Service SSL start\n" );

    return 0;
}

int initServer()
{
    const char *pTSPCertPath = "/Users/jykim/work/PKITester/data/tsp_server_cert.der";
    const char *pTSPPriPath = "/Users/jykim/work/PKITester/data/tsp_server_prikey.der";

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
