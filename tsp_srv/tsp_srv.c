#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "js_process.h"
#include "js_http.h"
#include "js_tsp.h"
#include "js_cfg.h"
#include "js_db.h"
#include "js_log.h"

#include "tsp_srv.h"

BIN     g_binTspCert = {0,0};
BIN     g_binTspPri = {0,0};

int     g_nPort = 9020;
int     g_nSSLPort = 9120;
int     g_nLogLevel = JS_LOG_LEVEL_INFO;


SSL_CTX *g_pSSLCTX = NULL;

static char g_sConfigPath[1024];
int g_nVerbose = 0;
JEnvList        *g_pEnvList = NULL;
static char g_sBuildInfo[1024];
const char *g_dbPath = NULL;
const char *g_pSerialPath = NULL;

const char *getBuildInfo()
{
    sprintf( g_sBuildInfo, "Version: %s Build Date : %s %s",
             JS_TSP_SRV_VERSION, __DATE__, __TIME__ );

    return g_sBuildInfo;
}

int TSP_Service( JThreadInfo *pThInfo )
{
    int ret = 0;
    JNameValList   *pHeaderList = NULL;
    JNameValList   *pRspHeaderList = NULL;
    JNameValList    *pParamList = NULL;

    char            *pBody = NULL;

    BIN             binReq = {0,0};
    BIN             binRsp = {0,0};
    const char      *pMethod = NULL;
    char            *pMethInfo = NULL;

    char            *pPath = NULL;
    int             nType = -1;

    printf( "Service start\n" );

    sqlite3* db = JS_DB_open( g_dbPath );
    if( db == NULL )
    {
        fprintf( stderr, "fail to open db file(%s)\n", g_dbPath );
        ret = -1;
        goto end;
    }

    ret = JS_HTTP_recvBin( pThInfo->nSockFd, &pMethInfo, &pHeaderList, &binReq );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to receive message(%d)\n", ret );
        goto end;
    }

    JS_LOG_write( JS_LOG_LEVEL_VERBOSE, "RecvBin Len: %d", binReq.nLen );

    if( pMethInfo ) printf( "MethInfo : %s\n", pMethInfo );
    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath, &pParamList );

    if( strcasecmp( pPath, "/PING" ) == 0 )
    {
        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else if( strcasecmp( pPath, "/TSP" ) == 0 )
    {
        ret = procTSP( db, &binReq, &binRsp );
        if( ret != 0 )
        {
            fprintf( stderr, "fail procTSP(%d)\n", ret );
            JS_LOG_write( JS_LOG_LEVEL_ERROR, "fail procTSP(%d)", ret );
            goto end;
        }

        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }

    JS_UTIL_createNameValList2("accept", "application/tsp-response", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/tps-response");

    ret = JS_HTTP_sendBin( pThInfo->nSockFd, pMethod, pRspHeaderList, &binRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to send message(%d)\n", ret );
        JS_LOG_write( JS_LOG_LEVEL_ERROR, "fail to send message(%d)", ret );
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
    if( db ) JS_DB_close( db );

    return ret;
}

int TSP_SSL_Service( JThreadInfo *pThInfo )
{
    int ret = 0;
    JNameValList   *pHeaderList = NULL;
    JNameValList   *pRspHeaderList = NULL;
    JNameValList    *pParamList = NULL;

    char            *pBody = NULL;

    BIN             binReq = {0,0};
    BIN             binRsp = {0,0};
    const char      *pMethod = NULL;
    char            *pMethInfo = NULL;

    char            *pPath = NULL;
    int             nType = -1;
    SSL             *pSSL = NULL;

    printf( "SSL Service start\n" );

    sqlite3* db = JS_DB_open( g_dbPath );
    if( db == NULL )
    {
        fprintf( stderr, "fail to open db file(%s)\n", g_dbPath );
        ret = -1;
        goto end;
    }

    ret = JS_SSL_accept( g_pSSLCTX, pThInfo->nSockFd, &pSSL );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to accept SSL(%d)\n", ret );
        goto end;
    }

    ret = JS_HTTPS_recvBin( pSSL, &pMethInfo, &pHeaderList, &binReq );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to receive message(%d)\n", ret );
        goto end;
    }

    JS_LOG_write( JS_LOG_LEVEL_VERBOSE, "RecvBin Len: %d", binReq.nLen );

    if( pMethInfo ) printf( "MethInfo : %s\n", pMethInfo );
    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath, &pParamList );

    if( strcasecmp( pPath, "/PING" ) == 0 )
    {
        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else if( strcasecmp( pPath, "/TSP" ) == 0 )
    {
        ret = procTSP( db, &binReq, &binRsp );
        if( ret != 0 )
        {
            fprintf( stderr, "fail procTSP(%d)\n", ret );
            JS_LOG_write( JS_LOG_LEVEL_ERROR, "fail procTSP(%d)", ret );
            goto end;
        }

        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }

    JS_UTIL_createNameValList2("accept", "application/tsp-response", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/tps-response");

    ret = JS_HTTPS_sendBin( pSSL, pMethod, pRspHeaderList, &binRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to send message(%d)\n", ret );
        JS_LOG_write( JS_LOG_LEVEL_ERROR, "fail to send message(%d)", ret );
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
    if( pSSL ) JS_SSL_clear( pSSL );
    if( db ) JS_DB_close( db );

    return ret;
}

int initServer()
{
    int ret = 0;
    const char *value = NULL;

    ret = JS_CFG_readConfig( g_sConfigPath, &g_pEnvList );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to open config file(%s)\n", g_sConfigPath );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "TSP_SRV_CERT_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'TSP_SRV_CERT_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileReadBER( value, &g_binTspCert );
    if( ret <= 0 )
    {
        fprintf( stderr, "fail to read tsp srv cert(%s)\n", value );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "TSP_SRV_PRIKEY_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'TSP_SRV_PRIKEY_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileReadBER( value, &g_binTspPri );
    if( ret <= 0 )
    {
        fprintf( stderr, "fail to read ocsp private key(%s)\n", value );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "LOG_LEVEL" );
    if( value ) g_nLogLevel = atoi( value );

    JS_LOG_setLevel( g_nLogLevel );

    value = JS_CFG_getValue( g_pEnvList, "LOG_PATH" );
    if( value )
        JS_LOG_open( value, "TSP", JS_LOG_TYPE_DAILY );
    else
        JS_LOG_open( "log", "TSP", JS_LOG_TYPE_DAILY );

    BIN binSSLCA = {0,0};
    BIN binSSLCert = {0,0};
    BIN binSSLPri = {0,0};

    value = JS_CFG_getValue( g_pEnvList, "SSL_CA_CERT_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'SSL_CA_CERT_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileReadBER( value, &binSSLCA );
    if( ret <= 0 )
    {
        fprintf( stderr, "fail to read ssl ca cert(%s)\n", value );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "SSL_CERT_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'SSL_CERT_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileReadBER( value, &binSSLCert );
    if( ret <= 0 )
    {
        fprintf( stderr, "fail to read ssl cert(%s)\n", value );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "SSL_PRIKEY_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'SSL_PRIKEY_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileReadBER( value, &binSSLPri );
    if( ret <= 0 )
    {
        fprintf( stderr, "fail to read ssl private key(%s)\n", value );
        exit(0);
    }

    JS_SSL_initServer( &g_pSSLCTX );
    JS_SSL_setCertAndPriKey( g_pSSLCTX, &binSSLPri, &binSSLCert );
    JS_SSL_setClientCACert( g_pSSLCTX, &binSSLCA );

    JS_BIN_reset( &binSSLCA );
    JS_BIN_reset( &binSSLCert );
    JS_BIN_reset( &binSSLPri );

    value = JS_CFG_getValue( g_pEnvList, "DB_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'DB_PATH'\n" );
        exit(0);
    }

    g_dbPath = JS_strdup( value );

    value = JS_CFG_getValue( g_pEnvList, "SERIAL_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'SERIAL_PATH'\n" );
        exit(0);
    }

    g_pSerialPath = JS_strdup( value );

    value = JS_CFG_getValue( g_pEnvList, "TSP_PORT" );
    if( value ) g_nPort = atoi( value );

    value = JS_CFG_getValue( g_pEnvList, "TSP_SSL_PORT" );
    if( value ) g_nSSLPort = atoi( value );

    printf( "TSP Server Init OK [Port:%d SSL:%d]\n", g_nPort, g_nSSLPort );
    JS_LOG_write( JS_LOG_LEVEL_INFO, "TSP Server Init OK [Port:%d SSL:%d]", g_nPort, g_nSSLPort );

    return 0;
}

void printUsage()
{
    printf( "JS TSP Server ( %s )\n", getBuildInfo() );
    printf( "[Options]\n" );
    printf( "-v         : Verbose on(%d)\n", g_nVerbose );
    printf( "-c config : set config file(%s)\n", g_sConfigPath );
    printf( "-h         : Print this message\n" );
}

int main( int argc, char *argv[] )
{
    int nOpt = 0;
    sprintf( g_sConfigPath, "%s", "../tsp_srv.cfg" );

    while(( nOpt = getopt( argc, argv, "c:vh")) != -1 )
    {
        switch( nOpt ) {
        case 'h':
            printUsage();
            return 0;

        case 'v':
            g_nVerbose = 1;
            break;

        case 'c':
            sprintf( g_sConfigPath, "%s", optarg );
            break;
        }
    }

    initServer();

    JS_THD_logInit( "./log", "tsp", 2 );
    JS_THD_registerService( "JS_TSP", NULL, g_nPort, 4, NULL, TSP_Service );
    JS_THD_registerService( "JS_TSP_SSL", NULL, g_nSSLPort, 4, NULL, TSP_SSL_Service );
    JS_THD_serviceStartAll();

    return 0;
}
