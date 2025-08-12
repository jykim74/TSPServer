#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "js_gen.h"
#include "js_process.h"
#include "js_http.h"
#include "js_tsp.h"
#include "js_cfg.h"
#include "js_db.h"
#include "js_log.h"
#include "js_pki.h"
#include "js_pkcs11.h"

#include "tsp_srv.h"

BIN     g_binTspCert = {0,0};
BIN     g_binTspPri = {0,0};
JP11_CTX        *g_pP11CTX = NULL;
int     g_nMsgDump = 0;

int     g_nPort = JS_TSP_PORT;
int     g_nSSLPort = JS_TSP_SSL_PORT;


SSL_CTX *g_pSSLCTX = NULL;

int     g_nConfigDB = 0;
static char g_sConfigPath[1024];
int g_nVerbose = 0;
JEnvList        *g_pEnvList = NULL;
static char g_sBuildInfo[1024];
const char *g_dbPath = NULL;


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

    LI( "Service start" );

    sqlite3* db = JS_DB_open( g_dbPath );
    if( db == NULL )
    {
        LE( "fail to open db file(%s)", g_dbPath );
        ret = -1;
        goto end;
    }

    ret = JS_HTTP_recvBin( pThInfo->nSockFd, &pMethInfo, &pHeaderList, &binReq );
    if( ret != 0 )
    {
        LE( "fail to receive message(%d)", ret );
        goto end;
    }

    LV( "RecvBin Len: %d", binReq.nLen );

    if( pMethInfo ) LI( "MethInfo : %s", pMethInfo );
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
            LE( "fail procTSP(%d)", ret );
            goto end;
        }

        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else
    {
        ret = -1;
        LE( "Invalid URL: %s", pPath );
        goto end;
    }

    JS_UTIL_createNameValList2("accept", "application/tsp-response", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/tps-response");

    ret = JS_HTTP_sendBin( pThInfo->nSockFd, pMethod, pRspHeaderList, &binRsp );
    if( ret != 0 )
    {
        LE( "fail to send message(%d)", ret );
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

    LI( "SSL Service start" );

    sqlite3* db = JS_DB_open( g_dbPath );
    if( db == NULL )
    {
        LE( "fail to open db file(%s)", g_dbPath );
        ret = -1;
        goto end;
    }

    ret = JS_SSL_initAccept( g_pSSLCTX, pThInfo->nSockFd, &pSSL );
    if( ret != 0 )
    {
        LE( "fail to accept SSL(%d)", ret );
        goto end;
    }

    ret = JS_HTTPS_recvBin( pSSL, &pMethInfo, &pHeaderList, &binReq );
    if( ret != 0 )
    {
        LE( "fail to receive message(%d)", ret );
        goto end;
    }

    LV( "RecvBin Len: %d", binReq.nLen );

    if( pMethInfo ) LI( "MethInfo : %s", pMethInfo );
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
            LE( "fail procTSP(%d)", ret );
            goto end;
        }

        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else
    {
        ret = -1;
        LE( "Invalid URL: %s", pPath );
        goto end;
    }

    JS_UTIL_createNameValList2("accept", "application/tsp-response", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/tps-response");

    ret = JS_HTTPS_sendBin( pSSL, pMethod, pRspHeaderList, &binRsp );
    if( ret != 0 )
    {
        LE( "fail to send message(%d)", ret );
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

int loginHSM()
{
    int ret = 0;
    int nFlags = 0;


    CK_ULONG uSlotCnt = 0;
    CK_SLOT_ID  sSlotList[10];

    int nUserType = 0;

    nFlags |= CKF_RW_SESSION;
    nFlags |= CKF_SERIAL_SESSION;
    nUserType = CKU_USER;

    int nSlotID = -1;
    const char *pLibPath = NULL;
    char sPIN[1024];
    const char *value = NULL;

    memset( sPIN, 0x00, sizeof(sPIN));

    pLibPath = JS_CFG_getValue( g_pEnvList, "TSP_HSM_LIB_PATH" );
    if( pLibPath == NULL )
    {
        LE( "You have to set 'TSP_HSM_LIB_PATH'" );
        return -1;
    }

    value = JS_CFG_getValue( g_pEnvList, "TSP_HSM_SLOT_ID" );
    if( value == NULL )
    {
        LE( "You have to set 'TSP_HSM_SLOT_ID'" );
        return -1;
    }

    nSlotID = atoi( value );

    value = JS_CFG_getValue( g_pEnvList, "TSP_HSM_PIN" );
    if( value == NULL )
    {
        ret = JS_GEN_getPassword( sPIN );
        if( ret != 0 )
        {
            LE( "You have to set 'TSP_HSM_PIN'" );
            return -1;
        }
    }
    else
    {
        memcpy( sPIN, value, strlen(value));
    }

    if( strncasecmp( value, "{ENC}", 5 ) == 0 )
    {
        JS_GEN_decPassword( sPIN, sPIN );
    }

    value = JS_CFG_getValue( g_pEnvList, "TSP_HSM_KEY_ID" );
    if( value == NULL )
    {
        LE( "You have to set 'TSP_HSM_KEY_ID'" );
        return -1;
    }

    JS_BIN_decodeHex( value, &g_binTspPri );

    ret = JS_PKCS11_LoadLibrary( &g_pP11CTX, pLibPath );
    if( ret != 0 )
    {
        LE( "fail to load library(%s:%d)", value, ret );
        return -2;
    }

    ret = JS_PKCS11_Initialize( g_pP11CTX, NULL );
    if( ret != CKR_OK )
    {
        LE( "fail to run initialize(%d)", ret );
        return -2;
    }

    ret = JS_PKCS11_GetSlotList2( g_pP11CTX, CK_TRUE, sSlotList, &uSlotCnt );
    if( ret != CKR_OK )
    {
        LE( "fail to run getSlotList fail(%d)", ret );
        return -2;
    }

    if( uSlotCnt < 1 )
    {
        LE( "there is no slot(%d)", uSlotCnt );
        return -2;
    }

    ret = JS_PKCS11_OpenSession( g_pP11CTX, sSlotList[nSlotID], nFlags );
    if( ret != CKR_OK )
    {
        LE( "fail to run opensession(%s:%x)", JS_PKCS11_GetErrorMsg(ret), ret );
        return -1;
    }

    ret = JS_PKCS11_Login( g_pP11CTX, nUserType, sPIN, strlen(sPIN) );
    if( ret != 0 )
    {
        LE( "fail to run login hsm(%d)", ret );
        return -1;
    }

    LI( "HSM Login success" );

    return 0;
}

int readPriKeyDB( sqlite3 *db )
{
    int ret = 0;
    const char *value = NULL;
    JDB_KeyPair sKeyPair;

    memset( &sKeyPair, 0x00, sizeof(sKeyPair));

    value = JS_CFG_getValue( g_pEnvList, "TSP_SRV_PRIKEY_NUM" );
    if( value == NULL )
    {
        LE( "You have to set 'TSP_SRV_PRIKEY_NUM'" );
        return -1;
    }

    ret = JS_DB_getKeyPair(db, atoi(value), &sKeyPair );
    if( ret != 1 )
    {
        LE( "There is no key pair: %d", atoi(value));
        return -1;
    }

    // 암호화 경우 복호화 필요함
    value = JS_CFG_getValue( g_pEnvList, "TSP_SRV_PRIKEY_ENC" );

    if( value && strcasecmp( value, "NO" ) == 0 )
    {
        JS_BIN_decodeHex( sKeyPair.pPrivate, &g_binTspPri );

        if( ret <= 0 )
        {
            LE( "fail to read private key file(%s:%d)", value, ret );
            return -2;
        }
    }
    else
    {
        BIN binEnc = {0,0};
        char sPasswd[1024];

        memset( sPasswd, 0x00, sizeof(sPasswd));

        value = JS_CFG_getValue( g_pEnvList, "TSP_SRV_PRIKEY_PASSWD" );
        if( value == NULL )
        {
            LE( "You have to set 'TSP_SRV_PRIKEY_PASSWD'" );
            return -3;
        }

        if( strncasecmp( value, "{ENC}", 5 ) == 0 )
        {
            JS_GEN_decPassword( value, sPasswd );
        }
        else
        {
            memcpy( sPasswd, value, strlen(value));
        }

        JS_BIN_decodeHex( sKeyPair.pPrivate, &binEnc );

        ret = JS_PKI_decryptPrivateKey( sPasswd, &binEnc, NULL, &g_binTspPri );
        if( ret != 0 )
        {
            LE( "invalid password (%d)", ret );
            return -3;
        }

        JS_BIN_reset( &binEnc );
    }

    JS_DB_resetKeyPair( &sKeyPair );

    return 0;
}


int readPriKey()
{
    int ret = 0;
    const char *value = NULL;

    value = JS_CFG_getValue( g_pEnvList, "TSP_SRV_PRIKEY_ENC" );
    if( value && strcasecmp( value, "NO" ) == 0 )
    {
        value = JS_CFG_getValue( g_pEnvList, "TSP_SRV_PRIKEY_PATH" );
        if( value == NULL )
        {
            LE( "You have to set 'TSP_SRV_PRIKEY_PATH'" );
            return -1;
        }

        ret = JS_BIN_fileReadBER( value, &g_binTspPri );
        if( ret <= 0 )
        {
            LE( "fail to read private key file(%s:%d)", value, ret );
            return -1;
        }

        LI( "PrivateKey read successfully" );
    }
    else
    {
        BIN binEnc = {0,0};
        char sPasswd[1024];

        memset( sPasswd, 0x00, sizeof(sPasswd));

        value = JS_CFG_getValue( g_pEnvList, "TSP_SRV_PRIKEY_PASSWD" );
        if( value == NULL )
        {
            ret = JS_GEN_getPassword( sPasswd );
            if( ret != 0 )
            {
                LE( "You have to set 'TSP_SRV_PRIKEY_PASSWD'" );
                return -2;
            }
        }
        else
        {
            memcpy( sPasswd, value, strlen(value));
        }

        if( strncasecmp( sPasswd, "{ENC}", 5 ) == 0 )
        {
            JS_GEN_decPassword( sPasswd, sPasswd );
        }

        value = JS_CFG_getValue( g_pEnvList, "TSP_SRV_PRIKEY_PATH" );
        if( value == NULL )
        {
            LE( "You have to set 'TSP_SRV_PRIKEY_PATH'" );
            return -2;
        }

        ret = JS_BIN_fileReadBER( value, &binEnc );
        if( ret <= 0 )
        {
            LE( "fail to read private key file(%s:%d)", value, ret );
            return -2;
        }

        ret = JS_PKI_decryptPrivateKey( sPasswd, &binEnc, NULL, &g_binTspPri );
        if( ret != 0 )
        {
            LE( "invalid password (%d)", ret );
            return -2;
        }

        LI( "Reading encrypted private key is success" );
    }

    return 0;
}


int initServer( sqlite3 *db )
{
    int ret = 0;
    const char *value = NULL;

    value = JS_CFG_getValue( g_pEnvList, "LOG_LEVEL" );
    if( value ) JS_LOG_setLevel( atoi(value) );

    value = JS_CFG_getValue( g_pEnvList, "LOG_PATH" );
    if( value )
        JS_LOG_open( value, "TSP", JS_LOG_TYPE_DAILY );
    else
        JS_LOG_open( "log", "TSP", JS_LOG_TYPE_DAILY );

    if( g_nConfigDB == 1 )
    {
        JDB_Cert sCert;
        memset( &sCert, 0x00, sizeof(sCert));

        value = JS_CFG_getValue( g_pEnvList, "TSP_SRV_CERT_NUM" );
        if( value == NULL )
        {
            LE( "You have to set 'TSSP_SRV_CERT_NUM'" );
            return -1;
        }

        JS_DB_getCert( db, atoi(value), &sCert );
        ret = JS_BIN_decodeHex( sCert.pCert, &g_binTspCert );

        JS_DB_resetCert( &sCert );
    }
    else
    {
        value = JS_CFG_getValue( g_pEnvList, "TSP_SRV_CERT_PATH" );
        if( value == NULL )
        {
            LE( "You have to set 'TSP_SRV_CERT_PATH'" );
            return -1;
        }

        ret = JS_BIN_fileReadBER( value, &g_binTspCert );
        if( ret <= 0 )
        {
            LE( "fail to read tsp srv cert(%s)", value );
            return -1;
        }
    }

    value = JS_CFG_getValue( g_pEnvList, "TSP_HSM_USE" );
    if( value && strcasecmp( value, "YES" ) == 0 )
    {
        ret = loginHSM();
        if( ret != 0 )
        {
            LE( "fail to login HSM:%d", ret );
            return -2;
        }
    }
    else
    {
        if( g_nConfigDB == 1 )
        {
            ret = readPriKeyDB( db );
        }
        else
        {
            ret = readPriKey();
        }

        if( ret != 0 )
        {
            LE( "fail to read private key:%d", ret );
            return -2;
        }
    }

    value = JS_CFG_getValue( g_pEnvList, "TSP_MSG_DUMP" );
    if( value && strcasecmp( value, "YES") == 0 )
    {
        g_nMsgDump = 1;
    }

    BIN binSSLCA = {0,0};
    BIN binSSLCert = {0,0};
    BIN binSSLPri = {0,0};

    value = JS_CFG_getValue( g_pEnvList, "SSL_CA_CERT_PATH" );
    if( value == NULL )
    {
        LE( "You have to set 'SSL_CA_CERT_PATH'" );
        return -3;
    }

    ret = JS_BIN_fileReadBER( value, &binSSLCA );
    if( ret <= 0 )
    {
        LE( "fail to read ssl ca cert(%s)", value );
        return -3;
    }

    value = JS_CFG_getValue( g_pEnvList, "SSL_CERT_PATH" );
    if( value == NULL )
    {
        LE( "You have to set 'SSL_CERT_PATH'" );
        return -3;
    }

    ret = JS_BIN_fileReadBER( value, &binSSLCert );
    if( ret <= 0 )
    {
        LE( "fail to read ssl cert(%s)", value );
        return -3;
    }

    value = JS_CFG_getValue( g_pEnvList, "SSL_PRIKEY_PATH" );
    if( value == NULL )
    {
        LE( "You have to set 'SSL_PRIKEY_PATH'" );
        return -3;
    }

    ret = JS_BIN_fileReadBER( value, &binSSLPri );
    if( ret <= 0 )
    {
        LE( "fail to read ssl private key(%s)", value );
        return -3;
    }

    JS_SSL_initServer( &g_pSSLCTX );
    JS_SSL_setCertAndPriKey( g_pSSLCTX, &binSSLPri, &binSSLCert );
    JS_SSL_setClientCACert( g_pSSLCTX, &binSSLCA );

    JS_BIN_reset( &binSSLCA );
    JS_BIN_reset( &binSSLCert );
    JS_BIN_reset( &binSSLPri );

    if( g_dbPath == NULL && g_nConfigDB == 0 )
    {
        value = JS_CFG_getValue( g_pEnvList, "DB_PATH" );
        if( value == NULL )
        {
            LE( "You have to set 'DB_PATH'" );
            return -4;
        }

        g_dbPath = JS_strdup( value );
        if( JS_UTIL_isFileExist( g_dbPath ) == 0 )
        {
            LE( "The data file is no exist[%s]", g_dbPath );
            return -4;
        }
    }

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
    printf( "-d dbfile  : Use DB config(%d)\n", g_nConfigDB );
    printf( "-h         : Print this message\n" );
}

#if !defined WIN32 && defined USE_PRC
static int MainProcessInit()
{
    return 0;
}

static int MainProcessTerm()
{
    return 0;
}

static int ChildProcessInit()
{
    return 0;
}

static int ChildProcessTerm()
{
    return 0;
}
#endif

int main( int argc, char *argv[] )
{
    int ret = 0;
    int nOpt = 0;
    sqlite3* db = NULL;

    chdir( "../../../" );
    sprintf( g_sConfigPath, "%s", "tsp_srv.cfg" );

    while(( nOpt = getopt( argc, argv, "c:d:vh")) != -1 )
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

        case 'd' :
            g_dbPath = JS_strdup( optarg );
            g_nConfigDB = 1;
            break;
        }
    }


    if( g_nConfigDB == 1 )
    {
        JDB_ConfigList *pConfigList = NULL;

        if( JS_UTIL_isFileExist( g_dbPath ) == 0 )
        {
            fprintf( stderr, "The data file is no exist[%s]\n", g_dbPath );
            exit(0);
        }

        db = JS_DB_open( g_dbPath );
        if( db == NULL )
        {
            fprintf( stderr, "fail to open db file(%s)\n", g_dbPath );
            exit(0);
        }

        ret = JS_DB_getConfigListByKind( db, JS_GEN_KIND_TSP_SRV, &pConfigList );
        if( ret <= 0 )
        {
            fprintf( stderr, "There is no config data in database: %d\n", ret );
            exit(0);
        }

        ret = JS_CFG_readConfigFromDB( pConfigList, &g_pEnvList );
        if( ret != 0 )
        {
            fprintf( stderr, "fail to open config file(%s)\n", g_sConfigPath );
            exit(0);
        }


        if( pConfigList ) JS_DB_resetConfigList( &pConfigList );
    }
    else
    {
        ret = JS_CFG_readConfig( g_sConfigPath, &g_pEnvList );
        if( ret != 0 )
        {
            fprintf( stderr, "fail to open config file(%s)\n", g_sConfigPath );
            exit(0);
        }
    }

    ret = initServer( db );
    if( ret != 0 )
    {
        LE( "fail to initialize server: %d", ret );
        exit( 0 );
    }

    if( g_nConfigDB == 1 )
    {
        if( db ) JS_DB_close( db );
    }

#if !defined WIN32 && defined USE_PRC
    JProcInit sProcInit;

    memset( &sProcInit, 0x00, sizeof(JProcInit));

    sProcInit.nCreateNum = 1;
    sProcInit.ParentInitFunction = MainProcessInit;
    sProcInit.ParemtTermFunction = MainProcessTerm;
    sProcInit.ChidInitFunction = ChildProcessInit;
    sProcInit.ChildTermFunction = ChildProcessTerm;

    JS_PRC_initRegister( &sProcInit );
    JS_PRC_register( "JS_TSP", NULL, g_nPort, 4, TSP_Service );
    JS_PRC_register( "JS_TSP_SSL", NULL, g_nSSLPort, 4, TSP_SSL_Service );
    JS_PRC_registerAdmin( NULL, g_nPort + 10 );

    JS_PRC_start();
    JS_PRC_detach();
#else
    JS_THD_registerService( "JS_TSP", NULL, g_nPort, 4, TSP_Service );
    JS_THD_registerService( "JS_TSP_SSL", NULL, g_nSSLPort, 4, TSP_SSL_Service );
    JS_THD_registerAdmin( NULL, g_nPort + 10 );
    JS_THD_serviceStartAll();
#endif

    return 0;
}
