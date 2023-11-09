#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "js_gen.h"
#include "js_bin.h"
#include "js_log.h"
#include "js_tsp.h"
#include "js_db.h"
#include "tsp_srv.h"
#include "js_pkcs11.h"
#include "openssl/ts.h"

extern BIN g_binTspCert;
extern BIN g_binTspPri;
extern int g_nMsgDump;
extern  JP11_CTX        *g_pP11CTX;

// extern const char *g_pSerialPath;

#if 1
static ASN1_INTEGER* serialCallback( TS_RESP_CTX *ctx, void *data )
{
    ASN1_INTEGER *pASerial = NULL;
    int nSerial = JS_DB_getNextVal( (sqlite3 *)data, "TB_SERIAL" );
    if( nSerial <= 0 )
    {
        LE( "fail to get serial value: %d", nSerial );
        return NULL;
    }

    LI( "Serial: %d", nSerial );
    pASerial = ASN1_INTEGER_new();

    ASN1_INTEGER_set( pASerial, nSerial );

    return pASerial;
}

#else
static ASN1_INTEGER* _nextSerial( const char *pSerialFile )
{
    int ret = -1;
    BIO *pIOIn = NULL;
    ASN1_INTEGER    *serial = NULL;
    BIGNUM *bn = NULL;

    if( !(serial = ASN1_INTEGER_new() ))
        goto err;

    if( !(pIOIn = BIO_new_file(pSerialFile, "r"))) {
        fprintf( stderr, "Warning: could not open fail %s for reading, using serial number: 1\n", pSerialFile );
        JS_LOG_write( JS_LOG_LEVEL_WARN, "Warning: could not open fail %s for reading, using serial number: 1", pSerialFile );


        if( !ASN1_INTEGER_set(serial, 1) )
            goto err;
    } else {
        char buf[1024];

        if( !a2i_ASN1_INTEGER( pIOIn, serial, buf, sizeof(buf))) {
            fprintf( stderr, "unable to load number from %s\n", pSerialFile );
            JS_LOG_write( JS_LOG_LEVEL_ERROR, "unable to load number from %s", pSerialFile );
            goto err;
        }

        if( !(bn = ASN1_INTEGER_to_BN( serial, NULL )))
            goto err;

        ASN1_INTEGER_free( serial );
        serial = NULL;

        if( !BN_add_word(bn, 1))
            goto err;

        if(!(serial = BN_to_ASN1_INTEGER(bn, NULL)))
            goto err;
    }

    ret = 0;
err:
    if( ret != 0 )
    {
        ASN1_INTEGER_free(serial );
        serial = NULL;
    }

    BIO_free_all(pIOIn);
    BN_free( bn );

    return serial;
}

static int _saveTSSerial( const char *pSerialFile, ASN1_INTEGER *serial )
{
    int ret = -1;
    BIO *out = NULL;

    if( !(out = BIO_new_file(pSerialFile, "w")))
        goto err;

    if( i2a_ASN1_INTEGER( out, serial) < 0 )
        goto err;

    if( BIO_puts( out, "\n" ) <= 0 )
        goto err;

    ret = 0;

err:
    if( ret != 0 )
    {
        fprintf( stderr, "could not save serial number to %s\n", pSerialFile );
        JS_LOG_write( JS_LOG_LEVEL_ERROR, "could not save serial number to %s", pSerialFile );
    }

    if( out ) BIO_free_all(out);
    return ret;
}

static ASN1_INTEGER* serialCallback( TS_RESP_CTX *ctx, void *data )
{
    const char *pSerialFile = (const char *)data;

    ASN1_INTEGER *serial = _nextSerial( pSerialFile );

    if( !serial )
    {
 //       TS_RESP_CTX_set_status_info( ctx, TS_STATUS_REJECTION, "Generation Error" );
 //       TS_RESP_CTX_add_failure_info( ctx, TS_INFO_ADD_INFO_NOT_AVAILABLE );
        return NULL;
    }
    else
    {
        _saveTSSerial( pSerialFile, serial );
    }

    return serial;
}
#endif

int msgDump( int nIsReq, const BIN *pMsg )
{
    char        sSavePath[1024];

    if( pMsg == NULL || pMsg->nLen <= 0 ) return -1;

    if( JS_UTIL_isFolderExist( "dump" ) == 0 )
    {
#ifdef WIN32
        mkdir( "dump" );
#else
        mkdir( "dump", 0755 );
#endif
    }

    if( nIsReq )
    {
        sprintf( sSavePath, "dump/tsp_req_%d_%d.bin", time(NULL), getpid() );
    }
    else
    {
        sprintf( sSavePath, "dump/tsp_rsp_%d_%d.bin", time(NULL), getpid());
    }


    return JS_BIN_fileWrite( pMsg, sSavePath );
}

int procTSP( sqlite3 *db, const BIN *pReq, BIN *pRsp )
{
    int     ret = 0;
    BIN     binMsg = {0,0};
    char    sHash[1024];
    char    sPolicy[1024];
//    const char *pPath = "D:/data/tsaserial";
    BIN     binTST = {0,0};
    BIN     binP7 = {0,0};
    int64_t nSerial = -1;
    JDB_TSP sTSP;
    char *pHexTSTInfo = NULL;
    char *pHexData = NULL;

    memset( &sTSP, 0x00, sizeof(sTSP));

    ret = JS_TSP_decodeRequest( pReq, &binMsg, sHash, sPolicy );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to decode tsp request(%d)\n", ret );
        JS_LOG_write( JS_LOG_LEVEL_ERROR, "fail to decode tsp request(%d)", ret );

        ret = JS_TSP_encodeFailResponse( JS_TS_STATUS_REJECTION, pRsp );

        goto end;
    }

    if( g_nMsgDump ) msgDump( 1, pReq );

    if( g_pP11CTX )
    {
        ret = JS_TSP_encodeResponseByP11(
            pReq, sHash, sPolicy, &g_binTspCert, &g_binTspPri, g_pP11CTX,
            (void *)serialCallback, (void *)db,
            &nSerial, &binTST, &binP7, pRsp );

        LI( "EncodeResponseByP11 Ret: %d", ret );
    }
    else
    {
        ret = JS_TSP_encodeResponse(
                pReq, sHash, sPolicy, &g_binTspCert, &g_binTspPri,
                (void *)serialCallback, (void *)db,
                &nSerial, &binTST, &binP7, pRsp );

        LI( "EncodeResponse Ret: %d", ret );
    }

    if( ret != 0 )
    {
        fprintf( stderr, "fail to encode tsp response(%d)\n", ret );
        JS_LOG_write( JS_LOG_LEVEL_ERROR, "fail to encode tsp response(%d)", ret );
        ret = JS_TSP_encodeFailResponse( JS_TS_STATUS_REJECTION, pRsp );
        goto end;
    }
    else
    {
        if( g_nMsgDump ) msgDump( 0, pRsp );
    }

    JS_BIN_encodeHex( &binTST, &pHexTSTInfo );
    JS_BIN_encodeHex( &binP7, &pHexData );

    JS_DB_setTSP( &sTSP, -1, time(NULL), nSerial, sHash, sPolicy, pHexTSTInfo, pHexData );

    ret = JS_DB_addTSP( db, &sTSP );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to add TSP to DB(%d)\n", ret );
        JS_LOG_write( JS_LOG_LEVEL_ERROR, "fail to add TSP to DB(%d)", ret );
        goto end;
    }

    JS_addAudit( db, JS_GEN_KIND_TSP_SRV, JS_GEN_OP_MAKE_TSP, NULL );
    JS_LOG_write( JS_LOG_LEVEL_INFO, "TSP success" );

end :
    JS_BIN_reset( &binMsg );
    JS_BIN_reset( &binTST );
    JS_BIN_reset( &binP7 );
    JS_DB_resetTSP( &sTSP );
    if( pHexTSTInfo ) JS_free( pHexTSTInfo );
    if( pHexData ) JS_free( pHexData );

    return ret;
}
