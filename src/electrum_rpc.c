/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of the  nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */

#include "electrum_rpc.h"

#include "shared.h"
#include "bitcoin_common.h"
#include "merkle.h"
#include "ujson.h"
#include "util.h"
#include "logging.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <sys/param.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SOCKET_READ(C,B,N) ((C)->ssl ? SSL_read((C)->ssl, (B), N) : read((C)->client_fd, (B), N))
#define SOCKET_WRITE(C,B,N) ((C)->ssl ? SSL_write((C)->ssl, (B), N) : write((C)->client_fd, (B), N))

#define SUBSRIPTION_MODE_HEADERS    0x01
#define SUBSRIPTION_MODE_SCRIPTHASH 0x02

struct client {
	int client_fd;
	SSL *ssl;
    struct {
        int subscr_mode;
        HashesVec scriphashes;
    } subscr;
};

int srv_fd = 0;
char *srv_addr = NULL;
int srv_port = 0;
char *srv_banner = NULL;
char *donation_address = NULL;
struct client clients[MAX_CLIENTS];

static int client_add(size_t index, int fd, SSL_CTX *ssl_ctx)
{
    struct client *client = &clients[index];
    client->client_fd = fd;
    client->ssl = NULL;
    client->subscr.subscr_mode = 0;
    hashes_vec_init(&client->subscr.scriphashes);

    if (ssl_ctx) {
        client->ssl = SSL_new(ssl_ctx);
        SSL_set_fd(client->ssl, fd);
        if (SSL_accept(client->ssl) <= 0) {
            logerrf("electrum rpc: ssl connection accept error");
//            ERR_print_errors_fp(stderr);
            return -1;
        }
    }

    return 0;
}

static inline void client_remove(size_t index)
{
    struct client *client = &clients[index];
    client->client_fd = -1;
    hashes_vec_free(&client->subscr.scriphashes);

    if (client->ssl) {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
        client->ssl = NULL;
    }
}

static int scripthash_status(TXDB *dbptr, MempoolCache *mc_ptr, uint8_t *status_hash, uint8_t *scripthash)
{
    char hashstr[65];
    size_t status_str_len = 0;

    HistoryItem *history_items = NULL;
    size_t utxo_sz = txdb_history(dbptr, scripthash, &history_items, INT32_MAX);

    MempoolTxInfo *infos = NULL;
    size_t infos_sz = mempool_lookup_txs(mc_ptr, scripthash, &infos);

    if (utxo_sz + infos_sz == 0) {
        return -1;
    }

    char *status = (char*) malloc((utxo_sz + infos_sz) * 75 * sizeof(char));
    char *statusp = status;

    size_t i;
    for (i = 0; i < utxo_sz; i++) {
        bytes_to_hex_reverse(history_items[i].txhash, 32, hashstr);
        statusp += sprintf(statusp, "%s:%d:", hashstr, history_items[i].height);
    }
    for (i = 0; i < infos_sz; i++) {
        bytes_to_hex_reverse(infos[i].tx_hash, 32, hashstr);
        statusp += sprintf(statusp, "%s:%d:", hashstr, -infos[i].has_unconf_inputs);
    }

    status_str_len = strlen(status);
    if (status_str_len) {
        sha256(status_hash, status, status_str_len);
    }

    if (utxo_sz)
        free(history_items);

    if (infos_sz)
        free(infos);

    free(status);

    return status_str_len > 0 ? 0 : -1;
}

/*
        RPC METHODS
*/
int not_implemented(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    return JSONRPC_OK;
}

int blockchain_block_header(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    /*
    {
        "id":"123",
        "jsonrpc":"2.0",
        "result":"010000000508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000112ba175a1e04b14ba9e7ea5f76ab640affeef5ec98173ac9799a852fa39add320cd6649ffff001d1e2de565"
    }
    */
    jsonobj *height_param = jsonobj_list_get_at(params, 0);
    if (!height_param || !JSONOBJ_IS_INT(height_param)) {
        return JSONRPC_INVALID_PARAMS;
    }

    long height = height_param->e.int_value;

    uint8_t header[BLOCK_HEADER_SIZE];
    char headerstr[(BLOCK_HEADER_SIZE * 2) + 1];

    if (txdb_get_block_header(dbptr, header, height))
        return JSONRPC_INTERNAL_ERROR;

    bytes_to_hex(header, BLOCK_HEADER_SIZE, headerstr);
    jsonobj_set_str(response, headerstr);
    return JSONRPC_OK;
}

int blockchain_block_headers(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    /*
    {
        "id":"123",
        "jsonrpc":"2.0",
        "result":
        {
            "count":4,
            "hex":"010000000508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d000
            00000112ba175a1e04b14ba9e7ea5f76ab640affeef5ec98173ac9799a852fa39add320cd6
            649ffff001d1e2de56501000000e915d9a478e3adf3186c07c61a22228b10fd87df343c927
            82ecc052c000000006e06373c80de397406dc3d19c90d71d230058d28293614ea58d6a57f8
            f5d32f8b8ce6649ffff001d173807f8010000007330d7adf261c69891e6ab08367d957e74d
            4044bc5d9cd06d656be9700000000b8c8754fabb0ffeb04ca263a1368c39c059ca0d4af315
            1b876f27e197ebb963bc8d06649ffff001d3f596a0c010000005e2b8043bd9f8db558c284e
            00ea24f78879736f4acd110258e48c2270000000071b22998921efddf90c75ac3151cacee8
            f8084d3e9cb64332427ec04c7d562994cd16649ffff001d37d1ae86",
            "max":2016
            }
        }
    }
    */
    int ret = JSONRPC_OK;
    jsonobj *height_param = jsonobj_list_get_at(params, 0);
    jsonobj *count_param = jsonobj_list_get_at(params, 1);
    if (!height_param || !JSONOBJ_IS_INT(height_param) ||
        !count_param || !JSONOBJ_IS_INT(count_param)) {
        return JSONRPC_INVALID_PARAMS;
    }

    long height = height_param->e.int_value;
    long count = count_param->e.int_value;
	if (count > MAX_RET_HEADERS)
		count = MAX_RET_HEADERS;
		
    char *headers = (char*) malloc((BLOCK_HEADER_SIZE*count*2+1) * sizeof(char));
	char *headers_ptr = headers;
    uint8_t header[BLOCK_HEADER_SIZE];
    long i;
	
    for (i = 0; i < count; i++) {
        if (txdb_get_block_header(dbptr, header, height + i)) {
            ret = JSONRPC_INTERNAL_ERROR;
            goto blockchain_block_headers_end;
        }

        bytes_to_hex(header, BLOCK_HEADER_SIZE, headers_ptr);
		headers_ptr += (BLOCK_HEADER_SIZE * 2);
    }
    *headers_ptr = '\0';
	
    response->type = JSON_OBJ;
    jsonobj_put_int(response, "count", count);
    jsonobj_put_str(response, "hex", headers);
    jsonobj_put_int(response, "max", MAX_RET_HEADERS);

blockchain_block_headers_end:
    free(headers);

    return ret;
}

int blockchain_estimatefee(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    jsonobj *conf_target_param = jsonobj_list_get_at(params, 0);
    if (!conf_target_param || !JSONOBJ_IS_INT(conf_target_param)) {
        return JSONRPC_INVALID_PARAMS;
    }

    long conf_target = conf_target_param->e.int_value;
    double feerate = estimatesmartfee(btc_rpc_ctx, conf_target);
    if (feerate < 0.0) {
        response->type = INT;
        response->e.int_value = -1;
    } else {
        response->type = DOUBLE;
        response->e.double_value = feerate;
    }

    return JSONRPC_OK;
}

int blockchain_relay_fee(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    BitcoinNetworkInfo network_info;
    if (getnetworkinfo(btc_rpc_ctx, &network_info)) {
        return JSONRPC_INTERNAL_ERROR;
    }

    if (network_info.version < 0) {
        return JSONRPC_INTERNAL_ERROR;
    }

    response->type = DOUBLE;
    response->e.double_value = network_info.relayfee;

    return JSONRPC_OK;
}

int blockchain_scripthash_getbalance(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    jsonobj *scripthash_param = jsonobj_list_get_at(params, 0);
    if (!scripthash_param || !JSONOBJ_IS_STRING(scripthash_param)) {
        return JSONRPC_INVALID_PARAMS;
    }

    uint8_t scripthash[32];
    if (reverse_hex_to_bytes(scripthash_param->e.string_value, scripthash) != 32) {
        return JSONRPC_INVALID_PARAMS;
    }

    char hs[65];
    bytes_to_hex(scripthash, 32, hs);

	long confirmed = 0, unconfirmed = 0;
    Utxo *utxos = NULL;
    size_t utxo_sz = txdb_lookup_utxos(dbptr, scripthash, &utxos, TXDB_UNSPENT);

	size_t i;
    for (i = 0; i < utxo_sz; i++) {
		confirmed += utxos[i].value;
    }
		
    for (i = 0; i < utxo_sz; i++) {
        Utxo *utxo = &utxos[i];
        if (mempool_tx_is_input(mc_ptr, utxo->txid_prefix))
            unconfirmed -= utxo->value;
    }


    if (utxos) {
        free(utxos);
    }

    utxo_sz = mempool_lookup_utxos(mc_ptr, scripthash, &utxos);
    for (i = 0; i < utxo_sz; i++) {
        unconfirmed += utxos[i].value;
    }

    if (utxos) {
        free(utxos);
    }
	
	/* JSON response format
	 * {
	 * 	"confirmed": 103873966,
	 * 	"unconfirmed": 2368440
	 * }
	 */
    response->type = JSON_OBJ;
    jsonobj_put_int(response, "confirmed", confirmed);
    jsonobj_put_int(response, "unconfirmed", unconfirmed);
	
    return JSONRPC_OK;
}

static int scripthash_history(MempoolCache *mc_ptr, TXDB *dbptr, jsonobj *response, uint8_t *scripthash, int confirmed)
{	
    jsonobj *obj;
    HistoryItem *history_items = NULL;
    char tx_hash_str[65];
	
    response->type = LIST;
		
    size_t i;
    if (confirmed) {
        size_t utxo_sz = txdb_history(dbptr, scripthash, &history_items, HISTORY_LIMIT);

        for (i = 0; i < utxo_sz; i++) {
            bytes_to_hex(bytesinv(history_items[i].txhash, 32), 32, tx_hash_str);

            obj = jsonobj_new();
            obj->type = JSON_OBJ;
            jsonobj_put_str(obj, "tx_hash", tx_hash_str);
            jsonobj_put_int(obj, "height", history_items[i].height);

            jsonobj_list_add_jsonobj(response, obj);
        }

	}

    MempoolTxInfo *infos = NULL;
    size_t infos_sz = mempool_lookup_txs(mc_ptr, scripthash, &infos);
    for (i = 0; i < infos_sz; i++) {
        bytes_to_hex(bytesinv(infos[i].tx_hash, 32), 32, tx_hash_str);

        obj = jsonobj_new();
        obj->type = JSON_OBJ;
        jsonobj_put_int(obj, "fee", infos[i].fee);
        jsonobj_put_str(obj, "tx_hash", tx_hash_str);
        jsonobj_put_int(obj, "height", -infos[i].has_unconf_inputs);

        jsonobj_list_add_jsonobj(response, obj);
    }

    if (infos) {
        free(infos);
    }

    if (history_items) {
        free(history_items);
    }
	
    return 0;
}

int blockchain_scripthash_gethistory(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    jsonobj *scripthash_param = jsonobj_list_get_at(params, 0);
    if (!scripthash_param || !JSONOBJ_IS_STRING(scripthash_param)) {
        return JSONRPC_INVALID_PARAMS;
    }

    uint8_t scripthash[32];
    if (reverse_hex_to_bytes(scripthash_param->e.string_value, scripthash) != 32) {
        return JSONRPC_INVALID_PARAMS;
    }
	
	/* JSON response format
	 * [
	 * 	{
	 * 		"height": 200004,
	 * 		"tx_hash": "acc3758bd2a26f869fcc67d48ff30b96464d476bca82c1cd6656e7d506816412"
	 *	},
	 * 	{
	 * 		"height": 215008,
	 * 		"tx_hash": "f3e1bf48975b8d6060a9de8884296abb80be618dc00ae3cb2f6cee3085e09403"
	 * 	}
	 * ]
	 */
	
    return scripthash_history(mc_ptr, dbptr, response, scripthash, 1);;
}

int blockchain_scripthash_getmempool(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    jsonobj *scripthash_param = jsonobj_list_get_at(params, 0);
    if (!scripthash_param || !JSONOBJ_IS_STRING(scripthash_param)) {
        return JSONRPC_INVALID_PARAMS;
    }

    uint8_t scripthash[32];
    if (reverse_hex_to_bytes(scripthash_param->e.string_value, scripthash) != 32) {
        return JSONRPC_INVALID_PARAMS;
    }
	
	/* JSON response format
	 * [
	 * 	{
	 * 		"tx_hash": "45381031132c57b2ff1cbe8d8d3920cf9ed25efd9a0beb764bdb2f24c7d1c7e3",
	 * 		"height": 0, 
	 * 		"fee": 24310
	 * 	}
	 * ]
	 */

    return scripthash_history(mc_ptr, dbptr, response, scripthash, 0);
}

int blockchain_scripthash_listunspent(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
	/* JSON response format
	 * [
	 * 	{
	 * 		"tx_pos": 0,
	 * 		"value": 45318048,
	 * 		"tx_hash": "9f2c45a12db0144909b5db269415f7319179105982ac70ed80d76ea79d923ebf",
	 * 		"height": 437146
	 *  	},
	 * 	{
	 * 		"tx_pos": 0,
	 * 		"value": 919195,
	 * 		"tx_hash": "3d2290c93436a3e964cfc2f0950174d8847b1fbe3946432c4784e168da0f019f",
	 * 		"height": 441696
	 * 	}
	 * ]
     */
    jsonobj *scripthash_param = jsonobj_list_get_at(params, 0);
    if (!scripthash_param || !JSONOBJ_IS_STRING(scripthash_param)) {
        return JSONRPC_INVALID_PARAMS;
    }

    uint8_t scripthash[32];
    if (reverse_hex_to_bytes(scripthash_param->e.string_value, scripthash) != 32) {
        return JSONRPC_INVALID_PARAMS;
    }

    jsonobj *obj;
    Utxo *utxos = NULL;
    char tx_hash_str[65];

    response->type = LIST;
    
    size_t i;
    size_t utxo_sz = txdb_lookup_utxos(dbptr, scripthash, &utxos, TXDB_UNSPENT);
    for (i = 0; i < utxo_sz; i++) {
        bytes_to_hex(bytesinv(utxos[i].txhash, 32), 32, tx_hash_str);

        obj = jsonobj_new();
        obj->type = JSON_OBJ;
        jsonobj_put_str(obj, "tx_hash", tx_hash_str);
        jsonobj_put_int(obj, "height", utxos[i].height);
        jsonobj_put_int(obj, "tx_pos", utxos[i].tx_pos);
        jsonobj_put_int(obj, "value", utxos[i].value);

        jsonobj_list_add_jsonobj(response, obj);
    }

    if (utxos) {
        free(utxos);
    }

    utxo_sz = mempool_lookup_utxos(mc_ptr, scripthash, &utxos);
    for (i = 0; i < utxo_sz; i++) {
        if (mempool_tx_is_input(mc_ptr, utxos[i].txid_prefix)) // note change with filtering rules like txdb one
            continue;

        bytes_to_hex(bytesinv(utxos[i].txhash, 32), 32, tx_hash_str);

        obj = jsonobj_new();
        obj->type = JSON_OBJ;
        jsonobj_put_str(obj, "tx_hash", tx_hash_str);
        jsonobj_put_int(obj, "height", utxos[i].height);
        jsonobj_put_int(obj, "tx_pos", utxos[i].tx_pos);
        jsonobj_put_int(obj, "value", utxos[i].value);

        jsonobj_list_add_jsonobj(response, obj);
    }

    if (utxos) {
        free(utxos);
    }

    return JSONRPC_OK;
}

int blockchain_headers_subscribe(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    client->subscr.subscr_mode |= SUBSRIPTION_MODE_HEADERS;

    uint8_t header[BLOCK_HEADER_SIZE];
    char headerstr[BLOCK_HEADER_SIZE*2+1];
    
    if (txdb_get_block_header(dbptr, header, dbptr->current_height))
        return JSONRPC_ELECTRUM_UNAVAIL_INDEX;

    response->type = JSON_OBJ;
    jsonobj_put_int(response, "height", dbptr->current_height);
    bytes_to_hex(header, BLOCK_HEADER_SIZE, headerstr);
    jsonobj_put_str(response, "hex", headerstr);

    return JSONRPC_OK;
}

int blockchain_scripthash_subscribe(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    jsonobj *scripthash_param = jsonobj_list_get_at(params, 0);
    if (!scripthash_param || !JSONOBJ_IS_STRING(scripthash_param)) {
        return JSONRPC_INVALID_PARAMS;
    }

    uint8_t scripthash[32];
    if (reverse_hex_to_bytes(scripthash_param->e.string_value, scripthash) != 32) {
        return JSONRPC_INVALID_PARAMS;
    }

    client->subscr.subscr_mode |= SUBSRIPTION_MODE_SCRIPTHASH;
    if (hashes_vec_find(&client->subscr.scriphashes, scripthash) == -1) {
        hashes_vec_add(&client->subscr.scriphashes, scripthash);

        uint8_t status_hash[32];
        if (!scripthash_status(dbptr, mc_ptr, status_hash, scripthash)) {
            char status_hashstr[65];
            bytes_to_hex(status_hash, 32, status_hashstr);
            jsonobj_set_str(response, status_hashstr);
        } else {
            response->type = JSON_NULL;
        }

        return JSONRPC_OK;
    }

    return JSONRPC_INTERNAL_ERROR;
}

int blockchain_scripthash_unsubscribe(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    jsonobj *scripthash_param = jsonobj_list_get_at(params, 0);
    if (!scripthash_param || !JSONOBJ_IS_STRING(scripthash_param)) {
        return JSONRPC_INVALID_PARAMS;
    }

    uint8_t scripthash[32];
    if (reverse_hex_to_bytes(scripthash_param->e.string_value, scripthash) != 32) {
        return JSONRPC_INVALID_PARAMS;
    }

    response->type = BOOL;
    response->e.bool_value = 0;

    long index = hashes_vec_find(&client->subscr.scriphashes, scripthash);
    if (index > -1) {
        hashes_vec_remove(&client->subscr.scriphashes, index);
        response->e.bool_value = 1;
    }

    return JSONRPC_OK;
}

int blockchain_transaction_broadcast(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    jsonobj *hex_param = jsonobj_list_get_at(params, 0);
    if (!hex_param || !JSONOBJ_IS_STRING(hex_param)) {
        return JSONRPC_INVALID_PARAMS;
    }

    char txhash[65];
    if (sendrawtransaction(btc_rpc_ctx, hex_param->e.string_value, -1.0, txhash)) {
        return 1;
    }

    /* Sets the status to updated only if the RPC caqll has been succeded, otherwise there is nothing to update */
    sync_thread_notify_update(sync_thread_ctx);

    jsonobj_set_str(response, txhash);
    return JSONRPC_OK;
}

int blockchain_transaction_get(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    int verbose = 0;
    jsonobj *txid_param = jsonobj_list_get_at(params, 0);
    jsonobj *verbose_param = jsonobj_list_get_at(params, 1);
    if (!txid_param || !JSONOBJ_IS_STRING(txid_param)) {
        return JSONRPC_INVALID_PARAMS;
    }

    if (verbose_param) {
        if (JSONOBJ_IS_BOOL(verbose_param)) {
            verbose = verbose_param->e.bool_value;
        } else {
            return JSONRPC_INVALID_PARAMS;
        }
    }

    int respo = getrawtransaction_json(btc_rpc_ctx, txid_param->e.string_value, verbose, response);
    if (respo)
        logdebugf("getrawtx err: %d: %s", respo, jsonrpc_strerror(respo));
    return respo;

}

int blockchain_transaction_get_merkle(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    /*
    {
      "merkle":
      [
        "713d6c7e6ce7bbea708d61162231eaa8ecb31c4c5dd84f81c20409a90069cb24",
        "03dbaec78d4a52fbaf3c7aa5d3fccd9d8654f323940716ddf5ee2e4bda458fde",
        "e670224b23f156c27993ac3071940c0ff865b812e21e0a162fe7a005d6e57851",
        "369a1619a67c3108a8850118602e3669455c70cdcdb89248b64cc6325575b885",
        "4756688678644dcb27d62931f04013254a62aeee5dec139d1aac9f7b1f318112",
        "7b97e73abc043836fd890555bfce54757d387943a6860e5450525e8e9ab46be5",
        "61505055e8b639b7c64fd58bce6fc5c2378b92e025a02583303f69930091b1c3",
        "27a654ff1895385ac14a574a0415d3bbba9ec23a8774f22ec20d53dd0b5386ff",
        "5312ed87933075e60a9511857d23d460a085f3b6e9e5e565ad2443d223cfccdc",
        "94f60b14a9f106440a197054936e6fb92abbd69d6059b38fdf79b33fc864fca0",
        "2d64851151550e8c4d337f335ee28874401d55b358a66f1bafab2c3e9f48773d"
      ],
      "block_height": 450538,
      "pos": 710
    }
    */

    uint8_t hash[32];
    char hashstr[65];
    jsonobj *txhash_param = jsonobj_list_get_at(params, 0);
    jsonobj *height_param = jsonobj_list_get_at(params, 1);
    if (!txhash_param || !JSONOBJ_IS_STRING(txhash_param)) {
        return JSONRPC_INVALID_PARAMS;
    }

    if (reverse_hex_to_bytes(txhash_param->e.string_value, hash) != 32) {
        return JSONRPC_INVALID_PARAMS;
    }

    if (!height_param || !JSONOBJ_IS_INT(height_param)) {
        return JSONRPC_INVALID_PARAMS;
    }


    HashesVec hashes;
    hashes_vec_init(&hashes);

    if (txdb_lookup_txhashes_at_height(dbptr, &hashes, height_param->e.int_value))
        return JSONRPC_INTERNAL_ERROR;

    long tx_pos = hashes_vec_find(&hashes, hash);
    if (tx_pos < 0) {
        hashes_vec_free(&hashes);
        return JSONRPC_INTERNAL_ERROR;
    }

    HashesVec branches;
    hashes_vec_init(&branches);
    if (merkle_branch_and_root(NULL, &branches, &hashes, tx_pos, 0)) {
        hashes_vec_free(&hashes);
        return JSONRPC_INTERNAL_ERROR;
    }

    response->type = JSON_OBJ;
    jsonobj *branches_obj = jsonobj_put_list(response, "merkle");
    jsonobj_put_int(response, "block_height", height_param->e.int_value);
    jsonobj_put_int(response, "pos", tx_pos);

    long i;
    for (i = 0; i < branches.size; i++) {
        bytes_to_hex_reverse(branches.v[i], 32, hashstr);
        jsonobj_list_add_str(branches_obj, hashstr);
    }

    hashes_vec_free(&hashes);
    hashes_vec_free(&branches);

    return JSONRPC_OK;
}

int blockchain_transaction_id_from_pos(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    /*
    When *merkle* is :const:`false`::

      "fc12dfcb4723715a456c6984e298e00c479706067da81be969e8085544b0ba08"

    When *merkle* is :const:`true`::

      {
        "tx_hash": "fc12dfcb4723715a456c6984e298e00c479706067da81be969e8085544b0ba08",
        "merkle":
        [
          "928c4275dfd6270349e76aa5a49b355eefeb9e31ffbe95dd75fed81d219a23f8",
          "5f35bfb3d5ef2ba19e105dcd976928e675945b9b82d98a93d71cbad0e714d04e",
          "f136bcffeeed8844d54f90fc3ce79ce827cd8f019cf1d18470f72e4680f99207",
          "6539b8ab33cedf98c31d4e5addfe40995ff96c4ea5257620dfbf86b34ce005ab",
          "7ecc598708186b0b5bd10404f5aeb8a1a35fd91d1febbb2aac2d018954885b1e",
          "a263aae6c470b9cde03b90675998ff6116f3132163911fafbeeb7843095d3b41",
          "c203983baffe527edb4da836bc46e3607b9a36fa2c6cb60c1027f0964d971b29",
          "306d89790df94c4632d652d142207f53746729a7809caa1c294b895a76ce34a9",
          "c0b4eff21eea5e7974fe93c62b5aab51ed8f8d3adad4583c7a84a98f9e428f04",
          "f0bd9d2d4c4cf00a1dd7ab3b48bbbb4218477313591284dcc2d7ca0aaa444e8d",
          "503d3349648b985c1b571f59059e4da55a57b0163b08cc50379d73be80c4c8f3"
        ]
      }
    */

    int merkle = 0;
    long pos = -1;
    jsonobj *height_param = jsonobj_list_get_at(params, 0);
    jsonobj *pos_param = jsonobj_list_get_at(params, 1);
    jsonobj *merkle_param = jsonobj_list_get_at(params, 2);
    if (!height_param || !JSONOBJ_IS_INT(height_param)) {
        return JSONRPC_INVALID_PARAMS;
    }
    if (pos_param && JSONOBJ_IS_INT(pos_param)) {
        pos = pos_param->e.int_value;
    } else {
        return JSONRPC_INVALID_PARAMS;
    }

    if (merkle_param) {
        if (JSONOBJ_IS_BOOL(merkle_param)) {
            merkle = merkle_param->e.bool_value;
        } else {
            return JSONRPC_INVALID_PARAMS;
        }
    }

    HashesVec hashes;
    hashes_vec_init(&hashes);

    if (txdb_lookup_txhashes_at_height(dbptr, &hashes, height_param->e.int_value))
        return JSONRPC_INTERNAL_ERROR;

    if (pos >= hashes.size) {
        hashes_vec_free(&hashes);
        return JSONRPC_INTERNAL_ERROR;
    }

    char hashstr[65];
    bytes_to_hex_reverse(hashes.v[pos], 32, hashstr);

    if (merkle) {
        HashesVec branches;
        hashes_vec_init(&branches);
        if (merkle_branch_and_root(NULL, &branches, &hashes, pos, 0)) {
            hashes_vec_free(&hashes);
            return JSONRPC_INTERNAL_ERROR;
        }

        response->type = JSON_OBJ;
        jsonobj_put_str(response, "tx_hash", hashstr);
        jsonobj *branches_obj = jsonobj_put_list(response, "merkle");

        long i;
        for (i = 0; i < branches.size; i++) {
            bytes_to_hex_reverse(branches.v[i], 32, hashstr);
            jsonobj_list_add_str(branches_obj, hashstr);
        }

        hashes_vec_free(&branches);
    } else {
        jsonobj_set_str(response, hashstr);
    }

    hashes_vec_free(&hashes);

    return 0;
}

int mempool_get_fee_histogram(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    response->type = LIST;

    size_t i;
    jsonobj *fe = NULL;

	FeeHistogram *hist = &mc_ptr->fee_histogram;
    for (i = 0; i < hist->size; i++) {
        fe = jsonobj_put_list(NULL, NULL);
        jsonobj_list_add_int(fe, hist->hist[i].rate);
        jsonobj_list_add_int(fe, hist->hist[i].vsize);
		
        jsonobj_list_add_list(response, fe);
    }

    return JSONRPC_OK;
}
/********************************************************************************************/

int server_ping(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    response->type = JSON_NULL;
	return 0;
}

static int protocol_version_atoi(const char *s)
{
    int mf = 100;
    int version = 0;
    while (*s != '\0') {
        if (isdigit(*s)) {
            version += mf * (*s - '0');
            mf /= 10;
        }
        s++;
    }

    return version;
}


int server_version(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    if (JSONOBJ_LIST_SIZE(params) < 2)
        return JSONRPC_INVALID_PARAMS;

    jsonobj *protocol_version = jsonobj_list_get_at(params, 1);
    int client_min = 0;
    int client_max = 0;
    int version = 0;
    char version_str[6];

    if (JSONOBJ_IS_LIST(protocol_version)) {
        client_min = protocol_version_atoi(jsonobj_list_get_at(protocol_version, 0)->e.string_value);
        client_max = protocol_version_atoi(jsonobj_list_get_at(protocol_version, 1)->e.string_value);
    } else if (JSONOBJ_IS_STRING(protocol_version)) {
        client_max = client_min = protocol_version_atoi(protocol_version->e.string_value);
    } else {
        return JSONRPC_INVALID_PARAMS;
    }

    version = MIN(client_max, ELECTRUM_PROTOCOL_MAX_NUMBER);
    if (MAX(client_min, ELECTRUM_PROTOCOL_MIN_NUMBER) > version) {
        return JSONRPC_ELECTRUM_BAD_REQUEST;
    }

	response->type = LIST;
    jsonobj_list_add_str(response, ELECTRUMSRVD_SERVER_NAME);

    if (version % 10) {
        snprintf(version_str, 6, "%d.%d.%d", version / 100, (version / 10) % 10, version % 10);
    } else {
        snprintf(version_str, 6, "%d.%d", version / 100, (version / 10) % 10);
    }
    jsonobj_list_add_str(response, ELECTRUM_PROTOCOL_MAX);
    return JSONRPC_OK;
}

int server_features(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    /*
    {
        "genesis_hash": "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
        "hosts": {"14.3.140.101": {"tcp_port": 51001, "ssl_port": 51002}},
        "protocol_max": "1.0",
        "protocol_min": "1.0",
        "pruning": null,
        "server_version": "ElectrumX 1.0.17",
        "hash_function": "sha256"
    }
    */
    response->type = JSON_OBJ;
    jsonobj_put_str(response, "genesis_hash", "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
    jsonobj *o = jsonobj_put_jsonobj(response, "hosts", NULL);
    o = jsonobj_put_jsonobj(o, srv_addr, NULL);
    jsonobj_put_int(o, "tcp_port", srv_port);
    jsonobj_put_null(o, "ssl_port");
    jsonobj_put_null(response, "pruning");
    jsonobj_put_str(response, "protocol_max", ELECTRUM_PROTOCOL_MAX);
    jsonobj_put_str(response, "protocol_min", ELECTRUM_PROTOCOL_MIN);
    jsonobj_put_str(response, "server_version", ELECTRUMSRVD_SERVER_NAME);
    jsonobj_put_str(response, "hash_function", "sha256");

    return JSONRPC_OK;
}

int server_banner(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    /*
    result
    "Welcome to Electrum!"
    */
    jsonobj_set_str(response, srv_banner);
    return 0;
}

int server_donation_address(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    /*
    result
    "1BWwXJH3q6PRsizBkSGm2Uw4Sz1urZ5sCj"
    */
    jsonobj_set_str(response, donation_address);
    return 0;
}

int server_peers_subscribe(MempoolCache *mc_ptr, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, jsonobj *params, jsonobj *response, struct client *client)
{
    response->type = LIST;

    return JSONRPC_OK;
}

/********************************************************************************************************************************/
/*
    Notify back clients
*/
int electrum_rpc_height_notify(TXDB *dbptr, uint32_t height)
{
    /*
        {
          "height": 520481,
          "hex": "00000020890208a0ae3a3892aa047c5468725846577cfcd9b512b50000000000000000005dc2b02f2d297a9064ee103036c14d678f9afc7e3d9409cf53fd58b82e938e8ecbeca05a2d2103188ce804c4"
        }
    */

    uint8_t header[BLOCK_HEADER_SIZE];
    char header_hex[BLOCK_HEADER_SIZE*2+1];
    if (txdb_get_block_header(dbptr, header, height)) {
        return 1;
    }

    jsonobj *resp = jsonobj_put_jsonobj(NULL, "", NULL);
    jsonobj_put_int(resp, "height", height);

    bytes_to_hex(header, BLOCK_HEADER_SIZE, header_hex);
    jsonobj_put_str(resp, "hex", header_hex);

    jsonobj *payload = jsonobj_put_jsonobj(NULL, "", NULL);
    jsonobj_put_str(payload, "jsonrpc", "2.0");
    jsonobj_put_str(payload, "method", "blockchain.headers.subscribe");
    jsonobj *params = jsonobj_put_list(payload, "params");
    jsonobj_list_add_jsonobj(params, resp);

    char *payload_str = jsonobj_to_str(payload);
    logdebugf("electrum rpc server: notify height: %s", payload_str);

    size_t payload_sz = strlen(payload_str);
    payload_str[payload_sz++] = '\n';
    jsonobj_free(payload);

    size_t i;
    struct client *client = NULL;
    for (i = 0; i < MAX_CLIENTS; i++) {
        client = &clients[i];
        if (client->client_fd > -1 && client->subscr.subscr_mode & SUBSRIPTION_MODE_HEADERS)
            SOCKET_WRITE(client, payload_str, payload_sz);
    }

    free(payload_str);

    return 0;
}

int electrum_rpc_new_scripthashes_notify(TXDB *dbptr, MempoolCache *mc_ptr, const HashesVec *new_scripthashes)
{
    ssize_t i;
    size_t j, payload_sz;

    char *payload_str;
    uint8_t status_hash[32];
    char hashstr[65];
    struct client *client = NULL;
    for (i = 0; i < new_scripthashes->size; i++) {
        payload_str = NULL;
        payload_sz = 0;

        for (j = 0; j < MAX_CLIENTS; j++) {
            client = &clients[j];
            if (client->client_fd > -1 &&
                (client->subscr.subscr_mode & SUBSRIPTION_MODE_SCRIPTHASH)
                && hashes_vec_find(&client->subscr.scriphashes, new_scripthashes->v[i]) != -1) {

                if (!payload_str && !scripthash_status(dbptr, mc_ptr, status_hash, new_scripthashes->v[i])) {
                    jsonobj *payload = jsonobj_put_jsonobj(NULL, "", NULL);
                    jsonobj_put_str(payload, "jsonrpc", "2.0");
                    jsonobj_put_str(payload, "method", "blockchain.scripthash.subscribe");
                    jsonobj *params = jsonobj_put_list(payload, "params");

                    bytes_to_hex_reverse(new_scripthashes->v[i], 32, hashstr);
                    jsonobj_list_add_str(params, hashstr);

                    bytes_to_hex(status_hash, 32, hashstr);
                    jsonobj_list_add_str(params, hashstr);

                    payload_str = jsonobj_to_str(payload);
                    logdebugf("electrum rpc server: notify scripthash status: %s", payload_str);

                    payload_sz = strlen(payload_str);
                    payload_str[payload_sz++] = '\n';
                    jsonobj_free(payload);
                }

                SOCKET_WRITE(client, payload_str, payload_sz);
            }

        }

        if (payload_str)
            free(payload_str);
    }

    return 0;
}

/***************************************************************

                        Rpc Server

****************************************************************/

struct rpc_func_handler {
	char *method;
    int (*funptr)(MempoolCache*, BitcoinRpcCtx*, TXDB*, SyncThreadCtx*, jsonobj*, jsonobj*, struct client*);
};

const struct rpc_func_handler rpc_handlers[] = {
    {.method = "blockchain.block.header", .funptr = &blockchain_block_header},
    {.method = "blockchain.block.headers", .funptr = &blockchain_block_headers},
    {.method = "blockchain.estimatefee", .funptr = &blockchain_estimatefee},
    {.method = "blockchain.headers.subscribe", .funptr = &blockchain_headers_subscribe},
    {.method = "blockchain.relayfee", .funptr = &blockchain_relay_fee},
    {.method = "blockchain.scripthash.get_balance", .funptr = &blockchain_scripthash_getbalance},
    {.method = "blockchain.scripthash.get_history", .funptr = &blockchain_scripthash_gethistory},
    {.method = "blockchain.scripthash.get_mempool", .funptr = &blockchain_scripthash_getmempool},
    {.method = "blockchain.scripthash.listunspent", .funptr = &blockchain_scripthash_listunspent},
    {.method = "blockchain.scripthash.subscribe", .funptr = &blockchain_scripthash_subscribe},
    {.method = "blockchain.scripthash.unsubscribe", .funptr = &blockchain_scripthash_unsubscribe},
    {.method = "blockchain.transaction.broadcast", .funptr = &blockchain_transaction_broadcast},
    {.method = "blockchain.transaction.get", .funptr = &blockchain_transaction_get},
    {.method = "blockchain.transaction.get_merkle", .funptr = &blockchain_transaction_get_merkle},
    {.method = "blockchain.transaction.id_from_pos", .funptr = &blockchain_transaction_id_from_pos},
    {.method = "mempool.get_fee_histogram", .funptr = &mempool_get_fee_histogram},
	
    {.method = "server.peers.subscribe", .funptr = &server_peers_subscribe},
    {.method = "server.ping", .funptr = &server_ping},
    {.method = "server.version", .funptr = &server_version},
    {.method = "server.features", .funptr = &server_features},
    {.method = "server.banner", .funptr = &server_banner},
    {.method = "server.donation_address", .funptr = &server_donation_address}
};

const int RPC_HANDLERS_SIZE = (sizeof(rpc_handlers) / sizeof(struct rpc_func_handler));

static int handle_request(struct client *client, MempoolCache *mcp, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx)
{
    int nread = 0;

    size_t capacity = 4096 + 1;
    size_t req_str_sz = 0, resp_str_sz = 0;
    char *req_buf = (char*) malloc(capacity * sizeof(char));
    char *req_str = NULL;
    char *resp_str = NULL;
    char *req_savep = NULL;

    jsonobj *request = NULL;
    jsonobj *response = NULL;
    jsonobj *result = NULL;
    jsonobj *e = NULL;
    jsonobj *id = NULL;
    int rpc_errno = 0;
    char *method = NULL;
    int i;

    while ((nread = SOCKET_READ(client, req_buf + req_str_sz, 4096)) > 0) {
        req_str_sz += nread;
        if (nread < 4096) {
            break;
        }
        if (capacity <= (req_str_sz + 4096)) {
            capacity *= 2;
            req_buf = (char*) realloc(req_buf, capacity * sizeof(char));
        }
    }
    if (!req_str_sz) {
        free(req_buf);
        return -1;
    }
    req_buf[req_str_sz] = '\0';
    req_savep = req_buf;

    /*
     * Sometimes electrum sends its requests in batch '\n' separated
     * so we need to cycle through requests using strtok_r
    */
    while ((req_str = strtok_r(req_savep, "\n", &req_savep))) {
        logdebugf("electrum rpc server: request %s", req_str);

        request = jsonobj_new();
        response = jsonobj_put_jsonobj(NULL, "", NULL);
        result = jsonobj_new();
        id = NULL;

        if (jsonobj_parse_str(request, req_str)) {
            rpc_errno = JSONRPC_PARSE_ERROR;
            goto send_error;
        }

        if (!jsonobj_lookup(request, "jsonrpc")) {
            rpc_errno = JSONRPC_INVALID_REQ;
            goto send_error;
        }

        id = jsonobj_remove(request, "id");
        if (!id) {
            rpc_errno = JSONRPC_INVALID_REQ;
            goto send_error;
        }

        e = jsonobj_lookup(request, "method");
        if (!e) {
            rpc_errno = JSONRPC_INVALID_REQ;
            goto send_error;
        }
        method = e->e.string_value;

        e = jsonobj_lookup(request, "params");
        for (i = 0; i < RPC_HANDLERS_SIZE; i++) {
            if (!strcmp(rpc_handlers[i].method, method)) {
                rpc_errno = rpc_handlers[i].funptr(mcp, btc_rpc_ctx, dbptr, sync_thread_ctx, e, result, client);
                if (rpc_errno)
                    goto send_error;

                jsonobj_put(response, "result", result);
                goto send_response;
            }
        }
        rpc_errno = JSONRPC_NO_METHOD;

send_error:
        logerrf("electrum_rpc: error: method=%s, error_code=%d, error_message=%s", method, rpc_errno, jsonrpc_strerror(rpc_errno));
        e = jsonobj_put_jsonobj(response, "error", NULL);
        jsonobj_put_int(e, "code", rpc_errno);
        jsonobj_put_str(e, "message", jsonrpc_strerror(rpc_errno));


send_response:
        jsonobj_put_str(response, "jsonrpc", "2.0");
        if (id) {
            jsonobj_put(response, "id", id);
        } else {
            jsonobj_put_null(response, "id");
        }

        resp_str = jsonobj_to_str(response);
        logdebugf("electrum rpc server: send response %s", resp_str);

        resp_str_sz = strlen(resp_str);
        resp_str[resp_str_sz++] = '\n';

        if (SOCKET_WRITE(client, resp_str, resp_str_sz) < 0) {
            logerrf("electrum rpc server: socket write fail: %s", strerror(errno));
            rpc_errno = -1;
        }

        free(resp_str);
        jsonobj_free(response);
        jsonobj_free(request);
    }
    free(req_buf);

    return rpc_errno;
}

int electrum_server_init(char *pub_addr, int port, char *donation_addr, char *banner)
{
    if (!pub_addr)
        return -1;

    srv_addr = pub_addr;
    srv_port = port;
    donation_address = donation_addr;
    srv_banner = banner;

    size_t i;
    for (i = 0; i < MAX_CLIENTS; i++) {
        client_add(i, -1, NULL);
    }

    return 0;
}

static SSL_CTX *create_ssl_ctx(const char *cert_path, const char *priv_key_path)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_DH_USE);
    if (SSL_CTX_use_certificate_file(ssl_ctx, cert_path, SSL_FILETYPE_PEM) != 1) {
        logerrf("electrum rpc: unable to load ssl certificate file %s", cert_path);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, priv_key_path, SSL_FILETYPE_PEM) != 1) {
        logerrf("electrum rpc: unable to load ssl private key file %s", priv_key_path);
        return NULL;
    }

    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        logerrf("electrum rpc: unable to load ssl certficate and private key mismatch", priv_key_path);
        return NULL;
    }

    return ssl_ctx;
}

int electrum_server_start(MempoolCache *mcp, BitcoinRpcCtx *btc_rpc_ctx, TXDB *dbptr, SyncThreadCtx *sync_thread_ctx, Configs *cfg)
{
    int sockfd, connfd, len;
    SSL_CTX *ssl_ctx = NULL;
    struct sockaddr_in servaddr, cli;

    const char *addr = cfg->listen_addr;
    int port = cfg->listen_port;

    // Create SSL context
    if (cfg->listen_ssl) {
        if ((ssl_ctx = create_ssl_ctx(cfg->ssl_cert_file, cfg->ssl_priv_key_file)) == NULL)
            return -1;
    }

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        logerrf("electrum rpc server: socket creation failed");
        return -1;
    }

    memset(&servaddr, 0, sizeof(servaddr));

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        logerrf("electrum rpc server: error: %s", strerror(errno));
        return -1;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
        logerrf("electrum rpc server: error: %s", strerror(errno));
        return -1;
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(addr);
    servaddr.sin_port = htons(port);

    if ((bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0) {
        logerrf("electrum rpc server: error: %s", strerror(errno));
        return -1;
    }

    if ((listen(sockfd, 5)) != 0) {
        logerrf("electrum rpc server: error: %s", strerror(errno));
        exit(0);
    }

    loginfof("electrum rpc server: socket is listening on %s:%d", addr, port);

    len = sizeof(cli);

    nfds_t nfds = MAX_CLIENTS+1;
    nfds_t i, clients_no = 0;
    struct pollfd fds[nfds];
    for (i = 0; i < nfds; i++) {
        fds[i].events = 0;
        fds[i].revents = 0;
        fds[i].fd = -1;
    }

    fds[0].fd = sockfd;
    fds[0].events = POLLIN | POLLPRI;

    while (is_electrumsrv_running() && (poll(fds, nfds, 300)) != -1) {
        if (fds[0].revents & POLLIN) {
            if ((connfd = accept(sockfd, (struct sockaddr*) &cli, (socklen_t*) &len)) < 0) {
                continue;
            }

            if (clients_no <= MAX_CLIENTS) {
                for (i = 1; i < nfds; i++) {
                    if (fds[i].fd == -1) {
                        if (client_add(i - 1, connfd, ssl_ctx)) {
                            loginfof("electrum rpc server: connection error %s:%d",
                                      inet_ntoa(cli.sin_addr),
                                      ntohs(cli.sin_port)
                                     );
                        } else {
                            fds[i].fd = connfd;
                            fds[i].events = POLLIN | POLLHUP | POLLPRI;
                            fds[i].revents = 0;
                            clients_no++;

                            loginfof("electrum rpc server: new connection: accept %s:%d",
                                      inet_ntoa(cli.sin_addr),
                                      ntohs(cli.sin_port)
                                      );
                        }

                        break;
                    }
                }
            } else {
                loginfof("electrum rpc server: new connection: limit reached rejected");
                close(connfd);
            }
        }

        for (i = 1; i < nfds; i++) {
            short revents = fds[i].revents;
            if (fds[i].fd > 0 && revents > 0) {
                if (revents & POLLIN) {
                    int error = handle_request(&clients[i - 1], mcp, btc_rpc_ctx, dbptr, sync_thread_ctx);
                    if (error == -1)
                        revents = POLLERR;
                }

                if ((revents & POLLERR) || (revents & POLLHUP)) {
                    //handle connection close
                    loginfof("electrum rpc server: connection removed");
                    client_remove(i - 1);

                    close(fds[i].fd);
                    fds[i].fd = -1;
                    fds[i].events = 0;
                    fds[i].revents = 0;
                    clients_no--;
                }
            }
        }
    }

    if (ssl_ctx)
        SSL_CTX_free(ssl_ctx);

    close(sockfd);
    return 0;
}
