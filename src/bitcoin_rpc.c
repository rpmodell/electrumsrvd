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

#include "bitcoin_rpc.h"

#include "util.h"
#include "logging.h"

#include <curl/curl.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

struct largebuf {
	size_t size;
	char *ptr;
};

static size_t write_response(void *ptr, size_t size, size_t nmemb, struct largebuf *buf)
{
	size_t bufsize = size * nmemb;
	if (!buf->ptr)
		buf->ptr = (char*) malloc(bufsize * sizeof(char));
	else
		buf->ptr = (char*) realloc(buf->ptr, (bufsize + buf->size) * sizeof(char));

	memcpy(buf->ptr + buf->size, ptr, bufsize);
    buf->size += bufsize;
	return bufsize;
}

int curl_core_rpc_req(BitcoinRpcCtx *ctx, const char *method, jsonobj *args, jsonobj *result)
{
	char *request_buf;
	struct largebuf response_buf;
	memset(&response_buf, 0, sizeof(struct largebuf));
	int ret = 0;
	struct curl_slist *hs = NULL;
	
	char id[24];
	memset(id, '\0', 24);
	sprintf(id, "%02x%02x%02x%02x%02x%02x", rand() % 256, rand() % 256, rand() % 256,  rand() % 256, rand() % 256, rand() % 256);

	jsonobj *req = jsonobj_put_jsonobj(NULL, "", NULL);
	jsonobj_put_str(req, "jsonrpc", "2.0");
	jsonobj_put_str(req, "id", id);
	jsonobj_put_str(req, "method", method);
    jsonobj_put(req, "params", args);
        
    request_buf = jsonobj_to_str(req);

    jsonobj_free(req);

	CURL *curl;
	CURLcode curl_ret = CURLE_OK;

	jsonobj *obj = NULL;
	jsonobj *resp = jsonobj_new();

	curl = curl_easy_init();
	if(!curl) {
		ret = -1;
		goto rpc_end;
	}

	hs = curl_slist_append(hs, "Content-Type: application/json");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hs);
	curl_easy_setopt(curl, CURLOPT_URL, ctx->rpchost);
	curl_easy_setopt(curl, CURLOPT_USERPWD, ctx->userpw);

	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_buf);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl/7.38.0");
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
	curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_buf);

	curl_ret = curl_easy_perform(curl);
		
    //assert(curl_ret == CURLE_OK);
	curl_slist_free_all(hs);
	curl_easy_cleanup(curl);

	if (curl_ret != CURLE_OK) {
		ret = -2;
		logerrf("curl request failed: %s", curl_easy_strerror(curl_ret));
		goto rpc_end;
	}

    ret = jsonobj_parse_str(resp, response_buf.ptr);
    if (ret) {
        logdebugf("json parse fail: %d", ret);
		ret = -3;
		goto rpc_end;	
    }
	
	jsonobj *id2 = jsonobj_lookup(resp, "id");
	if (!id2) {
		ret = -4;
		goto rpc_end;
	}

	assert(id2->type == STRING);
    if (strcmp(id2->e.string_value, id)) {
		ret = -5;
		goto rpc_end;
	}

	obj = jsonobj_lookup(resp, "error");
	if (obj && obj->type != JSON_NULL) {
        ret = JSONRPC_INTERNAL_ERROR;
		jsonobj *e = jsonobj_lookup(obj, "code");
		if (e)
            ret = e->e.int_value;
        const char *msg = jsonrpc_strerror(ret);
		if ((e = jsonobj_lookup(obj, "message")))
            msg = e->e.string_value;
		logerrf("bitcoin daemon rpc response error: code=%d, msg=%s", ret, msg); 
		goto rpc_end;
	} 

	obj = jsonobj_remove(resp, "result");
	if (!obj) {
        ret = -6;
		goto rpc_end;
	}
	memcpy(result, obj, sizeof(jsonobj));
    free(obj);

rpc_end:
	if (response_buf.ptr)
		free(response_buf.ptr);
	free(request_buf);
    jsonobj_free(resp);
	return ret;
}

int bitcoin_rpc_init(BitcoinRpcCtx *ctx, const char *host, const char *auth)
{
    if (!host || !auth)
        return -1;

    ctx->rpchost = (char*) host;
    ctx->userpw = (char*) auth;
    return 0;
}

/*
{                                         (json object) // we only care about chain for now
  "chain" : "str",                        (string) current network name (main, test, regtest)
  "blocks" : n,                           (numeric) the height of the most-work fully-validated chain. The genesis block has height 0
  "headers" : n,                          (numeric) the current number of headers we have validated
  "bestblockhash" : "str",                (string) the hash of the currently best block
  "difficulty" : n,                       (numeric) the current difficulty
  "mediantime" : n,                       (numeric) median time for the current best block
  "verificationprogress" : n,             (numeric) estimate of verification progress [0..1]
  "initialblockdownload" : true|false,    (boolean) (debug information) estimate of whether this node is in Initial Block Download mode
  "chainwork" : "hex",                    (string) total amount of work in active chain, in hexadecimal
  "size_on_disk" : n,                     (numeric) the estimated size of the block and undo files on disk
  "pruned" : true|false,                  (boolean) if the blocks are subject to pruning
  "pruneheight" : n,                      (numeric) lowest-height complete block stored (only present if pruning is enabled)
  "automatic_pruning" : true|false,       (boolean) whether automatic pruning is enabled (only present if pruning is enabled)
  "prune_target_size" : n,                (numeric) the target size used by pruning (only present if automatic pruning is enabled)
  .......
*/
int getblockchaininfo(BitcoinRpcCtx *ctx, char *chain)
{
    jsonobj *args = jsonobj_new();
    jsonobj *result = jsonobj_new();
    args->type = LIST;

    int ret = curl_core_rpc_req(ctx, "getblockchaininfo", args, result);
    if (ret) {
        logdebugf("ERROR GETTING CHAIN INFO->0!!! %d", ret);
        goto getblockchaininfo_end;
    }

    assert(result->type == JSON_OBJ);

    jsonobj *e = jsonobj_lookup(result, "chain");
    if ((ret = (e == NULL))) {
        logdebugf("ERROR GETTING CHAIN INFO!!!");
        goto getblockchaininfo_end;
    }

    strncpy(chain, e->e.string_value, 9);

getblockchaininfo_end:
    jsonobj_free(result);
    return ret;
}

/*
 * Rpc Method getnetworkinfo
 *
 * parameters []
 *
 * returns:
 * {                                                    (json object)
      "version" : n,                                     (numeric) the server version
      "subversion" : "str",                              (string) the server subversion string
      "protocolversion" : n,                             (numeric) the protocol version
      "localservices" : "hex",                           (string) the services we offer to the network
      "localservicesnames" : [                           (json array) the services we offer to the network, in human-readable form
        "str",                                           (string) the service name
        ...
      ],
      "localrelay" : true|false,                         (boolean) true if transaction relay is requested from peers
      "timeoffset" : n,                                  (numeric) the time offset
      "connections" : n,                                 (numeric) the total number of connections
      "connections_in" : n,                              (numeric) the number of inbound connections
      "connections_out" : n,                             (numeric) the number of outbound connections
      "networkactive" : true|false,                      (boolean) whether p2p networking is enabled
      "networks" : [                                     (json array) information per network
        {                                                (json object)
          "name" : "str",                                (string) network (ipv4, ipv6 or onion)
          "limited" : true|false,                        (boolean) is the network limited using -onlynet?
          "reachable" : true|false,                      (boolean) is the network reachable?
          "proxy" : "str",                               (string) ("host:port") the proxy that is used for this network, or empty if none
          "proxy_randomize_credentials" : true|false     (boolean) Whether randomized credentials are used
        },
        ...
      ],
      "relayfee" : n,                                    (numeric) minimum relay fee for transactions in BTC/kB
      "incrementalfee" : n,                              (numeric) minimum fee increment for mempool limiting or BIP 125 replacement in BTC/kB
      "localaddresses" : [                               (json array) list of local addresses
        {                                                (json object)
          "address" : "str",                             (string) network address
          "port" : n,                                    (numeric) network port
          "score" : n                                    (numeric) relative score
        },
        ...
      ],
      "warnings" : "str"                                 (string) any network and blockchain warnings
    }
 */
int getnetworkinfo(BitcoinRpcCtx *ctx, BitcoinNetworkInfo *info)
{
    jsonobj *args = jsonobj_new();
    jsonobj *result = jsonobj_new();
    args->type = LIST;

    int ret = curl_core_rpc_req(ctx, "getnetworkinfo", args, result);
    if (ret)
        goto getnetworkinfo_end;

    assert(result->type == JSON_OBJ);

    jsonobj *e = jsonobj_lookup(result, "version");
    if ((ret = (e == NULL)))
        goto getnetworkinfo_end;

    info->version = e->e.int_value;

    e = jsonobj_lookup(result, "subversion");
    if ((ret = (e == NULL)))
        goto getnetworkinfo_end;

    strcpy(info->subversion, e->e.string_value);

    e = jsonobj_lookup(result, "protocolversion");
    if ((ret = (e == NULL)))
        goto getnetworkinfo_end;

    info->protocolversion = e->e.int_value;

    e = jsonobj_lookup(result, "relayfee");
    if ((ret = (e == NULL)))
        goto getnetworkinfo_end;

    info->relayfee = e->e.double_value;

getnetworkinfo_end:
    jsonobj_free(result);
    return ret;
}

/*
 * Rpc Method getblockcount
 *
 * parameters 	[]
 *
 * returns:
 * 	n	The current block count
 */
int getblockcount(BitcoinRpcCtx *ctx, long *height)
{
	jsonobj *args = jsonobj_new();
	jsonobj *result = jsonobj_new();
	args->type = LIST;

	int ret = curl_core_rpc_req(ctx, "getblockcount", args, result);
	if (ret)
		goto getblockcount_end;

    assert(result->type == INT);
    (*height) = result->e.int_value;

getblockcount_end:
	jsonobj_free(result);
	return ret;
}

/*
 * Rpc Method getblockhash
 *
 * parameters:
 * 	height	The height index
 *
 * returns:
 * 	hash	The block hash as hex string
 */
int getblockhash(BitcoinRpcCtx *ctx, long blkno, char *hash)
{
	if (!hash) return -1;

	jsonobj *args = jsonobj_new();
	jsonobj *result = jsonobj_new();
	args->type = LIST;
	jsonobj_list_add_int(args, blkno);	

	int ret = curl_core_rpc_req(ctx, "getblockhash", args, result);
	if (ret)
		goto getblockhash_end;

	assert(result->type == STRING);

    strcpy(hash, result->e.string_value);

getblockhash_end:
	jsonobj_free(result);
	return ret;
}

/*
 * Rpc Method getblockheader
 *
 * parameters:
 * 	hash	The block hash as hex string
 *
 * returns:
 * 	header	The block header as hex string
 */
int getblockheader(BitcoinRpcCtx *ctx, const char *blkhash, uint8_t *header)
{
	if (!blkhash) return -1;
	jsonobj *args = jsonobj_new();
	jsonobj *result = jsonobj_new();
	args->type = LIST;
	jsonobj_list_add_str(args, blkhash);
	jsonobj_list_add_bool(args, 0);

	int ret = curl_core_rpc_req(ctx, "getblockheader", args, result);
	if (ret)
		goto getblockheader_end;

	assert(result->type == STRING);

    hex_to_bytes(result->e.string_value, header);

getblockheader_end:
	jsonobj_free(result);
	return ret;
}

/*
 * Rpc Method getblock
 *
 * parameters:
 * 	hash		The block hash as hex string
 *
 * returns:
 * 	rawblock	The block as char*
 */
int getrawblock(BitcoinRpcCtx *ctx, const char *blkhash, uint8_t **rawblock)
{
	//method: getblock(hash, 0) // 0 verbosity level is raw hex block
	if (!blkhash) return -1;

	jsonobj *args = jsonobj_new();
	jsonobj *result = jsonobj_new();
	args->type = LIST;
	jsonobj_list_add_str(args, blkhash);
	jsonobj_list_add_bool(args, 0);

	int ret = curl_core_rpc_req(ctx, "getblock", args, result);
	if (ret)
		goto getrawblock_end;

	assert(result->type == STRING);

    char *blockhex = result->e.string_value;
    (*rawblock) = (uint8_t*) malloc(strlen(blockhex) / 2 * sizeof(char));
	ret = hex_to_bytes(blockhex, *rawblock);

getrawblock_end:
	jsonobj_free(result);
	return ret;
}

int getrawtransaction(BitcoinRpcCtx *ctx, const char *txid, uint8_t **rawtx)
{
	//method: getblock(hash, 0) // 0 verbosity level is raw hex block
	if (!txid) return -1;
	//{"result":"000000000000000000002d36fa2094961bcc3a694ecca42bce078de80095fc5f","error":null,"id":"curltext"}

	jsonobj *args = jsonobj_new();
	jsonobj *result = jsonobj_new();
	args->type = LIST;
	jsonobj_list_add_str(args, txid);
    jsonobj_list_add_bool(args, 0);

    int ret = curl_core_rpc_req(ctx, "getrawtransaction", args, result);
	if (ret)
		goto getrawtransaction_end;

	assert(result->type == STRING);

    char *txhex = result->e.string_value;
    (*rawtx) = (uint8_t*) malloc(strlen(txhex) / 2 * sizeof(uint8_t));
	ret = hex_to_bytes(txhex, *rawtx);

getrawtransaction_end:
	jsonobj_free(result);
	return ret;
}

int getrawtransaction_json(BitcoinRpcCtx *ctx, const char *txid, int verbose, jsonobj *result)
{
    //method: getblock(hash, 0) // 0 verbosity level is raw hex block
    if (!txid) return -1;
    //{"result":"000000000000000000002d36fa2094961bcc3a694ecca42bce078de80095fc5f","error":null,"id":"curltext"}

    jsonobj *args = jsonobj_new();
    args->type = LIST;
    jsonobj_list_add_str(args, txid);
    jsonobj_list_add_bool(args, verbose);

    return curl_core_rpc_req(ctx, "getrawtransaction", args, result);
}

int getrawmempool(BitcoinRpcCtx *ctx, HashesVec *new_txs_hashes)
{
	/*
	 * Result (for verbose = false)
	 * [           (json array)
	 * 	"hex",    (string) The transaction id
	 * 	...
	 * ]
	 */

    int ret = 0;
	jsonobj *args = jsonobj_new();
	jsonobj *result = jsonobj_new();
	args->type = LIST;
	jsonobj_list_add_bool(args, 0);

    if ((ret = curl_core_rpc_req(ctx, "getrawmempool", args, result))) {
        logerrf("getrawmempool! -> fial!");
        goto getrawmempool_end;
	}

	assert(result->type == LIST);

	jsonobj *e = NULL;
    ssize_t pos = 0;
    size_t i;
    for (i = 0; i < JSONOBJ_LIST_SIZE(result); i++) {
        pos = hashes_vec_add(new_txs_hashes, NULL);
        e = jsonobj_list_get_at(result, i);
        reverse_hex_to_bytes(e->e.string_value, new_txs_hashes->v[pos]);
	}

getrawmempool_end:
	jsonobj_free(result);
    return ret;
}

int getmempoolentry(BitcoinRpcCtx *ctx, char *txid_str, MempoolEntry *mpe)
{
    /*
     * Result (for verbose = false)
     * [           (json array)
     * 	"hex",    (string) The transaction id
     * 	...
     * ]
     */

    int ret = 0;
    jsonobj *args = jsonobj_new();
    jsonobj *result = jsonobj_new();
    jsonobj *e = NULL, *ef = NULL;
    args->type = LIST;
    jsonobj_list_add_str(args, txid_str);

    if ((ret = curl_core_rpc_req(ctx, "getmempoolentry", args, result))) {
        goto getmempoolentry_end;
    }

    assert(result->type == JSON_OBJ);

    memset(mpe, 0, sizeof(MempoolEntry));

    e = jsonobj_lookup(result, "vsize");
    if ((ret = (e == NULL))) {
        goto getmempoolentry_end;
    }

    mpe->vsize = (size_t) e->e.int_value;

    e = jsonobj_lookup(result, "fees");
    if ((ret = (e == NULL))) {
        goto getmempoolentry_end;
    }

    ef = jsonobj_lookup(e, "base");
    if ((ret = (ef == NULL))) {
        goto getmempoolentry_end;
    }

    mpe->fee_base = ef->e.double_value;

    ef = jsonobj_lookup(e, "modified");
    if ((ret = (ef == NULL))) {
        goto getmempoolentry_end;
    }

    mpe->fee_mod = ef->e.double_value;

    ef = jsonobj_lookup(e, "ancestor");
    if ((ret = (ef == NULL))) {
        goto getmempoolentry_end;
    }

    mpe->fee_ancestor = ef->e.double_value;

    ef = jsonobj_lookup(e, "descendant");
    if ((ret = (ef == NULL))) {
        goto getmempoolentry_end;
    }

    mpe->fee_descendant = ef->e.double_value;

getmempoolentry_end:
    jsonobj_free(result);
    return ret;
}

int sendrawtransaction(BitcoinRpcCtx *ctx, const char *rawtx, double feerate, char *txhash)
{
    /*
     * Result
     * hex string The transaction hash in hex
     */
    int ret = 0;

    jsonobj *args = jsonobj_new();
    jsonobj *result = jsonobj_new();
    args->type = LIST;
    jsonobj_list_add_str(args, rawtx);
    if (feerate > 0.0) {
        jsonobj_list_add_double(args, feerate);
    }

    ret = curl_core_rpc_req(ctx, "sendrawtransaction", args, result);
    if (ret)
        goto sendrawtransaction_end;

    assert(result->type == STRING);

    strcpy(txhash, result->e.string_value);

sendrawtransaction_end:
    jsonobj_free(result);
    return ret;
}

double estimatesmartfee(BitcoinRpcCtx *ctx, int conf_target)
{
    /*
        estimatesmartfee conf_target ( "estimate_mode" )
        {                   (json object)
          "feerate" : n,    (numeric, optional) estimate fee rate in BTC/kB (only present if no errors were encountered)
          "errors" : [      (json array, optional) Errors encountered during processing (if there are any)
            "str",          (string) error
            ...
          ],
          "blocks" : n      (numeric) block number where estimate was found
                            The request target will be clamped between 2 and the highest target
                            fee estimation is able to return based on how long it has been running.
                            An error is returned if not enough transactions and blocks
                            have been observed to make an estimate for any number of blocks.
        }
    */
    jsonobj *args = jsonobj_put_list(NULL, NULL);
    jsonobj_list_add_int(args, conf_target);

    jsonobj *result = jsonobj_new();

    double feerate = -1.0;
    int ret = curl_core_rpc_req(ctx, "estimatesmartfee", args, result);
    if (ret)
        goto estimatesmartfee_end;

    assert(result->type == JSON_OBJ);

    jsonobj *e = jsonobj_lookup(result, "feerate");
    if (e)
        feerate = e->e.double_value;

estimatesmartfee_end:
    jsonobj_free(result);
    return feerate;
}
