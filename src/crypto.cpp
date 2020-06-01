/**
 * Copyright 2018 VMware
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hotstuff/entity.h"
#include "hotstuff/crypto.h"

namespace hotstuff {

secp256k1_context_t secp256k1_default_sign_ctx = new Secp256k1Context(true);
secp256k1_context_t secp256k1_default_verify_ctx = new Secp256k1Context(false);

QuorumCertSecp256k1::QuorumCertSecp256k1(
        const ReplicaConfig &config, const uint256_t &obj_hash):
            QuorumCert(), obj_hash(obj_hash), rids(config.nreplicas) {
    rids.clear();
}
   
bool QuorumCertSecp256k1::verify(const ReplicaConfig &config) {
    if (sigs.size() < config.nmajority) return false;
    for (size_t i = 0; i < rids.size(); i++)
        if (rids.get(i))
        {
            HOTSTUFF_LOG_DEBUG("checking cert(%d), obj_hash=%s",
                                i, get_hex10(obj_hash).c_str());
            if (!sigs[i].verify(obj_hash,
                            static_cast<const PubKeySecp256k1 &>(config.get_pubkey(i)),
                            secp256k1_default_verify_ctx))
            return false;
        }
    return true;
}

promise_t QuorumCertSecp256k1::verify(const ReplicaConfig &config, VeriPool &vpool) {
    if (sigs.size() < config.nmajority)
        return promise_t([](promise_t &pm) { pm.resolve(false); });
    std::vector<promise_t> vpm;
    for (size_t i = 0; i < rids.size(); i++)
        if (rids.get(i))
        {
            HOTSTUFF_LOG_DEBUG("checking cert(%d), obj_hash=%s",
                                i, get_hex10(obj_hash).c_str());
            vpm.push_back(vpool.verify(new Secp256k1VeriTask(obj_hash,
                            static_cast<const PubKeySecp256k1 &>(config.get_pubkey(i)),
                            sigs[i])));
        }
    return promise::all(vpm).then([](const promise::values_t &values) {
        for (const auto &v: values)
            if (!promise::any_cast<bool>(v)) return false;
        return true;
    });
}


BLSContext *BLSContext::instance = 0;


pubkey_bt PrivKeyBLS::get_pubkey() const {
    return new PubKeyBLS(*this);
}

QuorumCertBLS::QuorumCertBLS(){
    auto ctx = BLSContext::getInstance();
    element_init_G1(sigs, ctx->getPairing());
}

QuorumCertBLS::QuorumCertBLS(const ReplicaConfig &config, const uint256_t &obj_hash):
    QuorumCert(), obj_hash(obj_hash), rids(config.nreplicas) {
    rids.clear();
    auto ctx = BLSContext::getInstance();
    element_init_G1(sigs, ctx->getPairing());
}

bool QuorumCertBLS::verify(const ReplicaConfig &config){
    //Todo: maintain a variable to store the number of sigs
    HOTSTUFF_LOG_DEBUG("checking quorum cert, obj_hash=%s", get_hex10(obj_hash).c_str());
    auto ctx = BLSContext::getInstance();
    element_t t1, t2, t3, h;
    auto e = ctx->getPairing();
    auto g = ctx->getGenerator();
    element_init_G1(h, e);

    bytearray_t bt = obj_hash;
    element_from_hash(h, (char *)bt.data(), bt.size());
    element_init_GT(t1, e);
    element_init_GT(t2, e);
    element_init_GT(t3, e);

    element_pairing(t3, sigs, g);

    for (size_t i = 0; i < rids.size(); i++){
        if (rids.get(i))
        {
            element_pairing(t1, h, *(element_t *) static_cast<const PubKeyBLS &>(config.get_pubkey(i)).pubkey);
            element_mul(t2, t2, t1);
        }
    }

    return element_cmp(t2, t3);
}

promise_t QuorumCertBLS::verify(const ReplicaConfig &config, VeriPool &vpool) {
    MsgHashBLS msgHash(obj_hash);
    std::vector<promise_t> vpm;

    for (size_t i = 0; i < rids.size(); i++)
        if (rids.get(i))
        {
            HOTSTUFF_LOG_DEBUG("checking cert(%d), obj_hash=%s",
                               i, get_hex10(obj_hash).c_str());
            vpm.push_back(vpool.verify(new QuorumVeriTask(msgHash,
                    static_cast<const PubKeyBLS &>(config.get_pubkey(i)))));
        }
    if(!vpm.size()) return promise_t([](promise_t &pm) { pm.resolve(true); });

    return promise::all(vpm).then([this](const promise::values_t &values) {
        element_t t1, t2;
        auto ctx = BLSContext::getInstance();
        element_init_GT(t1, ctx->getPairing());
        element_init_GT(t2, ctx->getPairing());
        element_pairing(t1, sigs, ctx->getGenerator());

        for (const auto &v: values)
            element_mul(t2, t2, *(element_t *)promise::any_cast<GT>(v).t);

        return (bool) element_cmp(t1, t2);
    });
}

}
