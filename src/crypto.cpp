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


QuorumCertBLS::QuorumCertBLS(const ReplicaConfig &config, const uint256_t &obj_hash):
    QuorumCert(), obj_hash(obj_hash), rids(config.nreplicas) {
    sigs.clear();
    rids.clear();
}

bool QuorumCertBLS::verify(const ReplicaConfig &config){
    //Todo: maintain a variable to store the number of sigs
    HOTSTUFF_LOG_DEBUG("checking quorum cert, obj_hash=%s", get_hex10(obj_hash).c_str());
    auto ctx = BLSContext::getInstance();
    auto g = ctx->getGenerator();

    GT t1, t2, t3;
    G1 Hm;
    bytearray_t bt = obj_hash;
    std::string str(bt.begin(), bt.end());
    Hash(Hm, str);

    pairing(t3, sigs, g);
    for (size_t i = 0; i < rids.size(); i++){
        if (rids.get(i))
        {
            pairing(t1, Hm, static_cast<const PubKeyBLS &>(config.get_pubkey(i)).pubkey);
            t2 += t1;
        }
    }

    return t2 == t3;
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
        GT t1, t2;
        auto ctx = BLSContext::getInstance();
        auto g = ctx->getGenerator();
        pairing(t1, sigs, g);

        for (const auto &v: values)
            t2 += promise::any_cast<GT>(v);

        return t1 ==  t2;
    });
}

void Hash(G1& P, const std::string& m){
    Fp t;
    t.setHashOf(m);
    mapToG1(P, t);
}

}
