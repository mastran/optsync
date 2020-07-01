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
#include "hotstuff/consensus.h"
#include "hotstuff/hotstuff.h"

namespace hotstuff {

void Block::serialize(DataStream &s) const {
    s << htole((uint32_t)parent_hashes.size());
    for (const auto &hash: parent_hashes)
        s << hash;
    s << htole((uint32_t)cmds.size());
    for (auto cmd: cmds)
        s << cmd;
    if (qc)
        s << (uint8_t)1 << *qc << qc_ref_hash;
    else
        s << (uint8_t)0;
    s << slow_path;
    s << htole((uint32_t)extra.size()) << extra;
}

void Block::unserialize(DataStream &s, HotStuffCore *hsc) {
    uint32_t n;
    uint8_t flag;
    s >> n;
    n = letoh(n);
    parent_hashes.resize(n);
    for (auto &hash: parent_hashes)
        s >> hash;
    s >> n;
    n = letoh(n);
    cmds.resize(n);
    for (auto &cmd: cmds)
        s >> cmd;
//    for (auto &cmd: cmds)
//        cmd = hsc->parse_cmd(s);
    s >> flag;
    if (flag)
    {
        qc = hsc->parse_quorum_cert(s);
        s >> qc_ref_hash;
    } else qc = nullptr;
    s >> slow_path;
    s >> n;
    n = letoh(n);
    if (n == 0)
        extra.clear();
    else
    {
        auto base = s.get_data_inplace(n);
        extra = bytearray_t(base, base + n);
    }
    this->hash = _get_hash();
}

/** The following function removes qc from block hash.
 * qc could either be synchronous or responsive. So, the hash would change
 * if qc changes from synchronou to responsive.
 * **/
uint256_t Block::_get_hash() {
    DataStream s;
    s << htole((uint32_t)parent_hashes.size());
    for (const auto &hash: parent_hashes)
        s << hash;
    s << htole((uint32_t)cmds.size());
    for (auto cmd: cmds)
        s << cmd;
    if (qc)
        s << (uint8_t)1 << qc_ref_hash;
    else
        s << (uint8_t)0;
    s << htole((uint32_t)extra.size()) << extra;
    return s.get_hash();
}

}
