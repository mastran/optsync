#include "hotstuff/erasure.h"

namespace hotstuff {

    void Chunk::serialize(DataStream &s) const {
        s << htole(blk_size);
        s << htole((uint32_t)data.size()) << data;
    }

    void Chunk::unserialize(DataStream &s) {
        uint32_t n;
        s >> n;
        blk_size = letoh(n);

        s >> n;
        n = letoh(n);

        if (n == 0){
            data.clear();
        }else{
            auto base = s.get_data_inplace(n);
            data = bytearray_t(base, base+n);
        }
    }

}