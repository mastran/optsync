//
// Created by nibesh on 5/20/20.
//

#ifndef HOTSTUFF_ERASURE_H
#define HOTSTUFF_ERASURE_H

#include <cstdlib>

#include "hotstuff/type.h"
#include "hotstuff/entity.h"

#include "jerasure.h"
#include "reed_sol.h"

namespace hotstuff {

class Chunk;

using chunk_t = salticidae::ArcObj<Chunk>;
using chunkarray_t = std::vector<chunk_t>;
using intarray_t = std::vector<int>;


class Chunk {
    friend HotStuffCore;
    uint32_t blk_size;

    bytearray_t data;

    // add fields for accumulators to verify.

    public:
    Chunk():
            blk_size(0){}

    Chunk(const uint32_t blk_size, bytearray_t &&data):
             blk_size(blk_size), data(std::move(data)) {}

    uint32_t get_blk_size(){
        return blk_size;
    }

    bytearray_t &get_data(){
        return data;
    }

    void serialize(DataStream &s) const;

    void unserialize(DataStream &s);

    // add functions to verify
};


class Erasure {
    public:
    static chunkarray_t encode(int k, int m, int w, DataStream &s){
        uint32_t size = s.size();
        int *matrix;
        char **data, **coding;
        int i, blocksize, extra = 0, newsize;

        int x = (int) size / (k * w * sizeof(long));
        if (size >  x * k * w * (int) sizeof(long))
            x += 1;

        newsize = x * k * w * (int) sizeof(long);
        // blocksize must be multiple of sizeof(long)
        blocksize = newsize / k ;

        extra = newsize - size;

        for(i=0; i< extra; i++)
            s << '0';

        char *block = reinterpret_cast<char *>(s.data());

        data = (char **) malloc(sizeof(char*) * k);
        coding = (char **) malloc(sizeof(char *) * m);

        for (i = 0; i < m; i++)
            coding[i] = (char *)malloc(sizeof(char)*blocksize);

        for (i = 0; i < k; i++)
            data[i] = block+(i*blocksize);

        matrix = reed_sol_vandermonde_coding_matrix(k, m, w);
        jerasure_matrix_encode(k, m, w, matrix, data, coding, blocksize);
        chunkarray_t chunks;

        for(i=0; i<k; i++) {
            bytearray_t bt(data[i], data[i]+blocksize);
            chunks.push_back(new Chunk(size, std::move(bt)));
        }

        for(i=0; i<m; i++) {
            bytearray_t bt(coding[i], coding[i]+blocksize);
            chunks.push_back(new Chunk(size, std::move(bt)));
        }

        return chunks;
    }

    static bool decode(const int k, const int m, const int w, const chunkarray_t &chunks, intarray_t &erasures, DataStream &s){
        size_t size = chunks[0]->get_blk_size();
        int *matrix;
        char **data, **coding;
        int i, blocksize, extra = 0, newsize;
        int *_erasures = erasures.data();

        int x = (int) size / (k * w * sizeof(long));
        if (size >  x * k * w * (int) sizeof(long))
            x += 1;

        newsize = x * k * w * (int) sizeof(long);
        // blocksize must be multiple of sizeof(long)
        blocksize = newsize / k ;

        data = (char **) malloc(sizeof(char*) * k);
        coding = (char **) malloc(sizeof(char *) * m);

        for(i=0; i<k; i++)
            data[i] = (char *)chunks[i]->get_data().data();

        for(i=0; i<m; i++)
            coding[i] = (char *)chunks[k+i]->get_data().data();

        matrix = reed_sol_vandermonde_coding_matrix(k, m, w);
        i = jerasure_matrix_decode(k, m, w, matrix, 1, _erasures, data, coding, blocksize);
        // Decoding was unsuccessful
        if(i == -1)
            return false;

        for(i=0; i<k-1; i++) {
            bytearray_t arr(data[i], data[i]+blocksize);
            s << arr;
        }

        extra = newsize - size;
        bytearray_t arr(data[i], data[i]+blocksize-extra);
        s << arr;
        return true;
    }
};

}

#endif //HOTSTUFF_ERASURE_H
