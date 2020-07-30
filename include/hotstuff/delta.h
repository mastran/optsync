#ifndef HOTSTUFF_DELTA_H
#define HOTSTUFF_DELTA_H

#include <iostream>
#include <unordered_map>
#include <cmath>
#include <sys/time.h>

#include "salticidae/event.h"
#include "salticidae/stream.h"
#include "salticidae/util.h"

#include "hotstuff/type.h"
#include "hotstuff/entity.h"

using salticidae::ElapsedTime;

namespace hotstuff {

double average_without_outliers(double arr[], int n, double outlierConst=1.5);

class Delta {
    size_t nreplicas;
    size_t nmajority;

    ReplicaID replicaId;

    double curDelta;
    uint16_t curLoad;
    bool isDeltaValid;
    double defaultDelta = 10; /* 10 seconds */
    const int deltaMultiplier = 10;

    uint32_t curProbes;

    bool onProbe;
    uint256_t dummyData;
    const size_t probeBlkSize = 5000;
    std::vector<uint256_t> probeData;
    uint16_t load;

    std::vector<int> blocks;
    std::vector<double> lats;

    double maxSlopeCurProbe;

    std::unordered_map<uint32_t, std::pair<size_t, ElapsedTime>> waiting;
    std::unordered_map<uint16_t, std::vector<std::pair<struct timeval, double>>> elapsed;

    /* Record blk waiting times */
    std::unordered_map<const uint256_t, std::pair<size_t, ElapsedTime>> echo_waiting;

    public:
    Delta() = default;

    double get_curDelta() const{
        return curDelta;
    }

    void init(ReplicaID replicaId, size_t nreplicas, uint16_t backlog);

    const Probe get_current_probe();
    bool on_receive_probe_ok(const ProbeOk &probeOk);
    void add_waiting_probe(uint32_t probeId);
    void add_echo_waiting(uint256_t);
    void on_receive_echo_ok(uint256_t);

    uint8_t get_current_load() const {return load;}

    void increase_load(){load +=1;}

    void stop_probe(){onProbe = false;}

    void start_probe(){onProbe = true;}

    bool isProbing() const { return onProbe;}
    bool isCurDeltaValid() const { return isDeltaValid;}

    void clear_current_probe(){
        elapsed.clear();
        waiting.clear();
    }

    void clear_probe(){
        maxSlopeCurProbe = 0.0;
    }

    std::pair<int, double> currentProbeStats(uint16_t load);
    bool isDecidingProbe(uint16_t load);
    void setDeltaNLoad();
};
}

#endif //HOTSTUFF_ADJUST_DELTA_H
