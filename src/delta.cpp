#include "include/hotstuff/delta.h"
using namespace std;

namespace hotstuff {

// Partition algo for Quick Select
int partition(double arr[], int l, int r)
{
    double x = arr[r];
    int i = l;
    for (int j = l; j <= r - 1; j++) {
        if (arr[j] <= x) {
            swap(arr[i], arr[j]);
            i++;
        }
    }
    swap(arr[i], arr[r]);
    return i;
}

// Quick Select to compute percentiles
double kthSmallest(double arr[], int l, int r, int k)
{
    if (k > 0 && k <= r - l + 1) {

        int index = partition(arr, l, r);

        if (index - l == k - 1)
            return arr[index];

        if (index - l > k - 1)
            return kthSmallest(arr, l, index - 1, k);

        return kthSmallest(arr, index + 1, r,
                           k - index + l - 1);
    }
    return -1;
}

// Compute average by removing outliers
double average_without_outliers(double arr[], int n, double outlierConst){
    double upper_quartile = kthSmallest(arr, 0, n, (int) (.75* n));
    double lower_quartile = kthSmallest(arr, 0, n, (int) (.25* n));
    double IQR = (upper_quartile - lower_quartile) * outlierConst;

    double quartileSetLower = lower_quartile - IQR;
    double quartileSetUpper = upper_quartile + IQR;

    double sum = 0.0;
    int count = 0;
    for(int i=0; i< n; i++){
        if (quartileSetLower <= arr[i] && arr[i]  <= quartileSetUpper){
            sum += arr[i];
            count++;
        }
    }
    return (double) sum/count;
}

void Delta::init(ReplicaID replicaId, size_t nreplicas, uint16_t backlog){

    this->nreplicas = nreplicas;
    this->replicaId = replicaId;
    nmajority = (int) nreplicas/2 + 1;
    curDelta = defaultDelta;
    isDeltaValid = true;
    curProbes = 0;

    DataStream s;
    s << 0;
    dummyData = s.get_hash();

    for (uint32_t i = 0; i < probeBlkSize; i++)
        probeData.push_back(dummyData);

    load = 1;
    maxSlopeCurProbe = 0.0;
}

void Delta::add_waiting_probe(const uint32_t probeId){
    ElapsedTime et;
    et.start();
    waiting.insert(std::make_pair(probeId, std::make_pair(0, et)));
}

bool Delta::on_receive_probe_ok(const ProbeOk &probeOk) {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    auto it = waiting.find(probeOk.probeId);
    if(it == waiting.end()) return false;
    auto &confirmed = it->second.first;
    if (++confirmed < nreplicas - 1) return false;

    auto &et = it->second.second;
    et.stop();
    elapsed[probeOk.load].emplace_back(std::make_pair(tv, et.elapsed_sec));
    waiting.erase(it);
    return true;
}

const Probe Delta::get_current_probe() {
    Probe probe(probeData, curProbes++, replicaId, load);
//    return std::move(probe);
    return probe;
}

std::pair<int, double> Delta::currentProbeStats(uint16_t load){
    time_t begin_time = 0;
    int cnt = 0;
    std::vector<int> values;
    std::vector<double> lat;

    for (const auto &e: elapsed[load])
    {
        if (begin_time == 0) begin_time = e.first.tv_sec;
        if (begin_time + 1 < e.first.tv_sec){
            if (begin_time > 0)
                values.push_back(cnt);
            cnt = 1;
            begin_time += 1;
        } else cnt++;
        lat.push_back(e.second);
    }

    int sumThroughput = 0;
    for (auto &v: values) sumThroughput += v;

    double avgLat = average_without_outliers(lat.data(), lat.size()-1);
    int avgThroughput = (int) sumThroughput / values.size();

    return std::pair<int, double>(avgThroughput, avgLat);
}

bool Delta::isDecidingProbe(uint16_t load) {
    auto stats = currentProbeStats(load);
    bool retVal = false;
    if (load > 1){
        int prevBlks = blocks.back();
        double prevLat = lats.back();
        double curSlope = abs(stats.first - prevBlks)/ abs(stats.second-prevLat);

        if (curSlope < maxSlopeCurProbe / 4){
            retVal = true;
        } else if(curSlope > maxSlopeCurProbe){
            maxSlopeCurProbe = curSlope;
        }
    }

    blocks.push_back(stats.first);
    lats.push_back(stats.second);
    return retVal;
}

void Delta::setDeltaNLoad() {
    /*Finalize Delta*/
    curDelta = lats.back() * deltaMultiplier;
    curLoad = (uint16_t) load / 3;
}

void Delta::add_echo_waiting(const uint256_t blk_hash){
    ElapsedTime et;
    et.start();
    echo_waiting.insert(std::make_pair(blk_hash, std::make_pair(0, et)));
}

void Delta::on_receive_echo_ok(const uint256_t blk_hash) {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    auto it = echo_waiting.find(blk_hash);
    if(it == echo_waiting.end()) return ;
    auto &confirmed = it->second.first;
    if (++confirmed < nmajority) return ;

    auto &et = it->second.second;
    et.stop();
    echo_waiting.erase(it);
    if (et.elapsed_sec > curDelta) isDeltaValid = false;
}

}