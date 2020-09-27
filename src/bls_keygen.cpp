#include <error.h>
#include <iostream>
#include <mcl/bn256.hpp>

#include "salticidae/util.h"
#include "hotstuff/crypto.h"
#include "pbc/pbc.h"

using salticidae::Config;
using hotstuff::privkey_bt;
using hotstuff::pubkey_bt;

using namespace std;
using namespace mcl::bn256;

void KeyGen(Fr& s, G2& pub, const G2& Q)
{
    s.setRand();
    G2::mul(pub, Q, s); // pub = sQ
}

int main(int argc, char **argv) {
    Config config("hotstuff.conf");
    privkey_bt priv_key;
    auto opt_n = Config::OptValInt::create(1);
    config.add_opt("num", opt_n, Config::SET_VAL);
    config.parse(argc, argv);

    int n = opt_n->get();
    if (n < 1)
        error(1, 0, "n must be >0");

    initPairing();
    G2 Q;
    mapToG2(Q, 1);

    Fr s;
    G2 pub;
    std::cout << "g: " << Q.serializeToHexStr() << endl;
    while (n--)
    {
        KeyGen(s, pub, Q);
        std::cout << "pub: " << pub.serializeToHexStr() << endl;
        std::cout << "sec: " << s.serializeToHexStr() << endl;
    }
}
