#include <error.h>
#include <iostream>
#include "salticidae/util.h"
#include "hotstuff/crypto.h"
#include "pbc/pbc.h"

using salticidae::Config;
using hotstuff::privkey_bt;
using hotstuff::pubkey_bt;

using namespace std;

int main(int argc, char **argv) {
    Config config("hotstuff.conf");
    privkey_bt priv_key;
    auto opt_n = Config::OptValInt::create(1);
    config.add_opt("num", opt_n, Config::SET_VAL);
    config.parse(argc, argv);

    const char *paramFileName = "pairing.param";
    FILE *sysParamFile = fopen(paramFileName, "r");
    if (sysParamFile == NULL) {
        error(1, 0, "Can't open the parameter file ");
    }

    int n = opt_n->get();
    if (n < 1)
        error(1, 0, "n must be >0");

    pairing_t e;
    char s[8192];
    size_t count = fread(s, 1, 8192, sysParamFile);
    fclose(sysParamFile);
    if (count)
        if (pairing_init_set_buf(e, s, count)) {
            error(1, 0, "invalid pairing file");
        }

    element_t g, priv, pub;
    element_init_G2(g, e);
    element_init_G2(pub, e);
    element_init_Zr(priv, e);

    element_random(g);
    element_printf("g: %B\n", g);
    while (n--)
    {
        element_random(priv);
        element_pow_zn(pub, g, priv);
        element_printf("pub: %B\n", pub);
        element_printf("sec: %B\n", priv);
    }
}
