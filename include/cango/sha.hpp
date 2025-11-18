#ifndef INCLUDE_CANGO_SHA
#define INCLUDE_CANGO_SHA

namespace cango::sha {

class SHA256 {
public:
    static void preprocess();
    static void init_hash();
    static void init_consts();
    static void as_block();
    static void schedule();
    static void compress();
    static void hash();
};

}

#endif//INCLUDE_CANGO_SHA
