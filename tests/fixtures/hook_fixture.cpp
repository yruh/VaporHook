namespace {
volatile int fixture_delta = 7;
}

extern "C" __attribute__((visibility("default"), noinline)) int vaporhook_fixture_target(int value) {
    return value + fixture_delta;
}
