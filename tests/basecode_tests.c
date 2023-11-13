#include <criterion/criterion.h>
#include <criterion/logging.h>

#include "deet.h"
#include "test_common.h"

/*
 * These tests are very basic "blackbox" tests designed to mostly exercise
 * startup and shutdown of the program.
 */

Test(basecode_suite, startup_quit) {
    char *name = "startup_quit";
    setup_test(name);
    int err = run_using_system(name, "echo quit | ", "", "-p", STANDARD_LIMITS);
    assert_expected_status(EXIT_SUCCESS, err);
}

Test(basecode_suite, startup_EOF) {
    char *name = "startup_EOF";
    setup_test(name);
    int err = run_using_system(name, "", "", "-p", STANDARD_LIMITS);
    assert_expected_status(EXIT_SUCCESS, err);
}

Test(basecode_suite, hello_world) {
    char *name = "hello_world";
    setup_test(name);
    int err = run_using_system(name, "", "", "-p", STANDARD_LIMITS);
    assert_expected_status(EXIT_SUCCESS, err);
    assert_file_matches_cmdfilter(name, "out", "awk -F'\\t' '{ print $1 \" \" $4 \" \" $5; }'");
    assert_file_matches_cmdfilter(name, "err", "grep '^\\[' | awk '{ print $2; }'");
}

Test(basecode_suite, sleep_no_wait) {
    char *name = "sleep_no_wait";
    setup_test(name);
    int err = run_using_system(name, "", "", "-p", STANDARD_LIMITS);
    assert_expected_status(EXIT_SUCCESS, err);
    assert_file_matches_cmdfilter(name, "out", "awk -F'\\t' '{ print $1 \" \" $4 \" \" $5; }'");
    assert_file_matches_cmdfilter(name, "err", "grep '^\\[' | awk '{ print $2; }'");
}

Test(basecode_suite, sleep_wait) {
    char *name = "sleep_wait";
    setup_test(name);
    int err = run_using_system(name, "", "", "-p", STANDARD_LIMITS);
    assert_expected_status(EXIT_SUCCESS, err);
    assert_file_matches_cmdfilter(name, "out", "awk -F'\\t' '{ print $1 \" \" $4 \" \" $5; }'");
    assert_file_matches_cmdfilter(name, "err", "grep '^\\[' | awk '{ print $2; }'");
}
