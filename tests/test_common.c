#include <sys/stat.h>

#include "test_common.h"

char *test_infile;
char *test_output_dir;
char *test_outfile;
char *test_errfile;
char *test_altfile;

#define NEWSTREAM(f, s, v) \
do { \
    if((v) != NULL) \
        free(v); \
    (f) = open_memstream(&(v), &(s)); \
} while(0)

/*
 * Sets up to run a test.
 * Initialize various filenames, using the name of the test as a base,
 * and then initialize and run a command to remove old output from this test
 * and to make sure that the test output directory exists.
 */
int setup_test(char *name)
{
        FILE *f;
        size_t s;
        char *cmd = NULL;

        fprintf(stderr, "-----\n");

        NEWSTREAM(f, s, test_infile);
        fprintf(f, "%s/%s.in", TEST_REF_DIR, name);
        fclose(f);

        NEWSTREAM(f, s, test_output_dir);
        fprintf(f, "%s/%s", TEST_OUT_DIR, name);
        fclose(f);

        NEWSTREAM(f, s, test_outfile);
        fprintf(f, "%s/%s.out", test_output_dir, name);
        fclose(f);

        NEWSTREAM(f, s, test_errfile);
        fprintf(f, "%s/%s.err", test_output_dir, name);
        fclose(f);

        NEWSTREAM(f, s, test_altfile);
        fprintf(f, "%s/%s.alt", test_output_dir, name);
        fclose(f);

        NEWSTREAM(f, s, cmd);
        f = open_memstream(&cmd, &s);
        fprintf(f, "rm -fr %s; mkdir -p %s", test_output_dir, test_output_dir);
        fclose(f);

        fprintf(stderr, "setup(%s)\n", cmd);
        int ret = system(cmd);
        free(cmd);
        return ret;
}

/*
 * Run the program as a "black box" using system().
 * A shell command is constructed and run that first performs test setup,
 * then runs the program to be tested with input redirected from a test input
 * file and standard and error output redirected to separate output files.
 */
int run_using_system(char *name, char *pre_cmd, char *valgrind_cmd,
                     char *program_options, char *limits)
{
        FILE *f;
        size_t s;
        char *cmd = NULL;
        struct stat sbuf;

        setup_test(name);
        int staterr = stat(test_infile, &sbuf);
        NEWSTREAM(f, s, cmd);
        fprintf(f, "%s%s%s "PROGNAME" %s < %s > %s 2> %s",
                limits, pre_cmd, valgrind_cmd,
                program_options,
                staterr ? "/dev/null" : test_infile,
                test_outfile, test_errfile);
        fclose(f);
        fprintf(stderr, "run(%s)\n", cmd);
        int ret = system(cmd);
        free(cmd);
        return ret;
}

/*
 * The Wxxx macros have not worked properly with the return value from system(),
 * in spite of what the Linux man pages say about it.  So there is some fragile
 * hard-coding here to work around it.
 */

void assert_normal_exit(int status)
{
        cr_assert(/*!WIFSIGNALED(status)*/ !(status & 0x8000),
                  "The program terminated with an unexpected signal (%d).\n",
                  /* WTERMSIG(status) */ (status & 0x7f00) >> 8);
}

void assert_expected_status(int expected, int status)
{
        cr_assert(/*!WIFSIGNALED(status)*/ !(status & 0x8000),
                  "The program terminated with an unexpected signal (%d).\n",
                  /* WTERMSIG(status) */ (status & 0x7f00) >> 8);
        cr_assert_eq(
            WEXITSTATUS(status), expected,
            "The program did not exit with the expected status "
            "(expected 0x%x, was 0x%x).\n",
            expected, WEXITSTATUS(status));
}

void assert_signaled(int sig, int status)
{
        cr_assert(/*WIFSIGNALED(status)*/ status & 0x8000,
                  "The program did not terminate with a signal.\n");
        cr_assert(/*WTERMSIG(status)*/ (status & 0x7f00) >> 8 == sig,
                  "The program did not terminate with the expected signal "
                  "(expected %d, was %d).\n",
                  sig, WTERMSIG(status));
}

/*
 * Compare output from the program being tested with reference output,
 * after first possibly filtering the output using an arbitrary command.
 */
void assert_file_matches_cmdfilter(char *name, char *which, char *cmdfilter)
{
        FILE *f;
        size_t s;
        char *cmd = NULL;
        
        NEWSTREAM(f, s, cmd);
        if (cmdfilter) {
                fprintf(f,
                        "cat %s/%s/%s.%s | %s > %s/%s/%s.%s.flt; "
                        "cat %s/%s.%s | %s > %s/%s/%s.%s.ref; "
                        "diff --ignore-tab-expansion --ignore-trailing-space "
                        "--ignore-space-change --ignore-blank-lines "
                        "%s/%s/%s.%s.flt %s/%s/%s.%s.ref",
                        TEST_OUT_DIR, name, name, which, cmdfilter, TEST_OUT_DIR, name, name, which,
                        TEST_REF_DIR, name, which, cmdfilter, TEST_OUT_DIR, name, name, which,
                        TEST_OUT_DIR, name, name, which, TEST_OUT_DIR, name, name, which);
        } else {
                fprintf(f,
                        "diff --ignore-tab-expansion --ignore-trailing-space "
                        "--ignore-space-change --ignore-blank-lines "
                        "%s/%s/%s.%s %s/%s/%s.%s",
                        TEST_OUT_DIR, name, name, which, TEST_REF_DIR, name, name, which);
        }
        fclose(f);
        fprintf(stderr, "run(%s)\n", cmd);
        int err = system(cmd);
        free(cmd);
        cr_assert_eq(err, 0,
                     "The output was not what was expected (diff exited with "
                     "status %d).\n",
                     WEXITSTATUS(err));
}

/*
 * Compare the binary output from the program being tested with
 * reference output.
 */
void assert_binfile_matches(char *name)
{
        FILE *f;
        size_t s;
        char *cmd = NULL;

        NEWSTREAM(f, s, cmd);
        fprintf(f,
                "cmp %s/%s.bin %s/%s.bin",
                test_outfile, name, TEST_REF_DIR, name);
        fclose(f);
        int err = system(cmd);
        free(cmd);
        cr_assert_eq(err, 0,
                     "The output was not what was expected (cmp exited with "
                     "status %d).\n",
                     WEXITSTATUS(err));
}

void assert_no_valgrind_errors(int status)
{
        cr_assert_neq(WEXITSTATUS(status), 37,
                      "Valgrind reported errors -- see %s.err",
                      test_outfile);
}

