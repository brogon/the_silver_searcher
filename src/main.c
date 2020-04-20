#include <ctype.h>
#include <pcre.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef _WIN32
#include <windows.h>
#endif

#include "config.h"

#ifdef HAVE_TRE_TRE_H
#include <tre/tre.h> 
#endif

#ifdef HAVE_SYS_CPUSET_H
#include <sys/cpuset.h>
#endif

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#if defined(HAVE_PTHREAD_SETAFFINITY_NP) && defined(__FreeBSD__)
#include <pthread_np.h>
#endif

#include "log.h"
#include "options.h"
#include "search.h"
#include "util.h"

typedef struct {
    pthread_t thread;
    int id;
} worker_t;

int main(int argc, char **argv) {
    char **base_paths = NULL;
    char **paths = NULL;
	char *version = NULL;
    int i;
    int pcre_opts = PCRE_MULTILINE;
    int study_opts = 0;
    worker_t *workers = NULL;
    int workers_len;
    int num_cores;

#ifdef HAVE_PLEDGE
    if (pledge("stdio rpath proc exec", NULL) == -1) {
        die("pledge: %s", strerror(errno));
    }
#endif

    set_log_level(LOG_LEVEL_WARN);

    work_queue = NULL;
    work_queue_tail = NULL;
    root_ignores = init_ignore(NULL, "", 0);
    out_fd = stdout;

    parse_options(argc, argv, &base_paths, &paths);
    log_debug("PCRE Version: %s", pcre_version());
#ifdef HAVE_TRE_TRE_H
    tre_config(TRE_CONFIG_VERSION, &version);
    log_debug("TRE Version: %s", version);
#endif
    if (opts.stats) {
        memset(&stats, 0, sizeof(stats));
        gettimeofday(&(stats.time_start), NULL);
    }

#ifdef USE_PCRE_JIT
    int has_jit = 0;
    pcre_config(PCRE_CONFIG_JIT, &has_jit);
    if (has_jit) {
        study_opts |= PCRE_STUDY_JIT_COMPILE;
    }
#endif

#ifdef _WIN32
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        num_cores = si.dwNumberOfProcessors;
    }
#else
    num_cores = (int)sysconf(_SC_NPROCESSORS_ONLN);
#endif

    workers_len = num_cores < 8 ? num_cores : 8;
    if (opts.literal) {
        workers_len--;
    }
    if (opts.workers) {
        workers_len = opts.workers;
    }
    if (workers_len < 1) {
        workers_len = 1;
    }

    log_debug("Using %i workers", workers_len);
    done_adding_files = FALSE;
    workers = ag_calloc(workers_len, sizeof(worker_t));
    if (pthread_cond_init(&files_ready, NULL)) {
        die("pthread_cond_init failed!");
    }
    if (pthread_mutex_init(&print_mtx, NULL)) {
        die("pthread_mutex_init failed!");
    }
    if (opts.stats && pthread_mutex_init(&stats_mtx, NULL)) {
        die("pthread_mutex_init failed!");
    }
    if (pthread_mutex_init(&work_queue_mtx, NULL)) {
        die("pthread_mutex_init failed!");
    }

    if (opts.casing == CASE_SMART) {
        opts.casing = is_lowercase(opts.query) ? CASE_INSENSITIVE : CASE_SENSITIVE;
    }

#ifdef HAVE_TRE_TRE_H
    if (opts.tre_params.max_cost > 0) {
        /* If -k is specified, make the regexp literal.  This uses
           the \Q and \E extensions. If the string already contains
           occurrences of \E, we need to handle them separately.  This is a
           pain, but can't really be avoided if we want to create a regexp
           which works together with -w (see below). */
        if (opts.literal) {
            char *next_pos, *new_re, *new_re_end;
            int n = 0;
            int len;

            next_pos = opts.query;
            while (next_pos) {
                next_pos = strstr(next_pos, "\\E");
                if (next_pos) {
                    n++;
                    next_pos += 2;
                }
            }

            len = strlen(opts.query);
            new_re = malloc(len + 5 + n * 7);
            if (!new_re) {
                log_err("Out of memory");
                exit(2);
            }

            next_pos = opts.query;
            new_re_end = new_re;
            strcpy(new_re_end, "\\Q");
            new_re_end += 2;
            while (next_pos) {
                char *start = next_pos;
                next_pos = strstr(next_pos, "\\E");
                if (next_pos) {
                    strncpy(new_re_end, start, next_pos - start);
                    new_re_end += next_pos - start;
                    strcpy(new_re_end, "\\E\\\\E\\Q");
                    new_re_end += 7;
                    next_pos += 2;
                } else {
                    strcpy(new_re_end, start);
                    new_re_end += strlen(start);
                }
            }
            strcpy(new_re_end, "\\E");
            free(opts.query);
            opts.query = new_re;
            opts.query_len = strlen(new_re);
        }

        /* If -w is specified, prepend beginning-of-word and end-of-word
           assertions to the regexp before compiling. */
        if (opts.word_regexp) {
            char *tmp = opts.query;
            int len = strlen(tmp);
            opts.query = malloc(len + 7);
            if (opts.query == NULL) {
                log_err("Out of memory");
                exit(2);
            }
            strcpy(opts.query, "\\<(");
            strcpy(opts.query + 3, tmp);
            strcpy(opts.query + len + 3, ")\\>");
            free(tmp);
        }

        /* setup comparison flags */
        int comp_flags = REG_EXTENDED;
        if (opts.casing == CASE_INSENSITIVE) {
            comp_flags |= REG_ICASE;
        }
        if ( ! opts.multiline) {
            comp_flags |= REG_NEWLINE;
        }

        /* Compile the pattern. */
        int errcode = tre_regcomp(&opts.tre, opts.query, comp_flags);
        if (errcode) {
            char errbuf[256];
            tre_regerror(errcode, &opts.tre, errbuf, sizeof(errbuf));
            log_err("Bad regex! tre_regcomp() failed: %s", errbuf);
            exit(2);
        }
    } else {
#endif
        if (opts.literal) {
            if (opts.casing == CASE_INSENSITIVE) {
                /* Search routine needs the query to be lowercase */
                char *c = opts.query;
                for (; *c != '\0'; ++c) {
                    *c = (char)tolower(*c);
                }
            }
            generate_alpha_skip(opts.query, opts.query_len, alpha_skip_lookup, opts.casing == CASE_SENSITIVE);
            find_skip_lookup = NULL;
            generate_find_skip(opts.query, opts.query_len, &find_skip_lookup, opts.casing == CASE_SENSITIVE);
            generate_hash(opts.query, opts.query_len, h_table, opts.casing == CASE_SENSITIVE);
            if (opts.word_regexp) {
                init_wordchar_table();
                opts.literal_starts_wordchar = is_wordchar(opts.query[0]);
                opts.literal_ends_wordchar = is_wordchar(opts.query[opts.query_len - 1]);
            }
        } else {
            if (opts.casing == CASE_INSENSITIVE) {
                pcre_opts |= PCRE_CASELESS;
            }
            if (opts.word_regexp) {
                char *word_regexp_query;
                ag_asprintf(&word_regexp_query, "\\b(?:%s)\\b", opts.query);
                free(opts.query);
                opts.query = word_regexp_query;
                opts.query_len = strlen(opts.query);
            }
            compile_study(&opts.re, &opts.re_extra, opts.query, pcre_opts, study_opts);
        }
#ifdef HAVE_TRE_TRE_H
    }
#endif

    if (opts.search_stream) {
        search_stream(stdin, "");
    } else {
        for (i = 0; i < workers_len; i++) {
            workers[i].id = i;
            int rv = pthread_create(&(workers[i].thread), NULL, &search_file_worker, &(workers[i].id));
            if (rv != 0) {
                die("Error in pthread_create(): %s", strerror(rv));
            }
#if defined(HAVE_PTHREAD_SETAFFINITY_NP) && (defined(USE_CPU_SET) || defined(HAVE_SYS_CPUSET_H))
            if (opts.use_thread_affinity) {
#ifdef __linux__
                cpu_set_t cpu_set;
#elif __FreeBSD__
                cpuset_t cpu_set;
#endif
                CPU_ZERO(&cpu_set);
                CPU_SET(i % num_cores, &cpu_set);
                rv = pthread_setaffinity_np(workers[i].thread, sizeof(cpu_set), &cpu_set);
                if (rv) {
                    log_err("Error in pthread_setaffinity_np(): %s", strerror(rv));
                    log_err("Performance may be affected. Use --noaffinity to suppress this message.");
                } else {
                    log_debug("Thread %i set to CPU %i", i, i);
                }
            } else {
                log_debug("Thread affinity disabled.");
            }
#else
            log_debug("No CPU affinity support.");
#endif
        }

#ifdef HAVE_PLEDGE
        if (pledge("stdio rpath", NULL) == -1) {
            die("pledge: %s", strerror(errno));
        }
#endif
        for (i = 0; paths[i] != NULL; i++) {
            log_debug("searching path %s for %s", paths[i], opts.query);
            symhash = NULL;
            ignores *ig = init_ignore(root_ignores, "", 0);
            struct stat s = { .st_dev = 0 };
#ifndef _WIN32
            /* The device is ignored if opts.one_dev is false, so it's fine
             * to leave it at the default 0
             */
            if (opts.one_dev && lstat(paths[i], &s) == -1) {
                log_err("Failed to get device information for path %s. Skipping...", paths[i]);
            }
#endif
            search_dir(ig, base_paths[i], paths[i], 0, s.st_dev);
            cleanup_ignore(ig);
        }
        pthread_mutex_lock(&work_queue_mtx);
        done_adding_files = TRUE;
        pthread_cond_broadcast(&files_ready);
        pthread_mutex_unlock(&work_queue_mtx);
        for (i = 0; i < workers_len; i++) {
            if (pthread_join(workers[i].thread, NULL)) {
                die("pthread_join failed!");
            }
        }
    }

    if (opts.stats) {
        gettimeofday(&(stats.time_end), NULL);
        double time_diff = ((long)stats.time_end.tv_sec * 1000000 + stats.time_end.tv_usec) -
                           ((long)stats.time_start.tv_sec * 1000000 + stats.time_start.tv_usec);
        time_diff /= 1000000;
        printf("%zu matches\n%zu files contained matches\n%zu files searched\n%zu bytes searched\n%f seconds\n",
               stats.total_matches, stats.total_file_matches, stats.total_files, stats.total_bytes, time_diff);
        pthread_mutex_destroy(&stats_mtx);
    }

    if (opts.pager) {
        pclose(out_fd);
    }
    cleanup_options();
    pthread_cond_destroy(&files_ready);
    pthread_mutex_destroy(&work_queue_mtx);
    pthread_mutex_destroy(&print_mtx);
    cleanup_ignore(root_ignores);
    free(workers);
    for (i = 0; paths[i] != NULL; i++) {
        free(paths[i]);
        free(base_paths[i]);
    }
    free(base_paths);
    free(paths);
    if (find_skip_lookup) {
        free(find_skip_lookup);
    }
    return !opts.match_found;
}
