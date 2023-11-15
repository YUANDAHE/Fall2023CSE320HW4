
#define _GNU_SOURCE //for getline

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h> //signal
#include <sys/types.h>
#include <sys/stat.h>  //status
#include <sys/wait.h> //waitpid
#include <sys/ptrace.h> //for ptrace
#include <sys/user.h> //for user_regs
#include "deet.h"
#include "debug.h"
#include <time.h> //nansosleep

enum {
    CMD_HELP,
    CMD_QUIT,
    CMD_SHOW,
    CMD_RUN,
    CMD_STOP,
    CMD_CONT,
    CMD_RELEASE,
    CMD_WAIT,
    CMD_KILL,
    CMD_PEEK,
    CMD_POKE,
    CMD_BT,
    CMD_NONE,
};

#define JOB_SLEEP_NSEC  10000000

int g_job_id = 0;
struct job {
    int id, pid;
    PSTATE state;
   
    char ptraced;
    char ptrace_stopped;
    
    int status;
    int argc;
    char *argv[32];

    struct job *next;
};

struct job *job_head = NULL;
struct job *job_tail = NULL;

void job_add(struct job *job)
{
    job->next = NULL;
    
    if (job_head == NULL) {
        job_head = job;
        job_tail = job;
    } else {
        job_tail->next = job;
        job_tail = job;
    }
}

int my_get_a_line(int argc, char *argv[], char **line, size_t *line_len)
{
    char prompt = 1;
    if (argc > 1 && (strcmp(argv[1], "-p") == 0)) 
    {
        prompt = 0;
    }

    log_prompt();
    if (prompt) 
    {
        printf("deet> ");
    }

    //man getline for help
    int len = getline(line, line_len, stdin);
    if (len == -1) 
    {
        if (errno == EINTR) 
        {
            return 0;
        }
        
        return -1;
    }
    char *str = *line;
    log_input(str);

    if (len > 0 && str[len - 1] == '\n') 
    {
        str[len-1] = 0;
        len--;
    }
    if (len <= 0) 
    {
        return 0;
    }

    //skip space
    while (*str != 0 && strchr(" ", *str)) 
    {
        len--;
	    str++;
    }
    
    if (*str == 0 || len <= 0) {
        return 0;
    }

    return len;
}

char *psrse_cmd(char *line, int *cmd)
{
    *cmd = CMD_NONE;
    char *str = line;
    
    if (strncmp(str, "help", 4) == 0) 
    {
        *cmd = CMD_HELP;
        str += 4;
    } 
    else if (strncmp(str, "quit", 4) == 0) 
    {
        *cmd = CMD_QUIT;
        str += 4;
    } 
    else if (strncmp(str, "show", 4) == 0) 
    {
        *cmd = CMD_SHOW;
        str += 4;
    } 
    else if (strncmp(str, "run", 3) == 0) 
    {
        str += 3;
        *cmd = CMD_RUN;
    } 
    else if (strncmp(str, "stop", 4) == 0) 
    {
        str += 4;
        *cmd = CMD_STOP;
    } 
    else if (strncmp(str, "cont", 4) == 0) 
    {
        str += 4;
        *cmd = CMD_CONT;
    } 
    else if (strncmp(str, "release", 7) == 0) 
    {
        str += 7;
        *cmd = CMD_RELEASE;
    } 
    else if (strncmp(str, "wait", 4) == 0) 
    {
        str += 4;
        *cmd = CMD_WAIT;
    } 
    else if (strncmp(str, "kill", 4) == 0) 
    {
        str += 4;
        *cmd = CMD_KILL;
    }
    else if (strncmp(str, "peek", 4) == 0) 
    {
        str += 4;
        *cmd = CMD_PEEK;
    } 
    else if (strncmp(str, "poke", 4) == 0) 
    {
        str += 4;
        *cmd = CMD_POKE;
    } 
    else if (strncmp(str, "bt", 2) == 0) 
    {
        str += 2;
        *cmd = CMD_BT;
    } else {
        log_error(str);
        printf("?\n");
        *cmd = CMD_NONE;
        return NULL;
    }
    
    while (*str != 0 && strchr(" ", *str)) {
        str++;
    }

    return str;
}

static void help_msg(void)
{
    printf("Available commands:\n");
    printf("help -- Print this help message\n");
    printf("quit (<=0 args) -- Quit the program\n");
    printf("show (<=1 args) -- Show process info\n");
    printf("run (>=1 args) -- Start a process\n");
    printf("stop (1 args) -- Stop a running process\n");
    printf("cont (1 args) -- Continue a stopped process\n");
    printf("release (1 args) -- Stop tracing a process, allowing it to continue normally\n");
    printf("wait (1-2 args) -- Wait for a process to enter a specified state\n");
    printf("kill (1 args) -- Forcibly terminate a process\n");
    printf("peek (2-3 args) -- Read from the address space of a ptraced process\n");
    printf("poke (3 args) -- Write to the address space of a ptraced process\n");
    printf("bt (1 args) -- Show a stack trace for a ptraced process\n");

    return;
}

static void quit_system(void)
{
    int killed = 0;
    struct job *job = job_head;
    while (job) 
    {
        if (job->state != PSTATE_DEAD) 
        {
            log_state_change(job->pid, job->state, PSTATE_KILLED, job->status);
            job->state = PSTATE_KILLED;
            kill(job->pid, SIGKILL);
            killed++;
        }

        job = job->next;
    }

    if (killed) {
        //test error, so must wait a time,to quit
        struct timespec stime;
        stime.tv_sec = 0;
        stime.tv_nsec = JOB_SLEEP_NSEC;
        nanosleep(&stime, NULL);
    }
    
    return;
}

static char *job_state2string(PSTATE state)
{
    switch (state) 
    {
        case PSTATE_RUNNING:    return "running";
        case PSTATE_STOPPING:   return "stopping";
        case PSTATE_STOPPED:    return "stopped";
        case PSTATE_CONTINUING: return "continuing";
        case PSTATE_KILLED:     return "killed";
        case PSTATE_DEAD:       return "dead";
        case PSTATE_NONE:       return "none";
        default:                return "none";
    }
}

static PSTATE job_string2state(char *string)
{
    PSTATE state;
    
    if (strcmp(string, "running") == 0) 
    {
        state = PSTATE_RUNNING;
    } 
    else if (strcmp(string, "stopping") == 0) 
    {
        state = PSTATE_STOPPING;
    } 
    else if (strcmp(string, "stopped") == 0) 
    {
        state = PSTATE_STOPPED;
    } 
    else if (strcmp(string, "continuing") == 0) 
    {
        state = PSTATE_CONTINUING;
    } 
    else if (strcmp(string, "killed") == 0) 
    {
        state = PSTATE_KILLED;
    } 
    else if (strcmp(string, "dead") == 0) 
    {
        state = PSTATE_DEAD;
    } 
    else 
    {
        state = PSTATE_NONE;
    }

    return state;
}


static void job_print_state_msg(struct job *job, PSTATE new_state, int log)
{
    int i;

    if (log) {
        log_state_change(job->pid, job->state, new_state, job->status);
    }
    job->state = new_state;
    printf("%d\t%d\t%s\t%s\t", job->id, job->pid, job->ptraced ? "T" : "U", 
        job_state2string(job->state));
    if (job->state == PSTATE_DEAD) 
    {
        printf("0x%x\t", job->status);
    } 
    else 
    {
        printf("\t");
    }
    for (i = 0; i < job->argc; i++)
    {
        printf("%s ", job->argv[i]);
    }
    printf("\n");

    return;
}

static void show_job(void)
{
    struct job *job = job_head;
    
    while (job) 
    {
        job_print_state_msg(job, job->state, 0);
        job = job->next;
    }
}

struct job *find_job(int jid)
{
    struct job *job = job_head;
    while (job) 
    {
        if (job->id == jid) 
        {
            return job;
        }
        
        job = job->next;
    }

    return NULL;
}

struct job *find_pid_job(int pid)
{
    struct job *job = job_head;
    while (job) 
    {
        if (job->pid == pid) 
        {
            return job;
        }
        
        job = job->next;
    }

    return NULL;
}

static void run_check_job_ptraced(void)
{
    sigset_t mask;
    sigemptyset(&mask);

    struct job *job = job_head;
    while (job) 
    {
        while (job->ptrace_stopped == 0) 
        {
            sigsuspend(&mask);
        }
        
        job = job->next;
    }
}

void run_job(char *str)
{
    int pid;
    struct job *job = malloc(sizeof(struct job));
    if (job == NULL) {
        log_error("malloc error\n");
        return;
    }
    
    memset(job, 0x00, sizeof(struct job));

    run_check_job_ptraced();
    
    //parse job argc/argv
    char *token = strtok(str, " ");
    while (token) 
    {
        job->argv[job->argc] = strdup(token);
        job->argc++;
        token = strtok(NULL, " ");
    }

    char execv_path[256]= {0};
    pid = fork();
    if (pid == 0) 
    {
        //test find ,must parent running print running state
        struct timespec stime;
        stime.tv_sec = 0;
        stime.tv_nsec = JOB_SLEEP_NSEC;
        nanosleep(&stime, NULL);

        //dup out --> err
        dup2(STDERR_FILENO, STDOUT_FILENO);
        //to TRACEME
        ptrace(PTRACE_TRACEME, 0, NULL, NULL, NULL);

        //to execv job
        //1: system path
        if (execvp(job->argv[0], job->argv) == -1) 
        {
            //2: local path
            snprintf(execv_path, 128, "./%s", job->argv[0]);
            if (execv(execv_path, job->argv) == -1) 
            {
                log_error("execv error\n");
       		    exit(-1);
            }
       	}
        
        exit(0);
    }

    job->id = g_job_id++;
    job->ptraced = 1;
    job->next = NULL;
    job->pid = pid;
    
    job_add(job);
    job_print_state_msg(job, PSTATE_RUNNING, 1);

    return;
}

static void stop_job(char *str)
{
    int jid = atoi(str);
	struct job *job;

	job = find_job(jid);
	if (job == NULL) 
    {
		log_error("not find job\n");
		return;
	}

    job->state = PSTATE_STOPPING;
    kill(job->pid, SIGSTOP);

    return;
}

static void cont_job(char *str)
{
    int jid = atoi(str);
	struct job *job;

	job = find_job(jid);
	if (job == NULL) 
    {
		log_error("not find job\n");
		return;
	}

    //test fail, find cmd do fast, we must wait child to run ptrace and STOPED
    sigset_t mask;
    sigemptyset(&mask);
    while (job->ptrace_stopped == 0) 
    {
        sigsuspend(&mask);
    }
    
    if (job->ptraced) 
    {
        //ptrace cont
        job_print_state_msg(job, PSTATE_RUNNING, 1);
        ptrace(PTRACE_CONT, job->pid, NULL, NULL, NULL);
    } 
    else 
    {
        kill(job->pid, SIGCONT);
    }

    return;
}

static void release_job(char *str)
{
    int jid = atoi(str);
	struct job *job;

	job = find_job(jid);
	if (job == NULL) 
    {
		log_error("not find job\n");
		return;
	}

    //test fail, find cmd do fast, we must wait child to run ptrace and STOPED
    sigset_t mask;
    sigemptyset(&mask);
    while (job->ptrace_stopped == 0) 
    {
        sigsuspend(&mask);
    }

    job->state = PSTATE_CONTINUING;
    if (job->ptraced) {
        //ptrace detach
        job_print_state_msg(job, PSTATE_RUNNING, 1);
        ptrace(PTRACE_DETACH, job->pid, NULL, NULL, NULL);
    } else {
        kill(job->pid, SIGCONT);
    }

    //not attach ptrace
    job->ptraced = 0;

    return;
}

static void wait_job(char *str)
{
    int jid, index;
	struct job *job;
    PSTATE wait_state = PSTATE_DEAD;
    
    index = 0;
    char *token = strtok(str, " ");
    while (token) 
    {
        if (index == 0) 
        {
            jid = atoi(token);
        } 
        else 
        {
            wait_state = job_string2state(token);
        }
        index++;
        
        token = strtok(NULL, " ");
    }
    
    if (wait_state == PSTATE_NONE) {
        log_error("wait input state error\n");
        return;
    }

    if (wait_state == PSTATE_STOPPING) 
    {
        wait_state = PSTATE_STOPPED;
    } 
    else if (wait_state == PSTATE_CONTINUING) 
    {
        wait_state = PSTATE_RUNNING;
    } 
    else if (wait_state == PSTATE_KILLED) 
    {
        wait_state = PSTATE_DEAD;
    }

	job = find_job(jid);
	if (job == NULL) 
    {
		log_error("not find job\n");
		return;
	}
    
    sigset_t mask;
    sigemptyset(&mask);
    //to wait, sleep by sigsuspend
    while (job->state != wait_state) {
        if (job->state == PSTATE_DEAD) {
            break;
        }

        sigsuspend(&mask);
    }

    return;
}

static void kill_job(char *str)
{
    int jid = atoi(str);
	struct job *job;

	job = find_job(jid);
	if (job == NULL) 
    {
		log_error("not find job\n");
		return;
	}

    if (job->state == PSTATE_DEAD) 
    {
        return;
    }

    job_print_state_msg(job, PSTATE_KILLED, 1);
    
    kill(job->pid, SIGKILL);

    return;
}

static void peek_job(char *str)
{
	struct job *job;
    int jid;
    int index = 0;
    unsigned long addr = 0;
    unsigned long data = 0;
    
    char *token = strtok(str, " ");
    while (token) {
        if (index == 0) {
            jid = atoi(token);
        } else {
            sscanf(token, "%lx", &addr);
        }
        index++;
        token = strtok(NULL, " ");
    }
    if (addr == 0) {
        log_error("peek input error\n");
        return;
    }

	job = find_job(jid);
	if (job == NULL) 
    {
		log_error("not find job\n");
		return;
	}

    long ret = ptrace(PTRACE_PEEKDATA, job->pid, (void *)addr, (void *)data);
    if (ret < 0) 
    {
        log_error("ptrace PEEKDATA error\n");
        return;
    }

    printf("%016lx\t%016lx\n", addr, (unsigned long)ret);
    
    return;
}

static void poke_job(char *str)
{
	struct job *job;
    int jid;
    int index = 0;
    unsigned long mm_addr = 0;
    unsigned long mm_data = 0;
    
    char *token = strtok(str, " ");
    while (token) {
        if (index == 0) {
            jid = atoi(token);
        } else if (index == 1) {
            sscanf(token, "%lx", &mm_addr);
        } else {
            sscanf(token, "%lx", &mm_data);
        }
        index++;
        token = strtok(NULL, " ");
    }
    if (mm_addr == 0 || mm_data == 0) 
    {
        log_error("poke input error\n");
        return;
    }
    
	job = find_job(jid);
	if (job == NULL) 
    {
		log_error("not find job\n");
		return;
	}

    long ret = ptrace(PTRACE_POKEDATA, job->pid, (void *)mm_addr, (void *)mm_data);
    if (ret < 0) {
        log_error("ptrace POKEDATA error\n");
        return;
    }

    return;
}

static void bt_job(char *str)
{
    int jid = atoi(str);
	struct job *job;
    struct user_regs_struct regs;
    unsigned long *return_addr;
    unsigned long data;
    unsigned long *rbp_addr;
    long ptrace_ret;

	job = find_job(jid);
	if (job == NULL) 
    {
		log_error("not find job\n");
		return;
	}

    //get curr rbp
    long ret = ptrace(PTRACE_GETREGS, job->pid, NULL, &regs);
    if (ret < 0) {
        log_error("ptrace GETREGS");
        return;
    }
    if (regs.rbp == 0) {
        log_error("rbp zero??\n");
        return;
    }

    rbp_addr = (unsigned long *)regs.rbp;
    while (1) {
        data = 0;
        return_addr = rbp_addr + 1;
        ptrace_ret = ptrace(PTRACE_PEEKDATA, job->pid, (void *)return_addr, (void *)data);
        if (ptrace_ret < 0) {
            //log_error("ptrace PEEKDATA error\n");
            return;
        }
        data = (unsigned long)ptrace_ret;
        if (data == 0) {
            log_error("get prev callback addr data 0\n");
            return;
        }
        printf("%016lx\t%016lx\n", (unsigned long)rbp_addr, data);

        //get prev bp
        ptrace_ret = ptrace(PTRACE_PEEKDATA, job->pid, (void *)rbp_addr, (void *)data);
        if (ptrace_ret < 0) {
            //log_error("ptrace rbp PEEKDATA");
            return;
        }
        data = (unsigned long)ptrace_ret;
        if (data == 0) {
            log_error("get prev rbp data 0\n");
            return;
        }
        
        rbp_addr = (unsigned long *)data;
    }
}

static void do_child_status_print(pid_t pid, int status)
{
    int ret;
	struct job *job;

	job = find_pid_job(pid);
	if (job == NULL) 
    {
		return;
	}

	if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
        job->status = ret;
        job_print_state_msg(job, PSTATE_DEAD, 1);
        return;
	} 

    if (WIFSTOPPED(status)) {
		//ret = WSTOPSIG(status);
        if (job->ptrace_stopped == 0) {
            job->ptrace_stopped = 1;
            job_print_state_msg(job, PSTATE_STOPPED, 1);
        } else {
            job_print_state_msg(job, PSTATE_STOPPED, 1);
        }
        return;
	}

    if (WIFCONTINUED(status)) {
        job_print_state_msg(job, PSTATE_RUNNING, 1);
	}

    if (WIFSIGNALED(status)) 
    {
        job->status = 0;
		//ret = WTERMSIG(status);
        log_state_change(job->pid, job->state, PSTATE_DEAD, job->status);
		job->state = PSTATE_DEAD;
        return;
	}

	return;
}

static void job_sigchld(int sig, siginfo_t *info, void *data)
{
    pid_t pid;
    int status;

    log_signal(SIGCHLD);
    
    while ((pid = waitpid(-1, &status, WUNTRACED | WNOHANG | WCONTINUED)) > 0) {
        do_child_status_print(pid, status);
    }

    return;
}

static void job_sigint(int sig, siginfo_t *info, void *data)
{
    quit_system();

    exit(0);
}

int main(int argc, char *argv[]) 
{
    char *line = NULL;
    size_t line_len = 0;
    int readlen = 0;

    sigset_t mask;
    struct sigaction sa;
    memset(&sa, 0x00, sizeof(sa));

    sigemptyset(&mask);
    sa.sa_mask = mask,
    sa.sa_flags = SA_RESTART | SA_SIGINFO;
    sa.sa_sigaction = job_sigchld,
    sigaction(SIGCHLD, &sa, NULL);

    sa.sa_sigaction = job_sigint,
    sigaction(SIGINT, &sa, NULL);

    log_startup();
    
    while (1) 
    {
        readlen = my_get_a_line(argc, argv, &line, &line_len);
        if (readlen == -1) 
        {
            break;
        }
        if (readlen == 0) 
        {
            continue;
        }

        int cmd = CMD_NONE;
        char *str = psrse_cmd(line, &cmd);
        switch (cmd) {
            case CMD_HELP:
                help_msg();
                break;

            case CMD_QUIT:
                quit_system();
                break;

            case CMD_SHOW:
                show_job();
                break;

            case CMD_RUN:
                run_job(str);
                break;

            case CMD_STOP:
                stop_job(str);
                break;

            case CMD_CONT:
                cont_job(str);
                break;

            case CMD_RELEASE:
                release_job(str);
                break;

            case CMD_WAIT:
                wait_job(str);
                break;

            case CMD_KILL:
                kill_job(str);
                break;

            case CMD_PEEK:
                peek_job(str);
                break;

            case CMD_POKE:
                poke_job(str);
                break;

            case CMD_BT:
                bt_job(str);
                break;

            case CMD_NONE:
            default:
                break;
        }

        if (cmd == CMD_QUIT) 
        {
            break;
        }
    }

    free(line);
    log_shutdown();
    
    return 0;
}
