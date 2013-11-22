// Copyright (c) 2013 Ronald Ping Man Chan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <cmath>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/inotify.h>
#include <cerrno>
#include <dirent.h>
#include <csignal>
#include <vector>
#include <list>

using namespace std;

const char lockdir[] = "/var/lock/isolate";
char *isolate_directory = NULL, *fname = NULL, *fname2 = NULL, *cmd = NULL, *initcmd = NULL, *freecmd = NULL;
char *optstring = NULL;
int isolate_boxes = 0;
int ppid = -1;
unsigned long long ppid_starttime = -1, pid_starttime = -1;
char *buffer = NULL;

void init(char *&s, int n) {
  if (s != NULL) delete(s);
  s = new char[n];
  s[0]=0;
}

bool isolate_detect() {
  // read isolate config
  FILE *isolate_conf = popen("isolate --version","r");
  size_t sz=256;
  char *line = new char[sz];
  const char directory_key[] = "Sandbox directory: ", credentials_key[] = "Sandbox credentials: ";
  while (getline(&line, &sz, isolate_conf) != -1) {
    if (strncmp(line, directory_key, strlen(directory_key)) == 0) {
      init(isolate_directory,strlen(line)-strlen(directory_key)+10);
      strcpy(isolate_directory, line+strlen(directory_key));
      isolate_directory[strlen(isolate_directory)-1] = 0;
    }
    else if (strncmp(line, credentials_key, strlen(credentials_key)) == 0) {
      int a,b,c,d;
      if (sscanf(line+strlen(credentials_key), "uid=%d-%d gid=%d-%d", &a, &b, &c, &d)==4 && b-a==d-c) isolate_boxes = b-a+1;
    }
  }
  pclose(isolate_conf);
  if (isolate_directory == NULL) {
    fprintf(stderr,"isolate directory could not be detected.\n");
    return false;
  }
  if (isolate_boxes == 0) {
    fprintf(stderr,"Number of isolate boxes allocated is zero, re-install with a non-zero number of boxes.\n");
    return false;
  }
  return true;
}

void seedrand() { // seed with time, and pid in case multiple processes seed (use isolock) at the same time
  srand(time(NULL)); // could be duplicated if within 1 sec of each other
  srand(rand()+ppid); // could be duplicated if a process requests multiple locks
  srand(rand()+getpid()); // not readily duplicated - this is the process of isolock itself
}

int bigrand() {
  unsigned long long rd = rand()*RAND_MAX+rand();
  rd%=isolate_boxes;
  return (int)rd;
}

bool init(const char *dir) {
  struct stat st;
  if (stat(dir, &st) == 0 && S_ISDIR(st.st_mode)) return true;
  else if (mkdir(dir, 0777) == 0) return true;
  fprintf(stderr, "Lock directory %s could not be created.\n", fname);
  return false;
}

bool initlockdir() {
  if (!init(lockdir)) return false;
  if (chmod(lockdir, 0755)!=0) return false;
  return true;
}

bool _alarmed = false;
void sig_alarm(int signum) {
  // interrupts blocking system calls
  _alarmed = true;
}

bool alarmed() {
  bool ans = _alarmed;
  _alarmed = false;
  return ans;
}

list<int> locked;

int freelock(int box_id, char *optstring = NULL) {
  int pid, pidlock;
  // check that box_id belongs to process
  sprintf(fname, "%s/lock/%d.pidlock", lockdir, box_id);
  FILE *file = fopen(fname,"r");
  if (file == NULL) {
    fprintf(stderr, "Could not access lock file for box_id=%d.\n", box_id);
    return 1;
  }
  long long starttime;
  int count = fscanf(file, "%d:%lld\n", &pid, &starttime);
  if (count != 2) {
    fprintf(stderr, "Invalid pidlock file data for box_id=%d.\n", box_id);
    return 2;
  }
  fclose(file);
  if (pid != ppid && pid != getpid()) {
    fprintf(stderr, "Cannot unlock box_id=%d - it does not belong to you.\n", box_id);
    return 1;
  }
  
  // lock freeing authorised
  if (optstring == NULL) sprintf(freecmd, "isolate -b%d --cleanup 2>/dev/null 1>&2", box_id);
  else sprintf(freecmd, "isolate %s -b%d --cleanup 2>/dev/null 1>&2", optstring, box_id);
  int ignorestat = system(freecmd);
  sprintf(fname2, "%s/free/%d.pidlock", lockdir, box_id);
  int stat = rename(fname, fname2);
  if (stat == 0) {
    return 0;
  }
  else {
    fprintf(stderr, "Could not remove lock on box_id=%d - user has insufficient privileges.\n", box_id);
    return 1;
  }
}

void releaselocked() {
  for (list<int>::iterator it = locked.begin(); it != locked.end();) {
    if (freelock(*it)==0) locked.erase(it++);
  }
}

void panic(int code) {
  releaselocked(); 
  exit(code);
}

bool valid(int box_id) {
  return (box_id >= 0 && box_id < isolate_boxes);
}

int validate(int box_id) {
  if (!valid(box_id)) {
    fprintf(stderr, "%d is an invalid box_id.\n", box_id);
    panic(3);
  }
  return box_id;
}

void validate_option(char *s) {
  if (strcmp(s,"--")==0) {
    fprintf(stderr, "`--` is an invalid option.\n");
    panic(7);
  }
  for (int i=0;s[i]!=0;i++) {
    if (s[i] != '-' && s[i] != '=' && (s[i] < 'a' || s[i] > 'z') && (s[i] < 'A' || s[i] > 'Z') && s[i] != '/' && s[i] != ':' && (s[i] < '0' || s[i] > '9')) {
      fprintf(stderr, "`%s` is an invalid option.\n", s);
      panic(7);
    }
  }
}

int filter_pidlock(const struct dirent *entry) {
  char *p;
  long int bid = strtol(entry->d_name, &p, 10);
#ifdef _DIRENT_HAVE_D_TYPE 
  if (entry->d_type != DT_REG) return false;
#endif
  return (valid(bid) && strcmp(p,".pidlock")==0);
}

int randsort(const struct dirent **a, const struct dirent **b) {
  static int sel=0, seed=0;
  if (sel==0) {
    sel = 1;
    seed=rand();
  }
  int ans = seed & sel;
  if (sel < RAND_MAX/2+RAND_MAX%2) sel<<=1;
  else sel = 0;
  return ans;
}

unsigned long long get_starttime(int pid) { // get process start time (Note: using popen("ps") or similar would be slow because forks are slow)
  sprintf(fname2, "/proc/%d/stat", pid);
  FILE *f = fopen(fname2,"r");
  if (f == NULL) panic(11);
  unsigned long long starttime;
  if (fscanf(f,"%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d %llu", &starttime) == 1) {
    return starttime;
  }
  else panic(12);
}

void sig_panic(int signum) {
  fprintf(stderr, "Signal %d: %s\n", signum, strsignal(signum));
  panic(64+signum);
}

bool init() {
  if (!initlockdir()) return false;
  ppid = getppid();
  if (!isolate_detect()) return false;
  init(fname,max(strlen(isolate_directory),strlen(lockdir))+50);
  init(fname2,max(strlen(isolate_directory),strlen(lockdir))+50);
  init(cmd,2*max(strlen(isolate_directory),strlen(lockdir))+50);
  init(freecmd,150);
  ppid_starttime = get_starttime(ppid);
  pid_starttime = get_starttime(getpid());
  seedrand();
  sprintf(fname, "%s/lock", lockdir);
  if (!init(fname)) return false;
  sprintf(fname, "%s/free", lockdir);
  if (!init(fname)) return false;
  struct sigaction actalarm = {sig_alarm};
  sigaction(SIGALRM, &actalarm, NULL);
  struct sigaction actpanic = {sig_panic};
  // panic if signaled to exit
  sigaction(SIGINT, &actpanic, NULL);
  sigaction(SIGQUIT, &actpanic, NULL);
  sigaction(SIGILL, &actpanic, NULL);
  sigaction(SIGSEGV, &actpanic, NULL);
  sigaction(SIGTERM, &actpanic, NULL);
  return true;
}

bool valid_lock(int pid, unsigned long long starttime) {
  int stat = kill(pid, 0);
  if (stat != 0) return false;
  if (get_starttime(pid) != starttime) return false; // we are using start_time in jiffies in case of PID recycling
  return true;
}

bool lock_box(int box_id) {
  sprintf(fname, "%s/lock/%d.pidlock", lockdir, box_id);
  FILE *file = fopen(fname,"a+"); // atomic appends
  if (file == NULL) {
    fprintf(stderr,"Could not open file. Check user permissions.\n");
    panic(1);
  }
  // check if free
  int pid=-1, narg, valid=false;
  long long starttime;
  while (-1 != (narg = fscanf(file, "%d:%lld\n", &pid, &starttime))) {
    if (valid = valid_lock(pid, starttime)) break;
  }

  if (valid) {
    if (pid != getpid()) return false; // there is already a valid lock (which is not ours)
  }
  else { // no valid lock - apply for, and queue up our own lock
    // enter our entry
    fprintf(file, "%d:%lld\n", getpid(), pid_starttime);
    fflush(file);

    // see if we won the contest
    rewind(file);
    valid=false;
    while (-1 != (narg = fscanf(file, "%d:%lld\n", &pid, &starttime))) {
      if (valid_lock(pid, starttime)) {
        // is this us?
        if (pid == getpid() && starttime == pid_starttime) {
          valid=true;
          break;
        }
        else return false; // somebody beat us
      }
    }
    if (!valid) return false; // our append disappeared (somebody beat us)
  }
  // we have a good lock in the queue:
  // write pid file
  sprintf(fname2, "%s/free/%d.pidlock", lockdir, box_id);
  FILE *pidfile = fopen(fname2,"w");
  if (pidfile == NULL) return false;
  fprintf(pidfile, "%d:%lld\n", ppid, ppid_starttime);
  fclose(pidfile);

  // move pid file in-place (to remove queue)
  int stat = rename(fname2, fname);

  if (stat == 0) {
    locked.push_back(box_id);
    return true;
  }
  else return false;
}

int getfreelocks(int numlocks) {
  int initial_size = locked.size();
  if (numlocks == initial_size) return 0;
  // check any locks marked free
  sprintf(fname, "%s/free", lockdir);
  struct dirent **namelist;
  int n = scandir(fname, &namelist, filter_pidlock, randsort);
  for (int i=0;i<n;i++) {
    int box_id = atoi(namelist[i]->d_name);
    if (lock_box(box_id)) {
      if (locked.size() == numlocks) break;
    }
  }
  return locked.size()-initial_size;
}

int scanlocks(int numlocks) {
  int initial_size = locked.size();
  if (numlocks == initial_size) return 0;
  // scan any locks available
  int offset = bigrand();
  for (int i=0;i<isolate_boxes;i++) {
    int box_id = (offset+i)%isolate_boxes;
    if (lock_box(box_id)) {
      if (locked.size() == numlocks) break;
    }
  }
  return locked.size()-initial_size;
}

int getlocks(int numlocks = 1, double timeout = 0) {
  double tsec = 0;
  long tus = modf(timeout, &tsec)*1E6;
  long ts = tsec;
  getfreelocks(numlocks); // easy to get locks
  scanlocks(numlocks); // slower way to get locks

  // not enough locks
  if (locked.size() < numlocks) {
    releaselocked(); // release all locks (to avoid deadlocks)
    
    if (timeout < 0) return locked.size();

    int fd = -1, inotify = -1;
    try {
      // lock master (blocking)
      sprintf(fname, "%s/free", lockdir);
      fd = open(fname, O_RDONLY);
      if (fd == -1) throw; // lock failed
      struct itimerval timer = {{0,(ts==0&&tus==0)?0:1E5},{ts,tus}}; // interval 0.1 sec in case we miss alarm
      struct itimerval zero_timer = {{0,0},{0,0}};
      if (numlocks > 1) { // only need to acquire the lock if more than 1 box required
        alarmed();
        setitimer(ITIMER_REAL, &timer, NULL); // set timer
        int stat = flock(fd, LOCK_EX);
        setitimer(ITIMER_REAL, &zero_timer, &timer); // unset timer and retrieve remaining time
        if (alarmed() || stat != 0) throw; // lock failed
      }

      // acquire locks (blocking)
      inotify = inotify_init();
      if (inotify == -1) throw;
      if (inotify_add_watch(inotify, fname, IN_CREATE | IN_MOVED_TO) == -1) throw;
      
      setitimer(ITIMER_REAL, &timer, NULL);
      getfreelocks(numlocks);
      int buffer_size = sizeof(struct inotify_event)+256;
      init(buffer, buffer_size);
      while (!alarmed()) {
        int sz = read(inotify, buffer, buffer_size);
        if (sz==0) init(buffer, buffer_size*=2);
        else if (sz==-1) break;
        else {
          struct inotify_event *event = NULL;
          for (int i=0;i<sz;i+=sizeof(struct inotify_event) + event->len) {
            event = (struct inotify_event*)buffer+i;
            char *extension;
            long box_id = strtol(event->name, &extension, 10);
            if (strcmp(extension,".pidlock")==0 && valid(box_id)) {
              lock_box(box_id);
              if (locked.size()==numlocks) break;
            }
          }
        }
        if (locked.size()==numlocks) break;
      }
      setitimer(ITIMER_REAL, &zero_timer, &timer); // unset timer
      close(inotify);
      close(fd);
      if (locked.size()<numlocks) releaselocked();
    }
    catch (...) {
      if (inotify != -1) close(inotify);
      if (fd != -1) close(fd);
      return 0;
    }
  }

  return locked.size();
}

void usage() {
  fprintf(stderr, "%s", "\
Usage: isolock [-l|--lock] [<options>] [--] [<box_id(s)>] [<isolate-init-options>]\n\
       isolock (-f|--free) [--] <box_id(s)> [<isolate-clean-options>]\n\
\n\
Options:\n\
-l, --lock (default)\tAcquires a lock on a box_id,\n\
\t\t\tfinds an unused box_id if no specific box_id is specified\n\
\t\t\tand prints the acquired box_id to stdout on success\n\
-f, --free\t\tRelease locks on box_id(s), prints to stdout for\n\
\t\t\teach box_id unlocked\n\
-n=<N>\t\t\tAcquire locks for <N> boxes (only if no <box_id(s)> are given)\n\
-t=<T>, --timeout=<T>\tTimeout in seconds for acquiring locks on <N> boxes (without <box_id(s)>),\n\
\t\t\tblocks indefinitely if timeout is set to 0, no blocking if negative\n\
--noinit\t\tWhen locking boxes, will not initialize with isolate\n\
--\t\t\tStop parsing options\n\
\n\
Arguments:\n\
<box_id(s)>\t\tList of boxes (separate arguments, does not work with -n option)\n\
<isolate-init-options>\tOptions to pass to isolate, as `isolate --init <isolate-init-options>`\n\
<isolate-clean-options>\tOptions to pass to isolate, as `isolate --cleanup <isolate-clean-options>`\n\
\n\
Examples:\n\
isolock -l 4 6\n\
\tAcquires a lock on box_id=4 and box_id=6\n\
isolock -f 4 6\n\
\tReleases a previous lock on box_id=4 and box_id=6\n\
isolock > box_id.txt\n\
\tAcquires a lock on an unused box_id, saves the lock's box_id into box_id.txt\n\
isolock -- --cg\n\
\tAcquires a lock, and initializes the isolate box directory, with the --cg (control group) option\n\
isolock -n 4\n\
\tAcquire locks on 4 different box_ids, blocking indefinitely\n\
isolock -n4 -t=-1\n\
\tAcquire locks on 4 different box_ids, without blocking\n\
");
}

int mode = 'l';
int isolate_init = 1;

static const char short_opts[] = "lfhn:t:";
static const struct option long_opts[] = {
  {"lock", 0, NULL, 'l'},
  {"free", 0, NULL, 'f'},
  {"help", 0, NULL, 'h'},
  {"timeout", 1, NULL, 't'},
  {"noinit", 0, NULL, 'I'},
  {NULL, 0, 0, 0}
};

int main(int argc, char **argv) {
  if (!init()) return 10;
  int n=1;
  double t=0;
  int c;
  while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) >= 0) {
    switch (c) {
      case 'l':
      case 'f':
      case 'h':
        mode = c;
        break;
      case 'n':
        n = max(atoi(optarg),0);
        break;
      case 't':
        t = atof(optarg);
        break;
      case 'I':
        isolate_init = 0;
        break;
      default:
        usage();
        return 2;
    }
  }
  if (mode == 'h') {
    usage();
    return 0;
  }
  else if (mode == 'l') {
    int box_id = -1;
    int id_end = optind;
    while (id_end < argc && argv[id_end][0] != '-') id_end++;

    int optlength = 2;
    for (int i=id_end;i<argc;i++) optlength += strlen(argv[i])+2;
    init(optstring,optlength);
    int optn = 0;
    for (int i=id_end;i<argc;i++) {
      validate_option(argv[i]);
      sprintf(optstring+optn," %s",argv[i]);
      optn+=strlen(argv[i])+1;
    }

    if (optind < id_end) {
      for (int i=optind;i<id_end;i++) {
        box_id = atoi(argv[i]);
        validate(box_id);
      }
      for (int i=optind;i<id_end;i++) {
        box_id = atoi(argv[i]);
        if (!lock_box(box_id)) {
          fprintf(stderr, "Isolate box %d unavailable.\n", box_id);
        }
      }
    }
    else {
      if (!getlocks(n,t)) {
        fprintf(stderr, "Insufficient isolate boxes available.\n");
        return 1; // no box locked
      }
      else if (locked.size() < n) {
        fprintf(stderr, "Could not acquire %d locks, but could not release the %u acquired locks.\n", n, locked.size());
      }
    }
    // success
    vector<int> out;
    for (list<int>::iterator it=locked.begin();it!=locked.end();) {
      printf("%d\n", *it); // output box_id
      out.push_back(*it);
      locked.erase(it++);
    }
    if (isolate_init) for (vector<int>::iterator it=out.begin();it!=out.end();it++) { // init
      init(initcmd, strlen(optstring)+50);
      sprintf(initcmd, "isolate %s -b%d --init 2>/dev/null 1>&2", optstring, *it);
      int stat = system(initcmd);
      if (stat != 0) {
        fprintf(stderr, "Lock acquired, but `%s` command failed.\n", initcmd);
        return 256;
      }
    }
    return 0;
  }
  else if (mode == 'f') {
    int box_id = -1;
    int id_end = optind;
    while (id_end < argc && argv[id_end][0] != '-') id_end++;

    int optlength = 2;
    for (int i=id_end;i<argc;i++) optlength += strlen(argv[i])+2;
    init(optstring,optlength);
    int optn = 0;
    for (int i=id_end;i<argc;i++) {
      validate_option(argv[i]);
      sprintf(optstring+optn," %s",argv[i]);
      optn+=strlen(argv[i])+1;
    }
    init(freecmd, strlen(optstring)+100);

    if (optind >= id_end) {
      fprintf(stderr, "No box_id was specified - cannot free lock.\n");
      return 4;
    }
    else {
      for (int i=optind;i<id_end;i++) {
        box_id = atoi(argv[i]);
        validate(box_id);
      }
      int fails=0;
      for (int i=optind;i<id_end;i++) {
        box_id = atoi(argv[i]);
        if (freelock(box_id, optstring) == 0) printf("%d\n", box_id);
        else fails++;
      }
      return fails>0;
    }
  }
  else {
    fprintf(stderr, "Unknown mode.\n");
    return 2;
  }
}
