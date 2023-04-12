#ifndef GREG
#define GREG
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <string.h>

struct _rect { int x, y, w, h; };
enum _split_type { _HSPLIT, _VSPLIT };
static FILE **logs = NULL;

#define _with(...) \
  for (int _w = 1; _w; _w = 0) \
    for (__VA_ARGS__; _w; _w = 0)
#define _then(...) \
  for (int _t = 1; _t; ((__VA_ARGS__), _t = 0))
#define _stringize(...) _stringize1(__VA_ARGS__)
#define _stringize1(...) #__VA_ARGS__
#define _split(option, stringized) \
  _with(struct _rect _rects[16]) \
  _with(pid_t _pids[16]) \
  _then(_wait_for_children_to_die(_pids)) \
  _with(int _i = 0, _max) \
  _with( \
    memset(&_rects, 0x00, sizeof(_rects)), \
    memset(&_pids, 0x00, sizeof(_pids)), \
    _max = _parse_split(_get_terminal_dimensions(), &_rects, option, stringized) \
  ) \
  _split1
#define hsplit(...) _split(_HSPLIT, _stringize(__VA_ARGS__))
#define vsplit(...) _split(_VSPLIT, _stringize(__VA_ARGS__))

#define _split1 \
  if (_i < _max && (_pids[_i++] = fork()) == 0) \
    _then(exit(EXIT_SUCCESS)) \
    _with(pid_t pid) \
    _with(_i--) \
    if ((pid = fork()) != 0) \
      _hijack_child(pid, _rects[_i]); \
    else \
      _with( \
        ptrace(PTRACE_TRACEME, 0, NULL, NULL), \
        kill(getpid(), SIGSTOP) \
      ) \
      _then(exit(EXIT_SUCCESS))

#define and else _split1

static inline void _wait_for_children_to_die(pid_t *pids) {
  int status;
  
  for (int i = 0; i < 16 && pids[i] != 0; i++) {
    while (waitpid(pids[i], &status, 0) && !WIFEXITED(status))
      ;
  }
}

static inline void _hijack_child(pid_t pid, struct _rect rect) {
  int left_ptr = rect.x, up_ptr = rect.y;
  int status;
  pid = waitpid(-1, &status, 0);
  ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACEFORK);
  ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
  while ((pid = waitpid(-1, &status, 0)) && !WIFEXITED(status)) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    if (regs.orig_rax == 1 && regs.rdi == 1) { // write(stdout, ..., ...)
      const char *buf = (const char *) regs.rsi;
      size_t count = (size_t) regs.rdx;
      
      for (size_t i = 0; i < count; i++) {
        char c = ptrace(PTRACE_PEEKDATA, pid, &buf[i], NULL);
        if (c == '\x1b') {
          char escape[64];
          int escapei = 0;
          i++;
          c = '0';
          while (c >= '0' && c <= '9' || c == ';') {
            i++;
            c = ptrace(PTRACE_PEEKDATA, pid, &buf[i], NULL);
            escape[escapei++] = c;
          }
          escape[escapei] = '\0';
          escapei = 0;
          switch (c) {
            case 'A': {
              int val = 0;
              if (escape[escapei] >= '0' && escape[escapei] <= '9') {
                val = val * 10 + escape[escapei] - '0';
                escapei++;
              }
              val--;
              if (val == -1)
                val = 0;
              while (up_ptr > rect.y && val > 0) {
                up_ptr--;
                val--;
              }
              break;
            }
            case 'B': {
              int val = 0;
              if (escape[escapei] >= '0' && escape[escapei] <= '9') {
                val = val * 10 + escape[escapei] - '0';
                escapei++;
              }
              val--;
              if (val == -1)
                val = 0;
              while (up_ptr < rect.y + rect.h && val > 0) {
                up_ptr++;
                val--;
              }
              break;
            }
            case 'C': {
              int val = 0;
              if (escape[escapei] >= '0' && escape[escapei] <= '9') {
                val = val * 10 + escape[escapei] - '0';
                escapei++;
              }
              val--;
              if (val == -1)
                val = 0;
              while (left_ptr < rect.x + rect.w && val > 0) {
                left_ptr++;
                val--;
              }
              break;
            }
            case 'D': {
              int val = 0;
              if (escape[escapei] >= '0' && escape[escapei] <= '9') {
                val = val * 10 + escape[escapei] - '0';
                escapei++;
              }
              val--;
              if (val == -1)
                val = 0;
              while (left_ptr > rect.x && val > 0) {
                left_ptr--;
                val--;
              }
              break;
            }
            case 'H': {
              int col = 0, row = 0;
              if (escape[escapei] >= '0' && escape[escapei] <= '9') {
                row = row * 10 + escape[escapei] - '0';
                escapei++;
              }
              row--;
              if (row == -1)
                row = 0;
              escapei++;
              if (escape[escapei] >= '0' && escape[escapei] <= '9') {
                col = col * 10 + escape[escapei] - '0';
                escapei++;
              }
              
              col--;
              if (col == -1)
                col = 0;
              left_ptr = col + rect.x;
              if (left_ptr >= rect.x + rect.w)
                left_ptr = rect.x + rect.w - 1;
              
              row--;
              if (row == -1)
                row = 0;
              up_ptr = row + rect.y;
              if (up_ptr >= rect.y + rect.h)
                up_ptr = rect.y + rect.h - 1;
              break;
            }
            default: {
              fflush(stdout), printf("\x1b[%s", escape), fflush(stdout);
            }
          }
        } else if (c == '\n') {
          left_ptr = rect.x;
          up_ptr++;
          if (up_ptr >= rect.y + rect.h)
            fprintf(stderr, "error: ran out of buffer space (scrolling not supported yet)\n"), exit(EXIT_FAILURE);
        } else {
          fflush(stdout), printf("\x1b[%d;%dH%c\n", up_ptr + 1, left_ptr + 1, c), fflush(stdout);
          left_ptr++;
          if (left_ptr >= rect.x + rect.w) {
            left_ptr = rect.x;
            up_ptr++;
            if (up_ptr >= rect.y + rect.h)
              fprintf(stderr, "error: ran out of buffer space (scrolling not supported yet)\n"), exit(EXIT_FAILURE);
          }
        }
      }
      
      regs.orig_rax = -1;
      ptrace(PTRACE_SETREGS, pid, NULL, &regs);
      ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
      waitpid(pid, &status, 0);
      ptrace(PTRACE_GETREGS, pid, NULL, &regs);
      regs.rax = count;
      ptrace(PTRACE_SETREGS, pid, 0, &regs);
    }
    if (regs.orig_rax == 16 && regs.rdi == 1 && regs.rsi == TIOCGWINSZ) {
      struct winsize *w = (void *) regs.rdx;
      struct winsize our_w;

      our_w.ws_col = rect.w;
      our_w.ws_row = rect.h;
      long *ptr = (void *) &our_w;
      for (int i = 0; i < sizeof(struct winsize) / sizeof(long); i++)
        ptrace(PTRACE_POKEDATA, pid, &w[i], ptr[i]);
    }
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
  }
}

static inline struct _rect _get_terminal_dimensions(void) {
  struct _rect current_window;
  struct winsize w;
  if (!logs) {
    logs = mmap(NULL, sizeof(FILE *), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    *logs = fopen("/tmp/greg.log", "a");
  }
  ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
  current_window.x = 0;
  current_window.y = 0;
  current_window.w = w.ws_col;
  current_window.h = w.ws_row;
  return current_window;
}

static inline int _parse_split(
  struct _rect current_rect,
  struct _rect (*rects)[16],
  enum _split_type split_type,
  const char *args
) {
  int slots[16];
  int sloti = 0;
  const char *p = args;
  
  while (*p != '\0') {
    while (*p == ' ' || *p == ',')
      p++;
    if (*p == '.') {
      while (*p == '.')
        p++;
      slots[sloti++] = -1;
    } else if (*p >= '0' && *p <= '9') {
      int val = 0;
      while (*p >= '0' && *p <= '9') {
        val = val * 10 + *p - '0';
        p++;
      }
      if (*p == '%') {
        val = (current_rect.w * val) / 100;
        p++;
      }
      slots[sloti++] = val;
    }
  }
  int space_left = split_type == _HSPLIT ? current_rect.w
                 : split_type == _VSPLIT ? current_rect.h
                 : -1;
  int grows = 0;
  for (int i = 0; i < sloti; i++) {
    if (slots[i] == -1)
      grows++;
    else
      space_left -= slots[i];
  }
  int tally = 0;
  for (int i = 0, j = 1; i < sloti; i++) {
    if (slots[i] == -1) {
      slots[i] = (j * space_left) / grows - tally;
      tally = (j * space_left) / grows;
      j++;
    }
  }
  tally = split_type == _HSPLIT ? current_rect.x
        : split_type == _VSPLIT ? current_rect.y
        : -1;
  for (int i = 0; i < sloti; i++) {
    if (split_type == _HSPLIT) {
      (*rects)[i].x = tally;
      (*rects)[i].y = current_rect.y;
      (*rects)[i].w = slots[i];
      (*rects)[i].h = current_rect.h;
    } else if (split_type == _VSPLIT) {
      (*rects)[i].x = current_rect.x;
      (*rects)[i].y = tally;
      (*rects)[i].w = current_rect.w;
      (*rects)[i].h = slots[i];
    }
    tally += slots[i];
  }
  
  return sloti;
}

#endif
