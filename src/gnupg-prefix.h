#ifndef __ASSEMBLER__
#define rl_completion_matches(a,b) completion_matches(a,b)
#define rl_completion_func_t CPFunction
extern int rl_catch_signals;
extern int rl_inhibit_completion;
extern int rl_attempted_completion_over;
#define rl_cleanup_after_signal crl_cleanup_after_signal 
#define rl_free_line_state crl_free_line_state
void crl_cleanup_after_signal(void);
void crl_free_line_state(void);
#endif
