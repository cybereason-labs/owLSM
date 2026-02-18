/*
 * Dash shell node structures for eBPF
 * Generated from dash source code (src/nodes.h)
 * These structures have been stable since 2005
 */

 #ifndef DASH_NODES_H
 #define DASH_NODES_H
 
 // Node type constants
 #define DASH_NCMD 0
 #define DASH_NPIPE 1
 #define DASH_NREDIR 2
 #define DASH_NBACKGND 3
 #define DASH_NSUBSHELL 4
 #define DASH_NAND 5
 #define DASH_NOR 6
 #define DASH_NSEMI 7
 #define DASH_NIF 8
 #define DASH_NWHILE 9
 #define DASH_NUNTIL 10
 #define DASH_NFOR 11
 #define DASH_NCASE 12
 #define DASH_NCLIST 13
 #define DASH_NDEFUN 14
 #define DASH_NARG 15
 #define DASH_NTO 16
 #define DASH_NCLOBBER 17
 #define DASH_NFROM 18
 #define DASH_NFROMTO 19
 #define DASH_NAPPEND 20
 #define DASH_NTOFD 21
 #define DASH_NFROMFD 22
 #define DASH_NHERE 23
 #define DASH_NXHERE 24
 #define DASH_NNOT 25
 
 // Dash internal control characters (from parser.h)
 // These appear inside narg.text to encode quoting and expansion info.
 // They must be translated back to their original characters when reading.
 #define DASH_CTLESC       0x81  /* next byte is a literal (escaped) char */
 #define DASH_CTLVAR       0x82  /* variable substitution start */
 #define DASH_CTLENDVAR    0x83  /* variable substitution end */
 #define DASH_CTLBACKQ     0x84  /* backtick / command substitution */
 #define DASH_CTLARI       0x86  /* arithmetic expansion start */
 #define DASH_CTLENDARI    0x87  /* arithmetic expansion end */
 #define DASH_CTLQUOTEMARK 0x88  /* quote boundary marker */
 
 // Simple command: cmd arg1 arg2 ...
 struct dash_ncmd {
     int type;           // offset 0: DASH_NCMD (0)
     int linno;          // offset 4: line number
     void *assign;       // offset 8: variable assignments (union node *)
     void *args;         // offset 16: arguments - linked list of narg (union node *)
     void *redirect;     // offset 24: redirections (union node *)
 };
 
 // Pipeline: cmd1 | cmd2 | ...
 struct dash_npipe {
     int type;           // offset 0: DASH_NPIPE (1)
     int backgnd;        // offset 4: run in background
     void *cmdlist;      // offset 8: list of commands (struct nodelist *)
 };
 
 // Redirection wrapper
 struct dash_nredir {
     int type;           // offset 0: DASH_NREDIR (2), DASH_NBACKGND (3), DASH_NSUBSHELL (4)
     int linno;          // offset 4: line number
     void *n;            // offset 8: the command (union node *)
     void *redirect;     // offset 16: redirections (union node *)
 };
 
 // Binary operators: cmd1 && cmd2, cmd1 || cmd2, cmd1 ; cmd2
 struct dash_nbinary {
     int type;           // offset 0: DASH_NAND (5), DASH_NOR (6), DASH_NSEMI (7)
     void *ch1;          // offset 8: first child (union node *)
     void *ch2;          // offset 16: second child (union node *)
 };
 
 // Argument/word node - THIS IS THE KEY ONE FOR COMMAND TEXT
 struct dash_narg {
     int type;           // offset 0: DASH_NARG (15)
     void *next;         // offset 8: next argument in list (union node *)
     char *text;         // offset 16: THE COMMAND TEXT (raw, unexpanded)
     void *backquote;    // offset 24: commands in backquotes (struct nodelist *)
 };
 
 // Negation: ! cmd
 struct dash_nnot {
     int type;           // offset 0: DASH_NNOT (25)
     void *com;          // offset 8: the command (union node *)
 };
 
 // Nodelist for pipelines
 struct dash_nodelist {
     void *next;         // offset 0: next in list (struct nodelist *)
     void *n;            // offset 8: the node (union node *)
 };
 
 // File redirection: > file, < file, >> file, etc.
 struct dash_nfile {
     int type;           // offset 0: NTO (16), NCLOBBER (17), NFROM (18), NFROMTO (19), NAPPEND (20)
     // padding 4 bytes
     void *next;         // offset 8: next redirection (union node *)
     int fd;             // offset 16: file descriptor (0=stdin, 1=stdout, 2=stderr)
     // padding 4 bytes
     void *fname;        // offset 24: filename node (narg) - contains the path
     char *expfname;     // offset 32: expanded filename (may be NULL before expansion)
 };
 
 #endif // DASH_NODES_H