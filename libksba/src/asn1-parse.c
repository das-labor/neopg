/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.0.4"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 2

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1




/* Copy the first part of user declarations.  */
#line 42 "../../../libksba/src/asn1-parse.y" /* yacc.c:339  */

#ifndef BUILD_GENTOOLS
# include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>

#ifdef BUILD_GENTOOLS
# include "gen-help.h"
#else
# include "util.h"
# include "ksba.h"
#endif

#include "asn1-func.h"

/* It would be better to make yyparse static but there is no way to do
   this.  Let's hope that this macros works. */
#define yyparse _ksba_asn1_yyparse

/* #define YYDEBUG 1 */
#define MAX_STRING_LENGTH 129

/* Dummy print so that yytoknum will be defined.  */
#define YYPRINT(F, N, L)  do { } while (0);


/* constants used in the grammar */
enum {
  CONST_EXPLICIT = 1,
  CONST_IMPLICIT
};

struct parser_control_s {
  FILE *fp;
  int lineno;
  int debug;
  int result_parse;
  AsnNode parse_tree;
  AsnNode all_nodes;
};
#define PARSECTL ((struct parser_control_s *)parm)


#line 115 "asn1-parse.c" /* yacc.c:339  */

# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 1
#endif


/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    ASSIG = 258,
    NUM = 259,
    IDENTIFIER = 260,
    OPTIONAL = 261,
    INTEGER = 262,
    SIZE = 263,
    OCTET = 264,
    STRING = 265,
    SEQUENCE = 266,
    BIT = 267,
    UNIVERSAL = 268,
    PRIVATE = 269,
    DEFAULT = 270,
    CHOICE = 271,
    OF = 272,
    OBJECT = 273,
    STR_IDENTIFIER = 274,
    ksba_BOOLEAN = 275,
    ksba_TRUE = 276,
    ksba_FALSE = 277,
    APPLICATION = 278,
    ANY = 279,
    DEFINED = 280,
    SET = 281,
    BY = 282,
    EXPLICIT = 283,
    IMPLICIT = 284,
    DEFINITIONS = 285,
    TAGS = 286,
    ksba_BEGIN = 287,
    ksba_END = 288,
    UTCTime = 289,
    GeneralizedTime = 290,
    FROM = 291,
    IMPORTS = 292,
    TOKEN_NULL = 293,
    ENUMERATED = 294,
    UTF8STRING = 295,
    NUMERICSTRING = 296,
    PRINTABLESTRING = 297,
    TELETEXSTRING = 298,
    IA5STRING = 299,
    UNIVERSALSTRING = 300,
    BMPSTRING = 301
  };
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 97 "../../../libksba/src/asn1-parse.y" /* yacc.c:355  */

  unsigned int constant;
  char str[MAX_STRING_LENGTH];
  AsnNode node;

#line 205 "asn1-parse.c" /* yacc.c:355  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int yyparse (void *parm);



/* Copy the second part of user declarations.  */
#line 103 "../../../libksba/src/asn1-parse.y" /* yacc.c:358  */

static AsnNode new_node (struct parser_control_s *parsectl, node_type_t type);
#define NEW_NODE(a)  (new_node (PARSECTL, (a)))
static void set_name (AsnNode node, const char *name);
static void set_str_value (AsnNode node, const char *text);
static void set_ulong_value (AsnNode node, const char *text);
static void set_right (AsnNode node, AsnNode right);
static void append_right (AsnNode node, AsnNode right);
static void set_down (AsnNode node, AsnNode down);


static int yylex (YYSTYPE *lvalp, void *parm);
static void yyerror (void *parm, const char *s);

#line 235 "asn1-parse.c" /* yacc.c:358  */

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

#if !defined _Noreturn \
     && (!defined __STDC_VERSION__ || __STDC_VERSION__ < 201112)
# if defined _MSC_VER && 1200 <= _MSC_VER
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn YY_ATTRIBUTE ((__noreturn__))
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif


#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   202

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  57
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  52
/* YYNRULES -- Number of rules.  */
#define YYNRULES  119
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  210

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   301

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      49,    50,     2,    47,    51,    48,    56,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    52,     2,    53,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    54,     2,    55,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   184,   184,   185,   188,   189,   192,   199,   200,   203,
     204,   207,   208,   211,   216,   224,   225,   232,   237,   248,
     253,   261,   263,   270,   271,   272,   275,   281,   289,   291,
     296,   303,   308,   313,   320,   324,   330,   341,   347,   351,
     357,   363,   372,   376,   382,   386,   394,   395,   402,   403,
     410,   412,   419,   421,   428,   429,   436,   438,   445,   446,
     455,   456,   457,   458,   459,   460,   461,   467,   475,   479,
     486,   490,   498,   506,   512,   517,   524,   525,   526,   527,
     528,   529,   530,   531,   532,   533,   534,   535,   536,   542,
     546,   557,   561,   568,   575,   582,   584,   591,   596,   601,
     610,   615,   620,   629,   636,   640,   652,   659,   666,   675,
     684,   685,   688,   690,   697,   706,   707,   720,   721,   724
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 1
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "\"::=\"", "NUM", "IDENTIFIER",
  "\"OPTIONAL\"", "\"INTEGER\"", "\"SIZE\"", "\"OCTET\"", "\"STRING\"",
  "\"SEQUENCE\"", "\"BIT\"", "\"UNIVERSAL\"", "\"PRIVATE\"", "\"DEFAULT\"",
  "\"CHOICE\"", "\"OF\"", "\"OBJECT\"", "\"IDENTIFIER\"", "\"BOOLEAN\"",
  "\"TRUE\"", "\"FALSE\"", "\"APPLICATION\"", "\"ANY\"", "\"DEFINED\"",
  "\"SET\"", "\"BY\"", "\"EXPLICIT\"", "\"IMPLICIT\"", "\"DEFINITIONS\"",
  "\"TAGS\"", "\"BEGIN\"", "\"END\"", "\"UTCTime\"", "\"GeneralizedTime\"",
  "\"FROM\"", "\"IMPORTS\"", "\"NULL\"", "\"ENUMERATED\"",
  "\"UTF8String\"", "\"NumericString\"", "\"PrintableString\"",
  "\"TeletexString\"", "\"IA5String\"", "\"UniversalString\"",
  "\"BMPString\"", "'+'", "'-'", "'('", "')'", "','", "'['", "']'", "'{'",
  "'}'", "'.'", "$accept", "input", "pos_num", "neg_num", "pos_neg_num",
  "num_identifier", "pos_neg_identifier", "constant", "constant_list",
  "identifier_list", "obj_constant", "obj_constant_list", "class",
  "tag_type", "tag", "default", "integer_def", "boolean_def", "Time",
  "size_def2", "size_def", "octet_string_def", "utf8_string_def",
  "numeric_string_def", "printable_string_def", "teletex_string_def",
  "ia5_string_def", "universal_string_def", "bmp_string_def", "string_def",
  "bit_element", "bit_element_list", "bit_string_def", "enumerated_def",
  "object_def", "type_assig_right", "type_assig_right_tag",
  "type_assig_right_tag_default", "type_assig", "type_assig_list",
  "sequence_def", "set_def", "choise_def", "any_def", "type_def",
  "constant_def", "type_constant", "type_constant_list", "definitions_id",
  "imports_def", "explicit_implicit", "definitions", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,    43,    45,    40,
      41,    44,    91,    93,   123,   125,    46
};
# endif

#define YYPACT_NINF -120

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-120)))

#define YYTABLE_NINF -1

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
    -120,    26,  -120,   -31,     7,  -120,    42,    67,  -120,    31,
    -120,  -120,     1,  -120,  -120,    54,   105,  -120,  -120,    49,
      70,    93,  -120,    90,   124,   126,  -120,    22,   100,  -120,
    -120,  -120,    38,  -120,   130,    48,   134,   136,   125,  -120,
    -120,    42,    24,    89,   135,    13,   138,    95,   140,  -120,
     137,    16,  -120,  -120,  -120,   106,    24,    24,    24,    24,
      24,    24,    24,    25,    83,   112,   114,  -120,  -120,  -120,
    -120,  -120,  -120,  -120,  -120,  -120,  -120,  -120,  -120,  -120,
    -120,  -120,  -120,  -120,  -120,  -120,  -120,   107,   160,   162,
      42,   117,   159,  -120,  -120,    20,    24,   112,   163,   153,
     118,   163,  -120,   144,   112,   163,   156,   169,  -120,  -120,
    -120,  -120,  -120,  -120,  -120,   122,  -120,  -120,  -120,   172,
    -120,  -120,  -120,   129,    42,  -120,   123,   129,   128,   131,
       3,  -120,   -15,  -120,  -120,    48,  -120,    -6,   112,   169,
      46,   174,  -120,    51,   112,   132,  -120,    53,  -120,   133,
    -120,   127,     6,    42,   -28,  -120,     3,  -120,   178,   180,
    -120,  -120,   139,    20,  -120,    29,  -120,   163,  -120,  -120,
      59,  -120,  -120,  -120,  -120,   181,   169,  -120,  -120,   141,
    -120,     8,  -120,   142,   143,  -120,  -120,  -120,  -120,  -120,
      94,  -120,  -120,  -120,   145,  -120,   129,  -120,   129,  -120,
    -120,  -120,  -120,  -120,  -120,  -120,   146,   149,  -120,  -120
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     1,     0,     0,     3,     0,     0,     9,    10,
      19,    21,     0,   117,   118,     0,     0,   114,    22,     0,
       0,     0,    20,   115,     0,     0,    17,     0,     0,   110,
     111,   112,     0,    18,     0,     0,     0,     0,     0,   119,
     113,     0,    74,    34,     0,     0,     0,     0,     0,    37,
     104,     0,    38,    39,    88,     0,    46,    48,    50,    52,
      54,    56,    58,     0,    28,     0,    76,    78,    80,    81,
      60,    61,    62,    63,    64,    65,    66,    79,    82,    77,
      84,    89,   106,    83,    87,    85,    86,     0,     0,     0,
       0,     0,     0,    42,    75,     0,    44,     0,     0,     0,
      70,     0,    73,     0,     0,     0,     0,     0,    47,    49,
      51,    53,    55,    57,    59,     0,    23,    24,    25,     0,
      29,    30,    90,     0,     0,   109,     0,     0,     0,     0,
       0,    15,     0,    45,    98,     0,    95,     0,     0,     0,
       0,     0,   101,     0,     0,     0,    68,     0,    26,     0,
      10,     0,     0,     0,     0,    43,     0,     4,     0,     0,
       7,     8,     0,     0,    35,    91,    94,     0,    97,    99,
       0,   103,   105,   100,   102,     0,     0,    72,    27,     0,
     108,     0,    40,     0,     0,     5,     6,    13,    16,    93,
       0,    92,    96,    71,     0,    69,     0,   107,     0,    14,
      12,    32,    33,    11,    31,    67,     0,     0,    36,    41
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -120,  -120,  -120,  -120,  -114,  -119,  -120,    27,  -120,  -120,
     -12,   -40,  -120,  -120,  -120,  -120,  -120,  -120,  -120,    96,
     -42,  -120,  -120,  -120,  -120,  -120,  -120,  -120,  -120,  -120,
      11,    52,  -120,  -120,  -120,   -63,    57,  -120,    33,    21,
    -120,  -120,  -120,  -120,  -120,  -120,   170,  -120,  -120,  -120,
    -120,  -120
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,   160,   161,   162,    10,   204,   131,   132,    27,
      11,    12,   119,    64,    65,   191,    66,    67,    68,    93,
      94,    69,    70,    71,    72,    73,    74,    75,    76,    77,
     146,   147,    78,    79,    80,    81,    82,   166,   136,   137,
      83,    84,    85,    86,    29,    30,    31,    32,     4,    25,
      15,     5
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_uint8 yytable[] =
{
      18,    90,   122,    99,   151,     8,     9,   157,   154,   106,
       8,     9,     8,     9,   108,   109,   110,   111,   112,   113,
     114,    91,   182,     6,    91,   129,     2,    33,   183,   115,
      97,     3,    91,   104,   134,   189,   163,     7,   116,   117,
     164,   142,   184,    28,   190,   167,     8,     9,   118,   168,
     158,   159,    21,    42,   133,    43,    17,    44,    34,    45,
      46,   180,    92,   197,    47,    92,    48,    98,    49,   130,
     105,    39,    50,    92,    51,   169,   203,   206,    18,   207,
      16,   174,    52,    53,   152,    19,    54,    55,    56,    57,
      58,    59,    60,    61,    62,    13,    14,   167,   157,   200,
      63,   171,   167,    35,   176,    36,   173,    37,   177,    20,
     176,   120,   121,   181,   193,   201,   202,    42,    38,    43,
      22,    44,   140,    45,    46,    23,   143,    24,    47,    26,
      48,    28,    49,     8,   150,    41,    50,    87,    51,    88,
      18,   158,   159,    95,    89,    96,    52,    53,   100,   101,
      54,    55,    56,    57,    58,    59,    60,    61,    62,   102,
     107,   124,   103,   123,   125,   126,   127,    91,   135,    18,
     138,   141,   139,   144,   145,   148,   149,   153,   155,   172,
     156,   175,   185,   179,   186,   194,   178,   195,   128,   187,
     188,   170,   165,   199,     0,   205,   208,   196,   198,   209,
     192,     0,    40
};

static const yytype_int16 yycheck[] =
{
      12,    41,    65,    45,   123,     4,     5,     4,   127,    51,
       4,     5,     4,     5,    56,    57,    58,    59,    60,    61,
      62,     8,    50,    54,     8,     5,     0,     5,    56,     4,
      17,     5,     8,    17,    97,     6,    51,    30,    13,    14,
      55,   104,   156,     5,    15,    51,     4,     5,    23,    55,
      47,    48,     3,     5,    96,     7,    55,     9,    36,    11,
      12,    55,    49,    55,    16,    49,    18,    54,    20,    49,
      54,    33,    24,    49,    26,   138,   190,   196,    90,   198,
      49,   144,    34,    35,   124,    31,    38,    39,    40,    41,
      42,    43,    44,    45,    46,    28,    29,    51,     4,     5,
      52,    55,    51,     3,    51,     5,    55,     7,    55,     4,
      51,    28,    29,   153,    55,    21,    22,     5,    18,     7,
      50,     9,   101,    11,    12,    32,   105,    37,    16,     5,
      18,     5,    20,     4,     5,     5,    24,     3,    26,     3,
     152,    47,    48,    54,    19,    10,    34,    35,    10,    54,
      38,    39,    40,    41,    42,    43,    44,    45,    46,    19,
      54,    54,    25,    49,     4,     3,    49,     8,     5,   181,
      17,    27,    54,    17,     5,    53,     4,    54,    50,     5,
      49,    49,     4,    56,     4,     4,    53,   176,    92,    50,
     163,   139,   135,    50,    -1,    50,    50,    56,    56,    50,
     167,    -1,    32
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    58,     0,     5,   105,   108,    54,    30,     4,     5,
      62,    67,    68,    28,    29,   107,    49,    55,    67,    31,
       4,     3,    50,    32,    37,   106,     5,    66,     5,   101,
     102,   103,   104,     5,    36,     3,     5,     7,    18,    33,
     103,     5,     5,     7,     9,    11,    12,    16,    18,    20,
      24,    26,    34,    35,    38,    39,    40,    41,    42,    43,
      44,    45,    46,    52,    70,    71,    73,    74,    75,    78,
      79,    80,    81,    82,    83,    84,    85,    86,    89,    90,
      91,    92,    93,    97,    98,    99,   100,     3,     3,    19,
      68,     8,    49,    76,    77,    54,    10,    17,    54,    77,
      10,    54,    19,    25,    17,    54,    77,    54,    77,    77,
      77,    77,    77,    77,    77,     4,    13,    14,    23,    69,
      28,    29,    92,    49,    54,     4,     3,    49,    76,     5,
      49,    64,    65,    77,    92,     5,    95,    96,    17,    54,
      96,    27,    92,    96,    17,     5,    87,    88,    53,     4,
       5,    62,    68,    54,    62,    50,    49,     4,    47,    48,
      59,    60,    61,    51,    55,    93,    94,    51,    55,    92,
      88,    55,     5,    55,    92,    49,    51,    55,    53,    56,
      55,    68,    50,    56,    61,     4,     4,    50,    64,     6,
      15,    72,    95,    55,     4,    87,    56,    55,    56,    50,
       5,    21,    22,    61,    63,    50,    62,    62,    50,    50
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    57,    58,    58,    59,    59,    60,    61,    61,    62,
      62,    63,    63,    64,    64,    65,    65,    66,    66,    67,
      67,    68,    68,    69,    69,    69,    70,    70,    71,    71,
      71,    72,    72,    72,    73,    73,    73,    74,    75,    75,
      76,    76,    77,    77,    78,    78,    79,    79,    80,    80,
      81,    81,    82,    82,    83,    83,    84,    84,    85,    85,
      86,    86,    86,    86,    86,    86,    86,    87,    88,    88,
      89,    89,    90,    91,    92,    92,    92,    92,    92,    92,
      92,    92,    92,    92,    92,    92,    92,    92,    92,    93,
      93,    94,    94,    94,    95,    96,    96,    97,    97,    97,
      98,    98,    98,    99,   100,   100,   101,   102,   102,   102,
     103,   103,   104,   104,   105,   106,   106,   107,   107,   108
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,     1,     2,     2,     1,     1,     1,
       1,     1,     1,     3,     4,     1,     3,     1,     2,     1,
       4,     1,     2,     1,     1,     1,     3,     4,     1,     2,
       2,     2,     2,     2,     1,     4,     7,     1,     1,     1,
       4,     7,     1,     3,     2,     3,     1,     2,     1,     2,
       1,     2,     1,     2,     1,     2,     1,     2,     1,     2,
       1,     1,     1,     1,     1,     1,     1,     4,     1,     3,
       2,     5,     4,     2,     1,     2,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       2,     1,     2,     2,     2,     1,     3,     4,     3,     4,
       4,     3,     4,     4,     1,     4,     3,     7,     6,     4,
       1,     1,     1,     2,     4,     0,     5,     1,     1,     9
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY)                                        \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      YYPOPSTACK (yylen);                                       \
      yystate = *yyssp;                                         \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (parm, YY_("syntax error: cannot back up")); \
      YYERROR;                                                  \
    }                                                           \
while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)

/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value, parm); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*----------------------------------------.
| Print this symbol's value on YYOUTPUT.  |
`----------------------------------------*/

static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, void *parm)
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  YYUSE (parm);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, void *parm)
{
  YYFPRINTF (yyoutput, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep, parm);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, int yyrule, void *parm)
{
  unsigned long int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &(yyvsp[(yyi + 1) - (yynrhs)])
                                              , parm);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule, parm); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
yystrlen (const char *yystr)
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            /* Fall through.  */
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, void *parm)
{
  YYUSE (yyvaluep);
  YYUSE (parm);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/*----------.
| yyparse.  |
`----------*/

int
yyparse (void *parm)
{
/* The lookahead symbol.  */
int yychar;


/* The semantic value of the lookahead symbol.  */
/* Default value used for initialization, for pacifying older GCCs
   or non-GCC compilers.  */
YY_INITIAL_VALUE (static YYSTYPE yyval_default;)
YYSTYPE yylval YY_INITIAL_VALUE (= yyval_default);

    /* Number of syntax errors so far.  */
    int yynerrs;

    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        YYSTYPE *yyvs1 = yyvs;
        yytype_int16 *yyss1 = yyss;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * sizeof (*yyssp),
                    &yyvs1, yysize * sizeof (*yyvsp),
                    &yystacksize);

        yyss = yyss1;
        yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yytype_int16 *yyss1 = yyss;
        union yyalloc *yyptr =
          (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
                  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex (&yylval, parm);
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 4:
#line 188 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { strcpy((yyval.str),(yyvsp[0].str)); }
#line 1481 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 5:
#line 189 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { strcpy((yyval.str),(yyvsp[0].str)); }
#line 1487 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 6:
#line 193 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                  strcpy((yyval.str),"-");
                  strcat((yyval.str),(yyvsp[0].str));
                }
#line 1496 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 7:
#line 199 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { strcpy((yyval.str),(yyvsp[0].str)); }
#line 1502 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 8:
#line 200 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { strcpy((yyval.str),(yyvsp[0].str)); }
#line 1508 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 9:
#line 203 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {strcpy((yyval.str),(yyvsp[0].str));}
#line 1514 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 10:
#line 204 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {strcpy((yyval.str),(yyvsp[0].str));}
#line 1520 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 11:
#line 207 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {strcpy((yyval.str),(yyvsp[0].str));}
#line 1526 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 12:
#line 208 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {strcpy((yyval.str),(yyvsp[0].str));}
#line 1532 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 13:
#line 212 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                          (yyval.node) = NEW_NODE (TYPE_CONSTANT);
                          set_str_value ((yyval.node), (yyvsp[-1].str));
                        }
#line 1541 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 14:
#line 217 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                          (yyval.node) = NEW_NODE (TYPE_CONSTANT);
                          set_name ((yyval.node), (yyvsp[-3].str));
                          set_str_value ((yyval.node), (yyvsp[-1].str));
                        }
#line 1551 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 15:
#line 224 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.node)=(yyvsp[0].node); }
#line 1557 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 16:
#line 226 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                    (yyval.node) = (yyvsp[-2].node);
                    append_right ((yyvsp[-2].node), (yyvsp[0].node));
                  }
#line 1566 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 17:
#line 233 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                          (yyval.node) = NEW_NODE (TYPE_IDENTIFIER);
                          set_name((yyval.node),(yyvsp[0].str));
                        }
#line 1575 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 18:
#line 238 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                          AsnNode node;

                          (yyval.node)=(yyvsp[-1].node);
                          node = NEW_NODE (TYPE_IDENTIFIER);
                          set_name (node, (yyvsp[0].str));
                          append_right ((yyval.node), node);
                        }
#line 1588 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 19:
#line 249 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                   (yyval.node) = NEW_NODE (TYPE_CONSTANT);
                   set_str_value ((yyval.node), (yyvsp[0].str));
                 }
#line 1597 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 20:
#line 254 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                   (yyval.node) = NEW_NODE (TYPE_CONSTANT);
                   set_name ((yyval.node), (yyvsp[-3].str));
                   set_str_value ((yyval.node), (yyvsp[-1].str));
                 }
#line 1607 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 21:
#line 262 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.node)=(yyvsp[0].node);}
#line 1613 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 22:
#line 264 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                          (yyval.node)=(yyvsp[-1].node);
                          append_right ((yyval.node), (yyvsp[0].node));
                        }
#line 1622 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 23:
#line 270 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.constant) = CLASS_UNIVERSAL;   }
#line 1628 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 24:
#line 271 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.constant) = CLASS_PRIVATE;     }
#line 1634 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 25:
#line 272 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.constant) = CLASS_APPLICATION; }
#line 1640 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 26:
#line 276 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                  (yyval.node) = NEW_NODE (TYPE_TAG);
                  (yyval.node)->flags.class = CLASS_CONTEXT;
                  set_ulong_value ((yyval.node), (yyvsp[-1].str));
                }
#line 1650 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 27:
#line 282 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                  (yyval.node) = NEW_NODE (TYPE_TAG);
                  (yyval.node)->flags.class = (yyvsp[-2].constant);
                  set_ulong_value ((yyval.node), (yyvsp[-1].str));
                }
#line 1660 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 28:
#line 290 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 1666 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 29:
#line 292 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
           (yyval.node) = (yyvsp[-1].node);
           (yyval.node)->flags.explicit = 1;
         }
#line 1675 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 30:
#line 297 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
           (yyval.node) = (yyvsp[-1].node);
           (yyval.node)->flags.implicit = 1;
         }
#line 1684 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 31:
#line 304 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                 (yyval.node) = NEW_NODE (TYPE_DEFAULT);
                 set_str_value ((yyval.node), (yyvsp[0].str));
               }
#line 1693 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 32:
#line 309 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                 (yyval.node) = NEW_NODE (TYPE_DEFAULT);
                 (yyval.node)->flags.is_true = 1;
               }
#line 1702 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 33:
#line 314 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                 (yyval.node) = NEW_NODE (TYPE_DEFAULT);
                 (yyval.node)->flags.is_false = 1;
               }
#line 1711 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 34:
#line 321 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                 (yyval.node) = NEW_NODE (TYPE_INTEGER);
               }
#line 1719 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 35:
#line 325 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                 (yyval.node) = NEW_NODE (TYPE_INTEGER);
                 (yyval.node)->flags.has_list = 1;
                 set_down ((yyval.node), (yyvsp[-1].node));
               }
#line 1729 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 36:
#line 331 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                 (yyval.node) = NEW_NODE (TYPE_INTEGER);
                 (yyval.node)->flags.has_min_max = 1;
                 /* the following is wrong.  Better use a union for the value*/
                 set_down ((yyval.node), NEW_NODE (TYPE_SIZE) );
                 set_str_value ((yyval.node)->down, (yyvsp[-1].str));
                 set_name ((yyval.node)->down, (yyvsp[-4].str));
               }
#line 1742 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 37:
#line 342 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                (yyval.node) = NEW_NODE (TYPE_BOOLEAN);
              }
#line 1750 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 38:
#line 348 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
            (yyval.node) = NEW_NODE (TYPE_UTC_TIME);
          }
#line 1758 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 39:
#line 352 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
            (yyval.node) = NEW_NODE (TYPE_GENERALIZED_TIME);
          }
#line 1766 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 40:
#line 358 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
               (yyval.node) = NEW_NODE (TYPE_SIZE);
               (yyval.node)->flags.one_param = 1;
               set_str_value ((yyval.node), (yyvsp[-1].str));
             }
#line 1776 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 41:
#line 364 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
               (yyval.node) = NEW_NODE (TYPE_SIZE);
               (yyval.node)->flags.has_min_max = 1;
               set_str_value ((yyval.node), (yyvsp[-4].str));
               set_name ((yyval.node), (yyvsp[-1].str));
             }
#line 1787 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 42:
#line 373 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
               (yyval.node)=(yyvsp[0].node);
             }
#line 1795 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 43:
#line 377 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
               (yyval.node)=(yyvsp[-1].node);
             }
#line 1803 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 44:
#line 383 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                       (yyval.node) = NEW_NODE (TYPE_OCTET_STRING);
                     }
#line 1811 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 45:
#line 387 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                       (yyval.node) = NEW_NODE (TYPE_OCTET_STRING);
                       (yyval.node)->flags.has_size = 1;
                       set_down ((yyval.node),(yyvsp[0].node));
                     }
#line 1821 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 46:
#line 394 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.node) = NEW_NODE (TYPE_UTF8_STRING); }
#line 1827 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 47:
#line 396 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                       (yyval.node) = NEW_NODE (TYPE_UTF8_STRING);
                       (yyval.node)->flags.has_size = 1;
                       set_down ((yyval.node),(yyvsp[0].node));
                     }
#line 1837 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 48:
#line 402 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.node) = NEW_NODE (TYPE_NUMERIC_STRING); }
#line 1843 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 49:
#line 404 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                       (yyval.node) = NEW_NODE (TYPE_NUMERIC_STRING);
                       (yyval.node)->flags.has_size = 1;
                       set_down ((yyval.node),(yyvsp[0].node));
                     }
#line 1853 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 50:
#line 411 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.node) = NEW_NODE (TYPE_PRINTABLE_STRING); }
#line 1859 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 51:
#line 413 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                          (yyval.node) = NEW_NODE (TYPE_PRINTABLE_STRING);
                          (yyval.node)->flags.has_size = 1;
                          set_down ((yyval.node),(yyvsp[0].node));
                        }
#line 1869 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 52:
#line 420 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.node) = NEW_NODE (TYPE_TELETEX_STRING); }
#line 1875 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 53:
#line 422 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                       (yyval.node) = NEW_NODE (TYPE_TELETEX_STRING);
                       (yyval.node)->flags.has_size = 1;
                       set_down ((yyval.node),(yyvsp[0].node));
                     }
#line 1885 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 54:
#line 428 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.node) = NEW_NODE (TYPE_IA5_STRING); }
#line 1891 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 55:
#line 430 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                       (yyval.node) = NEW_NODE (TYPE_IA5_STRING);
                       (yyval.node)->flags.has_size = 1;
                       set_down ((yyval.node),(yyvsp[0].node));
                     }
#line 1901 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 56:
#line 437 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.node) = NEW_NODE (TYPE_UNIVERSAL_STRING); }
#line 1907 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 57:
#line 439 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                           (yyval.node) = NEW_NODE (TYPE_UNIVERSAL_STRING);
                           (yyval.node)->flags.has_size = 1;
                           set_down ((yyval.node),(yyvsp[0].node));
                         }
#line 1917 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 58:
#line 445 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.node) = NEW_NODE (TYPE_BMP_STRING); }
#line 1923 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 59:
#line 447 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                       (yyval.node) = NEW_NODE (TYPE_BMP_STRING);
                       (yyval.node)->flags.has_size = 1;
                       set_down ((yyval.node),(yyvsp[0].node));
                     }
#line 1933 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 67:
#line 468 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                   (yyval.node) = NEW_NODE (TYPE_CONSTANT);
                   set_name ((yyval.node), (yyvsp[-3].str));
                   set_str_value ((yyval.node), (yyvsp[-1].str));
                 }
#line 1943 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 68:
#line 476 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                        (yyval.node)=(yyvsp[0].node);
                      }
#line 1951 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 69:
#line 480 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                        (yyval.node)=(yyvsp[-2].node);
                        append_right ((yyval.node), (yyvsp[0].node));
                      }
#line 1960 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 70:
#line 487 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                     (yyval.node) = NEW_NODE (TYPE_BIT_STRING);
                   }
#line 1968 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 71:
#line 491 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                     (yyval.node) = NEW_NODE (TYPE_BIT_STRING);
                     (yyval.node)->flags.has_list = 1;
                     set_down ((yyval.node), (yyvsp[-1].node));
                   }
#line 1978 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 72:
#line 499 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                     (yyval.node) = NEW_NODE (TYPE_ENUMERATED);
                     (yyval.node)->flags.has_list = 1;
                     set_down ((yyval.node), (yyvsp[-1].node));
                   }
#line 1988 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 73:
#line 507 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                     (yyval.node) = NEW_NODE (TYPE_OBJECT_ID);
                   }
#line 1996 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 74:
#line 513 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                      (yyval.node) = NEW_NODE (TYPE_IDENTIFIER);
                      set_str_value ((yyval.node), (yyvsp[0].str));
                    }
#line 2005 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 75:
#line 518 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                      (yyval.node) = NEW_NODE (TYPE_IDENTIFIER);
                      (yyval.node)->flags.has_size = 1;
                      set_str_value ((yyval.node), (yyvsp[-1].str));
                      set_down ((yyval.node), (yyvsp[0].node));
                    }
#line 2016 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 76:
#line 524 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {(yyval.node)=(yyvsp[0].node);}
#line 2022 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 77:
#line 525 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {(yyval.node)=(yyvsp[0].node);}
#line 2028 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 78:
#line 526 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {(yyval.node)=(yyvsp[0].node);}
#line 2034 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 79:
#line 527 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {(yyval.node)=(yyvsp[0].node);}
#line 2040 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 81:
#line 529 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {(yyval.node)=(yyvsp[0].node);}
#line 2046 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 82:
#line 530 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {(yyval.node)=(yyvsp[0].node);}
#line 2052 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 83:
#line 531 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {(yyval.node)=(yyvsp[0].node);}
#line 2058 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 84:
#line 532 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {(yyval.node)=(yyvsp[0].node);}
#line 2064 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 85:
#line 533 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {(yyval.node)=(yyvsp[0].node);}
#line 2070 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 86:
#line 534 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {(yyval.node)=(yyvsp[0].node);}
#line 2076 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 87:
#line 535 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {(yyval.node)=(yyvsp[0].node);}
#line 2082 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 88:
#line 537 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                      (yyval.node) = NEW_NODE(TYPE_NULL);
                    }
#line 2090 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 89:
#line 543 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                             (yyval.node) = (yyvsp[0].node);
                           }
#line 2098 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 90:
#line 547 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
/*                               $2->flags.has_tag = 1; */
/*                               $$ = $2; */
/*                               set_right ($1, $$->down ); */
/*                               set_down ($$, $1); */
                             (yyval.node) = (yyvsp[-1].node);
                             set_down ((yyval.node), (yyvsp[0].node));
                           }
#line 2111 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 91:
#line 558 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                                   (yyval.node) = (yyvsp[0].node);
                                 }
#line 2119 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 92:
#line 562 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                                   (yyvsp[-1].node)->flags.has_default = 1;
                                   (yyval.node) = (yyvsp[-1].node);
                                   set_right ((yyvsp[0].node), (yyval.node)->down);
                                   set_down ((yyval.node), (yyvsp[0].node));
                                 }
#line 2130 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 93:
#line 569 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                                   (yyvsp[-1].node)->flags.is_optional = 1;
                                   (yyval.node) = (yyvsp[-1].node);
                                 }
#line 2139 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 94:
#line 576 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                 set_name ((yyvsp[0].node), (yyvsp[-1].str));
                 (yyval.node) = (yyvsp[0].node);
               }
#line 2148 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 95:
#line 583 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.node)=(yyvsp[0].node); }
#line 2154 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 96:
#line 585 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                      (yyval.node)=(yyvsp[-2].node);
                      append_right ((yyval.node), (yyvsp[0].node));
                    }
#line 2163 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 97:
#line 592 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                   (yyval.node) = NEW_NODE (TYPE_SEQUENCE);
                   set_down ((yyval.node), (yyvsp[-1].node));
                 }
#line 2172 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 98:
#line 597 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                   (yyval.node) = NEW_NODE (TYPE_SEQUENCE_OF);
                   set_down ((yyval.node), (yyvsp[0].node));
                 }
#line 2181 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 99:
#line 602 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                   (yyval.node) = NEW_NODE (TYPE_SEQUENCE_OF);
                   (yyval.node)->flags.has_size = 1;
                   set_right ((yyvsp[-2].node),(yyvsp[0].node));
                   set_down ((yyval.node),(yyvsp[-2].node));
                 }
#line 2192 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 100:
#line 611 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
               (yyval.node) = NEW_NODE (TYPE_SET);
               set_down ((yyval.node), (yyvsp[-1].node));
             }
#line 2201 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 101:
#line 616 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
               (yyval.node) = NEW_NODE (TYPE_SET_OF);
               set_down ((yyval.node), (yyvsp[0].node));
             }
#line 2210 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 102:
#line 621 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
               (yyval.node) = NEW_NODE (TYPE_SET_OF);
               (yyval.node)->flags.has_size = 1;
               set_right ((yyvsp[-2].node), (yyvsp[0].node));
               set_down ((yyval.node), (yyvsp[-2].node));
             }
#line 2221 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 103:
#line 630 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                  (yyval.node) = NEW_NODE (TYPE_CHOICE);
                  set_down ((yyval.node), (yyvsp[-1].node));
                }
#line 2230 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 104:
#line 637 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
               (yyval.node) = NEW_NODE (TYPE_ANY);
             }
#line 2238 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 105:
#line 641 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
               AsnNode node;

               (yyval.node) = NEW_NODE (TYPE_ANY);
               (yyval.node)->flags.has_defined_by = 1;
               node = NEW_NODE (TYPE_CONSTANT);
               set_name (node, (yyvsp[0].str));
               set_down((yyval.node), node);
             }
#line 2252 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 106:
#line 653 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
               set_name ((yyvsp[0].node), (yyvsp[-2].str));
               (yyval.node) = (yyvsp[0].node);
             }
#line 2261 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 107:
#line 660 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                   (yyval.node) = NEW_NODE (TYPE_OBJECT_ID);
                   (yyval.node)->flags.assignment = 1;
                   set_name ((yyval.node), (yyvsp[-6].str));
                   set_down ((yyval.node), (yyvsp[-1].node));
                 }
#line 2272 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 108:
#line 667 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                   (yyval.node) = NEW_NODE (TYPE_OBJECT_ID);
                   (yyval.node)->flags.assignment = 1;
                   (yyval.node)->flags.one_param = 1;
                   set_name ((yyval.node), (yyvsp[-5].str));
                   set_str_value ((yyval.node), (yyvsp[-4].str));
                   set_down ((yyval.node), (yyvsp[-1].node));
                 }
#line 2285 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 109:
#line 676 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                   (yyval.node) = NEW_NODE (TYPE_INTEGER);
                   (yyval.node)->flags.assignment = 1;
                   set_name ((yyval.node), (yyvsp[-3].str));
                   set_str_value ((yyval.node), (yyvsp[0].str));
                 }
#line 2296 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 110:
#line 684 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 2302 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 111:
#line 685 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 2308 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 112:
#line 689 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 2314 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 113:
#line 691 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                         (yyval.node) = (yyvsp[-1].node);
                         append_right ((yyval.node), (yyvsp[0].node));
                       }
#line 2323 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 114:
#line 698 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                     (yyval.node) = NEW_NODE (TYPE_OBJECT_ID);
                     set_down ((yyval.node), (yyvsp[-1].node));
                     set_name ((yyval.node), (yyvsp[-3].str));
                   }
#line 2333 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 115:
#line 706 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.node)=NULL;}
#line 2339 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 116:
#line 708 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                  AsnNode node;

                  (yyval.node) = NEW_NODE (TYPE_IMPORTS);
                  node = NEW_NODE (TYPE_OBJECT_ID);
                  set_name (node, (yyvsp[-1].str));
                  set_down (node, (yyvsp[0].node));
                  set_down ((yyval.node), node);
                  set_right ((yyval.node), (yyvsp[-3].node));
                }
#line 2354 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 117:
#line 720 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.constant) = CONST_EXPLICIT; }
#line 2360 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 118:
#line 721 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    { (yyval.constant) = CONST_IMPLICIT; }
#line 2366 "asn1-parse.c" /* yacc.c:1646  */
    break;

  case 119:
#line 727 "../../../libksba/src/asn1-parse.y" /* yacc.c:1646  */
    {
                 AsnNode node;

                 (yyval.node) = node = NEW_NODE (TYPE_DEFINITIONS);

                 if ((yyvsp[-6].constant) == CONST_EXPLICIT)
                   node->flags.explicit = 1;
                 else if ((yyvsp[-6].constant) == CONST_IMPLICIT)
                   node->flags.implicit = 1;

                 if ((yyvsp[-2].node))
                   node->flags.has_imports = 1;

                 set_name ((yyval.node), (yyvsp[-8].node)->name);
                 set_name ((yyvsp[-8].node), "");

                 if (!node->flags.has_imports)
                   set_right ((yyvsp[-8].node),(yyvsp[-1].node));
                 else
                   {
                     set_right ((yyvsp[-2].node),(yyvsp[-1].node));
                     set_right ((yyvsp[-8].node),(yyvsp[-2].node));
                   }

                 set_down ((yyval.node), (yyvsp[-8].node));

                 _ksba_asn_set_default_tag ((yyval.node));
                 _ksba_asn_type_set_config ((yyval.node));
                 PARSECTL->result_parse = _ksba_asn_check_identifier((yyval.node));
                 PARSECTL->parse_tree=(yyval.node);
               }
#line 2402 "asn1-parse.c" /* yacc.c:1646  */
    break;


#line 2406 "asn1-parse.c" /* yacc.c:1646  */
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (parm, YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (parm, yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval, parm);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp, parm);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (parm, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, parm);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[*yyssp], yyvsp, parm);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
#line 760 "../../../libksba/src/asn1-parse.y" /* yacc.c:1906  */



/*************************************************************/
/*  Function: yylex                                          */
/*  Description: looks for tokens in file_asn1 pointer file. */
/*  Return: int                                              */
/*    Token identifier or ASCII code or 0(zero: End Of File) */
/*************************************************************/
static int
yylex (YYSTYPE *lvalp, void *parm)
{
  int c,counter=0,k;
  char string[MAX_STRING_LENGTH];
  size_t len;
  FILE *fp = PARSECTL->fp;

  if (!PARSECTL->lineno)
    PARSECTL->lineno++; /* start with line one */

  while (1)
    {
      while ( (c=fgetc (fp))==' ' || c=='\t')
        ;
      if (c =='\n')
        {
          PARSECTL->lineno++;
          continue;
        }
      if(c==EOF)
        return 0;

      if ( c=='(' || c==')' || c=='[' || c==']'
           || c=='{' || c=='}' || c==',' || c=='.' || c=='+')
        return c;

      if (c=='-')
        {
          if ( (c=fgetc(fp))!='-')
            {
              ungetc(c,fp);
              return '-';
            }
          else
            {
              /* A comment finishes at the end of line */
              counter=0;
              while ( (c=fgetc(fp))!=EOF && c != '\n' )
                ;
              if (c==EOF)
                return 0;
              else
                continue; /* repeat the search */
            }
        }

      do
        {
          if (counter >= DIM (string)-1 )
            {
              fprintf (stderr,"%s:%d: token too long\n", "myfile:",
                       PARSECTL->lineno);
              return 0; /* EOF */
            }
          string[counter++]=c;
        }
      while ( !((c=fgetc(fp))==EOF
                || c==' '|| c=='\t' || c=='\n'
                || c=='(' || c==')' || c=='[' || c==']'
                || c=='{' || c=='}' || c==',' || c=='.'));

      ungetc (c,fp);
      string[counter]=0;
      /*fprintf (stderr, "yylex token `%s'\n", string);*/

      /* Is STRING a number? */
      for (k=0; k<counter; k++)
        {
          if(!isdigit(string[k]))
            break;
        }
      if (k>=counter)
        {
          strcpy (lvalp->str,string);
          if (PARSECTL->debug)
            fprintf (stderr,"%d: yylex found number `%s'\n",
                     PARSECTL->lineno, string);
          return NUM;
        }

      /* Is STRING a keyword? */
      len = strlen (string);
      for (k = 0; k < YYNTOKENS; k++)
        {
          if (yytname[k] && yytname[k][0] == '\"'
              && !strncmp (yytname[k] + 1, string, len)
              && yytname[k][len + 1] == '\"' && !yytname[k][len + 2])
            return yytoknum[k];
        }

      /* STRING is an IDENTIFIER */
      strcpy(lvalp->str,string);
      if (PARSECTL->debug)
        fprintf (stderr,"%d: yylex found identifier `%s'\n",
                 PARSECTL->lineno, string);
      return IDENTIFIER;
    }
}

static void
yyerror (void *parm, const char *s)
{
  (void)parm;
  /* Sends the error description to stderr */
  fprintf (stderr, "%s\n", s);
  /* Why doesn't bison provide a way to pass the parm to yyerror?
     Update: Newer bison versions allow for this.  We need to see how
     we can make use of it.  */
}



static AsnNode
new_node (struct parser_control_s *parsectl, node_type_t type)
{
  AsnNode node;

  node = xcalloc (1, sizeof *node);
  node->type = type;
  node->off = -1;
  node->link_next = parsectl->all_nodes;
  parsectl->all_nodes = node;

  return node;
}

static void
release_all_nodes (AsnNode node)
{
  AsnNode node2;

  for (; node; node = node2)
    {
      node2 = node->link_next;
      xfree (node->name);

      if (node->valuetype == VALTYPE_CSTR)
        xfree (node->value.v_cstr);
      else if (node->valuetype == VALTYPE_MEM)
        xfree (node->value.v_mem.buf);

      xfree (node);
    }
}

static void
set_name (AsnNode node, const char *name)
{
  _ksba_asn_set_name (node, name);
}

static void
set_str_value (AsnNode node, const char *text)
{
  if (text && *text)
    _ksba_asn_set_value (node, VALTYPE_CSTR, text, 0);
  else
    _ksba_asn_set_value (node, VALTYPE_NULL, NULL, 0);
}

static void
set_ulong_value (AsnNode node, const char *text)
{
  unsigned long val;

  if (text && *text)
    val = strtoul (text, NULL, 10);
  else
    val = 0;
  _ksba_asn_set_value (node, VALTYPE_ULONG, &val, sizeof(val));
}

static void
set_right (AsnNode node, AsnNode right)
{
  return_if_fail (node);

  node->right = right;
  if (right)
    right->left = node;
}

static void
append_right (AsnNode node, AsnNode right)
{
  return_if_fail (node);

  while (node->right)
    node = node->right;

  node->right = right;
  if (right)
    right->left = node;
}


static void
set_down (AsnNode node, AsnNode down)
{
  return_if_fail (node);

  node->down = down;
  if (down)
    down->left = node;
}


/**
 * ksba_asn_parse_file:
 * @file_name: Filename with the ASN module
 * @pointer: Returns the syntax tree
 * @debug: Enable debug output
 *
 * Parse an ASN.1 file and return an syntax tree.
 *
 * Return value: 0 for okay or an ASN_xx error code
 **/
int
ksba_asn_parse_file (const char *file_name, ksba_asn_tree_t *result, int debug)
{
  struct parser_control_s parsectl;

  *result = NULL;

  parsectl.fp = file_name? fopen (file_name, "r") : NULL;
  if ( !parsectl.fp )
    return gpg_error_from_syserror ();

  parsectl.lineno = 0;
  parsectl.debug = debug;
  parsectl.result_parse = gpg_error (GPG_ERR_SYNTAX);
  parsectl.parse_tree = NULL;
  parsectl.all_nodes = NULL;
  /* yydebug = 1; */
  if ( yyparse ((void*)&parsectl) || parsectl.result_parse )
    { /* error */
      fprintf (stderr, "%s:%d: parse error\n",
               file_name?file_name:"-", parsectl.lineno );
      release_all_nodes (parsectl.all_nodes);
      parsectl.all_nodes = NULL;
    }
  else
    { /* okay */
      ksba_asn_tree_t tree;

      _ksba_asn_change_integer_value (parsectl.parse_tree);
      _ksba_asn_expand_object_id (parsectl.parse_tree);
      tree = xmalloc ( sizeof *tree + (file_name? strlen (file_name):1) );
      tree->parse_tree = parsectl.parse_tree;
      tree->node_list = parsectl.all_nodes;
      strcpy (tree->filename, file_name? file_name:"-");
      *result = tree;
    }

  if (file_name)
    fclose (parsectl.fp);
  return parsectl.result_parse;
}

void
ksba_asn_tree_release (ksba_asn_tree_t tree)
{
  if (!tree)
    return;
  release_all_nodes (tree->node_list);
  tree->node_list = NULL;
  xfree (tree);
}


void
_ksba_asn_release_nodes (AsnNode node)
{
  /* FIXME: it does not work yet because the allocation function in
     asn1-func.c does not link all nodes together */
  release_all_nodes (node);
}
