// SPDX-License-Identifier: BSD-3-Clause
/*
 * (c) Freescale Semiconductor, Inc. 2011-2012 All rights reserved.
 * Copyright 2019, 2023-2024 NXP
 */

/*===========================================================================*/
/**
    @file    cst_parser.y

    @brief   Parser file for CSF language
 */

/*===========================================================================
                                INCLUDES
=============================================================================*/
%{
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <csf.h>

extern int32_t yylineno;

void yyerror(const char *str)
{
    fprintf(stderr,"error: line %d: %s\n",yylineno,str);
}

int32_t yywrap()
{
        return 1;
}

char buf[100];

%}

%union
{
    char *str;
    uint32_t  num;
    command_t *command;
    argument_t *argument;
    value_t value;
    pair_t *pair;
    triple_t *triple;
    quadruple_t *quadruple;
    block_t *block;
    number_t *number;
    keyword_t *keyword;
}

%token <num> NUMBER
%token <str> WORD
%token <str> FILENAME
%token EQUALS OR EOL LBRACK RBRACK COMMA DOT

%type <str> label
%token <num> exp
%type <pair> pair
%type <triple> triple
%type <quadruple> quadruple
%type <argument> pairs
%type <argument> triples
%type <argument> quadruples
%type <block> block
%type <argument> blocks
%type <argument> argument
%type <command> arguments
%type <command> command
%type <argument> numbers
%type <number> number
%type <argument> keywords
%type <keyword> keyword
%%

commands: /* empty */
        | commands command
        ;

command:
        LBRACK label RBRACK eol arguments
        {
            /* command record allocated when parsing arguments */
            $$ = $5;

            /* save the head */
            if(g_cmd_head == NULL)
            {
                g_cmd_head = $$;
            }

            /* maintain the cmd list using g_cmd_current */
            if(g_cmd_current == NULL)
            {
                g_cmd_current = $$;
                g_cmd_current->next = NULL;
            }
            else
            {
                g_cmd_current->next = $$;
                g_cmd_current = g_cmd_current->next;
                g_cmd_current->next = NULL;
            }

            $$->name = $2;              /* add name */
            $$->start_offset_cert_sig = 0;
            $$->size_cert_sig = 0;
            $$->cert_sig_data = NULL;
            if ((g_error_code = handle_command($$)) < SUCCESS) YYERROR;
        }
        ;

arguments:
        /* empty */
        {
            $$ = malloc(sizeof(command_t));
            $$->argument_count = 0;
            $$->argument = NULL;
        }
        | arguments argument
        {
            $$ = $1;
            $$->argument_count++;
            $2->next = $$->argument;    /* insert new argument at head */
            $$->argument = $2;
        }
        ;

argument:
        label EQUALS pairs eol
        {
            /* argument record allocated when parsing pairs */
            $$ = $3;
            $$->name = $1;               /* add name */
            if((g_error_code = set_argument_type($$)) != SUCCESS) YYERROR;
        }
        | label EQUALS triples eol
        {
            /* argument record allocated when parsing triples */
            $$ = $3;
            $$->name = $1;               /* add name */
            if((g_error_code = set_argument_type($$)) != SUCCESS) YYERROR;
        }
        | label EQUALS quadruples eol
        {
            /* argument record allocated when parsing quadruples */
            $$ = $3;
            $$->name = $1;               /* add name */
            if((g_error_code = set_argument_type($$)) != SUCCESS) YYERROR;
        }
        | label EQUALS blocks eol
        {
            /* argument record allocated when parsing blocks */
            $$ = $3;
            $$->name = $1;               /* add name */
            if((g_error_code = set_argument_type($$)) != SUCCESS) YYERROR;
        }
        | label EQUALS numbers eol
        {
            /* argument record allocated when parsing numbers */
            $$ = $3;
            $$->name = $1;               /* add name */
            if((g_error_code = set_argument_type($$)) != SUCCESS) YYERROR;
        }
        | label EQUALS keywords eol
        {
            /* argument record allocated when parsing numbers */
            $$ = $3;
            $$->name = $1;               /* add name */
            if((g_error_code = set_argument_type($$)) != SUCCESS) YYERROR;
        }
pairs:  pair
        {
            $$ = malloc(sizeof(argument_t));
            $$->next = NULL;
            $$->value_count = 1;
            $$->value_type = PAIR_TYPE;
            $$->value.pair = $1;
        }
        /* right recursion discouraged, but ok here since lists are small */
        | pair COMMA pairs
        {
            $$ = $3;
            $$->value_count++;
            $1->next = $$->value.pair;    /* insert new pair at head */
            $$->value.pair = $1;
        }
        ;

pair:   NUMBER NUMBER
        {
            $$ = malloc(sizeof(pair_t));
            $$->next = NULL;
            $$->first = $1;
            $$->second = $2;
        }
        | NUMBER DOT NUMBER
        {
            $$ = malloc(sizeof(pair_t));
            $$->next = NULL;
            $$->first = $1;
            $$->second = $3;
        }
        ;

triples:  triple
        {
            $$ = malloc(sizeof(argument_t));
            $$->next = NULL;
            $$->value_count = 1;
            $$->value_type = TRIPLE_TYPE;
            $$->value.triple = $1;
        }
        /* right recursion discouraged, but ok here since lists are small */
        | triple COMMA triples
        {
            $$ = $3;
            $$->value_count++;
            $1->next = $$->value.triple;    /* insert new triple at head */
            $$->value.triple = $1;
        }
        ;

triple:   NUMBER NUMBER NUMBER
        {
            $$ = malloc(sizeof(triple_t));
            $$->next = NULL;
            $$->first = $1;
            $$->second = $2;
        $$->third = $3;
        }
        | NUMBER DOT NUMBER DOT NUMBER
        {
            $$ = malloc(sizeof(triple_t));
            $$->next = NULL;
            $$->first = $1;
            $$->second = $3;
            $$->third = $5;
        }
        ;

quadruples:  quadruple
        {
            $$ = malloc(sizeof(argument_t));
            $$->next = NULL;
            $$->value_count = 1;
            $$->value_type = QUADRUPLE_TYPE;
            $$->value.quadruple = $1;
        }
        /* right recursion discouraged, but ok here since lists are small */
        | quadruple COMMA quadruples
        {
            $$ = $3;
            $$->value_count++;
            $1->next = $$->value.quadruple;    /* insert new quadruple at head */
            $$->value.quadruple = $1;
        }
        ;

quadruple:   NUMBER NUMBER NUMBER NUMBER
        {
            $$ = malloc(sizeof(quadruple_t));
            $$->next = NULL;
            $$->first = $1;
            $$->second = $2;
            $$->third = $3;
            $$->fourth = $4;
        }
        | NUMBER DOT NUMBER DOT NUMBER DOT NUMBER
        {
            $$ = malloc(sizeof(quadruple_t));
            $$->next = NULL;
            $$->first = $1;
            $$->second = $3;
            $$->third = $5;
            $$->fourth = $7;
        }
        ;

blocks:  block
        {
            $$ = malloc(sizeof(argument_t));
            $$->next = NULL;
            $$->value_count = 1;
            $$->value_type = BLOCK_TYPE;
            $$->value.block = $1;
        }
        /* right recursion discouraged, but ok here since lists are small */
        | block COMMA blocks
        {
            $$ = $3;
            $$->value_count++;
            $1->next = $$->value.block;    /* insert new block at head */
            $$->value.block = $1;
        }
        ;

block:  NUMBER NUMBER NUMBER FILENAME
        {
            $$ = malloc(sizeof(block_t));
            $$->next = NULL;
            $$->base_address = $1;
            $$->start = $2;
            $$->length = $3;
            $$->block_filename = $4;
        }
        ;

numbers: number
        {
            $$ = malloc(sizeof(argument_t));
            $$->next = NULL;
            $$->value_count = 1;
            $$->value_type = NUMBER_TYPE;
            $$->value.number = $1;
        }
        /* right recursion discouraged, but ok here since lists are small */
        | number COMMA numbers
        {
            $$ = $3;
            $$->value_count++;
            $1->next = $$->value.number;    /* insert new block at head */
            $$->value.number = $1;
        }
        ;

number:  NUMBER
        {
            $$ = malloc(sizeof(number_t));
            $$->next = NULL;
            $$->num_value = $1;
        }
        ;

keywords: keyword
        {
            $$ = malloc(sizeof(argument_t));
            $$->next = NULL;
            $$->value_count = 1;
            $$->value_type = KEYWORD_TYPE;
            $$->value.keyword = $1;
        }
        /* right recursion discouraged, but ok here since lists are small */
        | keyword COMMA keywords
        {
            $$ = $3;
            $$->value_count++;
            $1->next = $$->value.keyword;    /* insert new block at head */
            $$->value.keyword = $1;
        }
        ;

keyword: label
        {
            $$ = malloc(sizeof(keyword_t));
            $$->next = NULL;
            $$->string_value = $1;
            if((g_error_code = set_label($$)) != SUCCESS) YYERROR;
        }
        | FILENAME
        {
            $$ = malloc(sizeof(keyword_t));
            $$->next = NULL;
            $$->string_value = $1;
            $$->unsigned_value = 0xFFFFFFFF;
        }
        ;

label:  WORD
        {
            $$ = $1;
        }
        | label WORD
        {
            $$ = realloc($$, strlen($$) + strlen($2) + 1);
            $$ = strcat($$,$2);
        }
        | label NUMBER
        {
            /* Concat label with number into buf */
            sprintf(buf, "%s%d", $$, $2);
            /* Return buf to top of stack */
            $$ = realloc($$, strlen(buf) + 1);
            $$ = buf;
        }
        ;

eol: EOL | eol EOL
        ;
