#!/usr/bin/env python3
import sys
from sigma_rule_loader import load_sigma_rules
from AST import parse_rules
from postfix import convert_to_postfix
from serializer import write_json_file, to_json_string


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print(f"Usage: {sys.argv[0]} <rules_directory> [output.json]")
        print()
        print("Arguments:")
        print("  rules_directory  Directory containing .yml sigma rules")
        print("  output.json      Optional output file (default: print to stdout)")
        sys.exit(1)
    
    rules_directory = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) == 3 else None
    
    try:
        print("Step 1-2: Loading and validating rules...", file=sys.stderr)
        rules = load_sigma_rules(rules_directory)
        print(f"  Loaded {len(rules)} rules", file=sys.stderr)
        
        print("Step 3: Parsing detection sections (AST)...", file=sys.stderr)
        ast_ctx = parse_rules(rules)
        print(f"  Built tables: {len(ast_ctx.id_to_string)} strings, {len(ast_ctx.id_to_predicate)} predicates", file=sys.stderr)
        
        print("Step 4: Converting to postfix notation...", file=sys.stderr)
        postfix_ctx = convert_to_postfix(ast_ctx)
        total_tokens = sum(len(r.tokens) for r in postfix_ctx.rules)
        print(f"  Generated {total_tokens} total tokens across {len(postfix_ctx.rules)} rules", file=sys.stderr)
        
        print("Step 5: Serializing to JSON...", file=sys.stderr)
        if output_file:
            write_json_file(postfix_ctx, output_file)
            print(f"  Written to: {output_file}", file=sys.stderr)
        else:
            json_str = to_json_string(postfix_ctx)
            print(json_str)
        
        print("Done!", file=sys.stderr)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

