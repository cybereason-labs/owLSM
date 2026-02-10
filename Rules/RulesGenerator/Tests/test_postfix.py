"""Test suite for postfix module."""
import os
import pytest

from AST import ConditionExpr, ParsedRule, ParsedRulesContext, Predicate, parse_rules
from postfix import (
    condition_expr_to_postfix,
    convert_rule_to_postfix,
    convert_to_postfix,
    Token,
    OperatorType,
    PostfixRule,
)
from sigma_rule_loader import load_sigma_rules, SigmaRule


def evaluate_postfix(tokens, pred_values):
    """Reference implementation for testing postfix evaluation."""
    stack = []
    for token in tokens:
        if token.operator_type == OperatorType.OPERATOR_PREDICATE:
            stack.append(pred_values.get(token.predicate_idx, False))
        elif token.operator_type == OperatorType.OPERATOR_AND:
            b, a = stack.pop(), stack.pop()
            stack.append(a and b)
        elif token.operator_type == OperatorType.OPERATOR_OR:
            b, a = stack.pop(), stack.pop()
            stack.append(a or b)
        elif token.operator_type == OperatorType.OPERATOR_NOT:
            stack.append(not stack.pop())
    return stack[0]


class TestBasicPostfixConversion:
    """Tests for basic postfix conversion."""
    
    def test_single_pred(self):
        expr = ConditionExpr(operator_type="PRED", predicate_idx=5)
        tokens = condition_expr_to_postfix(expr)
        
        assert len(tokens) == 1
        assert tokens[0].operator_type == OperatorType.OPERATOR_PREDICATE
        assert tokens[0].predicate_idx == 5
    
    def test_simple_and(self):
        expr = ConditionExpr(operator_type="AND", children=[
            ConditionExpr(operator_type="PRED", predicate_idx=0),
            ConditionExpr(operator_type="PRED", predicate_idx=1)
        ])
        tokens = condition_expr_to_postfix(expr)
        
        assert len(tokens) == 3
        assert tokens[0] == Token(OperatorType.OPERATOR_PREDICATE, 0)
        assert tokens[1] == Token(OperatorType.OPERATOR_PREDICATE, 1)
        assert tokens[2] == Token(OperatorType.OPERATOR_AND)
    
    def test_simple_or(self):
        expr = ConditionExpr(operator_type="OR", children=[
            ConditionExpr(operator_type="PRED", predicate_idx=0),
            ConditionExpr(operator_type="PRED", predicate_idx=1)
        ])
        tokens = condition_expr_to_postfix(expr)
        
        assert len(tokens) == 3
        assert tokens[2] == Token(OperatorType.OPERATOR_OR)
    
    def test_simple_not(self):
        expr = ConditionExpr(operator_type="NOT", children=[
            ConditionExpr(operator_type="PRED", predicate_idx=0)
        ])
        tokens = condition_expr_to_postfix(expr)
        
        assert len(tokens) == 2
        assert tokens[1] == Token(OperatorType.OPERATOR_NOT)
    
    def test_multi_child_and(self):
        expr = ConditionExpr(operator_type="AND", children=[
            ConditionExpr(operator_type="PRED", predicate_idx=0),
            ConditionExpr(operator_type="PRED", predicate_idx=1),
            ConditionExpr(operator_type="PRED", predicate_idx=2)
        ])
        tokens = condition_expr_to_postfix(expr)
        
        # A B C AND AND
        assert len(tokens) == 5
        assert tokens[3] == Token(OperatorType.OPERATOR_AND)
        assert tokens[4] == Token(OperatorType.OPERATOR_AND)


class TestComplexExpressions:
    """Tests for complex expression conversion."""
    
    def test_nested_and_or(self):
        # A AND (B OR C)
        expr = ConditionExpr(operator_type="AND", children=[
            ConditionExpr(operator_type="PRED", predicate_idx=0),
            ConditionExpr(operator_type="OR", children=[
                ConditionExpr(operator_type="PRED", predicate_idx=1),
                ConditionExpr(operator_type="PRED", predicate_idx=2)
            ])
        ])
        tokens = condition_expr_to_postfix(expr)
        
        # A B C OR AND
        assert len(tokens) == 5
        assert tokens[3] == Token(OperatorType.OPERATOR_OR)
        assert tokens[4] == Token(OperatorType.OPERATOR_AND)
    
    def test_not_with_and(self):
        # A AND NOT B
        expr = ConditionExpr(operator_type="AND", children=[
            ConditionExpr(operator_type="PRED", predicate_idx=0),
            ConditionExpr(operator_type="NOT", children=[
                ConditionExpr(operator_type="PRED", predicate_idx=1)
            ])
        ])
        tokens = condition_expr_to_postfix(expr)
        
        # A B NOT AND
        assert len(tokens) == 4
        assert tokens[2] == Token(OperatorType.OPERATOR_NOT)
        assert tokens[3] == Token(OperatorType.OPERATOR_AND)


class TestPostfixEvaluation:
    """Tests for postfix evaluation."""
    
    def test_single_pred(self):
        tokens = [Token(OperatorType.OPERATOR_PREDICATE, 0)]
        assert evaluate_postfix(tokens, {0: True}) == True
        assert evaluate_postfix(tokens, {0: False}) == False
    
    def test_and_truth_table(self):
        tokens = [Token(OperatorType.OPERATOR_PREDICATE, 0), Token(OperatorType.OPERATOR_PREDICATE, 1), Token(OperatorType.OPERATOR_AND)]
        assert evaluate_postfix(tokens, {0: True, 1: True}) == True
        assert evaluate_postfix(tokens, {0: True, 1: False}) == False
        assert evaluate_postfix(tokens, {0: False, 1: True}) == False
        assert evaluate_postfix(tokens, {0: False, 1: False}) == False
    
    def test_or_truth_table(self):
        tokens = [Token(OperatorType.OPERATOR_PREDICATE, 0), Token(OperatorType.OPERATOR_PREDICATE, 1), Token(OperatorType.OPERATOR_OR)]
        assert evaluate_postfix(tokens, {0: True, 1: True}) == True
        assert evaluate_postfix(tokens, {0: True, 1: False}) == True
        assert evaluate_postfix(tokens, {0: False, 1: True}) == True
        assert evaluate_postfix(tokens, {0: False, 1: False}) == False
    
    def test_not(self):
        tokens = [Token(OperatorType.OPERATOR_PREDICATE, 0), Token(OperatorType.OPERATOR_NOT)]
        assert evaluate_postfix(tokens, {0: True}) == False
        assert evaluate_postfix(tokens, {0: False}) == True


class TestFullPipeline:
    """Tests for full rule-to-postfix pipeline."""
    
    def test_simple_rule(self):
        rule = SigmaRule(
            id=1, description="Test rule", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel1": {"process.file.filename": "evil.exe"},
                "sel2": {"Path|contains": "temp"},
                "condition": "sel1 and sel2"
            },
            source_file="test.yml"
        )
        
        ast_ctx = parse_rules([rule])
        postfix_ctx = convert_to_postfix(ast_ctx)
        
        assert len(postfix_ctx.rules) == 1
        assert postfix_ctx.rules[0].rule_id == 1
        assert len(postfix_ctx.rules[0].tokens) == 3  # PRED PRED AND
    
    def test_rule_with_not(self):
        rule = SigmaRule(
            id=1, description="Test NOT", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "suspicious": {"CommandLine|contains": "evil"},
                "trusted": {"Path|startswith": "/usr/"},
                "condition": "suspicious and not trusted"
            },
            source_file="test.yml"
        )
        
        ast_ctx = parse_rules([rule])
        postfix_ctx = convert_to_postfix(ast_ctx)
        
        tokens = postfix_ctx.rules[0].tokens
        assert len(tokens) == 4  # PRED PRED NOT AND
        ops = [t.operator_type for t in tokens]
        assert OperatorType.OPERATOR_NOT in ops
        assert OperatorType.OPERATOR_AND in ops


class TestFullPipelineIntegration:
    """Integration tests with actual rule files."""
    
    @pytest.fixture
    def valid_rules_dir(self):
        return os.path.join(os.path.dirname(__file__), 'valid_rules')
    
    def test_pipeline_with_test_files(self, valid_rules_dir):
        rules = load_sigma_rules(valid_rules_dir)
        ast_ctx = parse_rules(rules)
        postfix_ctx = convert_to_postfix(ast_ctx)
        
        assert len(postfix_ctx.rules) == 30
        
        for rule in postfix_ctx.rules:
            assert len(rule.tokens) > 0
            # Verify postfix is evaluatable
            pred_indices = {t.predicate_idx for t in rule.tokens if t.operator_type == OperatorType.OPERATOR_PREDICATE}
            pred_values = {idx: True for idx in pred_indices}
            evaluate_postfix(rule.tokens, pred_values)


class TestTokenLimit:
    """Tests for token limit handling."""
    
    def test_under_limit(self):
        values = [f"value{i}" for i in range(20)]
        rule = SigmaRule(
            id=1, description="Many values test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"CommandLine|contains": values}, "condition": "sel"},
            source_file="test.yml"
        )
        
        ast_ctx = parse_rules([rule])
        postfix_ctx = convert_to_postfix(ast_ctx)
        
        # 20 values = 20 PREDs + 19 ORs = 39 tokens
        assert len(postfix_ctx.rules[0].tokens) == 39
    
    def test_exceeds_limit_raises(self):
        values = [f"value{i}" for i in range(3500)]
        rule = SigmaRule(
            id=1, description="Too many values", action="BLOCK_EVENT", events=["CHMOD"],
            detection={"sel": {"CommandLine|contains": values}, "condition": "sel"},
            source_file="test.yml"
        )
        
        ast_ctx = parse_rules([rule])
        
        with pytest.raises(Exception, match="exceeds maximum token limit"):
            convert_to_postfix(ast_ctx)


class TestAllOfPostfix:
    """Tests for 'all of' postfix conversion."""
    
    def test_all_of_them_postfix(self):
        rule = SigmaRule(
            id=1, description="All of them test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel1": {"process.file.filename": "test1.exe"},
                "sel2": {"process.file.filename": "test2.exe"},
                "sel3": {"process.file.filename": "test3.exe"},
                "condition": "all of them"
            },
            source_file="test.yml"
        )
        
        ast_ctx = parse_rules([rule])
        postfix_ctx = convert_to_postfix(ast_ctx)
        
        tokens = postfix_ctx.rules[0].tokens
        # 3 PREDs + 2 ANDs = 5 tokens
        assert len(tokens) == 5
        
        pred_count = sum(1 for t in tokens if t.operator_type == OperatorType.OPERATOR_PREDICATE)
        and_count = sum(1 for t in tokens if t.operator_type == OperatorType.OPERATOR_AND)
        assert pred_count == 3
        assert and_count == 2


class TestXOfPostfix:
    """Tests for 'X of' postfix conversion."""
    
    def test_2_of_them_postfix(self):
        rule = SigmaRule(
            id=1, description="2 of them test", action="BLOCK_EVENT", events=["CHMOD"],
            detection={
                "sel1": {"process.file.filename": "test1.exe"},
                "sel2": {"process.file.filename": "test2.exe"},
                "sel3": {"process.file.filename": "test3.exe"},
                "condition": "2 of them"
            },
            source_file="test.yml"
        )
        
        ast_ctx = parse_rules([rule])
        postfix_ctx = convert_to_postfix(ast_ctx)
        
        tokens = postfix_ctx.rules[0].tokens
        pred_count = sum(1 for t in tokens if t.operator_type == OperatorType.OPERATOR_PREDICATE)
        and_count = sum(1 for t in tokens if t.operator_type == OperatorType.OPERATOR_AND)
        or_count = sum(1 for t in tokens if t.operator_type == OperatorType.OPERATOR_OR)
        
        # 3 combinations * 2 preds each = 6 PRED occurrences
        assert pred_count == 6
        assert and_count == 3
        assert or_count == 2
        
        # Verify evaluation: at least 2 of 3 must be true
        pred_indices = sorted(set(t.predicate_idx for t in tokens if t.operator_type == OperatorType.OPERATOR_PREDICATE))
        
        # All true -> true
        assert evaluate_postfix(tokens, {i: True for i in pred_indices}) == True
        
        # Two true -> true
        assert evaluate_postfix(tokens, {pred_indices[0]: True, pred_indices[1]: True, pred_indices[2]: False}) == True
        
        # One true -> false
        assert evaluate_postfix(tokens, {pred_indices[0]: True, pred_indices[1]: False, pred_indices[2]: False}) == False
