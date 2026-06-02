"""SPDX compound expression parsing and evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from repolens.policy.tiers import choose_higher_risk, choose_lower_risk
from repolens.policy.types import PolicyTier


class ParseError(ValueError):
    """Raised when a compound SPDX expression is malformed."""


@dataclass(frozen=True)
class EvalResult:
    tier: PolicyTier
    chosen_branch: str | None
    label: str | None
    reasons: tuple[str, ...] = tuple()
    caveats: tuple[str, ...] = tuple()


Token = tuple[str, str]


class _Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self._tokens = tokens
        self._index = 0

    def parse(self) -> "_Node":
        node = self._parse_or()
        if self._peek()[0] != "EOF":
            raise ParseError("Unexpected trailing token")
        return node

    def _parse_or(self) -> "_Node":
        node = self._parse_and()
        while self._peek()[0] == "OR":
            self._advance()
            rhs = self._parse_and()
            node = _OrNode(left=node, right=rhs)
        return node

    def _parse_and(self) -> "_Node":
        node = self._parse_with()
        while self._peek()[0] == "AND":
            self._advance()
            rhs = self._parse_with()
            node = _AndNode(left=node, right=rhs)
        return node

    def _parse_with(self) -> "_Node":
        node = self._parse_primary()
        if self._peek()[0] != "WITH":
            return node

        self._advance()
        token_type, token_text = self._advance()
        if token_type != "ID":
            raise ParseError("WITH must be followed by an SPDX exception id")
        if not isinstance(node, _LeafNode):
            raise ParseError("WITH applies only to a simple SPDX license id")
        return _WithNode(base=node, exception=token_text)

    def _parse_primary(self) -> "_Node":
        token_type, token_text = self._advance()
        if token_type == "ID":
            return _LeafNode(license_id=token_text)
        if token_type == "LPAREN":
            node = self._parse_or()
            if self._advance()[0] != "RPAREN":
                raise ParseError("Missing closing ')'")
            return node
        raise ParseError(f"Unexpected token: {token_text!r}")

    def _peek(self) -> Token:
        return self._tokens[self._index]

    def _advance(self) -> Token:
        token = self._tokens[self._index]
        self._index += 1
        return token


class _Node:
    def evaluate(self, mapper: Callable[[str, str | None], EvalResult]) -> EvalResult:
        raise NotImplementedError


@dataclass(frozen=True)
class _LeafNode(_Node):
    license_id: str

    def evaluate(self, mapper: Callable[[str, str | None], EvalResult]) -> EvalResult:
        return mapper(self.license_id, None)


@dataclass(frozen=True)
class _WithNode(_Node):
    base: _LeafNode
    exception: str

    def evaluate(self, mapper: Callable[[str, str | None], EvalResult]) -> EvalResult:
        result = mapper(self.base.license_id, self.exception)
        label = f"{self.base.license_id} WITH {self.exception}"
        return EvalResult(
            tier=result.tier,
            chosen_branch=None,
            label=label,
            reasons=result.reasons,
            caveats=result.caveats,
        )


@dataclass(frozen=True)
class _OrNode(_Node):
    left: _Node
    right: _Node

    def evaluate(self, mapper: Callable[[str, str | None], EvalResult]) -> EvalResult:
        left_result = self.left.evaluate(mapper)
        right_result = self.right.evaluate(mapper)
        chosen_tier = choose_lower_risk(left_result.tier, right_result.tier)

        if chosen_tier == left_result.tier:
            chosen_result = left_result
        else:
            chosen_result = right_result

        return EvalResult(
            tier=chosen_tier,
            chosen_branch=chosen_result.label,
            label=chosen_result.label,
            reasons=chosen_result.reasons,
            caveats=chosen_result.caveats,
        )


@dataclass(frozen=True)
class _AndNode(_Node):
    left: _Node
    right: _Node

    def evaluate(self, mapper: Callable[[str, str | None], EvalResult]) -> EvalResult:
        left_result = self.left.evaluate(mapper)
        right_result = self.right.evaluate(mapper)
        return EvalResult(
            tier=choose_higher_risk(left_result.tier, right_result.tier),
            chosen_branch=None,
            label=None,
            reasons=left_result.reasons + right_result.reasons,
            caveats=tuple(sorted(set(left_result.caveats + right_result.caveats))),
        )


def _tokenize(expression: str) -> list[Token]:
    tokens: list[Token] = []
    index = 0
    while index < len(expression):
        char = expression[index]
        if char.isspace():
            index += 1
            continue

        if char == "(":
            tokens.append(("LPAREN", char))
            index += 1
            continue

        if char == ")":
            tokens.append(("RPAREN", char))
            index += 1
            continue

        start = index
        while index < len(expression) and (
            not expression[index].isspace() and expression[index] not in "()"
        ):
            index += 1
        value = expression[start:index]
        upper_value = value.upper()
        if upper_value in {"AND", "OR", "WITH"}:
            tokens.append((upper_value, upper_value))
        else:
            tokens.append(("ID", value))

    tokens.append(("EOF", ""))
    return tokens


def evaluate_expression(
    expression: str, mapper: Callable[[str, str | None], EvalResult]
) -> EvalResult:
    parser = _Parser(_tokenize(expression))
    tree = parser.parse()
    return tree.evaluate(mapper)
